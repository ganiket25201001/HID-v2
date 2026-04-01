"""Hybrid LightGBM + rule safety classifier for HID Shield threat inference."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping

from lightgbm import Booster, Dataset, train
import numpy as np


class ThreatLevel(str, Enum):
    """Canonical file/device threat levels for the ML subsystem."""

    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    DANGEROUS = "DANGEROUS"
    CRITICAL = "CRITICAL"


@dataclass(slots=True)
class ClassificationResult:
    """Classification output for file-level inference."""

    level: ThreatLevel
    score: float
    confidence: float
    explanation: str
    contributions: dict[str, float]


class LightGBMClassifier:
    """Hybrid classifier using deterministic rules + LightGBM probability.

    Design:
    - Rule engine acts as hard safety guardrail and fast deterministic signal.
    - LightGBM estimates malicious probability from extracted features.
    - Hybrid score combines both, with escalation logic for high-confidence rules.
    """

    _RANK: dict[ThreatLevel, int] = {
        ThreatLevel.SAFE: 0,
        ThreatLevel.SUSPICIOUS: 1,
        ThreatLevel.DANGEROUS: 2,
        ThreatLevel.CRITICAL: 3,
    }

    _FEATURE_ORDER: tuple[str, ...] = (
        "entropy",
        "file_size",
        "extension_mismatch",
        "has_pe_header",
        "suspicious_imports_count",
        "yara_matches",
        "is_script",
        "is_hidden",
        "has_autorun_ref",
        "is_dual_hid",
    )

    _AGGRESSIVE_THRESHOLDS: dict[str, float] = {
        "suspicious": 0.45,
        "dangerous": 0.65,
        "critical": 0.85,
    }

    def __init__(self, model_path: Path | None = None) -> None:
        default_model = Path(__file__).resolve().parent / "models" / "hid_shield_model.txt"
        self._model_path = model_path or default_model
        self._booster: Booster | None = None
        self._load_or_bootstrap_model(self._model_path)

    def classify_features(self, features: Mapping[str, float]) -> ClassificationResult:
        """Classify one file using hybrid rules + LightGBM probability."""
        vector = self._to_model_vector(features)

        # Stage 1: deterministic safety rules.
        rule_score, rule_contributions = self._rule_score(features)
        rule_prob = self._bounded(rule_score / 100.0, 0.0, 1.0)

        # Stage 2: probabilistic model.
        model_prob, model_detail = self._predict_probability(vector)

        # Stage 3: hybrid fusion with aggressive weighting toward high-risk signals.
        risk_signal = self._risk_signal(features)
        hybrid_prob = (0.32 * rule_prob) + (0.55 * model_prob) + (0.13 * risk_signal)
        hybrid_prob = self._bounded(hybrid_prob, 0.0, 1.0)

        # Safety escalation for very strong rule evidence.
        if rule_score >= 82.0:
            hybrid_prob = max(hybrid_prob, 0.92)
        elif rule_score >= 66.0:
            hybrid_prob = max(hybrid_prob, 0.78)

        if risk_signal >= 0.86:
            hybrid_prob = max(hybrid_prob, 0.9)

        final_score = round(self._bounded(hybrid_prob * 100.0, 0.0, 100.0), 3)
        level = self._level_from_score(final_score)

        confidence = round(self._confidence_score(model_prob=model_prob, rule_prob=rule_prob), 4)
        top_feature_notes = self._build_feature_explanation(features, model_detail)
        family_hint = self._family_hint(features)
        contributions = {
            **rule_contributions,
            "rule_score": round(rule_score, 3),
            "rule_probability": round(rule_prob, 4),
            "model_probability": round(model_prob, 4),
            "hybrid_probability": round(hybrid_prob, 4),
            "confidence": confidence,
            "risk_signal": round(risk_signal, 4),
        }
        contributions.update(model_detail)

        explanation = (
            f"AGGRESSIVE_DETECTION Threat={level.value} score={final_score:.3f}; "
            f"model_p={model_prob:.4f}, rule_p={rule_prob:.4f}, hybrid_p={hybrid_prob:.4f}; "
            f"top_signals={top_feature_notes}; likely_family={family_hint}."
        )

        return ClassificationResult(
            level=level,
            score=final_score,
            confidence=confidence,
            explanation=explanation,
            contributions=contributions,
        )

    def classify_file(self, features: Mapping[str, float]) -> dict[str, object]:
        """Convenience file-classification output with confidence and explanation."""
        result = self.classify_features(features)
        return {
            "level": result.level.value,
            "score": result.score,
            "confidence": result.confidence,
            "explanation": result.explanation,
            "contributions": result.contributions,
        }

    def classify_device(self, file_results: Iterable[Mapping[str, object]]) -> dict[str, object]:
        """Classify device-level risk from file-level outputs."""
        rows = list(file_results)
        if not rows:
            return {
                "device_level": ThreatLevel.SAFE.value,
                "max_file_level": ThreatLevel.SAFE.value,
                "weighted_score": 0.0,
                "explanation": "No file classifications available; default SAFE.",
            }

        max_level = ThreatLevel.SAFE
        cumulative = 0.0
        dangerous_or_higher = 0

        for row in rows:
            level = self._parse_level(str(row.get("level", ThreatLevel.SAFE.value)))
            score = self._coerce_float(row.get("score", 0.0))
            cumulative += score
            if self._RANK[level] > self._RANK[max_level]:
                max_level = level
            if self._RANK[level] >= self._RANK[ThreatLevel.DANGEROUS]:
                dangerous_or_higher += 1

        avg_score = cumulative / len(rows)
        weighted_score = round((avg_score * 0.5) + (self._RANK[max_level] * 18.0), 3)

        explanation = (
            f"Device risk uses max-file-risk rule: {max_level.value}. "
            f"{dangerous_or_higher}/{len(rows)} files are DANGEROUS or CRITICAL. "
            f"Weighted support score={weighted_score:.3f}."
        )

        return {
            "device_level": max_level.value,
            "max_file_level": max_level.value,
            "weighted_score": weighted_score,
            "explanation": explanation,
            "file_count": len(rows),
            "dangerous_or_higher_count": dangerous_or_higher,
        }

    def _load_or_bootstrap_model(self, model_path: Path) -> None:
        """Load pre-trained model; fallback to synthetic bootstrap model."""
        if model_path.exists():
            try:
                self._booster = Booster(model_file=str(model_path))
                return
            except Exception:
                self._booster = None

        self._booster = self._train_bootstrap_model()

    def _train_bootstrap_model(self) -> Booster:
        """Train a tiny synthetic baseline model used when no model file exists."""
        training_vectors = [
            [1.5, 2048, 0, 0, 0, 0, 0, 0, 0, 0],
            [2.2, 4096, 0, 0, 0, 0, 0, 0, 0, 0],
            [4.8, 150000, 0, 1, 1, 0, 0, 0, 0, 0],
            [6.7, 300000, 1, 1, 3, 1, 0, 1, 0, 0],
            [7.9, 2000000, 1, 1, 6, 2, 0, 1, 0, 0],
            [7.4, 120000, 0, 0, 0, 1, 1, 1, 1, 1],
            [6.9, 90000, 0, 0, 0, 0, 1, 1, 1, 1],
            [7.8, 850000, 1, 1, 4, 2, 0, 1, 0, 0],
            [3.5, 12000, 0, 0, 0, 0, 1, 0, 0, 0],
            [5.0, 65000, 0, 0, 0, 0, 0, 1, 0, 0],
        ]
        labels = [0, 0, 0, 1, 1, 1, 1, 1, 0, 0]
        dataset = Dataset(
            np.asarray(training_vectors, dtype=np.float64),
            label=np.asarray(labels, dtype=np.float64),
            feature_name=list(self._FEATURE_ORDER),
        )
        params = {
            "objective": "binary",
            "metric": ["binary_logloss"],
            "learning_rate": 0.06,
            "num_leaves": 24,
            "feature_fraction": 0.9,
            "bagging_fraction": 0.9,
            "bagging_freq": 1,
            "min_data_in_leaf": 1,
            "seed": 42,
            "verbose": -1,
        }
        return train(params=params, train_set=dataset, num_boost_round=80)

    def _predict_probability(self, vector: list[float]) -> tuple[float, dict[str, float]]:
        """Predict malicious probability with optional contribution details."""
        details: dict[str, float] = {}
        try:
            if self._booster is not None:
                raw = self._booster.predict([vector])
                value = float(raw[0])

                contrib = self._booster.predict([vector], pred_contrib=True)
                if contrib and len(contrib[0]) >= len(self._FEATURE_ORDER):
                    for idx, name in enumerate(self._FEATURE_ORDER):
                        details[f"contrib_{name}"] = round(float(contrib[0][idx]), 6)
                return self._bounded(value, 0.0, 1.0), details
        except Exception:
            pass

        return 0.5, details

    def _build_feature_explanation(self, features: Mapping[str, float], model_detail: Mapping[str, float]) -> str:
        """Build concise top-signal explanation using model + rule context."""
        scored: list[tuple[str, float]] = []
        for name in self._FEATURE_ORDER:
            contrib_key = f"contrib_{name}"
            contrib = abs(float(model_detail.get(contrib_key, 0.0)))
            baseline = abs(float(features.get(name, 0.0)))

            # Aggressive weighting: prioritize high-risk indicators.
            risk_weight = 1.0
            if name in {"entropy", "suspicious_imports_count", "yara_matches"}:
                risk_weight = 1.8
            elif name in {"extension_mismatch", "has_autorun_ref", "is_hidden"}:
                risk_weight = 1.35

            score = ((contrib * 0.78) + (baseline * 0.22)) * risk_weight
            scored.append((name, score))

        top = [name for name, _ in sorted(scored, key=lambda item: item[1], reverse=True)[:3]]
        return ", ".join(top) if top else "no-strong-signal"

    def _confidence_score(self, *, model_prob: float, rule_prob: float) -> float:
        """Calibrate confidence from probability magnitude and model/rule agreement."""
        magnitude = abs(model_prob - 0.5) * 2.0
        agreement = 1.0 - abs(model_prob - rule_prob)
        confidence = (0.72 * magnitude) + (0.28 * agreement)
        return self._bounded(confidence, 0.0, 1.0)

    def _risk_signal(self, features: Mapping[str, float]) -> float:
        """Compute aggressive risk prior from high-impact suspicious features."""
        entropy = self._bounded(self._coerce_float(features.get("entropy", 0.0)) / 8.0, 0.0, 1.0)
        suspicious_imports = self._bounded(self._coerce_float(features.get("suspicious_imports_count", 0.0)) / 6.0, 0.0, 1.0)
        yara = self._bounded(self._coerce_float(features.get("yara_matches", 0.0)) / 3.0, 0.0, 1.0)
        mismatch = self._bounded(self._coerce_float(features.get("extension_mismatch", 0.0)), 0.0, 1.0)
        autorun = self._bounded(self._coerce_float(features.get("has_autorun_ref", 0.0)), 0.0, 1.0)

        return self._bounded(
            (0.36 * entropy)
            + (0.24 * suspicious_imports)
            + (0.24 * yara)
            + (0.10 * mismatch)
            + (0.06 * autorun),
            0.0,
            1.0,
        )

    def _family_hint(self, features: Mapping[str, float]) -> str:
        """Estimate likely malware family for richer UI explanations."""
        entropy = self._coerce_float(features.get("entropy", 0.0))
        suspicious_imports = self._coerce_float(features.get("suspicious_imports_count", 0.0))
        yara = self._coerce_float(features.get("yara_matches", 0.0))
        is_script = self._binary(self._coerce_float(features.get("is_script", 0.0)))
        is_hidden = self._binary(self._coerce_float(features.get("is_hidden", 0.0)))
        autorun = self._binary(self._coerce_float(features.get("has_autorun_ref", 0.0)))
        is_dual_hid = self._binary(self._coerce_float(features.get("is_dual_hid", 0.0)))

        if autorun and is_script and is_hidden:
            return "LNK/autorun exploit or worm dropper"
        if entropy >= 7.7 and suspicious_imports >= 5.0:
            return "Packed ransomware/trojan loader"
        if is_dual_hid and is_script:
            return "BadUSB HID spoofing payload"
        if is_script and yara >= 1.0:
            return "Obfuscated PowerShell/Cobalt Strike stager"
        if suspicious_imports >= 4.0:
            return "Metasploit shellcode or RAT stager"
        if entropy >= 7.4 and yara >= 2.0:
            return "Packed executable with shellcode behavior"
        return "Suspicious generic malware-like behavior"

    def _to_model_vector(self, features: Mapping[str, float]) -> list[float]:
        return [self._coerce_float(features.get(name, 0.0)) for name in self._FEATURE_ORDER]

    def _rule_score(self, features: Mapping[str, float]) -> tuple[float, dict[str, float]]:
        """Rule safety baseline retained from previous deterministic classifier."""
        entropy = self._bounded(features.get("entropy", 0.0), 0.0, 8.0)
        file_size = max(0.0, features.get("file_size", 0.0))
        extension_mismatch = self._binary(features.get("extension_mismatch", 0.0))
        has_pe_header = self._binary(features.get("has_pe_header", 0.0))
        suspicious_imports_count = max(0.0, features.get("suspicious_imports_count", 0.0))
        yara_matches = max(0.0, features.get("yara_matches", 0.0))
        is_script = self._binary(features.get("is_script", 0.0))
        is_hidden = self._binary(features.get("is_hidden", 0.0))
        has_autorun_ref = self._binary(features.get("has_autorun_ref", 0.0))
        is_dual_hid = self._binary(features.get("is_dual_hid", 0.0))

        contributions = {
            "entropy": round((entropy / 8.0) * 24.0, 3),
            "file_size": round(min(file_size / (1024.0 * 1024.0), 8.0) * 1.25, 3),
            "extension_mismatch": 8.0 * extension_mismatch,
            "has_pe_header": 6.0 * has_pe_header,
            "suspicious_imports_count": round(min(suspicious_imports_count, 6.0) * 4.0, 3),
            "yara_matches": round(min(yara_matches, 3.0) * 10.0, 3),
            "is_script": 6.0 * is_script,
            "is_hidden": 7.0 * is_hidden,
            "has_autorun_ref": 9.0 * has_autorun_ref,
            "is_dual_hid": 5.0 * is_dual_hid,
        }

        combo_boost = 0.0
        if has_pe_header and suspicious_imports_count >= 3.0:
            combo_boost += 8.0
        if is_script and has_autorun_ref:
            combo_boost += 10.0
        if entropy >= 7.6 and yara_matches >= 1.0:
            combo_boost += 12.0
        if is_script and is_hidden and entropy >= 6.8:
            combo_boost += 9.0
        if extension_mismatch and (has_pe_header or yara_matches >= 1.0):
            combo_boost += 7.0
        if suspicious_imports_count >= 5.0 and yara_matches >= 1.0:
            combo_boost += 11.0

        if combo_boost:
            contributions["combination_boost"] = combo_boost

        score = self._bounded(sum(contributions.values()), 0.0, 100.0)
        return round(score, 3), contributions

    def _level_from_score(self, score: float) -> ThreatLevel:
        probability = score / 100.0
        if probability >= self._AGGRESSIVE_THRESHOLDS["critical"]:
            return ThreatLevel.CRITICAL
        if probability >= self._AGGRESSIVE_THRESHOLDS["dangerous"]:
            return ThreatLevel.DANGEROUS
        if probability >= self._AGGRESSIVE_THRESHOLDS["suspicious"]:
            return ThreatLevel.SUSPICIOUS
        return ThreatLevel.SAFE

    def _parse_level(self, raw: str) -> ThreatLevel:
        normalized = raw.strip().upper()
        if normalized in ThreatLevel.__members__:
            return ThreatLevel[normalized]
        return ThreatLevel.SAFE

    def _coerce_float(self, value: object) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    def _bounded(self, value: float, lower: float, upper: float) -> float:
        return max(lower, min(upper, value))

    def _binary(self, value: float) -> float:
        return 1.0 if value >= 0.5 else 0.0

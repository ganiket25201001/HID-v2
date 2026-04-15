"""Production LightGBM classifier used for HID Shield threat inference."""

from __future__ import annotations

import os
import hashlib
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping

from lightgbm import Booster


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
    """Classify file and device risk using model probability plus rule guards."""

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
        self._rule_only_mode = self._should_use_rule_only_mode()
        self._booster: Booster | None = None
        if not self._rule_only_mode:
            self._booster = self._load_model(self._model_path)

    def classify_features(self, features: Mapping[str, float]) -> ClassificationResult:
        """Classify one file using hybrid model and rule signals."""
        vector = self._to_model_vector(features)

        rule_score, rule_contributions = self._rule_score(features)
        rule_prob = self._bounded(rule_score / 100.0, 0.0, 1.0)

        if self._booster is None:
            model_prob = self._rule_model_probability(features)
            model_detail: dict[str, float] = {}
        else:
            model_prob, model_detail = self._predict_probability(vector)

        risk_signal = self._risk_signal(features)
        hybrid_prob = (0.32 * rule_prob) + (0.55 * model_prob) + (0.13 * risk_signal)
        hybrid_prob = self._bounded(hybrid_prob, 0.0, 1.0)

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
            f"Threat={level.value} score={final_score:.3f}; "
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

    def _load_model(self, model_path: Path) -> Booster:
        """Load production model file with integrity verification.

        VULN-008 FIX: Verify SHA-256 checksum of the model file against a
        stored manifest to prevent loading tampered/malicious model files.
        """
        if not model_path.exists():
            raise FileNotFoundError(
                f"LightGBM model file not found: {model_path}. "
                "Run 'python ml/train_model.py' to generate ml/models/hid_shield_model.txt."
            )

        # Verify model integrity against stored checksum.
        checksum_path = model_path.with_suffix(model_path.suffix + ".sha256")
        actual_hash = self._compute_file_hash(model_path)

        if checksum_path.exists():
            expected_hash = checksum_path.read_text(encoding="utf-8").strip().split()[0]
            if actual_hash != expected_hash:
                raise RuntimeError(
                    f"Model integrity check FAILED for {model_path.name}. "
                    f"Expected SHA-256: {expected_hash[:16]}..., "
                    f"Got: {actual_hash[:16]}... "
                    "The model file may have been tampered with. "
                    "Re-run 'python ml/train_model.py' to regenerate."
                )
            print(f"[ML] Model integrity verified: {model_path.name}")
        else:
            # First load — create the checksum file.
            checksum_path.write_text(
                f"{actual_hash}  {model_path.name}\n", encoding="utf-8"
            )
            print(f"[ML] Model checksum created: {checksum_path.name}")

        return Booster(model_file=str(model_path))

    @staticmethod
    def _compute_file_hash(file_path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _should_use_rule_only_mode(self) -> bool:
        """Return True when native LightGBM should be bypassed for stability."""
        env_val = os.getenv("HID_SHIELD_DISABLE_LIGHTGBM", "").strip().lower()
        if env_val in {"1", "true", "yes", "on"}:
            return True

        # LightGBM native wheel in some environments may abort on Python 3.13.
        # Fall back to deterministic rule scoring instead of crashing the process.
        if sys.version_info >= (3, 13):
            return True

        return False

    def _rule_model_probability(self, features: Mapping[str, float]) -> float:
        """Estimate probability without LightGBM native model."""
        entropy = self._bounded(self._coerce_float(features.get("entropy", 0.0)) / 8.0, 0.0, 1.0)
        suspicious_imports = self._bounded(self._coerce_float(features.get("suspicious_imports_count", 0.0)) / 6.0, 0.0, 1.0)
        yara = self._bounded(self._coerce_float(features.get("yara_matches", 0.0)) / 3.0, 0.0, 1.0)
        mismatch = self._bounded(self._coerce_float(features.get("extension_mismatch", 0.0)), 0.0, 1.0)
        pe_header = self._bounded(self._coerce_float(features.get("has_pe_header", 0.0)), 0.0, 1.0)
        script = self._bounded(self._coerce_float(features.get("is_script", 0.0)), 0.0, 1.0)
        hidden = self._bounded(self._coerce_float(features.get("is_hidden", 0.0)), 0.0, 1.0)
        autorun = self._bounded(self._coerce_float(features.get("has_autorun_ref", 0.0)), 0.0, 1.0)

        return self._bounded(
            (0.30 * entropy)
            + (0.18 * suspicious_imports)
            + (0.16 * yara)
            + (0.09 * mismatch)
            + (0.09 * pe_header)
            + (0.07 * script)
            + (0.05 * hidden)
            + (0.06 * autorun),
            0.0,
            1.0,
        )

    def _predict_probability(self, vector: list[float]) -> tuple[float, dict[str, float]]:
        """Predict malicious probability with optional feature contribution details."""
        details: dict[str, float] = {}
        raw = self._booster.predict([vector])
        value = float(raw[0])

        try:
            contrib = self._booster.predict([vector], pred_contrib=True)
            if contrib and len(contrib[0]) >= len(self._FEATURE_ORDER):
                for idx, name in enumerate(self._FEATURE_ORDER):
                    details[f"contrib_{name}"] = round(float(contrib[0][idx]), 6)
        except Exception:
            # Contribution details are optional and should never block inference.
            pass

        return self._bounded(value, 0.0, 1.0), details

    def _build_feature_explanation(self, features: Mapping[str, float], model_detail: Mapping[str, float]) -> str:
        """Build concise top-signal explanation using model + rule context."""
        scored: list[tuple[str, float]] = []
        for name in self._FEATURE_ORDER:
            contrib_key = f"contrib_{name}"
            contrib = abs(float(model_detail.get(contrib_key, 0.0)))
            baseline = abs(float(features.get(name, 0.0)))

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
        """Compute deterministic rule contribution for known suspicious patterns."""
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

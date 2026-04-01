"""Deterministic rule-based fallback classifier for HID Shield."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping


class ThreatLevel(str, Enum):
    """Canonical file/device threat levels for the ML subsystem."""

    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    DANGEROUS = "DANGEROUS"
    CRITICAL = "CRITICAL"


@dataclass(slots=True)
class ClassificationResult:
    """Classification output for a file-level inference."""

    level: ThreatLevel
    score: float
    explanation: str
    contributions: dict[str, float]


class MockClassifier:
    """Deterministic weighted-scoring classifier used for simulation and fallback.

    Scoring policy:
    - Computes weighted risk score from feature vector.
    - Applies deterministic rule boosts for suspicious combinations.
    - Maps score to SAFE / SUSPICIOUS / DANGEROUS / CRITICAL.
    - Device-level risk always follows the max-file-risk rule.
    """

    _RANK: dict[ThreatLevel, int] = {
        ThreatLevel.SAFE: 0,
        ThreatLevel.SUSPICIOUS: 1,
        ThreatLevel.DANGEROUS: 2,
        ThreatLevel.CRITICAL: 3,
    }

    def classify_features(self, features: Mapping[str, float]) -> ClassificationResult:
        """Classify a single file feature dictionary into threat level."""
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

        # Base weighted score components.
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

        # Deterministic interaction boosts for high-confidence combinations.
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

        total_score = sum(contributions.values()) + combo_boost
        total_score = round(self._bounded(total_score, 0.0, 100.0), 3)

        if total_score >= 75.0:
            level = ThreatLevel.CRITICAL
        elif total_score >= 50.0:
            level = ThreatLevel.DANGEROUS
        elif total_score >= 24.0:
            level = ThreatLevel.SUSPICIOUS
        else:
            level = ThreatLevel.SAFE

        explanation = self._build_explanation(level=level, score=total_score, contributions=contributions, combo_boost=combo_boost)
        if combo_boost:
            contributions["combination_boost"] = combo_boost

        return ClassificationResult(
            level=level,
            score=total_score,
            explanation=explanation,
            contributions=contributions,
        )

    def classify_device(self, file_results: Iterable[Mapping[str, object]]) -> dict[str, object]:
        """Classify device-level risk from file-level outputs.

        The top-level rule is strict: device risk equals max file risk.
        Additional weighted score is returned as auxiliary explanation only.
        """
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
        weighted_score = round((avg_score * 0.4) + (self._RANK[max_level] * 20.0), 3)

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

    def _build_explanation(
        self,
        level: ThreatLevel,
        score: float,
        contributions: Mapping[str, float],
        combo_boost: float,
    ) -> str:
        """Build a concise deterministic explanation string."""
        top_signals = sorted(contributions.items(), key=lambda item: item[1], reverse=True)[:3]
        signals_text = ", ".join(f"{name}={value:.2f}" for name, value in top_signals if value > 0.0)
        if not signals_text:
            signals_text = "no strong indicators"

        combo_text = f" combination_boost={combo_boost:.2f}." if combo_boost > 0 else ""
        return (
            f"Threat={level.value} with score={score:.3f}; "
            f"dominant indicators: {signals_text}.{combo_text}"
        )

    def _parse_level(self, raw: str) -> ThreatLevel:
        """Convert raw text into `ThreatLevel`, defaulting safely."""
        normalized = raw.strip().upper()
        if normalized in ThreatLevel.__members__:
            return ThreatLevel[normalized]
        return ThreatLevel.SAFE

    def _coerce_float(self, value: object) -> float:
        """Convert unknown numeric input to float deterministically."""
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    def _bounded(self, value: float, lower: float, upper: float) -> float:
        """Clamp numeric values into a fixed interval."""
        return max(lower, min(upper, value))

    def _binary(self, value: float) -> float:
        """Normalize floating input into strict binary signal value."""
        return 1.0 if value >= 0.5 else 0.0

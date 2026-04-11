"""Main public classification API for HID Shield threat inference."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from PySide6.QtCore import QObject, Signal

from core.event_bus import event_bus
from database.db import get_db
from database.models import AlertSeverity, DeviceEvent, RiskLevel
from database.repository import AlertRepository, FileScanRepository
from ml.feature_extractor import FeatureExtractor
from ml.lightgbm_classifier import LightGBMClassifier, ThreatLevel
from ml.random_forest_classifier import (
    RandomForestThreatClassifier,
    RFThreatLabel,
)
from security.policy_engine import DeviceSnapshot, PolicyEngine


# ---------------------------------------------------------------------------
# Ensemble classification engine
# ---------------------------------------------------------------------------

# Mapping from RF labels → LightGBM ThreatLevel for unified comparison
_RF_TO_THREAT: dict[RFThreatLabel, ThreatLevel] = {
    RFThreatLabel.SAFE: ThreatLevel.SAFE,
    RFThreatLabel.SUSPICIOUS: ThreatLevel.SUSPICIOUS,
    RFThreatLabel.MALICIOUS: ThreatLevel.CRITICAL,
}

_THREAT_RANK: dict[ThreatLevel, int] = {
    ThreatLevel.SAFE: 0,
    ThreatLevel.SUSPICIOUS: 1,
    ThreatLevel.DANGEROUS: 2,
    ThreatLevel.CRITICAL: 3,
}


class EnsembleClassifier:
    """Run LightGBM + RandomForest in ensemble and merge results.

    Decision rules (per user spec):
    - Both must agree on SAFE for a file/device to be SAFE.
    - If they disagree, take the higher risk score as the final result.
    - If one says MALICIOUS and other says SAFE → classify as SUSPICIOUS.
    - The minimum classification when models disagree is SUSPICIOUS.
    """

    def __init__(self) -> None:
        self._lgbm = LightGBMClassifier()
        try:
            self._rf = RandomForestThreatClassifier()
            self._rf_available = True
            print("[ENSEMBLE] Both LightGBM and RandomForest models loaded.")
        except Exception as e:
            self._rf = None  # type: ignore[assignment]
            self._rf_available = False
            print(f"[ENSEMBLE] RandomForest unavailable ({e}), using LightGBM only.")

    def classify_features(
        self, lgbm_features: Mapping[str, float], rf_features: dict[str, float]
    ) -> dict[str, Any]:
        """Run both models and return merged ensemble result.

        Parameters
        ----------
        lgbm_features:
            Feature dict for LightGBM (10-feature vector).
        rf_features:
            Feature dict for RandomForest (8-feature vector).

        Returns
        -------
        dict
            Merged result with keys: level, score, confidence, explanation,
            contributions, lgbm_result, rf_result.
        """
        # --- LightGBM ---
        lgbm_result = self._lgbm.classify_features(lgbm_features)
        lgbm_level = lgbm_result.level
        lgbm_score = lgbm_result.score

        # --- RandomForest ---
        if self._rf_available and self._rf is not None:
            rf_result = self._rf.classify(rf_features)
            rf_level = _RF_TO_THREAT.get(rf_result.label, ThreatLevel.SAFE)
            rf_confidence = rf_result.confidence

            # --- Ensemble merge ---
            final_level = self._merge_levels(lgbm_level, rf_level)
            # Score: weighted average of both
            rf_score_normalized = rf_confidence * 100.0
            ensemble_score = round((lgbm_score * 0.55) + (rf_score_normalized * 0.45), 3)
            ensemble_confidence = round((lgbm_result.confidence * 0.55 + rf_confidence * 0.45), 4)

            explanation = (
                f"ENSEMBLE: final={final_level.value}, score={ensemble_score:.3f}; "
                f"LightGBM={lgbm_level.value}(s={lgbm_score:.3f}), "
                f"RandomForest={rf_result.label.value}(c={rf_confidence:.4f}); "
                f"{lgbm_result.explanation}"
            )

            return {
                "level": final_level.value,
                "score": ensemble_score,
                "confidence": ensemble_confidence,
                "explanation": explanation,
                "contributions": lgbm_result.contributions,
                "lgbm_level": lgbm_level.value,
                "lgbm_score": lgbm_score,
                "rf_level": rf_result.label.value,
                "rf_confidence": rf_confidence,
                "rf_probabilities": rf_result.probabilities,
            }
        else:
            # Fallback: LightGBM only
            return {
                "level": lgbm_level.value,
                "score": lgbm_score,
                "confidence": float(lgbm_result.confidence),
                "explanation": lgbm_result.explanation,
                "contributions": lgbm_result.contributions,
                "lgbm_level": lgbm_level.value,
                "lgbm_score": lgbm_score,
                "rf_level": None,
                "rf_confidence": None,
                "rf_probabilities": None,
            }

    def _merge_levels(self, lgbm: ThreatLevel, rf: ThreatLevel) -> ThreatLevel:
        """Merge two threat levels per the ensemble decision rules.

        - Both SAFE → SAFE
        - One SAFE, one anything higher → at least SUSPICIOUS
        - Otherwise → take the higher risk level
        """
        lgbm_rank = _THREAT_RANK[lgbm]
        rf_rank = _THREAT_RANK[rf]

        # Both agree on SAFE
        if lgbm_rank == 0 and rf_rank == 0:
            return ThreatLevel.SAFE

        # Disagreement: one is SAFE, other isn't → minimum SUSPICIOUS
        if lgbm_rank == 0 or rf_rank == 0:
            higher = max(lgbm_rank, rf_rank)
            # If one says MALICIOUS/CRITICAL and other says SAFE → SUSPICIOUS
            return ThreatLevel.SUSPICIOUS if higher >= 2 else ThreatLevel.SUSPICIOUS

        # Both agree on non-SAFE: take the higher risk
        return lgbm if lgbm_rank >= rf_rank else rf

    def classify_device(self, file_results: list[dict[str, Any]]) -> dict[str, Any]:
        """Delegate device-level classification to LightGBM backend."""
        return self._lgbm.classify_device(file_results)


class Classifier(QObject):
    """Classify file and device threats and integrate with scan event pipeline."""

    file_classified = Signal(dict)
    device_classified = Signal(dict)

    _THREAT_TO_RISK: dict[ThreatLevel, str] = {
        ThreatLevel.SAFE: RiskLevel.SAFE.value,
        ThreatLevel.SUSPICIOUS: RiskLevel.MEDIUM.value,
        ThreatLevel.DANGEROUS: RiskLevel.HIGH.value,
        ThreatLevel.CRITICAL: RiskLevel.CRITICAL.value,
    }

    def __init__(self, auto_subscribe: bool = True) -> None:
        super().__init__()
        self._feature_extractor = FeatureExtractor()
        self._backend = LightGBMClassifier()
        self._policy_engine = PolicyEngine()

        # Check AI integration flag
        self._ai_enabled = False
        try:
            import yaml
            cfg_path = Path(__file__).resolve().parent.parent / "config.yaml"
            if cfg_path.exists():
                with cfg_path.open() as f:
                    cfg = yaml.safe_load(f) or {}
                    self._ai_enabled = bool(cfg.get("policy", {}).get("enable_ai_agent", False))
        except Exception:
            pass
            
        if self._ai_enabled:
            from ai_agent.explanation_agent import ExplanationAgent
            self._ai_agent = ExplanationAgent()
        else:
            self._ai_agent = None

        if auto_subscribe:
            event_bus.scan_completed.connect(self._on_scan_completed)

    def classify_file(
        self,
        scan_result: Mapping[str, Any] | Any,
        device_context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Classify one file result and emit threat signal when necessary."""
        features = self._feature_extractor.build_feature_dict(
            scan_result=scan_result,
            device_context=device_context,
        )
        result = self._backend.classify_features(features)

        payload = {
            "level": result.level.value,
            "score": result.score,
            "confidence": float(result.confidence),
            "confidence_pct": round(float(result.confidence) * 100.0, 2),
            "explanation": result.explanation,
            "feature_vector": features,
            "contributions": result.contributions,
            "risk_level": self._THREAT_TO_RISK[result.level],
            "file_name": self._extract_name(scan_result),
            "file_path": self._extract_path(scan_result),
        }

        if result.level in {ThreatLevel.DANGEROUS, ThreatLevel.CRITICAL}:
            event_bus.threat_detected.emit(
                {
                    "scope": "file",
                    "file_name": payload["file_name"],
                    "file_path": payload["file_path"],
                    "threat_level": result.level.value,
                    "risk_level": payload["risk_level"],
                    "score": result.score,
                    "confidence": float(result.confidence),
                    "confidence_pct": round(float(result.confidence) * 100.0, 2),
                    "explanation": result.explanation,
                }
            )

        self.file_classified.emit(payload)
        return payload

    def classify_device(
        self,
        *,
        device_event_id: int,
        scan_summary: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Classify device-level risk using max-file-risk rule and persistence hooks."""
        summary = dict(scan_summary or {})
        rows = summary.get("files")
        if not isinstance(rows, list) or not rows:
            rows = self._load_rows_from_repository(device_event_id)

        device_context = summary.get("device") if isinstance(summary.get("device"), Mapping) else {}
        file_classifications = [
            self.classify_file(scan_result=row, device_context=device_context)
            for row in rows
            if isinstance(row, Mapping)
        ]

        device_result = self._backend.classify_device(file_classifications)
        max_level = ThreatLevel(device_result["device_level"])
        mapped_risk = self._THREAT_TO_RISK[max_level]

        policy_advice = self._evaluate_policy_advice(
            device_context=device_context,
            file_classifications=file_classifications,
        )

        result_payload = {
            "device_event_id": int(device_event_id),
            "device_level": device_result["device_level"],
            "risk_level": mapped_risk,
            "max_file_level": device_result["max_file_level"],
            "weighted_score": float(device_result["weighted_score"]),
            "explanation": str(device_result["explanation"]),
            "policy_advice": policy_advice,
            "file_count": int(device_result.get("file_count", 0)),
            "dangerous_or_higher_count": int(device_result.get("dangerous_or_higher_count", 0)),
            "files": file_classifications,
        }

        self._persist_device_risk(device_event_id=device_event_id, result_payload=result_payload)
        self._emit_device_threat_if_needed(result_payload)
        
        if self._ai_agent:
            self._ai_agent.request_explanation(event_id=int(device_event_id), payload=result_payload)
            
        self.device_classified.emit(result_payload)
        return result_payload

    def _on_scan_completed(self, device_event_id: int, summary: dict[str, Any]) -> None:
        """Auto-classify every completed scan emitted by FileScanner."""
        try:
            self.classify_device(device_event_id=int(device_event_id), scan_summary=summary)
        except Exception as exc:  # pragma: no cover
            event_bus.error_occurred.emit(f"ML classification failed for event #{device_event_id}: {exc}")

    def _load_rows_from_repository(self, device_event_id: int) -> list[dict[str, Any]]:
        """Load scan rows from repository when event payload does not include them."""
        with get_db() as session:
            records = FileScanRepository.get_scans_for_event(device_event_id, session=session)
            return [
                {
                    "file_path": row.file_path,
                    "file_name": row.file_name,
                    "size": row.file_size_bytes or 0,
                    "sha256": row.sha256_hash,
                    "md5": row.md5_hash,
                    "is_malicious": row.is_malicious,
                    "threat_name": row.threat_name,
                    "risk_level": row.risk_level,
                    "notes": row.notes,
                    "entropy": 0.0,
                    "heuristics": {},
                    "pe": {},
                }
                for row in records
            ]

    def _persist_device_risk(self, device_event_id: int, result_payload: Mapping[str, Any]) -> None:
        """Persist classified device risk and optional alert records."""
        with get_db() as session:
            event = session.get(DeviceEvent, int(device_event_id))
            if event is not None:
                event.risk_level = str(result_payload.get("risk_level", RiskLevel.SAFE.value))
                event.notes = str(result_payload.get("explanation", ""))
                session.flush()

            threat_level = str(result_payload.get("device_level", ThreatLevel.SAFE.value))
            if threat_level in {ThreatLevel.DANGEROUS.value, ThreatLevel.CRITICAL.value}:
                AlertRepository.create_alert(
                    session,
                    title="ML classifier escalated USB device risk",
                    message=(
                        f"Device event #{device_event_id} classified as {threat_level}. "
                        f"{result_payload.get('explanation', '')}"
                    ),
                    severity=(AlertSeverity.CRITICAL.value if threat_level == ThreatLevel.CRITICAL.value else AlertSeverity.WARNING.value),
                    category="file_scan",
                    device_event_id=int(device_event_id),
                    is_simulated=False,
                    source="ml.classifier",
                )

    def _evaluate_policy_advice(
        self,
        *,
        device_context: Mapping[str, Any],
        file_classifications: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Get policy-engine recommendation aligned with ML output."""
        max_entropy = max(
            (float(file_row.get("feature_vector", {}).get("entropy", 0.0)) for file_row in file_classifications),
            default=0.0,
        )
        malicious_count = sum(
            1
            for file_row in file_classifications
            if str(file_row.get("level", ThreatLevel.SAFE.value))
            in {ThreatLevel.DANGEROUS.value, ThreatLevel.CRITICAL.value}
        )

        snapshot = DeviceSnapshot(
            device_name=str(device_context.get("device_name", "Unknown Device")),
            vendor_id=self._as_optional_str(device_context.get("vendor_id")),
            product_id=self._as_optional_str(device_context.get("product_id")),
            serial=self._as_optional_str(device_context.get("serial_number")),
            manufacturer=self._as_optional_str(device_context.get("manufacturer")),
            device_type=str(device_context.get("device_type", "storage")),
            entropy_score=(max_entropy / 8.0 if max_entropy > 1.0 else max_entropy),
            keystroke_rate=None,
            malicious_file_count=malicious_count,
            total_file_count=len(file_classifications),
            is_simulated=False,
        )

        evaluated = self._policy_engine.evaluate(snapshot)
        return {
            "recommended_action": str(evaluated.recommended_action),
            "policy_risk_level": str(evaluated.risk_level),
            "confidence": float(evaluated.confidence),
            "triggered_rules": list(evaluated.triggered_rules),
        }

    def _emit_device_threat_if_needed(self, result_payload: Mapping[str, Any]) -> None:
        """Emit high-severity device threat events for UI and alert surfaces."""
        level = str(result_payload.get("device_level", ThreatLevel.SAFE.value))
        if level not in {ThreatLevel.DANGEROUS.value, ThreatLevel.CRITICAL.value}:
            return

        event_bus.threat_detected.emit(
            {
                "scope": "device",
                "device_event_id": int(result_payload.get("device_event_id", 0)),
                "threat_level": level,
                "risk_level": str(result_payload.get("risk_level", RiskLevel.SAFE.value)),
                "weighted_score": float(result_payload.get("weighted_score", 0.0)),
                "explanation": str(result_payload.get("explanation", "")),
            }
        )

    def _extract_name(self, scan_result: Mapping[str, Any] | Any) -> str:
        """Get human-readable file name from dict-like or object input."""
        if isinstance(scan_result, Mapping):
            return str(scan_result.get("file_name") or Path(str(scan_result.get("file_path", "unknown.bin"))).name)
        if hasattr(scan_result, "file_name"):
            return str(getattr(scan_result, "file_name"))
        if hasattr(scan_result, "file_path"):
            return Path(str(getattr(scan_result, "file_path"))).name
        return "unknown.bin"

    def _extract_path(self, scan_result: Mapping[str, Any] | Any) -> str:
        """Get file path from dict-like or object input safely."""
        if isinstance(scan_result, Mapping):
            return str(scan_result.get("file_path") or scan_result.get("file_name") or "unknown.bin")
        if hasattr(scan_result, "file_path"):
            return str(getattr(scan_result, "file_path"))
        if hasattr(scan_result, "file_name"):
            return str(getattr(scan_result, "file_name"))
        return "unknown.bin"

    def _as_optional_str(self, value: Any) -> str | None:
        """Normalize optional scalar value to trimmed string."""
        if value is None:
            return None
        text = str(value).strip()
        return text if text else None

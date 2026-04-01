"""Feature extraction utilities for HID Shield ML threat classification."""

from __future__ import annotations

import mimetypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


@dataclass(slots=True)
class ExtractedFeatures:
    """Strongly-typed representation of the model feature vector."""

    entropy: float
    file_size: float
    extension_mismatch: float
    has_pe_header: float
    suspicious_imports_count: float
    yara_matches: float
    is_script: float
    is_hidden: float
    has_autorun_ref: float
    is_dual_hid: float

    def to_vector(self) -> list[float]:
        """Return features in the required canonical model order."""
        return [
            self.entropy,
            self.file_size,
            self.extension_mismatch,
            self.has_pe_header,
            self.suspicious_imports_count,
            self.yara_matches,
            self.is_script,
            self.is_hidden,
            self.has_autorun_ref,
            self.is_dual_hid,
        ]

    def to_dict(self) -> dict[str, float]:
        """Return features as a named dictionary."""
        return {
            "entropy": self.entropy,
            "file_size": self.file_size,
            "extension_mismatch": self.extension_mismatch,
            "has_pe_header": self.has_pe_header,
            "suspicious_imports_count": self.suspicious_imports_count,
            "yara_matches": self.yara_matches,
            "is_script": self.is_script,
            "is_hidden": self.is_hidden,
            "has_autorun_ref": self.has_autorun_ref,
            "is_dual_hid": self.is_dual_hid,
        }


class FeatureExtractor:
    """Build deterministic feature vectors from scan results.

    Required feature order:
    [entropy, file_size, extension_mismatch, has_pe_header,
     suspicious_imports_count, yara_matches, is_script,
     is_hidden, has_autorun_ref, is_dual_hid]
    """

    FEATURE_ORDER: tuple[str, ...] = (
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

    _SCRIPT_EXTENSIONS: frozenset[str] = frozenset(
        {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh", ".hta", ".wsf", ".scr"}
    )
    _PE_EXTENSIONS: frozenset[str] = frozenset({".exe", ".dll", ".sys", ".ocx", ".com", ".scr"})

    def extract(
        self,
        scan_result: Any,
        device_context: Mapping[str, Any] | None = None,
    ) -> ExtractedFeatures:
        """Extract typed feature set from one file scan result.

        Parameters
        ----------
        scan_result:
            Either a dictionary-like scan payload or an ORM-like object.
        device_context:
            Optional dictionary containing device metadata.

        Returns
        -------
        ExtractedFeatures
            Deterministically extracted feature values.
        """
        row = self._as_dict(scan_result)
        file_path = Path(str(row.get("file_path") or row.get("file_name") or "unknown.bin"))
        suffix = file_path.suffix.lower()

        entropy = self._safe_float(row.get("entropy"), default=0.0)
        file_size = self._safe_float(
            row.get("size", row.get("file_size_bytes", 0.0)),
            default=0.0,
        )

        mime_type = str(row.get("mime_type") or mimetypes.guess_type(str(file_path))[0] or "")
        extension_mismatch = self._extension_mismatch_score(suffix=suffix, mime_type=mime_type)

        pe_block = row.get("pe") if isinstance(row.get("pe"), Mapping) else {}
        has_pe_header = 1.0 if bool(pe_block.get("is_pe", suffix in self._PE_EXTENSIONS)) else 0.0

        suspicious_imports = pe_block.get("suspicious_apis") if isinstance(pe_block, Mapping) else []
        suspicious_imports_count = float(len(suspicious_imports)) if isinstance(suspicious_imports, list) else 0.0

        heuristics = row.get("heuristics") if isinstance(row.get("heuristics"), Mapping) else {}
        yara_hits = heuristics.get("yara_hits") if isinstance(heuristics, Mapping) else []
        yara_matches = float(len(yara_hits)) if isinstance(yara_hits, list) else 0.0

        is_script = 1.0 if suffix in self._SCRIPT_EXTENSIONS else 0.0
        is_hidden = 1.0 if any(part.startswith(".") for part in file_path.parts) else 0.0
        has_autorun_ref = 1.0 if "autorun" in file_path.name.lower() else 0.0

        # Device-level structural hint from upstream scanner/device context.
        context = dict(device_context or {})
        device_type = str(context.get("device_type", "")).lower()
        dual_flag = bool(context.get("is_dual_hid", False))
        is_dual_hid = 1.0 if dual_flag or "composite" in device_type or "dual" in device_type else 0.0

        return ExtractedFeatures(
            entropy=round(entropy, 4),
            file_size=max(0.0, file_size),
            extension_mismatch=extension_mismatch,
            has_pe_header=has_pe_header,
            suspicious_imports_count=suspicious_imports_count,
            yara_matches=yara_matches,
            is_script=is_script,
            is_hidden=is_hidden,
            has_autorun_ref=has_autorun_ref,
            is_dual_hid=is_dual_hid,
        )

    def build_feature_vector(
        self,
        scan_result: Any,
        device_context: Mapping[str, Any] | None = None,
    ) -> list[float]:
        """Build the exact ordered feature vector expected by the classifier."""
        return self.extract(scan_result=scan_result, device_context=device_context).to_vector()

    def build_feature_dict(
        self,
        scan_result: Any,
        device_context: Mapping[str, Any] | None = None,
    ) -> dict[str, float]:
        """Build named feature dictionary for scoring and diagnostics."""
        return self.extract(scan_result=scan_result, device_context=device_context).to_dict()

    def build_model_vector(
        self,
        scan_result: Any,
        device_context: Mapping[str, Any] | None = None,
    ) -> list[float]:
        """Return model-ready vector (alias for probability model compatibility)."""
        return self.build_feature_vector(scan_result=scan_result, device_context=device_context)

    def build_probability_payload(
        self,
        scan_result: Any,
        device_context: Mapping[str, Any] | None = None,
    ) -> dict[str, object]:
        """Return payload used by probabilistic classifiers.

        Includes ordered names and values so gradient-boosting models can map
        consistent feature positions to human-readable explanations.
        """
        vector = self.build_model_vector(scan_result=scan_result, device_context=device_context)
        return {
            "feature_order": list(self.FEATURE_ORDER),
            "feature_vector": vector,
            "feature_dict": dict(zip(self.FEATURE_ORDER, vector)),
        }

    def _extension_mismatch_score(self, suffix: str, mime_type: str) -> float:
        """Compute extension vs MIME mismatch indicator (0 or 1)."""
        if not mime_type:
            return 0.0

        if suffix in {".txt", ".md", ".csv", ".json"} and mime_type.startswith("application/"):
            return 1.0
        if suffix in self._PE_EXTENSIONS and mime_type.startswith("text/"):
            return 1.0
        if suffix in {".jpg", ".jpeg", ".png", ".gif"} and mime_type.startswith("application/"):
            return 1.0
        return 0.0

    def _as_dict(self, value: Any) -> dict[str, Any]:
        """Convert dictionary-like or ORM-like input into a simple dictionary."""
        if isinstance(value, Mapping):
            return dict(value)

        # ORM-safe field extraction for FileScanResult-like objects.
        attributes = (
            "file_path",
            "file_name",
            "file_size_bytes",
            "sha256_hash",
            "md5_hash",
            "is_malicious",
            "threat_name",
            "risk_level",
            "notes",
        )
        payload: dict[str, Any] = {}
        for attr in attributes:
            if hasattr(value, attr):
                payload[attr] = getattr(value, attr)

        # Optional scanner-enriched fields.
        for optional_attr in ("entropy", "mime_type", "heuristics", "pe", "feature_vector"):
            if hasattr(value, optional_attr):
                payload[optional_attr] = getattr(value, optional_attr)

        return payload

    def _safe_float(self, value: Any, default: float = 0.0) -> float:
        """Safely coerce unknown values into deterministic float numbers."""
        try:
            if value is None:
                return default
            return float(value)
        except (TypeError, ValueError):
            return default

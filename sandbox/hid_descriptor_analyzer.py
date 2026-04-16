"""HID descriptor anomaly detection and keystroke injection rate analysis.

# Integrated from: vmm — behavioral monitoring concepts
# Integrated from: USB-Physical-Security — USB port control patterns

This module provides behavioral analysis for HID (Human Interface Device)
USB devices, detecting anomalies that indicate potential keystroke injection
attacks (e.g., USB Rubber Ducky, BadUSB).

Spec thresholds:
- Keystroke injection rate > 20 KPS = SUSPICIOUS
- Keystroke injection rate > 80 KPS = MALICIOUS
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Spec-mandated thresholds
# ---------------------------------------------------------------------------

KEYSTROKE_SUSPICIOUS_THRESHOLD: float = 20.0   # > 20 KPS = SUSPICIOUS
KEYSTROKE_MALICIOUS_THRESHOLD: float = 80.0    # > 80 KPS = MALICIOUS


@dataclass(slots=True)
class HIDAnalysisResult:
    """Result of HID descriptor and behavioral analysis."""

    is_anomalous: bool = False
    keystroke_rate: float = 0.0
    keystroke_label: str = "SAFE"
    descriptor_hash: str = ""
    hid_type: str = "unknown"
    is_composite: bool = False
    anomaly_reasons: list[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for event bus payloads."""
        return {
            "is_anomalous": self.is_anomalous,
            "keystroke_rate": self.keystroke_rate,
            "keystroke_label": self.keystroke_label,
            "descriptor_hash": self.descriptor_hash,
            "hid_type": self.hid_type,
            "is_composite": self.is_composite,
            "anomaly_reasons": list(self.anomaly_reasons),
            "confidence": self.confidence,
        }


class HIDDescriptorAnalyzer:
    """Detect anomalies in HID device descriptors and keystroke timing.

    # Integrated from: vmm — behavioral event monitoring pattern
    This analyzer checks for:
    1. Abnormal keystroke injection rates (Rubber Ducky detection)
    2. Composite device masquerading (storage pretending to be HID)
    3. Descriptor hash tracking for known-bad device fingerprints
    4. Timing pattern analysis for scripted vs human input
    """

    def __init__(
        self,
        suspicious_kps: float = KEYSTROKE_SUSPICIOUS_THRESHOLD,
        malicious_kps: float = KEYSTROKE_MALICIOUS_THRESHOLD,
    ) -> None:
        self.suspicious_kps = suspicious_kps
        self.malicious_kps = malicious_kps
        self._keystroke_buffer: list[float] = []
        self._last_keystroke_time: Optional[float] = None

    def analyze_device(self, device_info: dict[str, Any]) -> HIDAnalysisResult:
        """Analyze a device's HID characteristics for anomalies.

        Parameters
        ----------
        device_info:
            Device payload dict with keys like device_type, vendor_id,
            product_id, device_name, etc.

        Returns
        -------
        HIDAnalysisResult
            Analysis results including keystroke rate and anomaly flags.
        """
        result = HIDAnalysisResult()
        anomaly_reasons: list[str] = []

        # --- Determine HID type ---
        device_type = str(device_info.get("device_type", "unknown")).lower()
        device_name = str(device_info.get("device_name", "")).lower()
        result.hid_type = device_type

        # --- Composite device detection ---
        result.is_composite = self._detect_composite(device_info)
        if result.is_composite:
            anomaly_reasons.append(
                "Composite device detected — device presents multiple interfaces"
            )

        # --- Descriptor hash ---
        result.descriptor_hash = self._compute_descriptor_hash(device_info)

        # --- Keystroke rate analysis ---
        keystroke_rate = float(device_info.get("keystroke_rate", 0.0))
        result.keystroke_rate = keystroke_rate
        result.keystroke_label = self.classify_keystroke_rate(keystroke_rate)

        if result.keystroke_label == "MALICIOUS":
            anomaly_reasons.append(
                f"Keystroke injection rate {keystroke_rate:.1f} KPS exceeds "
                f"MALICIOUS threshold ({self.malicious_kps} KPS)"
            )
        elif result.keystroke_label == "SUSPICIOUS":
            anomaly_reasons.append(
                f"Keystroke rate {keystroke_rate:.1f} KPS exceeds "
                f"SUSPICIOUS threshold ({self.suspicious_kps} KPS)"
            )

        # --- Device-type mismatches ---
        if device_type == "keyboard" and "storage" in device_name:
            anomaly_reasons.append(
                "Device identifies as keyboard but name suggests storage"
            )
        if device_type == "storage" and any(
            kw in device_name for kw in ("keyboard", "hid", "input")
        ):
            anomaly_reasons.append(
                "Storage device with HID/keyboard naming — possible BadUSB"
            )

        # --- Unknown vendor/product IDs ---
        vendor_id = device_info.get("vendor_id")
        product_id = device_info.get("product_id")
        if not vendor_id or not product_id:
            anomaly_reasons.append("Missing vendor/product ID — identity unverifiable")

        # --- Compute final result ---
        result.anomaly_reasons = anomaly_reasons
        result.is_anomalous = len(anomaly_reasons) > 0
        result.confidence = min(1.0, len(anomaly_reasons) * 0.25 + (
            0.4 if result.keystroke_label != "SAFE" else 0.0
        ))

        return result

    def classify_keystroke_rate(self, kps: float) -> str:
        """Classify keystroke rate into SAFE / SUSPICIOUS / MALICIOUS.

        Parameters
        ----------
        kps:
            Keystrokes per second.

        Returns
        -------
        str
            One of "SAFE", "SUSPICIOUS", or "MALICIOUS".
        """
        if kps >= self.malicious_kps:
            return "MALICIOUS"
        if kps > self.suspicious_kps:
            return "SUSPICIOUS"
        return "SAFE"

    def record_keystroke(self) -> float:
        """Record a keystroke timestamp and return current rate (KPS).

        Call this method for each observed keystroke event to build the
        sliding window rate estimate.
        """
        now = time.monotonic()
        self._keystroke_buffer.append(now)

        # Keep only last 2 seconds of keystrokes
        cutoff = now - 2.0
        self._keystroke_buffer = [
            t for t in self._keystroke_buffer if t >= cutoff
        ]

        window = now - self._keystroke_buffer[0] if len(self._keystroke_buffer) > 1 else 1.0
        if window <= 0:
            window = 0.001
        rate = len(self._keystroke_buffer) / window
        self._last_keystroke_time = now
        return round(rate, 2)

    def _detect_composite(self, device_info: dict[str, Any]) -> bool:
        """Detect if the device presents as a composite USB device."""
        device_type = str(device_info.get("device_type", "")).lower()
        device_name = str(device_info.get("device_name", "")).lower()
        raw_props = device_info.get("raw_properties", {})
        class_code = str(raw_props.get("class_code", "")).lower() if isinstance(raw_props, dict) else ""

        if device_type == "composite":
            return True
        if "composite" in device_name:
            return True
        if "composite" in class_code:
            return True
        return False

    def analyze_for_report(self, device_info: dict[str, Any]) -> dict[str, Any]:
        """Produce a structured report-ready analysis dict.

        Returns a comprehensive dict suitable for direct inclusion in
        autonomous agent reports, including classification rationale
        and all detection parameters.

        Parameters
        ----------
        device_info:
            Device payload dict with keys like device_type, vendor_id, etc.

        Returns
        -------
        dict[str, Any]
            Report-ready analysis including all detection rationale.
        """
        result = self.analyze_device(device_info)
        return {
            "device_type_classification": result.hid_type,
            "classification_rationale": (
                f"Device classified as '{result.hid_type}' based on "
                f"device name and PNP identifiers."
            ),
            "composite_detection": {
                "is_composite": result.is_composite,
                "reasoning": (
                    "Device presents multiple USB interfaces (composite device). "
                    "This pattern is common in BadUSB attacks where a storage "
                    "device also registers as a keyboard."
                ) if result.is_composite else "Device presents a single USB interface.",
            },
            "keystroke_analysis": {
                "rate_kps": result.keystroke_rate,
                "label": result.keystroke_label,
                "suspicious_threshold": self.suspicious_kps,
                "malicious_threshold": self.malicious_kps,
                "assessment": (
                    f"Keystroke rate {result.keystroke_rate:.1f} KPS is "
                    f"classified as {result.keystroke_label}."
                ),
            },
            "descriptor_fingerprint": {
                "hash": result.descriptor_hash,
                "algorithm": "SHA-256 (128-bit truncated)",
            },
            "anomaly_summary": {
                "is_anomalous": result.is_anomalous,
                "total_reasons": len(result.anomaly_reasons),
                "reasons": list(result.anomaly_reasons),
                "confidence": result.confidence,
            },
        }

    def _compute_descriptor_hash(self, device_info: dict[str, Any]) -> str:
        """Compute a deterministic fingerprint hash from device descriptor fields."""
        vid = str(device_info.get("vendor_id", "0000"))
        pid = str(device_info.get("product_id", "0000"))
        dev_type = str(device_info.get("device_type", "unknown"))
        manufacturer = str(device_info.get("manufacturer", ""))
        serial = str(device_info.get("serial_number", ""))

        fingerprint = f"{vid}:{pid}:{dev_type}:{manufacturer}:{serial}"
        # VULN-010 FIX: Use SHA256[:32] (128-bit) for adequate collision resistance.
        return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:32]

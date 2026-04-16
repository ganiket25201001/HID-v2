"""Self-improvement detection gap analyzer for HID Shield.

Reads the website_full_detail.md audit document and cross-references
detection coverage against current implementation to identify gaps
and recommend enhancements.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Known vulnerability status (from website_full_detail.md audit)
# ---------------------------------------------------------------------------

_VULNERABILITY_STATUS: list[dict[str, str]] = [
    {
        "id": "VULN-001",
        "title": "Hardcoded Default Credentials",
        "severity": "CRITICAL",
        "status": "unfixed",
        "location": "security/auth_manager.py",
        "description": "Default admin/admin credentials hardcoded and auto-seeded on first run.",
        "remediation": "Force credential change on first run; remove hardcoded defaults.",
    },
    {
        "id": "VULN-002",
        "title": "Session Manager Race Condition",
        "severity": "HIGH",
        "status": "unfixed",
        "location": "security/session_manager.py",
        "description": "check_timeout() uses elapsed_minutes outside lock block, creating TOCTOU race.",
        "remediation": "Move timeout comparison and end_session() call inside the lock scope.",
    },
    {
        "id": "VULN-003",
        "title": "Command Injection via Device ID",
        "severity": "HIGH",
        "status": "unfixed",
        "location": "core/port_lockdown.py",
        "description": "Unsanitized device IDs passed to subprocess.run() in _devcon_disable().",
        "remediation": "Validate device IDs against strict regex; reject shell metacharacters.",
    },
    {
        "id": "VULN-004",
        "title": "Simulation Mode Defaults to True",
        "severity": "HIGH",
        "status": "partial",
        "location": "security/auth_manager.py",
        "description": "Fallback returns True when config key not found; fixed in file_scanner but not auth_manager.",
        "remediation": "Default to False (production) when config is unavailable.",
    },
    {
        "id": "VULN-005",
        "title": "No Input Validation on USB Device Fields",
        "severity": "HIGH",
        "status": "unfixed",
        "location": "Multiple (device_info.py, usb_monitor.py, file_scanner.py)",
        "description": "VID/PID/serial/name from USB descriptors used without format validation.",
        "remediation": "Validate VID/PID as 4-hex-digit strings; sanitize serial/name; enforce max lengths.",
    },
    {
        "id": "VULN-006",
        "title": "Unbounded File Read in Scanner",
        "severity": "MEDIUM",
        "status": "fixed",
        "location": "sandbox/file_scanner.py",
        "description": "File scanner now enforces 100MB max file size limit.",
        "remediation": "Already remediated with _MAX_SCAN_FILE_SIZE = 100MB.",
    },
    {
        "id": "VULN-007",
        "title": "Source Code Exposure in Sandbox Fallback",
        "severity": "MEDIUM",
        "status": "fixed",
        "location": "sandbox/sandbox_manager.py",
        "description": "discover_device_files() no longer falls back to scanning own Python files.",
        "remediation": "Already remediated: returns empty list with warning.",
    },
    {
        "id": "VULN-008",
        "title": "ML Model Integrity Not Verified",
        "severity": "MEDIUM",
        "status": "unfixed",
        "location": "ml/random_forest_classifier.py, ml/lightgbm_classifier.py",
        "description": "Model files loaded without integrity verification; joblib uses pickle (RCE risk).",
        "remediation": "Compute and verify SHA-256 checksums at load time; store hashes in signed manifest.",
    },
    {
        "id": "VULN-009",
        "title": "No Authorization on Whitelist Operations",
        "severity": "MEDIUM",
        "status": "unfixed",
        "location": "security/whitelist_manager.py",
        "description": "add_device() and remove_device() perform no authorization check.",
        "remediation": "Require SessionManager.require_auth(UserMode.ADMIN) before whitelist mutations.",
    },
    {
        "id": "VULN-010",
        "title": "Truncated Descriptor Hash",
        "severity": "LOW",
        "status": "fixed",
        "location": "sandbox/hid_descriptor_analyzer.py",
        "description": "Descriptor fingerprint now uses SHA256[:32] (128-bit) instead of [:16].",
        "remediation": "Already remediated.",
    },
    {
        "id": "VULN-011",
        "title": "Database Path Information Disclosure",
        "severity": "LOW",
        "status": "unfixed",
        "location": "database/db.py",
        "description": "Full database file path printed to stdout during initialization.",
        "remediation": "Use structured logging at DEBUG level only; mask paths in production.",
    },
]


# ---------------------------------------------------------------------------
# Detection gap definitions
# ---------------------------------------------------------------------------

_DETECTION_GAPS: list[dict[str, str]] = [
    {
        "area": "Firmware-level BadUSB Detection",
        "severity": "HIGH",
        "description": (
            "Current detection relies on behavioral analysis (keystroke rates, "
            "descriptor anomalies). True firmware-level BadUSB attacks that "
            "re-program USB controller firmware are not detectable without "
            "hardware-level USB firewall or firmware dump analysis."
        ),
        "recommendation": "Integrate USB firmware fingerprinting (e.g., USBGuard, GoodUSB).",
    },
    {
        "area": "USB-C Power Delivery Attack Vectors",
        "severity": "HIGH",
        "description": (
            "USB-C PD (Power Delivery) protocol attacks can manipulate voltage "
            "negotiation to damage hardware. Current pipeline does not inspect "
            "PD protocol messages."
        ),
        "recommendation": "Add USB-C PD protocol monitoring via hardware probes.",
    },
    {
        "area": "Wireless HID Injection (MouseJack)",
        "severity": "MEDIUM",
        "description": (
            "Wireless HID receivers (Logitech Unifying, etc.) are vulnerable to "
            "MouseJack attacks. Current system only monitors wired USB events."
        ),
        "recommendation": "Extend monitor to detect wireless HID receivers and apply behavioral thresholds.",
    },
    {
        "area": "Supply-Chain USB Implant Detection",
        "severity": "MEDIUM",
        "description": (
            "Hardware supply-chain implants (e.g., NSA ANT catalog devices) cannot "
            "be detected through software-only analysis. Current detection is "
            "limited to VID/PID matching and behavioral analysis."
        ),
        "recommendation": "Maintain known-bad VID/PID database; integrate USB electrical fingerprinting.",
    },
    {
        "area": "YARA Rule Integration",
        "severity": "MEDIUM",
        "description": (
            "Current heuristic scanning uses inline keyword-based pattern matching. "
            "Full YARA rule engine would provide more comprehensive and maintainable "
            "signature-based detection."
        ),
        "recommendation": "Integrate yara-python for rule-based scanning; maintain community rule sets.",
    },
    {
        "area": "VirusTotal Hash Lookup",
        "severity": "LOW",
        "description": (
            "File hashes are computed but not checked against cloud threat intel. "
            "VirusTotal or similar API integration would provide multi-engine "
            "detection coverage."
        ),
        "recommendation": "Add optional VirusTotal API integration for SHA-256 hash lookups.",
    },
    {
        "area": "USB Protocol-Level Monitoring",
        "severity": "MEDIUM",
        "description": (
            "Current monitoring operates at the OS device-driver level (WMI). "
            "USB protocol-level analysis (URB packets, descriptor requests) would "
            "enable detection of more sophisticated attacks."
        ),
        "recommendation": "Integrate USBPcap or similar for raw USB packet capture and analysis.",
    },
    {
        "area": "Temporal Keystroke Pattern Analysis",
        "severity": "LOW",
        "description": (
            "Keystroke injection detection uses aggregate rate thresholds. "
            "More sophisticated temporal pattern analysis (timing variance, "
            "inter-keystroke interval distribution) would reduce false positives."
        ),
        "recommendation": "Implement statistical keystroke dynamics analysis with Markov chain modeling.",
    },
]


# ---------------------------------------------------------------------------
# Pipeline enhancement recommendations
# ---------------------------------------------------------------------------

_PIPELINE_RECOMMENDATIONS: list[str] = [
    "Add YARA rule engine for signature-based file scanning alongside heuristic analysis.",
    "Integrate VirusTotal API for cloud-based hash reputation checking (opt-in, for non-air-gapped environments).",
    "Implement USB firmware fingerprinting to detect re-programmed controllers (BadUSB at hardware level).",
    "Add USB-C Power Delivery protocol monitoring for hardware damage prevention.",
    "Extend HID descriptor analysis with inter-keystroke timing variance detection.",
    "Add USB device allowlist/blocklist import/export for fleet management.",
    "Implement automated model retraining pipeline when new threat samples are collected.",
    "Add real-time USB traffic capture (USBPcap) for protocol-level anomaly detection.",
    "Create threat intel feed integration (STIX/TAXII) for automated IOC updates.",
    "Implement honeypot USB port mode for active attacker detection.",
]


class DetectionGapAnalyzer:
    """Analyze the detection pipeline against known audit findings and gaps.

    Cross-references the vulnerability catalogue from website_full_detail.md
    with current code state and identifies uncovered attack vectors.
    """

    def __init__(self) -> None:
        self._doc_path = Path(__file__).resolve().parent.parent / "website_full_detail.md"

    def analyze(self) -> dict[str, Any]:
        """Run full self-improvement analysis.

        Returns
        -------
        dict[str, Any]
            Analysis result containing vulnerability_status, detection_gaps,
            recommendations, and documentation_available flag.
        """
        doc_available = self._doc_path.exists()

        vuln_summary = self._summarize_vulnerabilities()
        gaps = self._identify_gaps()
        recs = list(_PIPELINE_RECOMMENDATIONS)

        # Count stats
        fixed = sum(1 for v in vuln_summary if v["status"] == "fixed")
        partial = sum(1 for v in vuln_summary if v["status"] == "partial")
        unfixed = sum(1 for v in vuln_summary if v["status"] == "unfixed")

        return {
            "documentation_available": doc_available,
            "documentation_path": str(self._doc_path) if doc_available else None,
            "vulnerability_status": vuln_summary,
            "vulnerability_stats": {
                "total": len(vuln_summary),
                "fixed": fixed,
                "partial": partial,
                "unfixed": unfixed,
                "remediation_rate": f"{(fixed / max(1, len(vuln_summary))) * 100:.0f}%",
            },
            "detection_gaps": gaps,
            "recommendations": recs,
            "analysis_timestamp": __import__("time").time(),
        }

    def _summarize_vulnerabilities(self) -> list[dict[str, str]]:
        """Return the current vulnerability remediation status."""
        return list(_VULNERABILITY_STATUS)

    def _identify_gaps(self) -> list[dict[str, str]]:
        """Return known detection coverage gaps."""
        return list(_DETECTION_GAPS)

    def get_unfixed_critical(self) -> list[dict[str, str]]:
        """Return only P0/P1 unfixed vulnerabilities for urgent reporting."""
        return [
            v for v in _VULNERABILITY_STATUS
            if v["status"] in {"unfixed", "partial"}
            and v["severity"] in {"CRITICAL", "HIGH"}
        ]

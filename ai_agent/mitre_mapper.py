"""MITRE ATT&CK technique mapper for USB/HID threat intelligence correlation.

Maps scan findings, HID behavioral anomalies, and file heuristics to
MITRE ATT&CK techniques and tactics. Supports both deterministic rule-based
mapping and optional Ollama-powered natural-language enrichment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# MITRE ATT&CK knowledge base (USB/HID-relevant subset)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MITRETechnique:
    """A single MITRE ATT&CK technique entry."""

    technique_id: str
    name: str
    tactic: str
    tactic_id: str
    description: str
    url: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "tactic_id": self.tactic_id,
            "description": self.description,
            "url": self.url,
        }


# Canonical technique catalogue for USB/HID attack vectors
_TECHNIQUE_CATALOGUE: dict[str, MITRETechnique] = {
    "T1200": MITRETechnique(
        technique_id="T1200",
        name="Hardware Additions",
        tactic="Initial Access",
        tactic_id="TA0001",
        description="Adversaries may introduce malicious hardware (e.g. USB implants, BadUSB devices) into a system to gain access.",
        url="https://attack.mitre.org/techniques/T1200/",
    ),
    "T1056.001": MITRETechnique(
        technique_id="T1056.001",
        name="Input Capture: Keylogging",
        tactic="Collection",
        tactic_id="TA0009",
        description="HID devices may capture or inject keystrokes at rates exceeding human capability.",
        url="https://attack.mitre.org/techniques/T1056/001/",
    ),
    "T1059.001": MITRETechnique(
        technique_id="T1059.001",
        name="Command and Scripting Interpreter: PowerShell",
        tactic="Execution",
        tactic_id="TA0002",
        description="PowerShell scripts on the USB may be used for payload execution.",
        url="https://attack.mitre.org/techniques/T1059/001/",
    ),
    "T1059.003": MITRETechnique(
        technique_id="T1059.003",
        name="Command and Scripting Interpreter: Windows Command Shell",
        tactic="Execution",
        tactic_id="TA0002",
        description="Batch files (.bat/.cmd) on USB can execute commands when triggered.",
        url="https://attack.mitre.org/techniques/T1059/003/",
    ),
    "T1059.005": MITRETechnique(
        technique_id="T1059.005",
        name="Command and Scripting Interpreter: Visual Basic",
        tactic="Execution",
        tactic_id="TA0002",
        description="VBScript files on USB may execute malicious payloads.",
        url="https://attack.mitre.org/techniques/T1059/005/",
    ),
    "T1059.007": MITRETechnique(
        technique_id="T1059.007",
        name="Command and Scripting Interpreter: JavaScript",
        tactic="Execution",
        tactic_id="TA0002",
        description="JavaScript files on USB may execute via Windows Script Host.",
        url="https://attack.mitre.org/techniques/T1059/007/",
    ),
    "T1547.001": MITRETechnique(
        technique_id="T1547.001",
        name="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        tactic="Persistence",
        tactic_id="TA0003",
        description="Autorun.inf or startup scripts establish persistence on the host.",
        url="https://attack.mitre.org/techniques/T1547/001/",
    ),
    "T1027": MITRETechnique(
        technique_id="T1027",
        name="Obfuscated Files or Information",
        tactic="Defense Evasion",
        tactic_id="TA0005",
        description="Files with high entropy may be encrypted, packed, or obfuscated to evade detection.",
        url="https://attack.mitre.org/techniques/T1027/",
    ),
    "T1027.002": MITRETechnique(
        technique_id="T1027.002",
        name="Obfuscated Files or Information: Software Packing",
        tactic="Defense Evasion",
        tactic_id="TA0005",
        description="Executable files with very high entropy suggest packing or UPX-style compression.",
        url="https://attack.mitre.org/techniques/T1027/002/",
    ),
    "T1055": MITRETechnique(
        technique_id="T1055",
        name="Process Injection",
        tactic="Privilege Escalation",
        tactic_id="TA0004",
        description="PE files importing injection APIs (VirtualAlloc, WriteProcessMemory, CreateRemoteThread) indicate process injection capability.",
        url="https://attack.mitre.org/techniques/T1055/",
    ),
    "T1548": MITRETechnique(
        technique_id="T1548",
        name="Abuse Elevation Control Mechanism",
        tactic="Privilege Escalation",
        tactic_id="TA0004",
        description="Scripts or executables attempting privilege escalation through UAC bypass or admin token manipulation.",
        url="https://attack.mitre.org/techniques/T1548/",
    ),
    "T1071": MITRETechnique(
        technique_id="T1071",
        name="Application Layer Protocol",
        tactic="Command and Control",
        tactic_id="TA0011",
        description="Scripts containing network or HTTP-related calls may establish C2 communication.",
        url="https://attack.mitre.org/techniques/T1071/",
    ),
    "T1485": MITRETechnique(
        technique_id="T1485",
        name="Data Destruction",
        tactic="Impact",
        tactic_id="TA0040",
        description="Scripts that modify or delete host file system content.",
        url="https://attack.mitre.org/techniques/T1485/",
    ),
    "T1091": MITRETechnique(
        technique_id="T1091",
        name="Replication Through Removable Media",
        tactic="Lateral Movement",
        tactic_id="TA0008",
        description="Malware may spread by writing copies to removable USB media.",
        url="https://attack.mitre.org/techniques/T1091/",
    ),
    "T1204.002": MITRETechnique(
        technique_id="T1204.002",
        name="User Execution: Malicious File",
        tactic="Execution",
        tactic_id="TA0002",
        description="Users may be tricked into executing malicious files from USB devices.",
        url="https://attack.mitre.org/techniques/T1204/002/",
    ),
}


# ---------------------------------------------------------------------------
# Rule-based mapping engine
# ---------------------------------------------------------------------------

@dataclass
class MITREMatch:
    """One matched MITRE technique with confidence and evidence."""

    technique: MITRETechnique
    confidence: float  # 0.0 – 1.0
    evidence: list[str] = field(default_factory=list)
    ai_explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        result = self.technique.to_dict()
        result["confidence"] = round(self.confidence, 3)
        result["evidence"] = list(self.evidence)
        if self.ai_explanation:
            result["ai_explanation"] = self.ai_explanation
        return result


class MITREMapper:
    """Map scan findings to MITRE ATT&CK techniques.

    The mapper uses deterministic rules first, then optionally queries
    Ollama for natural-language enrichment of each matched technique.
    """

    def __init__(self, *, enable_ollama: bool = False) -> None:
        self._enable_ollama = enable_ollama
        self._ollama_service: Any = None
        if enable_ollama:
            try:
                from ai_agent.advisory_service import AdvisoryAIService
                self._ollama_service = AdvisoryAIService()
            except Exception:
                self._ollama_service = None

    def map_findings(
        self,
        *,
        device_info: dict[str, Any],
        file_results: list[dict[str, Any]],
        hid_analysis: dict[str, Any] | None = None,
    ) -> list[MITREMatch]:
        """Run rule-based MITRE mapping and return matched techniques.

        Parameters
        ----------
        device_info:
            Device metadata dict (device_type, vendor_id, etc.).
        file_results:
            List of per-file scan result dicts from the scanner.
        hid_analysis:
            Optional HID descriptor analysis result dict.

        Returns
        -------
        list[MITREMatch]
            Matched techniques sorted by confidence (descending).
        """
        matches: dict[str, MITREMatch] = {}

        # --- Rule 1: Hardware Additions (any USB device) ---
        device_type = str(device_info.get("device_type", "unknown")).lower()
        if device_type in {"keyboard", "composite", "unknown"}:
            self._add_match(matches, "T1200", 0.6, f"Device type '{device_type}' may represent a hardware implant")

        # --- Rule 2: HID keystroke injection ---
        if hid_analysis:
            keystroke_rate = float(hid_analysis.get("keystroke_rate", 0.0))
            keystroke_label = str(hid_analysis.get("keystroke_label", "SAFE")).upper()
            if keystroke_label == "MALICIOUS":
                self._add_match(matches, "T1056.001", 0.95, f"Keystroke injection rate {keystroke_rate:.1f} KPS is MALICIOUS")
                self._add_match(matches, "T1200", 0.95, "BadUSB/Rubber Ducky keystroke injection behavior confirmed")
            elif keystroke_label == "SUSPICIOUS":
                self._add_match(matches, "T1056.001", 0.7, f"Keystroke rate {keystroke_rate:.1f} KPS is SUSPICIOUS")
                self._add_match(matches, "T1200", 0.7, "Possible HID-based attack device")

            if hid_analysis.get("is_composite"):
                self._add_match(matches, "T1200", 0.8, "Composite USB device presenting multiple interfaces")

        # --- Rule 3: File-level analysis ---
        for row in file_results:
            file_name = str(row.get("file_name", "")).lower()
            suffix = file_name.rsplit(".", 1)[-1] if "." in file_name else ""
            risk_level = str(row.get("risk_level", "safe")).lower()
            entropy = float(row.get("entropy", 0.0))
            heuristics = row.get("heuristics", {}) if isinstance(row.get("heuristics"), dict) else {}
            pe_info = row.get("pe", {}) if isinstance(row.get("pe"), dict) else {}

            # PowerShell scripts
            if suffix == "ps1":
                conf = 0.85 if risk_level in {"high", "critical"} else 0.5
                self._add_match(matches, "T1059.001", conf, f"PowerShell script found: {file_name}")

            # Batch/CMD scripts
            if suffix in {"bat", "cmd"}:
                conf = 0.7 if risk_level in {"high", "critical"} else 0.4
                self._add_match(matches, "T1059.003", conf, f"Windows command script found: {file_name}")

            # VBScript
            if suffix == "vbs":
                conf = 0.75 if risk_level in {"high", "critical"} else 0.45
                self._add_match(matches, "T1059.005", conf, f"VBScript found: {file_name}")

            # JavaScript
            if suffix == "js":
                conf = 0.65 if risk_level in {"high", "critical"} else 0.35
                self._add_match(matches, "T1059.007", conf, f"JavaScript found: {file_name}")

            # Autorun indicators
            if heuristics.get("autorun_reference") or file_name == "autorun.inf":
                self._add_match(matches, "T1547.001", 0.9, f"Autorun script or reference detected: {file_name}")
                self._add_match(matches, "T1091", 0.7, "Removable media autorun may enable replication")

            # High entropy (packing/encryption)
            if entropy >= 7.8:
                self._add_match(matches, "T1027.002", 0.85, f"Very high entropy ({entropy:.2f}) indicates packing: {file_name}")
                self._add_match(matches, "T1027", 0.80, f"Encrypted or obfuscated payload: {file_name}")
            elif entropy >= 7.2:
                self._add_match(matches, "T1027", 0.65, f"Elevated entropy ({entropy:.2f}) suggests obfuscation: {file_name}")

            # PE injection APIs
            suspicious_apis = pe_info.get("suspicious_apis", [])
            if isinstance(suspicious_apis, list) and suspicious_apis:
                injection_apis = {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx"}
                found_injection = [api for api in suspicious_apis if api in injection_apis]
                if found_injection:
                    self._add_match(
                        matches, "T1055", 0.9,
                        f"Process injection APIs imported: {', '.join(found_injection)} in {file_name}",
                    )

                escalation_apis = {"ShellExecuteA", "ShellExecuteW", "WinExec"}
                found_escalation = [api for api in suspicious_apis if api in escalation_apis]
                if found_escalation:
                    self._add_match(
                        matches, "T1548", 0.6,
                        f"Execution/elevation APIs: {', '.join(found_escalation)} in {file_name}",
                    )

            # Network-capable indicators in scripts
            yara_hits = heuristics.get("yara_hits", [])
            if isinstance(yara_hits, list):
                if "PowerShellExecutionRule" in yara_hits:
                    self._add_match(matches, "T1059.001", 0.8, f"PowerShell execution pattern detected in {file_name}")
                if "ThreadInjectionRule" in yara_hits:
                    self._add_match(matches, "T1055", 0.85, f"Thread injection pattern in {file_name}")

            # Executable files on USB
            if suffix in {"exe", "dll", "scr", "com", "sys"}:
                self._add_match(matches, "T1204.002", 0.5, f"Executable file on USB: {file_name}")
                if risk_level in {"high", "critical"}:
                    self._add_match(matches, "T1204.002", 0.85, f"High-risk executable: {file_name}")

            # Hidden path segments
            if heuristics.get("hidden_path"):
                self._add_match(matches, "T1027", 0.55, f"Hidden directory path for: {file_name}")

        # Enrich with Ollama if enabled
        if self._enable_ollama and self._ollama_service and matches:
            self._enrich_with_ollama(matches, device_info, file_results, hid_analysis)

        # Sort by confidence descending
        sorted_matches = sorted(matches.values(), key=lambda m: m.confidence, reverse=True)
        return sorted_matches

    def get_tactics_summary(self, matches: list[MITREMatch]) -> dict[str, list[dict[str, Any]]]:
        """Group matched techniques by MITRE tactic for report rendering."""
        by_tactic: dict[str, list[dict[str, Any]]] = {}
        for m in matches:
            tactic = m.technique.tactic
            if tactic not in by_tactic:
                by_tactic[tactic] = []
            by_tactic[tactic].append(m.to_dict())
        return by_tactic

    def _add_match(
        self,
        matches: dict[str, MITREMatch],
        technique_id: str,
        confidence: float,
        evidence: str,
    ) -> None:
        """Add or upgrade a technique match."""
        technique = _TECHNIQUE_CATALOGUE.get(technique_id)
        if technique is None:
            return

        existing = matches.get(technique_id)
        if existing is None:
            matches[technique_id] = MITREMatch(
                technique=technique,
                confidence=min(1.0, confidence),
                evidence=[evidence],
            )
        else:
            existing.confidence = min(1.0, max(existing.confidence, confidence))
            existing.evidence.append(evidence)

    def _enrich_with_ollama(
        self,
        matches: dict[str, MITREMatch],
        device_info: dict[str, Any],
        file_results: list[dict[str, Any]],
        hid_analysis: dict[str, Any] | None,
    ) -> None:
        """Query Ollama for natural-language explanation of each technique match."""
        if not self._ollama_service:
            return

        try:
            techniques_text = "\n".join(
                f"- {m.technique.technique_id} ({m.technique.name}): "
                f"confidence={m.confidence:.2f}, evidence: {'; '.join(m.evidence[:3])}"
                for m in matches.values()
            )

            device_name = device_info.get("device_name", "Unknown Device")
            device_type = device_info.get("device_type", "unknown")
            file_count = len(file_results)
            high_risk_count = sum(
                1 for r in file_results
                if str(r.get("risk_level", "")).lower() in {"high", "critical"}
            )

            prompt = (
                f"You are a cybersecurity analyst. A USB device '{device_name}' "
                f"(type: {device_type}) was connected and analyzed. "
                f"{file_count} files were scanned, {high_risk_count} are high-risk.\n\n"
                f"The following MITRE ATT&CK techniques were mapped:\n{techniques_text}\n\n"
                f"For each technique, provide a 1-2 sentence explanation of how this "
                f"finding relates to a real-world USB/HID attack scenario. "
                f"Be concise and actionable. Format as: TECHNIQUE_ID: explanation"
            )

            response = self._ollama_service._query_text_model(prompt)
            if not response:
                return

            # Parse line-by-line explanation
            for line in response.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                for tech_id in matches:
                    if tech_id in line:
                        explanation = line.split(":", 1)[-1].strip() if ":" in line else line
                        matches[tech_id].ai_explanation = explanation
                        break

        except Exception as exc:
            print(f"[MITRE] Ollama enrichment failed: {exc}")

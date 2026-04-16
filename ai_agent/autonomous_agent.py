"""Autonomous USB threat detection agent for HID Shield.

Orchestrates a 7-stage analysis pipeline upon USB device insertion:
1. USB Detection & Initialization (device metadata + HID classification)
2. Deep Content Analysis (recursive file scanning + heuristics)
3. Behavioral Analysis (HID descriptor + keystroke injection detection)
4. Intelligence Correlation (MITRE ATT&CK technique mapping)
5. Criticality Classification (ensemble ML + policy engine)
6. Structured Report Generation (JSON + markdown + PDF)
7. Self-Improvement Analysis (detection gap identification)

This agent operates with zero-trust assumptions and fail-closed logic.
It does NOT use Windows Sandbox bridge — all analysis is performed
locally through the existing scanner, ML, and policy subsystems.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Mapping

from PySide6.QtCore import QObject, QThread, Signal

from core.event_bus import event_bus


# ---------------------------------------------------------------------------
# Background worker thread
# ---------------------------------------------------------------------------


class _AnalysisWorker(QThread):
    """Execute the full 7-stage pipeline off the main thread."""

    finished = Signal(dict)

    def __init__(self, agent: "AutonomousUSBAgent", event_id: int, device_dict: dict[str, Any]) -> None:
        super().__init__()
        self._agent = agent
        self._event_id = event_id
        self._device_dict = dict(device_dict)

    def run(self) -> None:
        try:
            result = self._agent._execute_pipeline(self._event_id, self._device_dict)
            self.finished.emit(result)
        except Exception as exc:
            self.finished.emit({
                "event_id": self._event_id,
                "status": "error",
                "error": str(exc),
                "classification": {
                    "level": "HIGH",
                    "confidence": 0.5,
                    "risk_score": 75.0,
                    "policy_action": "block",
                    "explanation": f"Analysis pipeline failed: {exc}. Fail-closed to HIGH risk.",
                },
            })


# ---------------------------------------------------------------------------
# Autonomous USB Agent
# ---------------------------------------------------------------------------


class AutonomousUSBAgent(QObject):
    """Autonomous cybersecurity agent for USB threat detection.

    Subscribes to USB insertion events and runs a full 7-stage analysis
    pipeline asynchronously. Results are emitted via the global event bus
    and persisted to the database and reports directory.

    Constraints:
    - Zero trust: every device starts as untrusted
    - Fail-closed: any analysis failure escalates to HIGH risk
    - Explainable: every classification has a traceable rule chain
    """

    report_ready = Signal(dict)

    def __init__(self) -> None:
        super().__init__()
        self._workers: list[_AnalysisWorker] = []
        self._lock = threading.RLock()
        self._active = False

        # Lazy-loaded subsystem references
        self._mitre_mapper: Any = None
        self._report_generator: Any = None
        self._gap_analyzer: Any = None
        self._hid_analyzer: Any = None
        self._policy_engine: Any = None
        self._classifier_backend: Any = None

    def start_monitoring(self) -> None:
        """Subscribe to USB insertion events and begin autonomous monitoring."""
        if self._active:
            return
        self._active = True
        event_bus.usb_device_inserted.connect(self._on_device_inserted)
        event_bus.scan_completed.connect(self._on_scan_completed)
        print("[AGENT] Autonomous USB Agent activated — zero-trust monitoring engaged.")

    def stop_monitoring(self) -> None:
        """Disconnect monitoring signals."""
        self._active = False
        try:
            event_bus.usb_device_inserted.disconnect(self._on_device_inserted)
            event_bus.scan_completed.disconnect(self._on_scan_completed)
        except RuntimeError:
            pass
        print("[AGENT] Autonomous USB Agent deactivated.")

    def analyze_device_sync(self, device_dict: dict[str, Any], event_id: int = 0) -> dict[str, Any]:
        """Run the full pipeline synchronously (for testing / scripting)."""
        return self._execute_pipeline(event_id, device_dict)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_device_inserted(self, device_payload: dict[str, Any]) -> None:
        """Queue autonomous analysis when a USB device is detected."""
        print(f"[AGENT] USB device detected: {device_payload.get('device_name', 'Unknown')}")
        self._emit_progress(0, 0, "USB device detected — initiating autonomous analysis")

    def _on_scan_completed(self, event_id: int, summary: dict[str, Any]) -> None:
        """Trigger full autonomous analysis after FileScanner completes."""
        if int(event_id) <= 0:
            return

        payload = summary if isinstance(summary, dict) else {}
        device_dict = payload.get("device", {}) if isinstance(payload.get("device"), dict) else {}

        # Merge scan results into device context
        device_dict["_scan_summary"] = payload

        worker = _AnalysisWorker(self, int(event_id), device_dict)
        worker.finished.connect(self._on_analysis_complete)
        with self._lock:
            self._workers.append(worker)
        worker.start()

    def _on_analysis_complete(self, result: dict[str, Any]) -> None:
        """Handle completed autonomous analysis."""
        event_id = result.get("event_id", 0)
        status = result.get("status", "unknown")
        level = result.get("classification", {}).get("level", "UNKNOWN")

        print(f"[AGENT] Analysis complete for event #{event_id}: {level} (status={status})")

        # Emit to global event bus
        event_bus.autonomous_report_ready.emit(result)
        self.report_ready.emit(result)

        # Persist to database
        self._persist_report(event_id, result)

        # Cleanup finished workers
        with self._lock:
            self._workers = [w for w in self._workers if w.isRunning()]

    # ------------------------------------------------------------------
    # 7-Stage Analysis Pipeline
    # ------------------------------------------------------------------

    def _execute_pipeline(self, event_id: int, device_dict: dict[str, Any]) -> dict[str, Any]:
        """Execute all 7 analysis stages sequentially."""
        start_time = time.time()

        # Initialize subsystems (lazy)
        self._ensure_subsystems()

        scan_summary = device_dict.pop("_scan_summary", {})
        file_results = scan_summary.get("files", []) if isinstance(scan_summary.get("files"), list) else []

        # ── Stage 1: USB Detection & Initialization ──
        self._emit_progress(event_id, 5, "Stage 1: USB Detection & Initialization")
        device_summary = self._stage_1_device_metadata(device_dict)

        # ── Stage 2: Deep Content Analysis ──
        self._emit_progress(event_id, 20, "Stage 2: Deep Content Analysis")
        content_analysis = self._stage_2_content_analysis(file_results)

        # ── Stage 3: Behavioral Analysis ──
        self._emit_progress(event_id, 40, "Stage 3: Behavioral Analysis")
        behavioral = self._stage_3_behavioral_analysis(device_dict)

        # ── Stage 4: Intelligence Correlation (MITRE ATT&CK) ──
        self._emit_progress(event_id, 55, "Stage 4: MITRE ATT&CK Intelligence Correlation")
        mitre_matches = self._stage_4_mitre_correlation(
            device_info=device_dict,
            file_results=file_results,
            hid_analysis=behavioral.get("hid_analysis"),
        )

        # ── Stage 5: Criticality Classification ──
        self._emit_progress(event_id, 70, "Stage 5: Criticality Classification")
        classification = self._stage_5_classification(
            device_dict=device_dict,
            file_results=file_results,
            behavioral=behavioral,
            mitre_matches=mitre_matches,
            scan_summary=scan_summary,
        )

        # ── Stage 6: Structured Report Generation ──
        self._emit_progress(event_id, 85, "Stage 6: Generating Structured Report")
        analysis_data = {
            "event_id": event_id,
            "device_summary": device_summary,
            "file_results": file_results,
            "suspicious_findings": content_analysis.get("suspicious_findings", []),
            "behavioral_analysis": behavioral,
            "mitre_mapping": [m.to_dict() for m in mitre_matches],
            "classification": classification,
            "recommendations": self._build_recommendations(classification, mitre_matches),
        }

        # ── Stage 7: Self-Improvement Analysis ──
        self._emit_progress(event_id, 95, "Stage 7: Self-Improvement Analysis")
        analysis_data["self_improvement"] = self._stage_7_self_improvement()

        # Generate report
        report = self._report_generator.generate(analysis_data)
        report["event_id"] = event_id
        report["status"] = "completed"
        report["pipeline_duration_seconds"] = round(time.time() - start_time, 2)

        self._emit_progress(event_id, 100, f"Analysis complete: {classification.get('level', 'UNKNOWN')}")

        return report

    # ------------------------------------------------------------------
    # Stage implementations
    # ------------------------------------------------------------------

    def _stage_1_device_metadata(self, device_dict: dict[str, Any]) -> dict[str, Any]:
        """Stage 1: Extract and validate USB device metadata."""
        device_type = str(device_dict.get("device_type", "unknown")).lower()
        is_hid = device_type in {"keyboard", "mouse", "composite"}

        vid = device_dict.get("vendor_id")
        pid = device_dict.get("product_id")
        hardware_id = f"USB\\VID_{(vid or '0000').upper()}&PID_{(pid or '0000').upper()}"

        summary = {
            "device_name": device_dict.get("device_name", "Unknown Device"),
            "vendor_id": vid or "N/A",
            "product_id": pid or "N/A",
            "serial_number": device_dict.get("serial_number") or device_dict.get("serial") or "N/A",
            "manufacturer": device_dict.get("manufacturer", "N/A"),
            "device_type": device_type,
            "is_hid_device": is_hid,
            "mount_point": device_dict.get("mount_point", "N/A"),
            "hardware_id": hardware_id,
            "is_simulated": bool(device_dict.get("is_simulated", False)),
        }

        print(f"[AGENT] Stage 1: Device={summary['device_name']}, Type={device_type}, HID={is_hid}")
        return summary

    def _stage_2_content_analysis(self, file_results: list[dict[str, Any]]) -> dict[str, Any]:
        """Stage 2: Analyze file scan results for suspicious content."""
        suspicious: list[dict[str, Any]] = []
        suspicious_extensions = {".exe", ".bat", ".ps1", ".vbs", ".js", ".dll", ".cmd", ".scr", ".com", ".sys"}

        for row in file_results:
            file_name = str(row.get("file_name", ""))
            risk_level = str(row.get("risk_level", "safe")).lower()
            entropy = float(row.get("entropy", 0.0))
            threat_name = row.get("threat_name")
            heuristics = row.get("heuristics", {}) if isinstance(row.get("heuristics"), dict) else {}

            reasons: list[str] = []

            # Check extension
            suffix = f".{file_name.rsplit('.', 1)[-1].lower()}" if "." in file_name else ""
            if suffix in suspicious_extensions:
                reasons.append(f"Suspicious file extension: {suffix}")

            # Check risk level
            if risk_level in {"high", "critical"}:
                reasons.append(f"Risk level: {risk_level.upper()}")

            # Check entropy
            if entropy >= 7.8:
                reasons.append(f"Very high entropy ({entropy:.2f}) — possible encrypted payload")
            elif entropy >= 7.2:
                reasons.append(f"Elevated entropy ({entropy:.2f}) — possible packing")

            # Check autorun
            if heuristics.get("autorun_reference"):
                reasons.append("Autorun script or reference detected")

            # Check hidden path
            if heuristics.get("hidden_path"):
                reasons.append("Hidden directory path segment")

            # Check YARA hits
            yara_hits = heuristics.get("yara_hits", [])
            if isinstance(yara_hits, list) and yara_hits:
                reasons.append(f"Pattern matches: {', '.join(yara_hits)}")

            if reasons:
                suspicious.append({
                    "file_name": file_name,
                    "file_path": str(row.get("file_path", "")),
                    "risk_level": risk_level,
                    "threat_name": threat_name or "N/A",
                    "entropy": entropy,
                    "sha256": row.get("sha256", "N/A"),
                    "reason": "; ".join(reasons),
                    "reasons": reasons,
                })

        print(f"[AGENT] Stage 2: {len(file_results)} files analyzed, {len(suspicious)} suspicious")
        return {
            "total_files": len(file_results),
            "suspicious_count": len(suspicious),
            "suspicious_findings": suspicious,
        }

    def _stage_3_behavioral_analysis(self, device_dict: dict[str, Any]) -> dict[str, Any]:
        """Stage 3: Analyze HID behavioral characteristics."""
        hid_result = self._hid_analyzer.analyze_device(device_dict)
        hid_dict = hid_result.to_dict()

        result = {
            "hid_analysis": hid_dict,
            "keystroke_injection_detected": hid_result.keystroke_label != "SAFE",
            "composite_device_detected": hid_result.is_composite,
            "anomaly_count": len(hid_result.anomaly_reasons),
        }

        print(f"[AGENT] Stage 3: HID={hid_result.hid_type}, KPS={hid_result.keystroke_rate:.1f}, Label={hid_result.keystroke_label}")
        return result

    def _stage_4_mitre_correlation(
        self,
        device_info: dict[str, Any],
        file_results: list[dict[str, Any]],
        hid_analysis: dict[str, Any] | None,
    ) -> list[Any]:
        """Stage 4: Map findings to MITRE ATT&CK techniques."""
        matches = self._mitre_mapper.map_findings(
            device_info=device_info,
            file_results=file_results,
            hid_analysis=hid_analysis,
        )
        print(f"[AGENT] Stage 4: {len(matches)} MITRE ATT&CK techniques matched")
        return matches

    def _stage_5_classification(
        self,
        device_dict: dict[str, Any],
        file_results: list[dict[str, Any]],
        behavioral: dict[str, Any],
        mitre_matches: list[Any],
        scan_summary: dict[str, Any],
    ) -> dict[str, Any]:
        """Stage 5: Compute final criticality classification.

        Classification levels:
        - HIGH: Confirmed malicious payloads, HID attack behavior, active exploitation
        - MEDIUM: Suspicious scripts/hidden files, potential attack indicators
        - LOW: Clean or benign files, no suspicious behavior
        """
        risk_score = 0.0
        reasons: list[str] = []

        # Factor 1: File-level risk
        high_risk_files = sum(
            1 for f in file_results
            if str(f.get("risk_level", "")).lower() in {"high", "critical"}
        )
        medium_risk_files = sum(
            1 for f in file_results
            if str(f.get("risk_level", "")).lower() == "medium"
        )
        if high_risk_files > 0:
            risk_score += min(40, high_risk_files * 15)
            reasons.append(f"{high_risk_files} high-risk file(s) detected")
        if medium_risk_files > 0:
            risk_score += min(20, medium_risk_files * 5)
            reasons.append(f"{medium_risk_files} medium-risk file(s) detected")

        # Factor 2: HID behavioral anomalies
        hid = behavioral.get("hid_analysis", {})
        keystroke_label = str(hid.get("keystroke_label", "SAFE")).upper()
        if keystroke_label == "MALICIOUS":
            risk_score += 40
            reasons.append("MALICIOUS keystroke injection rate detected")
        elif keystroke_label == "SUSPICIOUS":
            risk_score += 20
            reasons.append("SUSPICIOUS keystroke rate detected")

        if behavioral.get("composite_device_detected"):
            risk_score += 10
            reasons.append("Composite USB device (multiple interfaces)")

        anomaly_count = behavioral.get("anomaly_count", 0)
        if anomaly_count > 0:
            risk_score += min(15, anomaly_count * 5)
            reasons.append(f"{anomaly_count} HID anomaly reason(s)")

        # Factor 3: MITRE technique count and confidence
        high_conf_mitre = sum(1 for m in mitre_matches if m.confidence >= 0.8)
        if high_conf_mitre > 0:
            risk_score += min(20, high_conf_mitre * 7)
            reasons.append(f"{high_conf_mitre} high-confidence MITRE technique(s)")

        # Factor 4: Scan summary signals
        scan_risk = str(scan_summary.get("risk_level", "safe")).lower()
        if scan_risk in {"high", "critical"}:
            risk_score += 15
            reasons.append(f"Scanner reported {scan_risk.upper()} risk")

        # Factor 5: Max entropy
        max_entropy = max(
            (float(f.get("entropy", 0.0)) for f in file_results),
            default=0.0,
        )
        if max_entropy >= 7.8:
            risk_score += 10
            reasons.append(f"Maximum entropy {max_entropy:.2f} (encrypted/packed)")

        # Clamp score
        risk_score = min(100.0, risk_score)

        # Classify
        if risk_score >= 60:
            level = "HIGH"
            policy_action = "block"
        elif risk_score >= 30:
            level = "MEDIUM"
            policy_action = "quarantine"
        else:
            level = "LOW"
            policy_action = "allow"

        confidence = min(1.0, risk_score / 100.0 + 0.2)
        if not file_results and not behavioral.get("keystroke_injection_detected"):
            confidence = max(0.3, confidence - 0.2)

        explanation = "; ".join(reasons) if reasons else "No significant threat indicators detected"

        result = {
            "level": level,
            "confidence": round(confidence, 3),
            "risk_score": round(risk_score, 1),
            "policy_action": policy_action,
            "explanation": explanation,
            "factors": reasons,
            "file_risk_breakdown": {
                "high": high_risk_files,
                "medium": medium_risk_files,
                "total": len(file_results),
            },
        }

        print(f"[AGENT] Stage 5: Classification={level}, Score={risk_score:.1f}, Action={policy_action}")
        return result

    def _build_recommendations(
        self,
        classification: dict[str, Any],
        mitre_matches: list[Any],
    ) -> list[dict[str, str]]:
        """Build actionable recommendations based on classification and findings."""
        level = classification.get("level", "LOW")
        recommendations: list[dict[str, str]] = []

        if level == "HIGH":
            recommendations.append({
                "action": "Block Device",
                "priority": "HIGH",
                "description": "Immediately block USB device access and eject. Confirmed or strongly suspected malicious activity.",
            })
            recommendations.append({
                "action": "Quarantine Files",
                "priority": "HIGH",
                "description": "Move all files from the USB to quarantine for forensic preservation.",
            })
            recommendations.append({
                "action": "Alert SOC Team",
                "priority": "HIGH",
                "description": "Notify the Security Operations Center for incident response investigation.",
            })
            recommendations.append({
                "action": "Host Integrity Check",
                "priority": "MEDIUM",
                "description": "Run host endpoint integrity scan to detect any payload execution that may have occurred.",
            })

        elif level == "MEDIUM":
            recommendations.append({
                "action": "Quarantine Suspicious Files",
                "priority": "MEDIUM",
                "description": "Isolate flagged files for manual review. Allow safe files with monitoring.",
            })
            recommendations.append({
                "action": "Enhanced Monitoring",
                "priority": "MEDIUM",
                "description": "Enable detailed logging for this device and monitor for behavioral changes.",
            })
            recommendations.append({
                "action": "Manual Review Required",
                "priority": "MEDIUM",
                "description": "A security analyst should review the flagged indicators before granting full access.",
            })

        else:  # LOW
            recommendations.append({
                "action": "Allow with Monitoring",
                "priority": "LOW",
                "description": "Device appears clean. Allow access with standard audit logging enabled.",
            })

        # MITRE-specific recommendations
        has_injection = any(m.technique.technique_id == "T1055" for m in mitre_matches if hasattr(m, "technique"))
        if has_injection:
            recommendations.append({
                "action": "Process Injection Alert",
                "priority": "HIGH",
                "description": "PE files with process injection APIs detected. Block execution and analyze in isolated environment.",
            })

        has_persistence = any(
            m.technique.technique_id in {"T1547.001", "T1091"}
            for m in mitre_matches if hasattr(m, "technique")
        )
        if has_persistence:
            recommendations.append({
                "action": "Check Persistence Mechanisms",
                "priority": "MEDIUM",
                "description": "Autorun or persistence indicators found. Verify no startup modifications were made to the host.",
            })

        return recommendations

    def _stage_7_self_improvement(self) -> dict[str, Any]:
        """Stage 7: Run self-improvement detection gap analysis."""
        try:
            result = self._gap_analyzer.analyze()
            print(f"[AGENT] Stage 7: {result['vulnerability_stats']['unfixed']} unfixed vulns, "
                  f"{len(result['detection_gaps'])} detection gaps identified")
            return result
        except Exception as exc:
            print(f"[AGENT] Stage 7: Self-improvement analysis failed: {exc}")
            return {"error": str(exc)}

    # ------------------------------------------------------------------
    # Subsystem initialization
    # ------------------------------------------------------------------

    def _ensure_subsystems(self) -> None:
        """Lazy-initialize analysis subsystems on first use."""
        if self._mitre_mapper is not None:
            return

        from ai_agent.mitre_mapper import MITREMapper
        from ai_agent.report_generator import ReportGenerator
        from ai_agent.detection_gap_analyzer import DetectionGapAnalyzer
        from sandbox.hid_descriptor_analyzer import HIDDescriptorAnalyzer

        # Check if Ollama is enabled for MITRE enrichment
        enable_ollama = False
        try:
            from ai_agent.config import load_ai_settings
            enable_ollama = bool(load_ai_settings().enabled)
        except Exception:
            pass

        self._mitre_mapper = MITREMapper(enable_ollama=enable_ollama)
        self._report_generator = ReportGenerator()
        self._gap_analyzer = DetectionGapAnalyzer()
        self._hid_analyzer = HIDDescriptorAnalyzer()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist_report(self, event_id: int, report: dict[str, Any]) -> None:
        """Save report summary to database as a system alert."""
        try:
            from database.db import get_db
            from database.repository import AlertRepository

            classification = report.get("final_classification", report.get("classification", {}))
            level = str(classification.get("level", "LOW")).upper()
            severity = "critical" if level == "HIGH" else "warning" if level == "MEDIUM" else "info"

            with get_db() as session:
                AlertRepository.create_alert(
                    session,
                    title=f"Autonomous Agent Report: {level} Threat Level",
                    message=(
                        f"Event #{event_id}: Autonomous analysis classified device as {level}. "
                        f"Risk score: {classification.get('risk_score', 0):.1f}/100. "
                        f"Action: {classification.get('policy_action', 'N/A')}. "
                        f"Duration: {report.get('pipeline_duration_seconds', 0):.1f}s."
                    ),
                    severity=severity,
                    category="policy",
                    device_event_id=event_id if event_id > 0 else None,
                    is_simulated=False,
                    source="ai_agent.autonomous_agent",
                )
        except Exception as exc:
            print(f"[AGENT] Failed to persist report to database: {exc}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _emit_progress(self, event_id: int, progress: int, message: str) -> None:
        """Emit progress updates via event bus."""
        clamped = max(0, min(100, int(progress)))
        try:
            event_bus.autonomous_analysis_progress.emit(event_id, clamped, message)
        except Exception:
            pass
        print(f"[AGENT] {clamped:>3}% | {message}")

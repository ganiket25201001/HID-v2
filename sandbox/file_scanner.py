"""Asynchronous file scanning pipeline for HID Shield sandbox analysis."""

from __future__ import annotations

import hashlib
import mimetypes
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import yaml
from PySide6.QtCore import QObject, Signal

from core.event_bus import event_bus
from core.port_lockdown import PortLockdown
from database.db import get_db
from database.models import DeviceEvent, PolicyAction, RiskLevel
from database.repository import AlertRepository, DeviceRepository, FileScanRepository
from sandbox.entropy_analyzer import ShannonEntropyAnalyzer
from sandbox.pe_analyzer import PEHeaderAnalyzer
from sandbox.sandbox_manager import SandboxManager
from sandbox.windows_sandbox_bridge import WindowsSandboxBridge
from security.policy_engine import DeviceSnapshot, PolicyEngine


class FileScanner(QObject):
    """Run multi-stage sandbox analysis for one USB device at a time.

    Scans are executed asynchronously using a background thread pool. Progress and
    completion notifications are emitted through both local Qt signals and the
    global event bus so the rest of the application can react in real time.
    """

    progress_updated = Signal(int, str)
    file_scanned = Signal(dict)
    scan_finished = Signal(int, dict)

    def __init__(self) -> None:
        """Initialize scanner dependencies and worker infrastructure."""
        super().__init__()
        self._runtime_config = self._load_runtime_config()
        self._simulation_mode = self._is_simulation_mode()
        self._isolate_drive_on_insert = bool(
            self._runtime_config.get("windows_sandbox", {}).get(
                "isolate_drive_letter_on_insert", True
            )
        )
        self._require_windows_sandbox = bool(
            self._runtime_config.get("windows_sandbox", {}).get(
                "require_windows_sandbox", True
            )
        )
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="hid-scan")

        self._port_lockdown = PortLockdown()
        self._sandbox_manager = SandboxManager()
        self._windows_sandbox = WindowsSandboxBridge()
        self._entropy_analyzer = ShannonEntropyAnalyzer()
        self._pe_analyzer = PEHeaderAnalyzer(simulation_mode=self._simulation_mode)
        self._policy_engine = PolicyEngine(simulation_mode=self._simulation_mode)

    def scan_device(self, device: Any) -> int:
        """Queue asynchronous scan for one connected device.

        Parameters
        ----------
        device:
            Device model object. The scanner supports either dataclass-style
            attributes or dictionary payloads.

        Returns
        -------
        int
            Device event ID used for event bus correlation.
        """
        with self._lock:
            device_dict = self._device_to_dict(device)
            self._enforce_host_isolation(device_dict)
            event_id = self._create_initial_device_event(device_dict)
            event_bus.scan_started.emit(event_id)
            self._emit_progress(event_id, 0, f"Scan started for event #{event_id} ({device_dict.get('device_name', 'Unknown')})")
            self._executor.submit(self._scan_worker, event_id, device_dict)
            return event_id

    # ------------------------------------------------------------------
    # Internal worker pipeline
    # ------------------------------------------------------------------

    def _scan_worker(self, event_id: int, device_dict: dict[str, Any]) -> None:
        """Execute full sandbox and analysis pipeline in background thread."""
        session = self._sandbox_manager.create_session()
        session_id = session.session_id

        try:
            source_files = self._sandbox_manager.discover_device_files(device_dict)
            files = self._sandbox_manager.shadow_copy_files(
                session_id=session_id,
                source_files=source_files,
            )

            if not files:
                summary = {
                    "device": device_dict,
                    "files": [],
                    "risk_level": RiskLevel.SAFE.value,
                    "message": "No readable files found on the connected USB volume.",
                }
                self._finalize_scan(event_id, summary, RiskLevel.SAFE.value, PolicyAction.MONITOR.value)
                return

            all_rows, analysis_engine = self._run_analysis_pipeline(
                event_id=event_id,
                device_dict=device_dict,
                session_id=session_id,
                source_files=source_files,
                staged_files=files,
            )

            if analysis_engine == "sandbox_unavailable":
                summary = {
                    "device": device_dict,
                    "files": [],
                    "total_files": 0,
                    "safe_files": 0,
                    "medium_risk_files": 0,
                    "high_risk_files": 0,
                    "max_entropy": 0.0,
                    "analysis_engine": analysis_engine,
                    "summary_note": (
                        "Strict isolation mode is enabled and Windows Sandbox results "
                        "were unavailable. Device remains blocked."
                    ),
                    "risk_level": RiskLevel.CRITICAL.value,
                    "recommended_action": PolicyAction.BLOCK.value,
                    "timestamp": int(time.time()),
                }
                self._finalize_scan(
                    event_id,
                    summary,
                    RiskLevel.CRITICAL.value,
                    PolicyAction.BLOCK.value,
                )
                return

            summary = self._build_summary(device_dict=device_dict, rows=all_rows)
            summary["analysis_engine"] = analysis_engine
            if analysis_engine == "windows_sandbox":
                summary["summary_note"] = "Windows Sandbox scan finished with isolated analysis pipeline."
            risk_level, action = self._evaluate_device_policy(device_dict=device_dict, rows=all_rows)
            summary["risk_level"] = risk_level
            summary["recommended_action"] = action

            self._finalize_scan(event_id, summary, risk_level, action)
        except Exception as exc:  # pragma: no cover - defensive safety net
            error_summary = {
                "device": device_dict,
                "files": [],
                "risk_level": RiskLevel.HIGH.value,
                "error": str(exc),
            }
            self._emit_progress(event_id, 100, f"Scan failed for event #{event_id}: {exc}")
            self._finalize_scan(event_id, error_summary, RiskLevel.HIGH.value, PolicyAction.PROMPT.value)
        finally:
            self._sandbox_manager.cleanup_session(session_id)

    def _run_analysis_pipeline(
        self,
        *,
        event_id: int,
        device_dict: dict[str, Any],
        session_id: str,
        source_files: list[Path],
        staged_files: list[Path],
    ) -> tuple[list[dict[str, Any]], str]:
        """Run sandbox-first analysis and fallback to local analyzers if needed."""
        sandbox_rows = self._analyze_with_windows_sandbox(
            event_id=event_id,
            session_id=session_id,
            source_files=source_files,
            staged_files=staged_files,
            device_dict=device_dict,
        )
        if sandbox_rows is not None:
            return sandbox_rows, "windows_sandbox"

        if self._require_windows_sandbox and self._windows_sandbox.enabled:
            self._emit_progress(
                event_id,
                15,
                "Windows Sandbox unavailable in strict mode. Blocking access.",
            )
            return [], "sandbox_unavailable"

        all_rows: list[dict[str, Any]] = []
        total_files = len(staged_files)

        for index, (source_path, file_path) in enumerate(zip(source_files, staged_files), start=1):
            progress = int((index / total_files) * 100)
            self._emit_progress(event_id, progress, f"Analyzing {file_path.name} ({index}/{total_files})")

            row = self._analyze_single_file(
                file_path=file_path,
                source_path=source_path,
                event_id=event_id,
                device_dict=device_dict,
            )
            all_rows.append(row)
            self.file_scanned.emit(row)

            if row["risk_level"] in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value}:
                event_bus.threat_detected.emit(
                    {
                        "device_event_id": event_id,
                        "file_name": row["file_name"],
                        "risk_level": row["risk_level"],
                        "threat_name": row.get("threat_name"),
                    }
                )

        return all_rows, "host_local"

    def _analyze_with_windows_sandbox(
        self,
        *,
        event_id: int,
        session_id: str,
        source_files: list[Path],
        staged_files: list[Path],
        device_dict: dict[str, Any],
    ) -> list[dict[str, Any]] | None:
        """Run file analysis inside Windows Sandbox and normalize output rows."""
        if self._simulation_mode:
            return None
        if not self._windows_sandbox.is_available():
            return None

        self._emit_progress(event_id, 10, "Launching Windows Sandbox for isolated USB analysis...")

        sandbox_output = self._windows_sandbox.analyze_staged_files(
            session_id=session_id,
            staged_files=staged_files,
        )
        if not sandbox_output:
            self._emit_progress(
                event_id,
                12,
                "Windows Sandbox result unavailable, falling back to local analyzers.",
            )
            return None

        staged_map: dict[str, Path] = {
            staged.name: source
            for source, staged in zip(source_files, staged_files)
        }
        rows: list[dict[str, Any]] = []
        total_rows = len(sandbox_output)

        for index, item in enumerate(sandbox_output, start=1):
            staged_name = str(item.get("sandbox_name") or "").strip()
            source_path = staged_map.get(staged_name, Path(staged_name or f"sandbox_{index}"))

            row = self._build_row_from_sandbox_result(
                source_path=source_path,
                sandbox_row=item,
                device_dict=device_dict,
            )
            self._persist_file_result(event_id=event_id, row=row)
            rows.append(row)
            self.file_scanned.emit(row)

            progress = 15 + int((index / max(1, total_rows)) * 80)
            self._emit_progress(
                event_id,
                progress,
                f"Sandbox analyzed {row['file_name']} ({index}/{total_rows})",
            )

            if row["risk_level"] in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value}:
                event_bus.threat_detected.emit(
                    {
                        "device_event_id": event_id,
                        "file_name": row["file_name"],
                        "risk_level": row["risk_level"],
                        "threat_name": row.get("threat_name"),
                    }
                )

        return rows

    def _build_row_from_sandbox_result(
        self,
        *,
        source_path: Path,
        sandbox_row: dict[str, Any],
        device_dict: dict[str, Any],
    ) -> dict[str, Any]:
        """Normalize one Windows Sandbox row into repository/UI output shape."""
        mime_type, _ = mimetypes.guess_type(str(source_path))
        mime_type = mime_type or "application/octet-stream"

        entropy = self._safe_float(sandbox_row.get("entropy"), default=0.0)
        risk_level = str(sandbox_row.get("risk_level", RiskLevel.LOW.value)).strip().lower()
        if risk_level not in {
            RiskLevel.SAFE.value,
            RiskLevel.LOW.value,
            RiskLevel.MEDIUM.value,
            RiskLevel.HIGH.value,
            RiskLevel.CRITICAL.value,
        }:
            risk_level = RiskLevel.LOW.value

        file_size = int(self._safe_float(sandbox_row.get("size"), default=0.0))
        feature_vector = {
            "size_kb": round(file_size / 1024.0, 3),
            "entropy": float(entropy),
            "is_executable": int(source_path.suffix.lower() in {".exe", ".dll", ".scr", ".com", ".sys"}),
            "suspicious_api_count": 0,
            "has_autorun": int(source_path.name.lower() == "autorun.inf"),
            "has_hidden_path": int(any(part.startswith(".") for part in source_path.parts)),
            "has_script_behavior": int(source_path.suffix.lower() in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh"}),
            "yara_hits": 0,
        }

        return {
            "file_path": str(source_path),
            "file_name": source_path.name,
            "size": file_size,
            "mime_type": mime_type,
            "sha256": self._optional_str(sandbox_row.get("sha256")),
            "md5": None,
            "entropy": float(entropy),
            "entropy_classification": "sandbox_estimated",
            "entropy_explanation": "Estimated inside Windows Sandbox script.",
            "pe": {},
            "heuristics": {"source": "windows_sandbox"},
            "is_malicious": risk_level in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value},
            "risk_level": risk_level,
            "threat_name": self._optional_str(sandbox_row.get("threat_name")),
            "notes": self._optional_str(sandbox_row.get("notes")) or "Windows Sandbox scan result.",
            "feature_vector": feature_vector,
            "device_name": device_dict.get("device_name"),
            "analysis_engine": "windows_sandbox",
        }

    def _enforce_host_isolation(self, device_dict: dict[str, Any]) -> None:
        """Detach drive letter before scanning to reduce host-level exposure."""
        if self._simulation_mode:
            return
        if not self._isolate_drive_on_insert:
            return
        if bool(device_dict.get("host_isolated", False)):
            return

        mount_point = self._optional_str(device_dict.get("mount_point"))
        device_id = self._optional_str(device_dict.get("device_id"))
        if not mount_point or not device_id:
            return

        isolated = self._port_lockdown.isolate_mount_point(device_id=device_id, mount_point=mount_point)
        if not isolated:
            return

        device_dict["original_mount_point"] = mount_point
        device_dict["mount_point"] = isolated
        device_dict["host_isolated"] = True

    def _analyze_single_file(
        self,
        file_path: Path,
        source_path: Path,
        event_id: int,
        device_dict: dict[str, Any],
    ) -> dict[str, Any]:
        """Perform MIME, entropy, PE, and heuristic checks for one file."""
        # VULN-006: Enforce max file size to prevent memory exhaustion.
        _MAX_SCAN_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
        try:
            file_size = file_path.stat().st_size
        except OSError:
            file_size = 0
        if file_size > _MAX_SCAN_FILE_SIZE:
            print(
                f"[SCANNER] Skipping oversized file ({file_size / (1024*1024):.1f} MB): "
                f"{source_path.name}"
            )
            return {
                "file_path": str(source_path),
                "file_name": source_path.name,
                "file_size_bytes": file_size,
                "risk_level": "medium",
                "threat_name": "oversized_file",
                "notes": f"File exceeds max scan size ({_MAX_SCAN_FILE_SIZE // (1024*1024)} MB). Skipped.",
                "sha256": "",
                "md5": "",
                "skipped": True,
            }

        file_bytes = file_path.read_bytes()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        md5_hash = hashlib.md5(file_bytes).hexdigest()  # noqa: S324 - legacy display compatibility

        mime_type, _ = mimetypes.guess_type(str(file_path))
        mime_type = mime_type or "application/octet-stream"

        entropy_info = self._entropy_analyzer.analyze_bytes(file_bytes)
        pe_info = self._pe_analyzer.analyze_file(file_path)
        heuristics = self._run_heuristics(file_path=file_path, file_bytes=file_bytes, mime_type=mime_type)

        risk_level, threat_name, notes = self._score_threat(
            file_path=file_path,
            entropy_info=entropy_info,
            pe_info=pe_info,
            heuristics=heuristics,
        )

        feature_vector = {
            "size_kb": round(len(file_bytes) / 1024.0, 3),
            "entropy": float(entropy_info.get("entropy", 0.0)),
            "is_executable": int(file_path.suffix.lower() in {".exe", ".dll", ".scr", ".com", ".sys"}),
            "suspicious_api_count": len(pe_info.get("suspicious_apis", [])),
            "has_autorun": int(heuristics["autorun_reference"]),
            "has_hidden_path": int(heuristics["hidden_path"]),
            "has_script_behavior": int(heuristics["script_like"]),
            "yara_hits": len(heuristics["yara_hits"]),
        }

        row = {
            "file_path": str(source_path),
            "file_name": source_path.name,
            "size": len(file_bytes),
            "mime_type": mime_type,
            "sha256": sha256_hash,
            "md5": md5_hash,
            "entropy": float(entropy_info.get("entropy", 0.0)),
            "entropy_classification": str(entropy_info.get("classification", "unknown")),
            "entropy_explanation": str(entropy_info.get("explanation", "")),
            "pe": pe_info,
            "heuristics": heuristics,
            "is_malicious": risk_level in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value},
            "risk_level": risk_level,
            "threat_name": threat_name,
            "notes": notes,
            "feature_vector": feature_vector,
            "device_name": device_dict.get("device_name"),
        }

        self._persist_file_result(event_id=event_id, row=row)
        return row

    # ------------------------------------------------------------------
    # Scoring and heuristics
    # ------------------------------------------------------------------

    def _run_heuristics(self, file_path: Path, file_bytes: bytes, mime_type: str) -> dict[str, Any]:
        """Run heuristic YARA-like, script, hidden, and autorun checks."""
        lower_name = file_path.name.lower()
        lower_path = str(file_path).replace("\\", "/").lower()

        yara_hits: list[str] = []
        if any(keyword in lower_name for keyword in ("payload", "dropper", "inject", "rat", "meter")):
            yara_hits.append("SuspiciousFilenameRule")
        if b"powershell" in file_bytes.lower() or b"invoke-expression" in file_bytes.lower():
            yara_hits.append("PowerShellExecutionRule")
        if b"createRemoteThread".lower() in file_bytes.lower():
            yara_hits.append("ThreadInjectionRule")

        is_script_like = (
            file_path.suffix.lower() in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh"}
            or mime_type.startswith("text/")
        )
        hidden_path = any(part.startswith(".") for part in file_path.parts)
        autorun_reference = lower_name == "autorun.inf" or "autorun" in lower_path

        return {
            "yara_hits": yara_hits,
            "script_like": is_script_like,
            "hidden_path": hidden_path,
            "autorun_reference": autorun_reference,
        }

    def _score_threat(
        self,
        file_path: Path,
        entropy_info: dict[str, object],
        pe_info: dict[str, object],
        heuristics: dict[str, Any],
    ) -> tuple[str, str | None, str]:
        """Aggregate analyzer findings into risk level and explanation."""
        score = 0
        notes: list[str] = []

        entropy = float(entropy_info.get("entropy", 0.0))
        if entropy >= 7.8:
            score += 40
            notes.append("Entropy extremely high (possible encrypted payload)")
        elif entropy >= 7.2:
            score += 28
            notes.append("Entropy very high (possible packer)")
        elif entropy >= 6.5:
            score += 16
            notes.append("Entropy elevated")

        suspicious_apis = pe_info.get("suspicious_apis", [])
        if isinstance(suspicious_apis, list) and suspicious_apis:
            score += min(35, 12 + (len(suspicious_apis) * 4))
            notes.append(f"Suspicious PE APIs: {', '.join(suspicious_apis[:4])}")

        yara_hits = heuristics.get("yara_hits", [])
        if isinstance(yara_hits, list) and yara_hits:
            score += 25
            notes.append(f"YARA-like hit(s): {', '.join(yara_hits)}")

        if bool(heuristics.get("script_like")):
            score += 8
            notes.append("Script-like file behavior")
        if bool(heuristics.get("hidden_path")):
            score += 12
            notes.append("Hidden path segment detected")
        if bool(heuristics.get("autorun_reference")):
            score += 22
            notes.append("Autorun behavior indicator")

        extension = file_path.suffix.lower()
        if extension in {".exe", ".dll", ".scr", ".com", ".sys"}:
            score += 5

        if score >= 76:
            return RiskLevel.CRITICAL.value, "Trojan.BadUSB.Loader", "; ".join(notes)
        if score >= 52:
            return RiskLevel.HIGH.value, "Suspicious.Payload", "; ".join(notes)
        if score >= 28:
            return RiskLevel.MEDIUM.value, "Anomalous.File", "; ".join(notes)
        if score >= 10:
            return RiskLevel.LOW.value, None, "; ".join(notes) if notes else "Minor anomalies detected"
        return RiskLevel.SAFE.value, None, "No major indicators detected"

    # ------------------------------------------------------------------
    # Persistence and summary
    # ------------------------------------------------------------------

    def _create_initial_device_event(self, device: Any) -> int:
        """Create initial database event row used for the scan correlation ID."""
        device_dict = self._device_to_dict(device)
        with get_db() as session:
            event = DeviceRepository.create_event(
                session,
                device_name=str(device_dict.get("device_name", "Unknown Device")),
                vendor_id=self._optional_str(device_dict.get("vendor_id")),
                product_id=self._optional_str(device_dict.get("product_id")),
                serial=self._optional_str(device_dict.get("serial_number")),
                manufacturer=self._optional_str(device_dict.get("manufacturer")),
                device_type=str(device_dict.get("device_type", "storage")),
                risk_level=RiskLevel.LOW.value,
                action_taken=PolicyAction.MONITOR.value,
                is_simulated=bool(device_dict.get("is_simulated", self._simulation_mode)),
                notes="Scan queued by FileScanner",
            )
            return int(event.id)

    def _persist_file_result(self, event_id: int, row: dict[str, Any]) -> None:
        """Persist per-file scan output to database repository."""
        with get_db() as session:
            FileScanRepository.log_file_scan(
                session,
                device_event_id=event_id,
                file_path=str(row["file_path"]),
                file_name=str(row["file_name"]),
                file_size_bytes=int(row.get("size", 0)),
                sha256_hash=self._optional_str(row.get("sha256")),
                md5_hash=self._optional_str(row.get("md5")),
                is_malicious=bool(row.get("is_malicious", False)),
                threat_name=self._optional_str(row.get("threat_name")),
                scan_engine="HIDShield Sandbox v1",
                risk_level=str(row.get("risk_level", RiskLevel.SAFE.value)),
                is_simulated=bool(row.get("is_simulated", self._simulation_mode)),
                notes=self._optional_str(row.get("notes")),
            )

    def _evaluate_device_policy(self, device_dict: dict[str, Any], rows: list[dict[str, Any]]) -> tuple[str, str]:
        """Evaluate aggregate scan results via policy engine."""
        malicious_count = sum(1 for row in rows if bool(row.get("is_malicious")))
        max_entropy = max((float(row.get("entropy", 0.0)) for row in rows), default=0.0)

        snapshot = DeviceSnapshot(
            device_name=str(device_dict.get("device_name", "Unknown Device")),
            vendor_id=self._optional_str(device_dict.get("vendor_id")),
            product_id=self._optional_str(device_dict.get("product_id")),
            serial=self._optional_str(device_dict.get("serial_number")),
            manufacturer=self._optional_str(device_dict.get("manufacturer")),
            device_type=str(device_dict.get("device_type", "storage")),
            entropy_score=max_entropy / 8.0 if max_entropy > 1.0 else max_entropy,
            keystroke_rate=None,
            malicious_file_count=malicious_count,
            total_file_count=len(rows),
            is_simulated=self._simulation_mode,
        )
        evaluation = self._policy_engine.evaluate(snapshot)
        return str(evaluation.risk_level), str(evaluation.recommended_action)

    def _finalize_scan(
        self,
        event_id: int,
        summary: dict[str, Any],
        risk_level: str,
        action: str,
    ) -> None:
        """Commit final device-level state and emit completion notifications."""
        with get_db() as session:
            event = session.get(DeviceEvent, event_id)
            if event is not None:
                event.risk_level = risk_level
                event.action_taken = action
                event.entropy_score = float(summary.get("max_entropy", 0.0)) / 8.0
                event.notes = self._optional_str(summary.get("summary_note"))
                session.flush()

            if risk_level in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value}:
                AlertRepository.create_alert(
                    session,
                    title="Threat detected during USB file scan",
                    message=(
                        f"Device event #{event_id} completed with {risk_level.upper()} risk. "
                        f"Recommended action: {action}."
                    ),
                    severity=("critical" if risk_level == RiskLevel.CRITICAL.value else "warning"),
                    category="file_scan",
                    device_event_id=event_id,
                    is_simulated=self._simulation_mode,
                    source="sandbox.file_scanner",
                )

        event_bus.scan_completed.emit(event_id, summary)
        event_bus.policy_action_applied.emit(event_id, action)
        self.scan_finished.emit(event_id, summary)
        self._emit_progress(event_id, 100, f"Scan complete for event #{event_id} ({risk_level.upper()})")

    def _build_summary(self, device_dict: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
        """Create summary payload compatible with existing UI screens."""
        safe_count = sum(1 for row in rows if row["risk_level"] in {RiskLevel.SAFE.value, RiskLevel.LOW.value})
        medium_count = sum(1 for row in rows if row["risk_level"] == RiskLevel.MEDIUM.value)
        high_count = sum(1 for row in rows if row["risk_level"] in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value})
        max_entropy = max((float(row.get("entropy", 0.0)) for row in rows), default=0.0)

        return {
            "device": device_dict,
            "files": rows,
            "total_files": len(rows),
            "safe_files": safe_count,
            "medium_risk_files": medium_count,
            "high_risk_files": high_count,
            "max_entropy": round(max_entropy, 4),
            "summary_note": "Sandbox scan finished with full pipeline.",
            "timestamp": int(time.time()),
        }

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _emit_progress(self, event_id: int, value: int, message: str) -> None:
        """Emit local signal and console output for interactive test visibility."""
        clamped = max(0, min(100, int(value)))
        self.progress_updated.emit(clamped, message)
        event_bus.scan_progress.emit(event_id, clamped, message)
        print(f"[SCANNER] {clamped:>3}% | {message}")

    def _device_to_dict(self, device: Any) -> dict[str, Any]:
        """Normalize device object to canonical scanner payload."""
        if isinstance(device, dict):
            payload = dict(device)
        elif hasattr(device, "to_dict") and callable(device.to_dict):
            payload = dict(device.to_dict())
        else:
            payload = {
                "device_id": self._safe_attr(device, "device_id"),
                "device_name": self._safe_attr(device, "device_name") or self._safe_attr(device, "name") or "Unknown Device",
                "vendor_id": self._safe_attr(device, "vendor_id"),
                "product_id": self._safe_attr(device, "product_id"),
                "serial_number": self._safe_attr(device, "serial_number") or self._safe_attr(device, "serial"),
                "manufacturer": self._safe_attr(device, "manufacturer"),
                "device_type": self._safe_attr(device, "device_type") or "storage",
                "is_simulated": bool(self._safe_attr(device, "is_simulated")),
                "mount_point": self._safe_attr(device, "mount_point"),
            }

        if "device_name" not in payload:
            payload["device_name"] = payload.get("name", "Unknown Device")
        if "serial_number" not in payload:
            payload["serial_number"] = payload.get("serial")
        if "device_type" not in payload or not payload["device_type"]:
            payload["device_type"] = "storage"
        if "is_simulated" not in payload:
            payload["is_simulated"] = self._simulation_mode
        if "mount_point" not in payload:
            payload["mount_point"] = payload.get("drive_letter")

        return payload

    def _safe_attr(self, obj: Any, attr: str) -> Any:
        """Read object attribute defensively without raising exceptions."""
        try:
            return getattr(obj, attr)
        except Exception:
            return None

    def _optional_str(self, value: Any) -> str | None:
        """Normalize optional scalar values to string or None."""
        if value is None:
            return None
        as_text = str(value).strip()
        return as_text if as_text else None

    def _safe_float(self, value: Any, default: float) -> float:
        """Safely coerce unknown values to float for score normalization."""
        try:
            if value is None:
                return default
            return float(value)
        except (TypeError, ValueError):
            return default

    def _is_simulation_mode(self) -> bool:
        """Resolve simulation mode from env variable and config fallback."""
        env_value = os.getenv("HID_SHIELD_SIMULATION_MODE", "").strip().lower()
        if env_value in {"1", "true", "yes"}:
            return True
        if env_value in {"0", "false", "no"}:
            return False

        config_path = Path(__file__).resolve().parent.parent / "config.yaml"
        if config_path.exists():
            with config_path.open("r", encoding="utf-8") as stream:
                config = yaml.safe_load(stream) or {}
                return bool(config.get("simulation_mode", False))
        return False

    def _load_runtime_config(self) -> dict[str, Any]:
        """Load full runtime YAML config for scanner feature toggles."""
        config_path = Path(__file__).resolve().parent.parent / "config.yaml"
        if not config_path.exists():
            return {}
        with config_path.open("r", encoding="utf-8") as stream:
            return yaml.safe_load(stream) or {}

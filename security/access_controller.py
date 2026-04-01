"""Final security enforcement orchestration for HID Shield."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

import yaml
from PySide6.QtCore import QObject, Signal

from core.event_bus import event_bus
from core.port_lockdown import PortLockdown
from database.db import get_db
from database.models import AlertCategory, AlertSeverity, DeviceEvent, PolicyAction, RiskLevel
from database.repository import AlertRepository, DeviceRepository, UserActionRepository
from ml.classifier import Classifier
from security.auth_manager import AuthManager
from security.policy_engine import DeviceSnapshot, PolicyEngine
from security.session_manager import SessionManager, UserMode
from security.whitelist_manager import WhitelistManager


class AccessMode(str, Enum):
    """Supported access decisions after USB threat analysis."""

    ALLOW_SAFE_ONLY = "allow_safe_only"
    MANAGE_SUSPICIOUS = "manage_suspicious"
    BLOCK_AND_EJECT = "block_and_eject"
    GRANT_FULL_ACCESS = "grant_full_access"


@dataclass(slots=True)
class AccessDecision:
    """Structured output of one access-control decision cycle."""

    device_event_id: int
    mode: AccessMode
    policy_action: str
    risk_level: str
    reason: str


class AccessController(QObject):
    """Coordinate scan completion, classification, policy, session, and actions.

    The controller subscribes to `event_bus.scan_completed`, computes a final access
    mode, records audit logs, and emits action signals for UI/state synchronization.

    In SIMULATION_MODE this controller never performs real mount/eject operations.
    """

    decision_made = Signal(dict)
    device_allowed = Signal(dict)
    device_blocked = Signal(dict)
    device_quarantined = Signal(dict)

    def __init__(self) -> None:
        """Build controller dependencies and subscribe to scan events."""
        super().__init__()
        self._simulation_mode = self._is_simulation_mode()
        self._lock = threading.RLock()

        self._classifier = Classifier(auto_subscribe=False)
        self._policy_engine = PolicyEngine(simulation_mode=self._simulation_mode)
        self._auth_manager = AuthManager()
        self._port_lockdown = PortLockdown()
        self._session_manager = SessionManager.instance()
        self._whitelist_manager = WhitelistManager()

        # Cache latest scan context so DecisionPanel buttons can trigger actions.
        self._latest_context: dict[int, dict[str, Any]] = {}

        event_bus.scan_completed.connect(self._on_scan_completed)

    # ------------------------------------------------------------------
    # Public orchestration API
    # ------------------------------------------------------------------

    def handle_scan_completed(
        self,
        device: Mapping[str, Any] | Any,
        scan_results: list[Mapping[str, Any]] | list[dict[str, Any]],
        *,
        device_event_id: int = 0,
    ) -> dict[str, Any]:
        """Handle post-scan enforcement flow and apply final access action."""
        device_payload = self._device_to_dict(device)
        files = [dict(row) for row in scan_results if isinstance(row, Mapping)]

        classification = self._classifier.classify_device(
            device_event_id=max(0, int(device_event_id)),
            scan_summary={"device": device_payload, "files": files},
        )

        serial = self._as_optional_str(
            device_payload.get("serial_number") or device_payload.get("serial")
        )
        is_whitelisted = bool(serial and self._whitelist_manager.is_whitelisted(serial))

        mode = self._select_mode(
            risk_level=str(classification.get("risk_level", RiskLevel.SAFE.value)),
            classifier_level=str(classification.get("device_level", "SAFE")),
            is_whitelisted=is_whitelisted,
            file_rows=files,
            device_payload=device_payload,
        )

        decision = self._apply_mode(
            mode=mode,
            device_event_id=int(device_event_id),
            device_payload=device_payload,
            file_rows=files,
            reason=self._build_decision_reason(
                mode=mode,
                is_whitelisted=is_whitelisted,
                classifier_level=str(classification.get("device_level", "SAFE")),
                policy_advice=classification.get("policy_advice", {}),
            ),
            initiated_by="auto",
        )

        result = {
            "device_event_id": decision.device_event_id,
            "mode": decision.mode.value,
            "policy_action": decision.policy_action,
            "risk_level": decision.risk_level,
            "reason": decision.reason,
            "is_whitelisted": is_whitelisted,
            "classification": classification,
        }

        self.decision_made.emit(result)
        return result

    def attach_decision_panel(self, panel: Any) -> bool:
        """Bind DecisionPanel action buttons to controller enforcement methods."""
        required = ("allow_safe_btn", "manage_susp_btn", "block_all_btn", "grant_full_btn")
        if not all(hasattr(panel, field) for field in required):
            return False

        panel.allow_safe_btn.clicked.connect(
            lambda: self._execute_manual_mode(AccessMode.ALLOW_SAFE_ONLY, panel)
        )
        panel.manage_susp_btn.clicked.connect(
            lambda: self._execute_manual_mode(AccessMode.MANAGE_SUSPICIOUS, panel)
        )
        panel.block_all_btn.clicked.connect(
            lambda: self._execute_manual_mode(AccessMode.BLOCK_AND_EJECT, panel)
        )
        panel.grant_full_btn.clicked.connect(
            lambda: self._execute_manual_mode(AccessMode.GRANT_FULL_ACCESS, panel)
        )
        return True

    def unlock_all_ports_with_key(self, security_key: str) -> bool:
        """Unlock all USB storage ports when a valid security key is provided."""
        key = security_key.strip()
        if not key:
            print("[ACCESS] Security key unlock rejected: empty key.")
            return False

        if not self._auth_manager.verify_security_key(key):
            print("[ACCESS] Security key unlock rejected: invalid key.")
            return False

        unlocked = False
        if hasattr(self._port_lockdown, "unlock_all_ports"):
            unlocked = bool(getattr(self._port_lockdown, "unlock_all_ports")())
        else:
            unlocked = bool(self._port_lockdown.unlock_all_usb_storage())

        if unlocked:
            with get_db() as session:
                AlertRepository.create_alert(
                    session,
                    title="Security key global unlock executed",
                    message="All USB ports were unlocked using the security key.",
                    severity=AlertSeverity.INFO.value,
                    category=AlertCategory.POLICY.value,
                    device_event_id=None,
                    is_simulated=self._simulation_mode,
                    source="security.access_controller",
                )

            print("[ACCESS] Security key unlock executed: all USB ports unlocked.")
            return True

        print("[ACCESS] Security key accepted, but USB unlock operation failed.")
        return False

    # ------------------------------------------------------------------
    # Scan-event integration
    # ------------------------------------------------------------------

    def _on_scan_completed(self, device_event_id: int, summary: dict[str, Any]) -> None:
        """Handle global scan completion event and trigger enforcement flow."""
        payload = summary if isinstance(summary, dict) else {}
        device_payload = payload.get("device") if isinstance(payload.get("device"), Mapping) else {}
        rows = payload.get("files") if isinstance(payload.get("files"), list) else []

        with self._lock:
            self._latest_context[int(device_event_id)] = {
                "device": dict(device_payload),
                "files": [dict(row) for row in rows if isinstance(row, Mapping)],
            }

        try:
            result = self.handle_scan_completed(
                device=device_payload,
                scan_results=[dict(row) for row in rows if isinstance(row, Mapping)],
                device_event_id=int(device_event_id),
            )
            print(
                "[ACCESS] Final action "
                f"event_id={result['device_event_id']} mode={result['mode']} "
                f"policy_action={result['policy_action']}"
            )
        except Exception as exc:  # pragma: no cover - defensive runtime guard
            print(f"[ACCESS] Enforcement pipeline failed for event #{device_event_id}: {exc}")

    # ------------------------------------------------------------------
    # Decision and action execution
    # ------------------------------------------------------------------

    def _select_mode(
        self,
        *,
        risk_level: str,
        classifier_level: str,
        is_whitelisted: bool,
        file_rows: list[dict[str, Any]],
        device_payload: Mapping[str, Any],
    ) -> AccessMode:
        """Pick one of four access modes using risk, session, whitelist, policy."""
        current_mode = self._session_manager.get_current_mode()
        is_admin = current_mode == UserMode.ADMIN.value

        policy_snapshot = self._build_policy_snapshot(
            device_payload=device_payload,
            file_rows=file_rows,
        )
        policy_eval = self._policy_engine.evaluate(policy_snapshot)

        normalized_risk = str(risk_level).lower()
        classifier_upper = str(classifier_level).upper()

        if normalized_risk in {RiskLevel.CRITICAL.value, RiskLevel.HIGH.value} or classifier_upper in {"CRITICAL", "DANGEROUS"}:
            if policy_eval.recommended_action in {PolicyAction.BLOCK.value, PolicyAction.QUARANTINE.value}:
                return AccessMode.BLOCK_AND_EJECT
            if is_admin:
                return AccessMode.MANAGE_SUSPICIOUS
            return AccessMode.BLOCK_AND_EJECT

        if is_whitelisted and is_admin:
            return AccessMode.GRANT_FULL_ACCESS

        if normalized_risk in {RiskLevel.MEDIUM.value} or classifier_upper == "SUSPICIOUS":
            return AccessMode.MANAGE_SUSPICIOUS if is_admin else AccessMode.ALLOW_SAFE_ONLY

        if is_whitelisted:
            return AccessMode.GRANT_FULL_ACCESS if is_admin else AccessMode.ALLOW_SAFE_ONLY

        return AccessMode.ALLOW_SAFE_ONLY

    def _apply_mode(
        self,
        *,
        mode: AccessMode,
        device_event_id: int,
        device_payload: Mapping[str, Any],
        file_rows: list[dict[str, Any]],
        reason: str,
        initiated_by: str,
    ) -> AccessDecision:
        """Persist and emit action effects for one selected mode."""
        risk_level = self._compute_effective_risk(file_rows=file_rows)

        policy_action: str
        if mode == AccessMode.BLOCK_AND_EJECT:
            policy_action = PolicyAction.BLOCK.value
        elif mode == AccessMode.GRANT_FULL_ACCESS:
            policy_action = PolicyAction.ALLOW.value
        elif mode == AccessMode.MANAGE_SUSPICIOUS:
            policy_action = PolicyAction.PROMPT.value
        else:
            policy_action = PolicyAction.MONITOR.value

        # Simulation-mode behavior: persist and emit only, no real mounts/ejects.
        self._persist_action(
            device_event_id=device_event_id,
            policy_action=policy_action,
            risk_level=risk_level,
            reason=reason,
            initiated_by=initiated_by,
        )

        decision = AccessDecision(
            device_event_id=device_event_id,
            mode=mode,
            policy_action=policy_action,
            risk_level=risk_level,
            reason=reason,
        )

        self._emit_action_signals(
            decision=decision,
            device_payload=device_payload,
            file_rows=file_rows,
        )

        print(
            "[ACCESS] Applied mode "
            f"{mode.value} for event #{device_event_id} (simulation={self._simulation_mode})"
        )
        return decision

    def _execute_manual_mode(self, mode: AccessMode, panel: Any) -> None:
        """Execute an operator-selected mode from DecisionPanel button events."""
        event_id = int(getattr(panel, "_last_event_id", 0) or 0)
        device_payload = getattr(panel, "_last_device_payload", {})
        rows = getattr(panel, "_scan_files", [])

        if not isinstance(device_payload, Mapping):
            device_payload = {}
        if not isinstance(rows, list):
            rows = []

        self._apply_mode(
            mode=mode,
            device_event_id=event_id,
            device_payload=dict(device_payload),
            file_rows=[dict(row) for row in rows if isinstance(row, Mapping)],
            reason=f"Manual action from DecisionPanel: {mode.value}",
            initiated_by="operator",
        )

    # ------------------------------------------------------------------
    # Persistence and signaling
    # ------------------------------------------------------------------

    def _persist_action(
        self,
        *,
        device_event_id: int,
        policy_action: str,
        risk_level: str,
        reason: str,
        initiated_by: str,
    ) -> None:
        """Write final access action into device event, user action, and alert log."""
        with get_db() as session:
            if device_event_id > 0:
                DeviceRepository.update_action(session, event_id=device_event_id, new_action=policy_action)
                event = session.get(DeviceEvent, device_event_id)
                if event is not None:
                    event.risk_level = risk_level
                    event.notes = reason
                    session.flush()

                UserActionRepository.log_action(
                    session,
                    device_event_id=device_event_id,
                    action=policy_action,
                    operator_id=self._session_manager.get_operator_id(),
                    reason=reason,
                    was_override=(initiated_by == "operator"),
                    previous_action=None,
                    notes=f"initiated_by={initiated_by}",
                )

            AlertRepository.create_alert(
                session,
                title="Final USB access decision applied",
                message=(
                    f"event_id={device_event_id}; action={policy_action}; "
                    f"risk={risk_level}; reason={reason}"
                ),
                severity=(AlertSeverity.WARNING.value if policy_action == PolicyAction.BLOCK.value else AlertSeverity.INFO.value),
                category=AlertCategory.POLICY.value,
                device_event_id=(device_event_id if device_event_id > 0 else None),
                is_simulated=self._simulation_mode,
                source="security.access_controller",
            )

    def _emit_action_signals(
        self,
        *,
        decision: AccessDecision,
        device_payload: Mapping[str, Any],
        file_rows: list[dict[str, Any]],
    ) -> None:
        """Emit final action updates to event bus and local controller signals."""
        action_payload = {
            "event_type": (
                "device_blocked"
                if decision.policy_action == PolicyAction.BLOCK.value
                else "device_allowed"
            ),
            "device_event_id": decision.device_event_id,
            "mode": decision.mode.value,
            "policy_action": decision.policy_action,
            "risk_level": decision.risk_level,
            "reason": decision.reason,
            "device": dict(device_payload),
            "files": file_rows,
        }

        # Existing global event bus signal used as final action notifier.
        event_bus.policy_action_applied.emit(decision.device_event_id, decision.policy_action)
        event_bus.threat_detected.emit(action_payload)

        if decision.policy_action == PolicyAction.BLOCK.value:
            self.device_blocked.emit(action_payload)
            self.device_quarantined.emit(action_payload)
        else:
            self.device_allowed.emit(action_payload)

    # ------------------------------------------------------------------
    # Helper logic
    # ------------------------------------------------------------------

    def _build_policy_snapshot(
        self,
        *,
        device_payload: Mapping[str, Any],
        file_rows: list[dict[str, Any]],
    ) -> DeviceSnapshot:
        """Build policy-engine snapshot from latest scan context."""
        max_entropy = max((self._safe_float(row.get("entropy"), 0.0) for row in file_rows), default=0.0)
        malicious_count = sum(
            1
            for row in file_rows
            if str(row.get("risk_level", "")).lower() in {"high", "critical"}
            or bool(row.get("is_malicious", False))
        )

        return DeviceSnapshot(
            device_name=str(device_payload.get("device_name", "Unknown Device")),
            vendor_id=self._as_optional_str(device_payload.get("vendor_id")),
            product_id=self._as_optional_str(device_payload.get("product_id")),
            serial=self._as_optional_str(device_payload.get("serial_number") or device_payload.get("serial")),
            manufacturer=self._as_optional_str(device_payload.get("manufacturer")),
            device_type=str(device_payload.get("device_type", "storage")),
            entropy_score=(max_entropy / 8.0 if max_entropy > 1.0 else max_entropy),
            keystroke_rate=None,
            malicious_file_count=malicious_count,
            total_file_count=len(file_rows),
            is_simulated=self._simulation_mode,
        )

    def _compute_effective_risk(self, *, file_rows: list[dict[str, Any]]) -> str:
        """Compute final risk-level string from file row severities."""
        rank = {
            RiskLevel.SAFE.value: 0,
            RiskLevel.LOW.value: 1,
            RiskLevel.MEDIUM.value: 2,
            RiskLevel.HIGH.value: 3,
            RiskLevel.CRITICAL.value: 4,
        }
        current = RiskLevel.SAFE.value
        for row in file_rows:
            value = str(row.get("risk_level", RiskLevel.SAFE.value)).lower()
            if value in rank and rank[value] > rank[current]:
                current = value
        return current

    def _build_decision_reason(
        self,
        *,
        mode: AccessMode,
        is_whitelisted: bool,
        classifier_level: str,
        policy_advice: Any,
    ) -> str:
        """Build traceable reason string for auditing and console output."""
        advice = policy_advice if isinstance(policy_advice, Mapping) else {}
        recommended = str(advice.get("recommended_action", "n/a"))
        return (
            f"mode={mode.value}; classifier_level={classifier_level}; "
            f"whitelisted={is_whitelisted}; policy_recommendation={recommended}; "
            f"session={self._session_manager.get_current_mode()}"
        )

    def _device_to_dict(self, device: Mapping[str, Any] | Any) -> dict[str, Any]:
        """Normalize device payload to plain dictionary for downstream logic."""
        if isinstance(device, Mapping):
            payload = dict(device)
        elif hasattr(device, "to_dict") and callable(device.to_dict):
            payload = dict(device.to_dict())
        else:
            payload = {
                "device_name": getattr(device, "device_name", getattr(device, "name", "Unknown Device")),
                "vendor_id": getattr(device, "vendor_id", None),
                "product_id": getattr(device, "product_id", None),
                "serial_number": getattr(device, "serial_number", getattr(device, "serial", None)),
                "manufacturer": getattr(device, "manufacturer", None),
                "device_type": getattr(device, "device_type", "storage"),
            }

        if "device_name" not in payload:
            payload["device_name"] = payload.get("name", "Unknown Device")
        if "serial_number" not in payload:
            payload["serial_number"] = payload.get("serial")
        if "device_type" not in payload:
            payload["device_type"] = "storage"
        return payload

    def _as_optional_str(self, value: Any) -> str | None:
        """Convert scalar to optional trimmed string."""
        if value is None:
            return None
        text = str(value).strip()
        return text if text else None

    def _safe_float(self, value: Any, default: float) -> float:
        """Safely convert unknown numeric values to float."""
        try:
            if value is None:
                return default
            return float(value)
        except (TypeError, ValueError):
            return default

    def _is_simulation_mode(self) -> bool:
        """Resolve simulation mode from environment variable and config fallback."""
        env_val = os.getenv("HID_SHIELD_SIMULATION_MODE", "").strip().lower()
        if env_val in {"1", "true", "yes"}:
            return True
        if env_val in {"0", "false", "no"}:
            return False

        cfg_path = Path(__file__).resolve().parent.parent / "config.yaml"
        if cfg_path.exists():
            with cfg_path.open("r", encoding="utf-8") as stream:
                config = yaml.safe_load(stream) or {}
                return bool(config.get("simulation_mode", True))
        return True

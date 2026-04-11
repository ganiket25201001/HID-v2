"""Settings screen for HID Shield runtime and policy configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.event_bus import event_bus
from core.usb_monitor import USBEventEmitter
from database.db import get_db
from database.models import AlertCategory, AlertSeverity
from database.repository import AlertRepository
from security.auth_manager import AuthManager
from security.policy_engine import PolicyEngine
from security.session_manager import SessionManager
from ui.styles.theme import Theme
from ui.widgets.animated_button import AnimatedButton
from ui.widgets.glass_card import GlassCard


class SettingsScreen(QWidget):
    """Bonus sixth screen for policy, account, notification, and storage settings.

    The screen persists values in `config.yaml`, applies selected runtime settings,
    and emits monitor-restart requests so the host shell can refresh USB monitoring.
    """

    settings_applied = Signal(dict)
    usb_monitor_restart_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Create settings UI and load current values from config/state managers."""
        super().__init__(parent)

        self._project_root = Path(__file__).resolve().parent.parent
        self._config_path = self._project_root / "config.yaml"

        self._session_manager = SessionManager.instance()
        self._policy_engine = PolicyEngine()
        self._auth_manager = AuthManager()

        self._usb_monitor: USBEventEmitter | None = None
        self._config: dict[str, Any] = {}

        self._build_ui()
        self.load_settings()

    # ------------------------------------------------------------------
    # Public integration methods
    # ------------------------------------------------------------------

    def attach_usb_monitor(self, monitor: USBEventEmitter | None) -> None:
        """Attach monitor instance so Save & Apply can restart it directly."""
        self._usb_monitor = monitor

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Build tabbed settings layout with cyberpunk card styling."""
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        title = QLabel("System Settings")
        title.setStyleSheet(
            f"font-size: 30px; font-weight: 800; color: {Theme.ACCENT_CYAN};"
        )
        subtitle = QLabel("Configure policy, account, notifications, and storage behavior")
        subtitle.setStyleSheet(f"font-size: 13px; color: {Theme.TEXT_SECONDARY};")

        root.addWidget(title)
        root.addWidget(subtitle)

        self.tabs = QTabWidget(self)
        self.tabs.setDocumentMode(True)

        self.tabs.addTab(self._build_policy_tab(), "Policy Configuration")
        self.tabs.addTab(self._build_account_tab(), "Account")
        self.tabs.addTab(self._build_notifications_tab(), "Notifications")
        self.tabs.addTab(self._build_storage_tab(), "Storage")
        self.tabs.addTab(self._build_about_tab(), "About")

        root.addWidget(self.tabs, stretch=1)

        footer = QHBoxLayout()
        footer.addStretch(1)

        self.reload_btn = QPushButton("Reload")
        self.reload_btn.clicked.connect(self.load_settings)

        self.save_apply_btn = AnimatedButton(
            "Save & Apply",
            accent_color=Theme.ACCENT_GREEN,
        )
        self.save_apply_btn.setMinimumHeight(42)
        self.save_apply_btn.clicked.connect(self.save_and_apply)

        footer.addWidget(self.reload_btn)
        footer.addWidget(self.save_apply_btn)

        root.addLayout(footer)

    def _build_policy_tab(self) -> QWidget:
        """Create policy-configuration tab widgets."""
        host = QWidget(self)
        layout = QVBoxLayout(host)
        layout.setContentsMargins(0, 0, 0, 0)

        card = GlassCard(glow=False)
        form = QFormLayout(card)
        form.setContentsMargins(18, 16, 18, 16)
        form.setSpacing(10)

        self.default_action_combo = QComboBox(self)
        self.default_action_combo.addItems([
            "Scan and Prompt", 
            "Scan and Allow", 
            "Scan and Block", 
            "Scan and Monitor"
        ])

        self.entropy_spin = QDoubleSpinBox(self)
        self.entropy_spin.setRange(0.0, 1.0)
        self.entropy_spin.setSingleStep(0.01)
        self.entropy_spin.setDecimals(2)

        self.max_kps_spin = QSpinBox(self)
        self.max_kps_spin.setRange(1, 1000)

        self.cooldown_spin = QSpinBox(self)
        self.cooldown_spin.setRange(0, 3600)

        self.log_keystrokes_check = QCheckBox("Enable keystroke logging")
        self.enable_ai_agent_check = QCheckBox("Enable AI Explanations (Gemma 4)")

        form.addRow("Default Action", self.default_action_combo)
        form.addRow("Entropy Threshold", self.entropy_spin)
        form.addRow("Max Keystrokes / sec", self.max_kps_spin)
        form.addRow("Cooldown Seconds", self.cooldown_spin)
        form.addRow("Privacy", self.log_keystrokes_check)
        form.addRow("AI Integration", self.enable_ai_agent_check)

        layout.addWidget(card)
        layout.addStretch(1)
        return host

    def _build_account_tab(self) -> QWidget:
        """Create account/session tab widgets."""
        host = QWidget(self)
        layout = QVBoxLayout(host)
        layout.setContentsMargins(0, 0, 0, 0)

        card = GlassCard(glow=False)
        form = QFormLayout(card)
        form.setContentsMargins(18, 16, 18, 16)
        form.setSpacing(10)

        self.current_mode_label = QLabel("GUEST")
        self.current_mode_label.setStyleSheet(f"color: {Theme.ACCENT_CYAN};")
        self.operator_label = QLabel("anonymous")
        self.operator_label.setStyleSheet(f"color: {Theme.TEXT_SECONDARY};")

        self.session_timeout_spin = QSpinBox(self)
        self.session_timeout_spin.setRange(1, 240)

        self.new_pin_edit = QLineEdit(self)
        self.new_pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_pin_edit.setPlaceholderText("New 6-digit PIN")
        self.confirm_pin_edit = QLineEdit(self)
        self.confirm_pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_pin_edit.setPlaceholderText("Confirm new PIN")

        form.addRow("Current Session Mode", self.current_mode_label)
        form.addRow("Operator", self.operator_label)
        form.addRow("Session Timeout (minutes)", self.session_timeout_spin)
        form.addRow("Change PIN", self.new_pin_edit)
        form.addRow("Confirm PIN", self.confirm_pin_edit)

        note = QLabel("Leave PIN fields empty to keep current PIN unchanged.")
        note.setStyleSheet(f"font-size: 12px; color: {Theme.TEXT_SECONDARY};")

        layout.addWidget(card)
        layout.addWidget(note)
        layout.addStretch(1)
        return host

    def _build_notifications_tab(self) -> QWidget:
        """Create notifications and alert behavior tab widgets."""
        host = QWidget(self)
        layout = QVBoxLayout(host)
        layout.setContentsMargins(0, 0, 0, 0)

        card = GlassCard(glow=False)
        form = QFormLayout(card)
        form.setContentsMargins(18, 16, 18, 16)
        form.setSpacing(10)

        self.sound_check = QCheckBox("Play sound for threat alerts")
        self.toast_check = QCheckBox("Show desktop toast notifications")
        self.alert_severity_combo = QComboBox(self)
        self.alert_severity_combo.addItems(["info", "warning", "error", "critical"])

        form.addRow("Sound", self.sound_check)
        form.addRow("Toast Notifications", self.toast_check)
        form.addRow("Minimum Alert Severity", self.alert_severity_combo)

        layout.addWidget(card)
        layout.addStretch(1)
        return host

    def _build_storage_tab(self) -> QWidget:
        """Create storage/logging tab widgets."""
        host = QWidget(self)
        layout = QVBoxLayout(host)
        layout.setContentsMargins(0, 0, 0, 0)

        card = GlassCard(glow=False)
        form = QFormLayout(card)
        form.setContentsMargins(18, 16, 18, 16)
        form.setSpacing(10)

        self.db_path_edit = QLineEdit(self)
        self.db_path_edit.setReadOnly(True)
        self.log_level_combo = QComboBox(self)
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.log_rotation_edit = QLineEdit(self)
        self.log_retention_edit = QLineEdit(self)

        form.addRow("Database Path", self.db_path_edit)
        form.addRow("Log Level", self.log_level_combo)
        form.addRow("Log Rotation", self.log_rotation_edit)
        form.addRow("Log Retention", self.log_retention_edit)

        layout.addWidget(card)
        layout.addStretch(1)
        return host

    def _build_about_tab(self) -> QWidget:
        """Create about tab with static product metadata labels."""
        host = QWidget(self)
        layout = QVBoxLayout(host)
        layout.setContentsMargins(0, 0, 0, 0)

        card = GlassCard(glow=True)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(18, 16, 18, 16)
        card_layout.setSpacing(8)

        self.about_title = QLabel("HID Shield")
        self.about_title.setStyleSheet(
            f"font-size: 24px; font-weight: 800; color: {Theme.ACCENT_CYAN};"
        )
        self.about_version = QLabel("Version: 1.0.0")
        self.about_description = QLabel("Intelligent USB Security System")
        self.about_description.setWordWrap(True)

        for widget in (self.about_version, self.about_description):
            widget.setStyleSheet(f"color: {Theme.TEXT_PRIMARY};")

        card_layout.addWidget(self.about_title)
        card_layout.addWidget(self.about_version)
        card_layout.addWidget(self.about_description)
        card_layout.addStretch(1)

        layout.addWidget(card)
        layout.addStretch(1)
        return host

    # ------------------------------------------------------------------
    # Load/save operations
    # ------------------------------------------------------------------

    def load_settings(self) -> None:
        """Load settings from config file and runtime managers into form widgets."""
        self._config = self._read_config()

        policy_cfg = self._config.setdefault("policy", {})
        security_cfg = self._config.setdefault("security", {})
        notify_cfg = self._config.setdefault("notifications", {})
        logging_cfg = self._config.setdefault("logging", {})
        db_cfg = self._config.setdefault("database", {})
        app_cfg = self._config.setdefault("app", {})

        action_val = str(policy_cfg.get("default_action", "prompt")).lower()
        action_map = {
            "prompt": "Scan and Prompt",
            "allow": "Scan and Allow",
            "block": "Scan and Block",
            "monitor": "Scan and Monitor"
        }
        self.default_action_combo.setCurrentText(action_map.get(action_val, "Scan and Prompt"))
        self.entropy_spin.setValue(float(policy_cfg.get("entropy_threshold", 0.65)))
        self.max_kps_spin.setValue(int(policy_cfg.get("max_keystroke_rate", 80)))
        self.cooldown_spin.setValue(int(policy_cfg.get("cooldown_seconds", 30)))
        self.log_keystrokes_check.setChecked(bool(policy_cfg.get("log_keystrokes", False)))
        self.enable_ai_agent_check.setChecked(bool(policy_cfg.get("enable_ai_agent", False)))

        timeout_minutes = int(security_cfg.get("session_timeout_minutes", 15))
        self.session_timeout_spin.setValue(timeout_minutes)
        self.current_mode_label.setText(self._session_manager.get_current_mode())
        self.operator_label.setText(self._session_manager.get_operator_id() or "anonymous")
        self.new_pin_edit.clear()
        self.confirm_pin_edit.clear()

        self.sound_check.setChecked(bool(notify_cfg.get("sound_enabled", True)))
        self.toast_check.setChecked(bool(notify_cfg.get("toast_enabled", True)))
        self.alert_severity_combo.setCurrentText(str(notify_cfg.get("min_severity", "warning")))

        self.db_path_edit.setText(str(db_cfg.get("path", "hid_shield.db")))
        self.log_level_combo.setCurrentText(str(logging_cfg.get("level", "INFO")))
        self.log_rotation_edit.setText(str(logging_cfg.get("rotation", "10 MB")))
        self.log_retention_edit.setText(str(logging_cfg.get("retention", "30 days")))

        self.about_title.setText(str(app_cfg.get("name", "HID Shield")))
        self.about_version.setText(f"Version: {app_cfg.get('version', '1.0.0')}")
        self.about_description.setText(str(app_cfg.get("description", "Intelligent USB Security System")))

    def save_and_apply(self) -> None:
        """Validate form state, persist to config.yaml, and apply runtime updates."""
        pin_result = self._validate_and_update_pin()
        if pin_result is False:
            return

        # Update config structure from current widgets.
        self._config.setdefault("policy", {})
        self._config.setdefault("security", {})
        self._config.setdefault("notifications", {})
        self._config.setdefault("logging", {})

        ui_text = self.default_action_combo.currentText()
        reverse_map = {
            "Scan and Prompt": "prompt",
            "Scan and Allow": "allow",
            "Scan and Block": "block",
            "Scan and Monitor": "monitor"
        }
        self._config["policy"]["default_action"] = reverse_map.get(ui_text, "prompt")
        self._config["policy"]["entropy_threshold"] = float(self.entropy_spin.value())
        self._config["policy"]["max_keystroke_rate"] = int(self.max_kps_spin.value())
        self._config["policy"]["cooldown_seconds"] = int(self.cooldown_spin.value())
        self._config["policy"]["log_keystrokes"] = bool(self.log_keystrokes_check.isChecked())
        self._config["policy"]["enable_ai_agent"] = bool(self.enable_ai_agent_check.isChecked())

        self._config["security"]["session_timeout_minutes"] = int(self.session_timeout_spin.value())

        self._config["notifications"]["sound_enabled"] = bool(self.sound_check.isChecked())
        self._config["notifications"]["toast_enabled"] = bool(self.toast_check.isChecked())
        self._config["notifications"]["min_severity"] = self.alert_severity_combo.currentText()

        self._config["logging"]["level"] = self.log_level_combo.currentText()
        self._config["logging"]["rotation"] = self.log_rotation_edit.text().strip() or "10 MB"
        self._config["logging"]["retention"] = self.log_retention_edit.text().strip() or "30 days"

        self._write_config(self._config)
        self._apply_runtime_settings()
        self._record_settings_update_alert()

        self.settings_applied.emit(dict(self._config))
        event_bus.policy_action_applied.emit(-1, "settings_updated")

        QMessageBox.information(self, "Settings Applied", "Configuration saved and applied successfully.")

    # ------------------------------------------------------------------
    # Validation and runtime application
    # ------------------------------------------------------------------

    def _validate_and_update_pin(self) -> bool | None:
        """Validate optional PIN fields and update AuthManager when provided."""
        pin_a = self.new_pin_edit.text().strip()
        pin_b = self.confirm_pin_edit.text().strip()

        if not pin_a and not pin_b:
            return None
        if pin_a != pin_b:
            QMessageBox.warning(self, "PIN Mismatch", "New PIN and confirmation do not match.")
            return False
        if not (pin_a.isdigit() and len(pin_a) == 6):
            QMessageBox.warning(self, "Invalid PIN", "PIN must be a 6-digit numeric value.")
            return False

        self._auth_manager.set_new_pin(pin_a)
        return True

    def _apply_runtime_settings(self) -> None:
        """Apply settings in-memory and request USB monitor restart."""
        timeout_minutes = int(self.session_timeout_spin.value())
        self._session_manager.set_timeout_minutes(timeout_minutes)

        self._policy_engine = PolicyEngine()

        # Restart attached USB monitor if available; otherwise emit restart request.
        if self._usb_monitor is not None:
            try:
                self._usb_monitor.stop()
            except Exception:
                pass
            try:
                self._usb_monitor.start()
            except Exception:
                self.usb_monitor_restart_requested.emit()
        else:
            self.usb_monitor_restart_requested.emit()

    def _record_settings_update_alert(self) -> None:
        """Persist settings-update audit event in alert repository."""
        with get_db() as session:
            AlertRepository.create_alert(
                session,
                title="Settings updated and applied",
                message="Configuration changes were saved from SettingsScreen.",
                severity=AlertSeverity.INFO,
                category=AlertCategory.SYSTEM,
                is_simulated=True,
                source="ui.settings_screen",
            )

    # ------------------------------------------------------------------
    # Config I/O helpers
    # ------------------------------------------------------------------

    def _read_config(self) -> dict[str, Any]:
        """Read config.yaml and return configuration dictionary."""
        if self._config_path.exists():
            with self._config_path.open("r", encoding="utf-8") as stream:
                data = yaml.safe_load(stream) or {}
                return data if isinstance(data, dict) else {}
        return {}

    def _write_config(self, data: dict[str, Any]) -> None:
        """Write validated configuration dictionary back to config.yaml."""
        with self._config_path.open("w", encoding="utf-8") as stream:
            yaml.safe_dump(data, stream, sort_keys=False, allow_unicode=False)

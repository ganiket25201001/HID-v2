"""Live USB detection screen with approval-gated access flow."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QProgressBar, QVBoxLayout, QWidget

from core.event_bus import event_bus
from core.port_lockdown import PortLockdown
from core.usb_monitor import USBEventEmitter
from ui.styles.theme import Theme
from ui.widgets.animated_button import AnimatedButton
from ui.widgets.glass_card import GlassCard
from ui.widgets.pipeline_widget import PipelineWidget


class LiveUSBDetectionScreen(QWidget):
    """Live USB detection/scan progress screen."""

    def __init__(self, usb_emitter: USBEventEmitter | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._usb_emitter = usb_emitter
        self._lockdown = PortLockdown()
        self._current_device: dict[str, Any] = {}
        self._current_event_id: int = 0
        self._live_spin = 0

        self._ticker = QTimer(self)
        self._ticker.setInterval(450)
        self._ticker.timeout.connect(self._tick_waiting_progress)

        self._build_ui()
        self._wire_signals()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(26, 20, 26, 20)
        root.setSpacing(14)

        title = QLabel("Live USB Detection")
        title.setStyleSheet(f"font-size: 28px; font-weight: 800; color: {Theme.ACCENT_CYAN};")
        subtitle = QLabel("USB is isolated immediately and remains hidden until operator approval")
        subtitle.setStyleSheet(f"font-size: 14px; color: {Theme.TEXT_SECONDARY};")
        root.addWidget(title)
        root.addWidget(subtitle)

        self.pipeline = PipelineWidget(self)
        self.pipeline.setVisible(False)
        root.addWidget(self.pipeline)

        progress_card = GlassCard(glow=True)
        progress_layout = QVBoxLayout(progress_card)
        progress_layout.setContentsMargins(16, 14, 16, 14)

        row = QHBoxLayout()
        self.status = QLabel("Waiting for USB insertion...")
        self.status.setStyleSheet(f"font-size: 15px; color: {Theme.TEXT_PRIMARY};")
        self.file_count = QLabel("Files inspected: 0")
        self.file_count.setStyleSheet(f"font-size: 14px; color: {Theme.ACCENT_GREEN}; font-weight: 700;")

        row.addWidget(self.status)
        row.addStretch(1)
        row.addWidget(self.file_count)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFixedHeight(26)
        self.progress.setStyleSheet(
            f"""
            QProgressBar {{
                background-color: {Theme.BG_TERTIARY};
                border: 1px solid {Theme.BORDER};
                border-radius: 10px;
                text-align: center;
                color: {Theme.TEXT_PRIMARY};
                font-weight: 700;
            }}
            QProgressBar::chunk {{
                background-color: {Theme.ACCENT_CYAN};
                border-radius: 8px;
                margin: 1px;
            }}
            """
        )

        progress_layout.addLayout(row)
        progress_layout.addWidget(self.progress)
        root.addWidget(progress_card)

        info_card = GlassCard(glow=False)
        info_layout = QGridLayout(info_card)
        info_layout.setContentsMargins(16, 14, 16, 14)
        info_layout.setHorizontalSpacing(18)
        info_layout.setVerticalSpacing(10)

        info_layout.addWidget(QLabel("Device"), 0, 0)
        info_layout.addWidget(QLabel("Serial"), 1, 0)
        info_layout.addWidget(QLabel("Access State"), 2, 0)

        self.device_name = QLabel("-")
        self.serial = QLabel("-")
        self.access_state = QLabel("BLOCKED (awaiting decision)")
        self.access_state.setStyleSheet(f"font-size: 14px; color: {Theme.ACCENT_MAGENTA}; font-weight: 700;")

        info_layout.addWidget(self.device_name, 0, 1)
        info_layout.addWidget(self.serial, 1, 1)
        info_layout.addWidget(self.access_state, 2, 1)

        root.addWidget(info_card)

        foot = QHBoxLayout()
        foot.addStretch(1)
        self.decision_button = AnimatedButton("Make Decision", accent_color=Theme.ACCENT_CYAN)
        self.decision_button.setFixedSize(170, 40)
        self.decision_button.setVisible(False)
        
        self.cancel_button = AnimatedButton("Cancel Scan", accent_color=Theme.ACCENT_MAGENTA)
        self.cancel_button.setFixedSize(170, 40)
        
        foot.addWidget(self.decision_button)
        foot.addWidget(self.cancel_button)
        root.addLayout(foot)

    def _wire_signals(self) -> None:
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.decision_button.clicked.connect(self._show_decision_panel)

        event_bus.usb_device_inserted.connect(self._on_usb_inserted)
        event_bus.scan_started.connect(self._on_scan_started)
        event_bus.scan_progress.connect(self._on_scan_progress)
        event_bus.scan_completed.connect(self._on_scan_completed)
        event_bus.device_access_state_changed.connect(self._on_access_state_changed)

    def _on_usb_inserted(self, payload: dict[str, Any]) -> None:
        self._current_device = dict(payload)
        self._current_event_id = 0

        self.device_name.setText(str(payload.get("device_name") or "Unknown USB Device"))
        self.serial.setText(str(payload.get("serial_number") or payload.get("serial") or "n/a"))

        # Enforce immediate block so device does not get normal explorer access
        # before explicit approval from Decision Panel.
        device_id = str(payload.get("device_id") or payload.get("serial_number") or "unknown-device")
        self._lockdown.apply_policy(device_id=device_id, action="block")
        self.access_state.setText("BLOCKED (awaiting decision)")
        self.access_state.setStyleSheet(f"font-size: 14px; color: {Theme.ACCENT_MAGENTA}; font-weight: 700;")

        self.pipeline.setVisible(True)
        self.pipeline.reset_pipeline()
        self.pipeline.start_intro_animation()

        self.progress.setValue(5)
        self.file_count.setText("Files inspected: 0")
        self.status.setText("USB detected and isolated. Waiting for scanner...")
        self.decision_button.setVisible(False)
        self.cancel_button.setVisible(True)
        self._live_spin = 5
        self._ticker.start()

    def _on_scan_started(self, event_id: int) -> None:
        self._current_event_id = int(event_id)
        self.status.setText("Scan started: analyzing file stream...")
        if self.progress.value() < 10:
            self.progress.setValue(10)

    def _on_scan_progress(self, event_id: int, progress: int, message: str) -> None:
        if self._current_event_id and int(event_id) != self._current_event_id:
            return
        self.progress.setValue(max(0, min(100, int(progress))))
        self.status.setText(message or "Scanning...")

    def _tick_waiting_progress(self) -> None:
        if self.progress.value() >= 95:
            return
        self._live_spin = min(95, self._live_spin + 2)
        self.progress.setValue(self._live_spin)

    def _on_scan_completed(self, event_id: int, summary: dict[str, Any]) -> None:
        if self._current_event_id and int(event_id) != self._current_event_id:
            return

        self._current_event_id = int(event_id)
        self._ticker.stop()

        files = summary.get("files") if isinstance(summary, dict) else None
        count = len(files) if isinstance(files, list) else int(summary.get("files_scanned") or 0)

        self.file_count.setText(f"Files inspected: {count}")
        self.progress.setValue(100)
        self.pipeline.set_progress(100)
        self.status.setText("Scan completed. USB remains blocked until approval.")
        
        self.cancel_button.setVisible(False)
        self.decision_button.setVisible(True)

    def _show_decision_panel(self) -> None:
        if self._current_event_id:
            event_bus.scan_completed.emit(self._current_event_id, {"event_id": self._current_event_id})

    def _on_access_state_changed(self, event_id: int, action: str) -> None:
        if self._current_event_id and int(event_id) != self._current_event_id:
            return

        device_id = str(self._current_device.get("device_id") or self._current_device.get("serial_number") or "unknown-device")
        action_norm = str(action).lower().strip()

        if action_norm.startswith("allow"):
            self._lockdown.apply_policy(device_id=device_id, action="allow")
            self.access_state.setText("ALLOWED")
            self.access_state.setStyleSheet(f"font-size: 14px; color: {Theme.ACCENT_GREEN}; font-weight: 700;")
            self.status.setText("Access approved by operator.")
        elif action_norm == "block":
            self._lockdown.apply_policy(device_id=device_id, action="block")
            self.access_state.setText("BLOCKED")
            self.access_state.setStyleSheet(f"font-size: 14px; color: {Theme.ACCENT_MAGENTA}; font-weight: 700;")
            self.status.setText("Access blocked by operator.")

    def cancel_scan(self) -> None:
        device_id = str(self._current_device.get("device_id") or self._current_device.get("serial_number") or "unknown-device")
        self._lockdown.apply_policy(device_id=device_id, action="block")
        self._ticker.stop()
        self.status.setText("Scan cancelled. USB remains blocked.")
        event_bus.device_access_state_changed.emit(self._current_event_id, "block")
        event_bus.policy_action_applied.emit(self._current_event_id, "block")

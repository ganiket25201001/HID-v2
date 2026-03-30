"""
hid_shield.ui.usb_detection
===========================
Live USB Detection takeover screen (Screen 2).

Design
------
* Full-screen cinematic detection view shown when a USB insertion event arrives.
* Integrates with the global ``event_bus`` and receives ``usb_device_inserted``.
* Hosts a central ``PipelineWidget`` and a real-time scan status panel.
* In ``SIMULATION_MODE`` this screen runs an 8-second fake scan loop and emits
  ``scan_completed`` when done.
"""

from __future__ import annotations

import os
import random
from pathlib import Path
from typing import Any, Final

import yaml
from PySide6.QtCore import (
    QEasingCurve,
    Property,
    QPropertyAnimation,
    QRect,
    Qt,
    QTimer,
    Signal,
    QVariantAnimation,
)
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from core.event_bus import event_bus
from core.port_lockdown import PortLockdown
from core.usb_monitor import USBEventEmitter
from ui.styles.theme import Theme
from ui.widgets.animated_button import AnimatedButton
from ui.widgets.glass_card import GlassCard
from ui.widgets.pipeline_widget import PipelineWidget


def _is_simulation_mode() -> bool:
    """Resolve simulation mode from env var first, then ``config.yaml`` fallback."""
    env_val = os.getenv("HID_SHIELD_SIMULATION_MODE", "").strip().lower()
    if env_val in ("true", "1", "yes"):
        return True
    if env_val in ("false", "0", "no"):
        return False

    cfg_path = Path(__file__).resolve().parent.parent / "config.yaml"
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as cfg_file:
            return bool((yaml.safe_load(cfg_file) or {}).get("simulation_mode", True))
    return True


class _GlowingUSBIcon(QWidget):
    """Animated USB plug icon with a breathing neon pulse effect."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(168, 168)
        self._pulse: float = 0.0

        self._pulse_animation = QVariantAnimation(self)
        self._pulse_animation.setStartValue(0.15)
        self._pulse_animation.setEndValue(1.0)
        self._pulse_animation.setDuration(1200)
        self._pulse_animation.setEasingCurve(QEasingCurve.Type.InOutSine)
        self._pulse_animation.setLoopCount(-1)
        self._pulse_animation.valueChanged.connect(self._on_pulse_changed)
        self._pulse_animation.start()

    def _on_pulse_changed(self, value: Any) -> None:
        """Update pulse value and trigger a repaint for smooth glow motion."""
        self._pulse = float(value)
        self.update()

    def paintEvent(self, event: Any) -> None:  # noqa: ARG002 - Qt override
        """Draw a stylized USB glyph with animated aura and center emblem."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect().adjusted(8, 8, -8, -8)
        center = rect.center()

        # Layered pulse rings create the dramatic takeover effect.
        ring_color = QColor(Theme.ACCENT_CYAN)
        ring_color.setAlpha(int(45 + self._pulse * 70))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(ring_color)
        painter.drawEllipse(center, int(68 + self._pulse * 12), int(68 + self._pulse * 12))

        ring2 = QColor(Theme.ACCENT_CYAN)
        ring2.setAlpha(int(15 + self._pulse * 35))
        painter.setBrush(ring2)
        painter.drawEllipse(center, int(84 + self._pulse * 12), int(84 + self._pulse * 12))

        body_path = QPainterPath()
        body_rect = rect.adjusted(34, 24, -34, -26)
        body_path.addRoundedRect(body_rect, 18, 18)

        body_fill = QColor(Theme.BG_TERTIARY)
        body_fill.setAlpha(245)
        painter.setBrush(body_fill)

        body_pen = QPen(QColor(Theme.ACCENT_CYAN))
        body_pen.setWidth(2)
        painter.setPen(body_pen)
        painter.drawPath(body_path)

        # USB trident-like simplified mark.
        painter.setPen(QPen(QColor(Theme.ACCENT_CYAN), 3))
        cx = body_rect.center().x()
        top = body_rect.y() + 22
        bottom = body_rect.bottom() - 16

        painter.drawLine(cx, bottom, cx, top)
        painter.drawLine(cx, top, cx - 16, top - 16)
        painter.drawLine(cx, top, cx + 16, top - 16)
        painter.drawEllipse(cx - 3, top - 23, 6, 6)
        painter.drawRect(cx - 20, top - 20, 8, 8)
        painter.drawRect(cx + 12, top - 20, 8, 8)


class LiveUSBDetectionScreen(QWidget):
    """Full-screen USB detection takeover view.

    Signals
    -------
    scan_completed(dict)
        Emitted when scanning completes with a summary payload.
    scan_cancelled(dict)
        Emitted when the operator aborts scan and a block action is applied.
    """

    scan_completed = Signal(dict)
    scan_cancelled = Signal(dict)

    _SIM_TICK_MS: Final[int] = 400
    _SIM_SCAN_SECONDS: Final[float] = 8.0

    def __init__(self, usb_emitter: USBEventEmitter | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("liveUsbDetectionScreen")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(f"background-color: {Theme.BG_PRIMARY};")

        self._usb_emitter: USBEventEmitter | None = usb_emitter
        self._simulation_mode: bool = _is_simulation_mode()
        if self._usb_emitter is not None:
            # Respect the monitor's resolved mode if an emitter instance is supplied.
            self._simulation_mode = bool(self._usb_emitter.simulation_mode)

        self._lockdown = PortLockdown()

        self._current_device: dict[str, Any] = {}
        self._is_scanning: bool = False
        self._scan_tick: int = 0
        self._scan_total_ticks: int = int((self._SIM_SCAN_SECONDS * 1000) / self._SIM_TICK_MS)
        self._file_count: int = 0

        self._slide_anim: QPropertyAnimation | None = None
        self._progress_glow: float = 0.0

        self._scan_timer = QTimer(self)
        self._scan_timer.setInterval(self._SIM_TICK_MS)
        self._scan_timer.timeout.connect(self._on_fake_scan_tick)

        self._progress_glow_anim = QVariantAnimation(self)
        self._progress_glow_anim.setStartValue(0.2)
        self._progress_glow_anim.setEndValue(1.0)
        self._progress_glow_anim.setDuration(900)
        self._progress_glow_anim.setEasingCurve(QEasingCurve.Type.InOutSine)
        self._progress_glow_anim.setLoopCount(-1)
        self._progress_glow_anim.valueChanged.connect(self._on_progress_glow_changed)

        self._build_ui()
        self._wire_signals()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Build the takeover layout with centered pipeline and info panels."""
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(56, 42, 56, 42)
        root_layout.setSpacing(20)

        # Header section
        header_wrap = QVBoxLayout()
        header_wrap.setSpacing(10)

        top_line = QLabel("LIVE USB DETECTION")
        top_line.setProperty("class", "h1")
        top_line.setAlignment(Qt.AlignmentFlag.AlignCenter)
        top_line.setStyleSheet(
            f"font-size: 42px; font-weight: 800; letter-spacing: 2px; color: {Theme.ACCENT_CYAN};"
        )

        subtitle = QLabel("Realtime deep inspection and policy enforcement in progress")
        subtitle.setProperty("class", "subtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet(f"font-size: 15px; color: {Theme.TEXT_SECONDARY};")

        header_wrap.addWidget(top_line)
        header_wrap.addWidget(subtitle)
        root_layout.addLayout(header_wrap)

        # Device icon spotlight.
        icon_row = QHBoxLayout()
        icon_row.addStretch(1)
        self.device_icon = _GlowingUSBIcon(self)
        icon_row.addWidget(self.device_icon)
        icon_row.addStretch(1)
        root_layout.addLayout(icon_row)

        # Pipeline center stage.
        self.pipeline = PipelineWidget(self)
        root_layout.addWidget(self.pipeline)

        # Progress + file count panel.
        progress_card = GlassCard(glow=True)
        progress_layout = QVBoxLayout(progress_card)
        progress_layout.setContentsMargins(20, 18, 20, 18)
        progress_layout.setSpacing(8)

        labels_row = QHBoxLayout()
        labels_row.setSpacing(12)

        self.scan_status_label = QLabel("Awaiting USB insertion...")
        self.scan_status_label.setStyleSheet(f"font-size: 14px; color: {Theme.TEXT_PRIMARY};")

        self.file_count_label = QLabel("Files inspected: 0")
        self.file_count_label.setStyleSheet(f"font-size: 14px; color: {Theme.ACCENT_GREEN}; font-weight: 700;")
        self.file_count_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        labels_row.addWidget(self.scan_status_label)
        labels_row.addStretch(1)
        labels_row.addWidget(self.file_count_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p%")
        self.progress_bar.setFixedHeight(26)
        self.progress_bar.setStyleSheet(self._build_progress_stylesheet())

        progress_layout.addLayout(labels_row)
        progress_layout.addWidget(self.progress_bar)

        root_layout.addWidget(progress_card)

        # Device info panel.
        info_card = GlassCard(glow=False)
        info_layout = QGridLayout(info_card)
        info_layout.setContentsMargins(20, 16, 20, 16)
        info_layout.setHorizontalSpacing(18)
        info_layout.setVerticalSpacing(8)

        info_title = QLabel("Device Intelligence")
        info_title.setProperty("class", "h2")
        info_title.setStyleSheet(f"font-size: 18px; color: {Theme.ACCENT_CYAN};")

        self.device_name_value = QLabel("-")
        self.serial_value = QLabel("-")
        self.capacity_value = QLabel("-")

        for label in (self.device_name_value, self.serial_value, self.capacity_value):
            label.setStyleSheet(f"font-size: 14px; color: {Theme.TEXT_PRIMARY}; font-weight: 600;")

        info_layout.addWidget(info_title, 0, 0, 1, 2)
        info_layout.addWidget(self._meta_label("Device"), 1, 0)
        info_layout.addWidget(self.device_name_value, 1, 1)
        info_layout.addWidget(self._meta_label("Serial"), 2, 0)
        info_layout.addWidget(self.serial_value, 2, 1)
        info_layout.addWidget(self._meta_label("Capacity"), 3, 0)
        info_layout.addWidget(self.capacity_value, 3, 1)

        root_layout.addWidget(info_card)

        # Footer actions.
        action_row = QHBoxLayout()
        action_row.addStretch(1)

        self.cancel_button = AnimatedButton("Cancel Scan", accent_color=Theme.ACCENT_MAGENTA)
        self.cancel_button.setFixedSize(172, 42)

        action_row.addWidget(self.cancel_button)
        root_layout.addLayout(action_row)

    def _wire_signals(self) -> None:
        """Attach event bus and UI handlers for lifecycle management."""
        self.cancel_button.clicked.connect(self.cancel_scan)
        event_bus.usb_device_inserted.connect(self._on_usb_device_inserted)

    # ------------------------------------------------------------------
    # Qt Properties / Styling helpers
    # ------------------------------------------------------------------

    def get_progress_glow(self) -> float:
        """Return dynamic glow intensity for the progress bar border."""
        return self._progress_glow

    def set_progress_glow(self, value: float) -> None:
        """Set dynamic glow intensity for the progress bar border."""
        self._progress_glow = max(0.0, min(1.0, value))
        self.progress_bar.setStyleSheet(self._build_progress_stylesheet())

    progress_glow = Property(float, get_progress_glow, set_progress_glow)

    def _on_progress_glow_changed(self, value: Any) -> None:
        """Animation callback for glowing progress rail edge."""
        self.set_progress_glow(float(value))

    def _build_progress_stylesheet(self) -> str:
        """Build the progress bar style string with animated glow alpha."""
        edge_alpha = int(110 + (self._progress_glow * 120))
        glow = f"rgba(0, 212, 255, {edge_alpha})"
        return f"""
            QProgressBar {{
                background-color: {Theme.BG_TERTIARY};
                border: 1px solid {Theme.BORDER_LIGHT};
                border-radius: 10px;
                text-align: center;
                color: {Theme.TEXT_PRIMARY};
                font-weight: 700;
                padding: 1px;
            }}
            QProgressBar::chunk {{
                background-color: {Theme.ACCENT_CYAN};
                border-radius: 8px;
                border: 1px solid {glow};
                margin: 1px;
            }}
        """

    def _meta_label(self, text: str) -> QLabel:
        """Factory for secondary metadata labels."""
        label = QLabel(text)
        label.setStyleSheet(f"font-size: 13px; color: {Theme.TEXT_SECONDARY};")
        return label

    # ------------------------------------------------------------------
    # Event-driven screen behavior
    # ------------------------------------------------------------------

    def _on_usb_device_inserted(self, payload: dict[str, Any]) -> None:
        """Event bus callback to auto-display this screen on insertion events."""
        self._current_device = dict(payload)
        self._populate_device_info(payload)
        self._show_with_slide_up()
        self.start_scan(payload)

    def _show_with_slide_up(self) -> None:
        """Animate the widget from below to a centered takeover position."""
        if self.parentWidget() is not None:
            parent_rect = self.parentWidget().rect()
        elif self.screen() is not None:
            parent_rect = self.screen().geometry()
        else:
            parent_rect = QRect(0, 0, 1280, 800)

        target = QRect(
            int(parent_rect.width() * 0.05),
            int(parent_rect.height() * 0.04),
            int(parent_rect.width() * 0.90),
            int(parent_rect.height() * 0.92),
        )
        start = QRect(target.x(), parent_rect.height() + 20, target.width(), target.height())

        self.setGeometry(start)
        self.show()
        self.raise_()

        self._slide_anim = QPropertyAnimation(self, b"geometry", self)
        self._slide_anim.setDuration(420)
        self._slide_anim.setStartValue(start)
        self._slide_anim.setEndValue(target)
        self._slide_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._slide_anim.start()

    def _populate_device_info(self, payload: dict[str, Any]) -> None:
        """Populate Device Intelligence panel values from event payload."""
        self.device_name_value.setText(str(payload.get("device_name") or "Unknown USB Device"))

        serial = str(payload.get("serial_number") or payload.get("device_id") or "Unknown")
        self.serial_value.setText(serial)

        capacity_bytes = int(payload.get("capacity_bytes") or 0)
        self.capacity_value.setText(self._format_capacity(capacity_bytes))

    def _format_capacity(self, capacity_bytes: int) -> str:
        """Format byte capacity into human-readable units."""
        if capacity_bytes <= 0:
            return "Not reported"

        units = ["B", "KB", "MB", "GB", "TB"]
        value = float(capacity_bytes)
        unit_idx = 0
        while value >= 1024.0 and unit_idx < len(units) - 1:
            value /= 1024.0
            unit_idx += 1
        return f"{value:.1f} {units[unit_idx]}"

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------

    def start_scan(self, device_payload: dict[str, Any] | None = None) -> None:
        """Start scan UI flow, and simulation ticks when in simulation mode."""
        if self._is_scanning:
            return

        if device_payload is not None:
            self._current_device = dict(device_payload)
            self._populate_device_info(device_payload)

        self._is_scanning = True
        self._scan_tick = 0
        self._file_count = 0

        self.progress_bar.setValue(0)
        self.file_count_label.setText("Files inspected: 0")
        self.scan_status_label.setText("Scan started: analyzing file signatures...")

        self.pipeline.reset_pipeline()
        self.pipeline.start_intro_animation()

        self._progress_glow_anim.start()
        event_bus.scan_started.emit(0)

        if self._simulation_mode:
            self._scan_timer.start()

    def _on_fake_scan_tick(self) -> None:
        """Advance simulation progress every 400ms until completion."""
        if not self._is_scanning:
            self._scan_timer.stop()
            return

        self._scan_tick += 1
        progress = int((self._scan_tick / self._scan_total_ticks) * 100)
        progress = min(100, progress)

        # Simulate a realistic file throughput with slight jitter.
        self._file_count += random.randint(14, 46)

        self.progress_bar.setValue(progress)
        self.file_count_label.setText(f"Files inspected: {self._file_count}")
        self.pipeline.set_progress(progress)

        if progress < 35:
            self.scan_status_label.setText("Stage 1/4: Device fingerprinting and signature intake")
        elif progress < 70:
            self.scan_status_label.setText("Stage 2/4: Shield heuristics and behavior profiling")
        elif progress < 95:
            self.scan_status_label.setText("Stage 3/4: Sandbox execution and intent tracing")
        else:
            self.scan_status_label.setText("Stage 4/4: Final classification and policy decision")

        if progress >= 100:
            self._scan_timer.stop()
            self._finalize_scan()

    def _finalize_scan(self) -> None:
        """Complete scan state and broadcast completion payloads."""
        self._is_scanning = False
        self._progress_glow_anim.stop()
        self.progress_glow = 0.25

        self.pipeline.set_progress(100)
        self.scan_status_label.setText("Scan complete: no active threats detected")

        summary: dict[str, Any] = {
            "device": self._current_device,
            "files_scanned": self._file_count,
            "risk_level": "low",
            "blocked": False,
            "simulated": self._simulation_mode,
        }

        self.scan_completed.emit(summary)
        event_bus.scan_completed.emit(0, summary)

    def cancel_scan(self) -> None:
        """Abort the scan and enforce a block policy for the active device."""
        if not self._is_scanning and not self._current_device:
            return

        self._scan_timer.stop()
        self._progress_glow_anim.stop()
        self._is_scanning = False

        device_id = str(self._current_device.get("device_id") or "unknown-device")
        blocked = self._lockdown.apply_policy(device_id=device_id, action="block")

        self.scan_status_label.setText("Scan aborted: device blocked by operator")

        result_payload: dict[str, Any] = {
            "device": self._current_device,
            "files_scanned": self._file_count,
            "blocked": bool(blocked),
            "simulated": self._simulation_mode,
            "reason": "cancelled_by_operator",
        }

        self.scan_cancelled.emit(result_payload)
        event_bus.policy_action_applied.emit(0, "block")
        event_bus.scan_completed.emit(0, result_payload)

    # ------------------------------------------------------------------
    # Standalone behavior
    # ------------------------------------------------------------------

    def showEvent(self, event: Any) -> None:
        """Start a local demo scan in SIMULATION_MODE when opened standalone."""
        super().showEvent(event)
        if self._simulation_mode and not self._is_scanning and not self._current_device:
            # Seed a realistic synthetic payload for direct manual screen testing.
            demo_payload = {
                "device_id": "SIM-DEMO-USB-0001",
                "device_name": "Demo USB Storage Device",
                "serial_number": "SIM-TEST-8842",
                "capacity_bytes": 64_000_000_000,
            }
            self._on_usb_device_inserted(demo_payload)

    def paintEvent(self, event: Any) -> None:  # noqa: ARG002 - Qt override
        """Draw subtle backdrop gradients to reinforce the full-screen takeover feel."""
        super().paintEvent(event)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect()

        top_glow = QColor(Theme.ACCENT_CYAN)
        top_glow.setAlpha(28)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(top_glow)
        painter.drawRoundedRect(rect.adjusted(24, 16, -24, -rect.height() + 150), 18, 18)

        bottom_glow = QColor(Theme.ACCENT_MAGENTA)
        bottom_glow.setAlpha(16)
        painter.setBrush(bottom_glow)
        painter.drawRoundedRect(rect.adjusted(36, rect.height() - 180, -36, -30), 20, 20)

        edge_pen = QPen(QColor(Theme.BORDER_LIGHT))
        edge_pen.setWidth(1)
        painter.setPen(edge_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(rect.adjusted(2, 2, -2, -2), 14, 14)

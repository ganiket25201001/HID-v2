"""Primary PySide6 shell for HID Shield."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QMainWindow, QPushButton, QStackedWidget, QVBoxLayout, QWidget

from core.event_bus import event_bus
from core.usb_monitor import USBEventEmitter
from ui.dashboard import DashboardScreen
from ui.decision_panel import DecisionPanel
from ui.login_dialog import LoginDialog
from ui.logs_screen import LogsScreen
from ui.settings_screen import SettingsScreen
from ui.styles.theme import Theme, build_stylesheet, load_fonts
from ui.threat_analysis import ThreatAnalysisScreen
from ui.usb_detection import LiveUSBDetectionScreen
from ui.widgets.animated_button import AnimatedButton


class ToastNotification(QFrame):
    """Small transient toast for USB/event notifications."""

    def __init__(self, parent: QWidget, message: str) -> None:
        super().__init__(parent)
        self.setObjectName("toast")
        self.setFixedSize(360, 74)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(10)

        badge = QLabel("LIVE")
        badge.setStyleSheet(
            f"font-size: 11px; font-weight: 800; letter-spacing: 1px; color: {Theme.ACCENT_CYAN};"
        )

        txt = QLabel(message)
        txt.setWordWrap(True)
        txt.setStyleSheet(f"font-size: 13px; color: {Theme.TEXT_PRIMARY};")

        layout.addWidget(badge)
        layout.addWidget(txt, stretch=1)

        self.setStyleSheet(
            f"""
            QFrame#toast {{
                background-color: {Theme.BG_TERTIARY};
                border: 1px solid {Theme.ACCENT_CYAN};
                border-radius: 10px;
            }}
            """
        )

        prect = parent.rect()
        self.move(prect.width() - self.width() - 24, prect.height() - self.height() - 24)
        QTimer.singleShot(3800, self.deleteLater)


class HIDShieldMainWindow(QMainWindow):
    """Main application shell with premium sidebar + stacked screens."""

    def __init__(self) -> None:
        super().__init__()

        load_fonts()
        self.setStyleSheet(build_stylesheet())
        self.setWindowTitle("HID Shield")
        self.resize(1360, 860)
        self.setMinimumSize(QSize(1040, 700))

        self._usb_monitor: USBEventEmitter | None = None

        self.central_container = QWidget(self)
        self.setCentralWidget(self.central_container)
        self.root = QVBoxLayout(self.central_container)
        self.root.setContentsMargins(0, 0, 0, 0)
        self.root.setSpacing(0)

        self._build_top_bar()
        self._build_content_shell()

        self.decision_panel = DecisionPanel(self.central_container)
        self.decision_panel.hide()

        self._wire_signals()
        QTimer.singleShot(0, self._ensure_authenticated)

    def _build_top_bar(self) -> None:
        bar = QFrame(self)
        bar.setObjectName("topBar")
        bar.setFixedHeight(72)

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(24, 0, 24, 0)
        layout.setSpacing(12)

        logo = QLabel("HS")
        logo.setFixedSize(40, 40)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet(
            f"font-size: 13px; font-weight: 900; color: {Theme.BG_PRIMARY};"
            f"background-color: {Theme.ACCENT_CYAN}; border-radius: 20px;"
        )

        title = QLabel("HID SHIELD")
        title.setStyleSheet(
            f"font-size: 34px; font-weight: 800; letter-spacing: 3px; color: {Theme.ACCENT_CYAN};"
        )

        self.live_state = QLabel("REAL-TIME MONITORING")
        self.live_state.setStyleSheet(
            f"font-size: 12px; color: {Theme.ACCENT_GREEN}; font-weight: 700;"
            f"padding: 6px 10px; border: 1px solid {Theme.ACCENT_GREEN}; border-radius: 8px;"
        )

        quit_btn = AnimatedButton("Exit", accent_color=Theme.ACCENT_MAGENTA)
        quit_btn.setFixedSize(110, 38)
        quit_btn.clicked.connect(self.close)

        layout.addWidget(logo)
        layout.addWidget(title)
        layout.addStretch(1)
        layout.addWidget(self.live_state)
        layout.addWidget(quit_btn)

        self.root.addWidget(bar)

    def _build_content_shell(self) -> None:
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        self.sidebar = QFrame(self)
        self.sidebar.setFixedWidth(250)
        self.sidebar.setStyleSheet(
            f"background-color: rgba(17, 24, 39, 0.94); border-right: 1px solid {Theme.BORDER};"
        )
        side = QVBoxLayout(self.sidebar)
        side.setContentsMargins(14, 20, 14, 20)
        side.setSpacing(10)

        nav = [
            ("Dashboard", 0),
            ("Live USB", 1),
            ("Threat Analysis", 2),
            ("Logs & Reports", 3),
            ("Settings", 4),
        ]
        self.nav_buttons: list[QPushButton] = []
        for text, idx in nav:
            btn = QPushButton(text)
            btn.setCheckable(True)
            btn.setMinimumHeight(46)
            if idx == 0:
                btn.setChecked(True)
            btn.clicked.connect(lambda _checked=False, i=idx: self._nav_clicked(i))
            self.nav_buttons.append(btn)
            side.addWidget(btn)

        side.addStretch(1)
        version = QLabel("HID Shield v1.0.0")
        version.setStyleSheet(f"font-size: 12px; color: {Theme.TEXT_DISABLED};")
        side.addWidget(version, alignment=Qt.AlignmentFlag.AlignCenter)

        content = QWidget(self)
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(24, 20, 24, 20)

        self.stack = QStackedWidget(self)
        self.dashboard_screen = DashboardScreen(self)
        self.live_usb_screen = LiveUSBDetectionScreen(parent=self)
        self.threat_analysis_screen = ThreatAnalysisScreen(self)
        self.logs_screen = LogsScreen(self)
        self.settings_screen = SettingsScreen(self)

        self.stack.addWidget(self.dashboard_screen)
        self.stack.addWidget(self.live_usb_screen)
        self.stack.addWidget(self.threat_analysis_screen)
        self.stack.addWidget(self.logs_screen)
        self.stack.addWidget(self.settings_screen)

        content_layout.addWidget(self.stack)

        body.addWidget(self.sidebar)
        body.addWidget(content, stretch=1)
        self.root.addLayout(body, stretch=1)

    def _wire_signals(self) -> None:
        event_bus.usb_device_inserted.connect(self._on_usb_inserted)
        event_bus.usb_device_inserted.connect(lambda _p: self._nav_clicked(1))
        event_bus.scan_completed.connect(self._on_scan_completed)
        event_bus.threat_detected.connect(self._on_threat_detected)
        event_bus.logs_refresh_requested.connect(lambda _p: self.logs_screen.refresh_all_tables())

    def _on_usb_inserted(self, payload: dict[str, Any]) -> None:
        device_name = str(payload.get("device_name") or "Unknown USB Device")
        ToastNotification(self.central_container, f"USB detected: {device_name}\nAccess is blocked until approval.").show()

        # Request all major panels to refresh context.
        event_bus.dashboard_refresh_requested.emit({"source": "usb_inserted", "device": payload})
        event_bus.logs_refresh_requested.emit({"source": "usb_inserted"})

    def _on_scan_completed(self, event_id: int, summary: dict[str, Any]) -> None:
        self._nav_clicked(2)
        event_bus.dashboard_refresh_requested.emit({"source": "scan_completed", "event_id": event_id})
        event_bus.logs_refresh_requested.emit({"source": "scan_completed", "event_id": event_id})

    def _on_threat_detected(self, payload: dict[str, Any]) -> None:
        title = str(payload.get("threat_level") or "THREAT")
        ToastNotification(self.central_container, f"Threat detected: {title}").show()
        event_bus.dashboard_refresh_requested.emit({"source": "threat_detected"})
        event_bus.logs_refresh_requested.emit({"source": "threat_detected"})

    def _nav_clicked(self, index: int) -> None:
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == index)
        self.stack.setCurrentIndex(index)

    def _ensure_authenticated(self) -> None:
        from security.session_manager import SessionManager

        if SessionManager.instance().is_authenticated():
            return

        access_controller = getattr(self, "_access_controller", None)
        dialog = LoginDialog(access_controller=access_controller, parent=self)
        dialog.login_success.connect(self._on_login_success)

        result = dialog.exec()
        if result == 0 or not SessionManager.instance().is_authenticated():
            self.close()

    def _on_login_success(self, payload: dict[str, Any]) -> None:
        security_key = str(payload.get("security_key", "") or "").strip()
        access_controller = getattr(self, "_access_controller", None)
        if security_key and access_controller is not None:
            access_controller.unlock_all_ports_with_key(security_key)

    def set_usb_monitor(self, monitor: USBEventEmitter) -> None:
        self._usb_monitor = monitor
        self.live_usb_screen._usb_emitter = monitor
        self.settings_screen.attach_usb_monitor(monitor)

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._usb_monitor is not None:
            self._usb_monitor.stop()
        super().closeEvent(event)

"""
hid_shield.ui.main_window
=========================
Primary PySide6 window application shell.

Design
------
* Centralised `HIDShieldMainWindow` class holding the layout structure.
* Top bar: Logo, Cyberpunk Clock, Operator Badge.
* Left Sidebar: Navigation buttons (Dashboard, Live USB, Logs, Policies, Settings).
* Central Area: ``QStackedWidget`` swapping out main views. Uses the custom
  ``GlassCard`` container for content panelling.
* Status bar at bottom right handles the SIMULATION_MODE warning indicator.
* Event Bus Integration: Listens for ``usb_device_inserted`` and shows a transient
  toast notification containing the device name.
"""

from __future__ import annotations

import os
from typing import Any

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core.usb_monitor import USBEventEmitter
from core.event_bus import event_bus
from ui.dashboard import DashboardScreen
from ui.decision_panel import DecisionPanel
from ui.login_dialog import LoginDialog
from ui.logs_screen import LogsScreen
from ui.settings_screen import SettingsScreen
from ui.styles.theme import Theme, build_stylesheet, load_fonts
from ui.threat_analysis import ThreatAnalysisScreen
from ui.usb_detection import LiveUSBDetectionScreen
from ui.widgets.animated_button import AnimatedButton
from ui.widgets.glass_card import GlassCard


class ToastNotification(QFrame):
    """Temporary notification pop-up (Toast) sliding in from bottom right."""

    def __init__(self, parent: QWidget, message: str) -> None:
        super().__init__(parent)
        self.setObjectName("toastFrame")
        self.setFixedSize(300, 60)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 8, 16, 8)
        
        icon = QLabel("NOTICE")
        icon.setStyleSheet(
            "font-size: 10px; font-weight: 700; letter-spacing: 1px; "
            f"color: {Theme.ACCENT_CYAN};"
        )
        
        msg = QLabel(message)
        msg.setStyleSheet("color: " + Theme.TEXT_PRIMARY + "; font-weight: bold;")
        msg.setWordWrap(True)
        
        layout.addWidget(icon)
        layout.addWidget(msg, stretch=1)
        
        self.setStyleSheet(f"""
            QFrame#toastFrame {{
                background-color: {Theme.BG_TERTIARY};
                border: 1px solid {Theme.ACCENT_CYAN};
                border-radius: 8px;
            }}
        """)
        
        # Position at bottom right
        parent_rect = parent.rect()
        self.move(parent_rect.width() - self.width() - 24, 
                  parent_rect.height() - self.height() - 24)
                  
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.deleteLater)
        self.timer.start(4000)  # Show for 4 seconds


class HIDShieldMainWindow(QMainWindow):
    """The master PySide6 window shell for HID Shield.
    
    Layout:
    [ TopBar (Logo + Clock + Admin Badge) ]
    [ SideBar (Nav) ] | [ Central StackedWidget (GlassCards) ]
    """

    def __init__(self) -> None:
        super().__init__()

        # --- Initialisation ------------------------------------------------
        load_fonts()
        self.setStyleSheet(build_stylesheet())
        
        self.setWindowTitle("HID Shield")
        self.resize(1280, 800)
        self.setMinimumSize(QSize(960, 640))

        self._usb_monitor: USBEventEmitter | None = None
        
        # We need a central widget to hold our custom layout grid
        self.central_container = QWidget(self)
        self.setCentralWidget(self.central_container)

        self.main_layout = QVBoxLayout(self.central_container)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # --- Build UI Regions ----------------------------------------------
        self._build_top_bar()
        
        # Horizontal split: Sidebar (left) + Stacked content (right)
        self.h_split_layout = QHBoxLayout()
        self.h_split_layout.setContentsMargins(0, 0, 0, 0)
        self.h_split_layout.setSpacing(0)
        
        self._build_sidebar()
        self._build_central_stack()
        
        self.main_layout.addLayout(self.h_split_layout, stretch=1)

        # Overlay decision panel remains hidden until scan completion.
        self.decision_panel = DecisionPanel(self.central_container)
        self.decision_panel.hide()

        # --- Subscriptions -------------------------------------------------
        # Connect to the global event bus to show toast messages when USB devices arrive
        event_bus.usb_device_inserted.connect(self._on_usb_inserted)
        event_bus.usb_device_inserted.connect(self._show_live_usb_screen)
        event_bus.scan_completed.connect(self._show_threat_analysis_screen)

        # Enforce authentication gate before normal operation begins.
        QTimer.singleShot(0, self._ensure_authenticated)

    # -----------------------------------------------------------------------
    # Component Builders
    # -----------------------------------------------------------------------

    def _build_top_bar(self) -> None:
        self.top_bar = QFrame()
        self.top_bar.setObjectName("topBar")
        self.top_bar.setFixedHeight(64)
        
        layout = QHBoxLayout(self.top_bar)
        layout.setContentsMargins(24, 0, 24, 0)
        
        # Logo + Title
        logo = QLabel("H")
        logo.setFixedSize(28, 28)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet(
            f"font-size: 15px; font-weight: 800; color: {Theme.BG_PRIMARY};"
            f"background-color: {Theme.ACCENT_CYAN}; border-radius: 14px;"
        )
        
        title = QLabel("HID SHIELD")
        title.setProperty("class", "h1")
        title.setStyleSheet(
            f"color: {Theme.ACCENT_CYAN}; letter-spacing: 3px; font-weight: 800;"
            "font-size: 32px;"
        )
        
        layout.addWidget(logo)
        layout.addSpacing(12)
        layout.addWidget(title)
        
        layout.addStretch()
        
        # Status Badge (SIMULATION MODE indicator)
        env_sim = os.getenv("HID_SHIELD_SIMULATION_MODE", "false").lower()
        if env_sim in ("true", "1", "yes"):
            sim_badge = QLabel("⚡ SIMULATION MODE")
            sim_badge.setStyleSheet(f"""
                color: {Theme.ACCENT_GREEN};
                font-weight: bold;
                padding: 4px 12px;
                border: 1px solid {Theme.ACCENT_GREEN};
                border-radius: 4px;
                background-color: rgba(0, 255, 136, 0.1);
            """)
            layout.addWidget(sim_badge)
            layout.addSpacing(16)
        
        # Profile / Exit
        exit_btn = AnimatedButton("System Exit", accent_color=Theme.ACCENT_MAGENTA)
        exit_btn.setFixedSize(120, 36)
        exit_btn.clicked.connect(self.close)
        
        layout.addWidget(exit_btn)
        
        self.main_layout.addWidget(self.top_bar)

    def _build_sidebar(self) -> None:
        self.sidebar = QFrame()
        self.sidebar.setObjectName("sideBar")
        self.sidebar.setFixedWidth(240)
        
        layout = QVBoxLayout(self.sidebar)
        layout.setContentsMargins(12, 24, 12, 24)
        layout.setSpacing(8)
        
        nav_items = [
            ("Dashboard", 0),
            ("Live USB", 1),
            ("Threat Analysis", 2),
            ("Logs & Reports", 3),
            ("Settings", 4),
        ]
        
        self.nav_buttons: list[QPushButton] = []
        for text, index in nav_items:
            btn = QPushButton(text)
            btn.setProperty("class", "nav-button")
            btn.setCheckable(True)
            if index == 0:
                btn.setChecked(True)
            
            # Use a lambda default arg capture to avoid late-binding loop variable
            btn.clicked.connect(lambda checked=False, idx=index: self._nav_clicked(idx))
            
            self.nav_buttons.append(btn)
            layout.addWidget(btn)
            
        layout.addStretch()
        
        # Version at bottom of sidebar
        version = QLabel("v1.0.0-beta")
        version.setStyleSheet(f"color: {Theme.TEXT_DISABLED}; font-size: 12px;")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(version)
        
        self.h_split_layout.addWidget(self.sidebar)

    def _build_central_stack(self) -> None:
        """The main right-hand content area containing stacked views."""
        
        # Wrap everything in a standard container with padding
        content_container = QWidget()
        self.h_split_layout.addWidget(content_container, stretch=1)
        
        cc_layout = QVBoxLayout(content_container)
        cc_layout.setContentsMargins(32, 32, 32, 32)
        
        # The QStackedWidget allows us to swap views by sidebar index
        self.stack = QStackedWidget()
        cc_layout.addWidget(self.stack)

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

    # -----------------------------------------------------------------------
    # Signal Handlers
    # -----------------------------------------------------------------------

    def _nav_clicked(self, index: int) -> None:
        """Handle sidebar navigation state mapping to the StackedWidget."""
        for i, btn in enumerate(self.nav_buttons):
            if i == index:
                btn.setChecked(True)
                self.stack.setCurrentIndex(index)
            else:
                btn.setChecked(False)

    def _on_usb_inserted(self, payload: dict[str, Any]) -> None:
        """Global bus signal receiver for USB insert events.
        
        Spawns a ToastNotification dynamically to alert the user.
        """
        device_name = payload.get("device_name", "Unknown USB Device")
        ToastNotification(self.central_container, f"Device detected:\n{device_name}").show()

    def _show_live_usb_screen(self, _: dict[str, Any]) -> None:
        """Bring the Live USB screen into view when a device is inserted."""
        self._nav_clicked(1)

    def _show_threat_analysis_screen(self, _event_id: int, _summary: dict[str, Any]) -> None:
        """Bring the Threat Analysis screen into view after scan completion."""
        self._nav_clicked(2)

    def _ensure_authenticated(self) -> None:
        """Display blocking login dialog when no user session is active."""
        from security.session_manager import SessionManager

        session_manager = SessionManager.instance()
        if session_manager.is_authenticated():
            return

        access_controller = getattr(self, "_access_controller", None)
        dialog = LoginDialog(access_controller=access_controller, parent=self)
        dialog.login_success.connect(self._on_login_success)

        result = dialog.exec()
        if result == 0 or not session_manager.is_authenticated():
            self.close()

    def _on_login_success(self, payload: dict[str, Any]) -> None:
        """Handle post-login hooks, including optional key-based unlock."""
        security_key = str(payload.get("security_key", "") or "").strip()
        access_controller = getattr(self, "_access_controller", None)
        if security_key and access_controller is not None:
            access_controller.unlock_all_ports_with_key(security_key)

    def set_usb_monitor(self, monitor: USBEventEmitter) -> None:
        """Attach running USB monitor so settings can restart it safely."""
        self._usb_monitor = monitor
        self.live_usb_screen._usb_emitter = monitor
        self.settings_screen.attach_usb_monitor(monitor)

    def closeEvent(self, event: QCloseEvent) -> None:
        """Stop background monitor thread before window shutdown."""
        if self._usb_monitor is not None:
            self._usb_monitor.stop()
        super().closeEvent(event)

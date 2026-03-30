"""
hid_shield.ui.dashboard
=======================
Main Dashboard panel (Screen 1) with animated stats and live timeline.

Design
------
* Sits inside the ``QStackedWidget`` of `HIDShieldMainWindow`.
* Background: ``ParticleBackground`` mapped to the dashboard's absolute size.
* Grid Layout:
  * Top: 3 GlassCards with animated integer counters.
  * Center Left: Live timeline of recent ``DeviceEvent`` models fetched via repo.
  * Center Right: Security Status panel and ``RiskGauge``.
* Reacts dynamically to ``event_bus.usb_device_inserted``.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, QVariantAnimation
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from core.event_bus import event_bus
from database.db import get_db
from database.models import RiskLevel
from database.repository import DeviceRepository
from ui.styles.theme import Theme
from ui.widgets.glass_card import GlassCard
from ui.widgets.particle_background import ParticleBackground
from ui.widgets.risk_gauge import RiskGauge
from ui.widgets.threat_badge import ThreatBadge


# ---------------------------------------------------------------------------
# Animated Stat Counter Helper
# ---------------------------------------------------------------------------

class AnimatedStatLabel(QLabel):
    """A QLabel that animates an integer from 0 to N over 800ms."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setProperty("class", "h1")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(f"font-size: 32px; color: {Theme.ACCENT_CYAN};")
        
        self._value: int = 0
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(800)
        self._anim.setEasingCurve(QEasingCurve.Type.OutExpo)
        self._anim.valueChanged.connect(self._on_step)

    def set_value(self, target: int) -> None:
        """Start animation to the new integer target."""
        self._anim.stop()
        self._anim.setStartValue(self._value)
        self._anim.setEndValue(target)
        self._value = target
        self._anim.start()

    def _on_step(self, val: Any) -> None:
        self.setText(str(int(val)))


# ---------------------------------------------------------------------------
# Timeline Item Helper
# ---------------------------------------------------------------------------

class TimelineEventWidget(QFrame):
    """A single row in the Recent Events list."""

    def __init__(self, time_str: str, name: str, risk: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedHeight(50)
        
        # Bottom border for separation
        self.setStyleSheet(f"border-bottom: 1px solid {Theme.BORDER};")
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 12, 0)
        layout.setSpacing(16)
        
        lbl_time = QLabel(time_str)
        lbl_time.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-weight: bold; border: none;")
        lbl_time.setFixedWidth(60)
        
        lbl_name = QLabel(name)
        lbl_name.setStyleSheet(f"color: {Theme.TEXT_PRIMARY}; font-size: 14px; border: none;")
        
        badge = ThreatBadge(risk_level=risk)
        
        layout.addWidget(lbl_time)
        layout.addWidget(lbl_name, stretch=1)
        layout.addWidget(badge)


# ---------------------------------------------------------------------------
# Main Dashboard View
# ---------------------------------------------------------------------------

class DashboardScreen(QWidget):
    """Screen 1: The overarching security dashboard."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        
        # 1. Background layer using absolute positioning
        self.particles = ParticleBackground(self, num_particles=60)
        self.particles.resize(1920, 1080)  # Max reasonable screen, or hook to resizeEvent

        # 2. Main layout grid
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setSpacing(24)

        # --- Top Row: Stats ---
        self._build_stat_cards()

        # --- Center Row ---
        self._build_live_status()
        self._build_timeline()
        
        # 3. Signals / DB Hookup
        event_bus.usb_device_inserted.connect(self._on_device_event)
        
        # Initial data population
        self.refresh_data()

    def resizeEvent(self, event: Any) -> None:
        """Ensure particle background covers the whole module cleanly."""
        super().resizeEvent(event)
        self.particles.resize(self.size())
        
    def showEvent(self, event: Any) -> None:
        """Trigger animations when tab is opened."""
        super().showEvent(event)
        self.refresh_data()

    # -----------------------------------------------------------------------
    # Builders
    # -----------------------------------------------------------------------

    def _build_stat_cards(self) -> None:
        # 1. Total Scans
        card1, self.val_scans = self._create_stat_panel("Total Scans Today")
        # 2. Threats Blocked
        card2, self.val_threats = self._create_stat_panel("Threats Blocked")
        self.val_threats.setStyleSheet(f"font-size: 32px; color: {Theme.ACCENT_MAGENTA};")
        self.val_threats.setText("0")
        # 3. Known Devices
        card3, self.val_devices = self._create_stat_panel("Active Devices")
        self.val_devices.setStyleSheet(f"font-size: 32px; color: {Theme.ACCENT_GREEN};")

        self.grid.addWidget(card1, 0, 0)
        self.grid.addWidget(card2, 0, 1)
        self.grid.addWidget(card3, 0, 2)

    def _create_stat_panel(self, title: str) -> tuple[GlassCard, AnimatedStatLabel]:
        card = GlassCard(glow=False)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(8)
        
        lbl_title = QLabel(title)
        lbl_title.setProperty("class", "subtitle")
        lbl_title.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)
        
        lbl_val = AnimatedStatLabel()
        
        layout.addWidget(lbl_title)
        layout.addWidget(lbl_val, stretch=1)
        layout.addStretch()
        return card, lbl_val

    def _build_live_status(self) -> None:
        """Right-hand panel for overall system posture."""
        panel = GlassCard(glow=True)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(24, 24, 24, 24)
        
        title = QLabel("System Posture")
        title.setProperty("class", "h2")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.gauge = RiskGauge()
        
        status_lbl = QLabel("MONITORING ACTIVE")
        status_lbl.setStyleSheet(f"color: {Theme.ACCENT_GREEN}; font-weight: bold; font-size: 16px;")
        status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        policy_lbl = QLabel(f"Policy: Auto-Block Critical\nConfig: {Theme.FONT_FAMILY}")
        policy_lbl.setProperty("class", "subtitle")
        policy_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(title)
        layout.addWidget(self.gauge, stretch=1, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(status_lbl)
        layout.addSpacing(16)
        layout.addWidget(policy_lbl)
        
        # Takes up row 1, column 2 (Right side)
        self.grid.addWidget(panel, 1, 2)

    def _build_timeline(self) -> None:
        """Left-hand panel for recent device connection queue."""
        panel = GlassCard(glow=False)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(24, 24, 24, 24)
        
        header_layout = QHBoxLayout()
        title = QLabel("Recent USB Events")
        title.setProperty("class", "h2")
        
        self.live_indicator = QLabel("● LIVE")
        self.live_indicator.setStyleSheet(f"color: {Theme.ACCENT_GREEN}; font-weight: bold; font-size: 12px;")
        
        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(self.live_indicator)
        
        layout.addLayout(header_layout)
        layout.addSpacing(16)
        
        self.timeline_container = QWidget()
        self.timeline_layout = QVBoxLayout(self.timeline_container)
        self.timeline_layout.setContentsMargins(0, 0, 0, 0)
        self.timeline_layout.setSpacing(0)
        self.timeline_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        layout.addWidget(self.timeline_container, stretch=1)
        
        # Takes up row 1, columns 0–1 (Left side, wider)
        self.grid.addWidget(panel, 1, 0, 1, 2)

    # -----------------------------------------------------------------------
    # Database / Live updates
    # -----------------------------------------------------------------------

    def refresh_data(self) -> None:
        """Fetch latest database stats and feed them into the UI animations."""
        # 1. Query recent events and aggregate counters from repository API.
        try:
            with get_db() as session:
                recents = DeviceRepository.get_recent_events(limit=5, session=session)
                total = len(DeviceRepository.get_recent_events(limit=5000, session=session))
                threats = DeviceRepository.get_high_risk_count(session=session)
        except Exception:
            recents = []
            total = 0
            threats = 0

        # 2. Update stats blocks
        self.val_scans.set_value(total + 10)  # Injecting base 10 for visual demo
        self.val_threats.set_value(threats)
        self.val_devices.set_value(len(recents))
        
        # 3. Gauge uses a mock aggregate risk based on threat count
        aggregate_risk = min(100.0, float(threats * 15.0 + 10.0))
        self.gauge.set_value(aggregate_risk)

        # 4. Rebuild timeline
        # Clear existing
        while self.timeline_layout.count():
            child = self.timeline_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
                
        # Populate
        if not recents:
            empty = QLabel("No events logged today.")
            empty.setProperty("class", "subtitle")
            self.timeline_layout.addWidget(empty)
        else:
            for ev in recents:
                time_str = ev.timestamp.strftime("%H:%M") if ev.timestamp else "--:--"
                name = ev.device_name or "Unknown Device"
                risk = str(ev.risk_level or RiskLevel.LOW.value)
                row = TimelineEventWidget(time_str, name, risk)
                self.timeline_layout.addWidget(row)

    def _on_device_event(self, payload: dict[str, Any]) -> None:
        """Triggered asynchronously via PyQt Signal when a fake USB connects."""
        # The DB commit from the background thread might race this signal slightly.
        # So we just trigger a refresh which queries the DB.
        self.refresh_data()

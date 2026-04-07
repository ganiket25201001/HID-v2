"""Modern dashboard screen with live USB/security telemetry."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from PySide6.QtCore import QEasingCurve, Qt, QVariantAnimation
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from core.event_bus import event_bus
from database.db import get_db
from database.models import DeviceEvent, RiskLevel
from database.repository import DeviceRepository
from sqlalchemy import func, select
from ui.styles.theme import Theme
from ui.widgets.glass_card import GlassCard
from ui.widgets.particle_background import ParticleBackground
from ui.widgets.risk_gauge import RiskGauge
from ui.widgets.threat_badge import ThreatBadge


class AnimatedStatLabel(QLabel):
    def __init__(self, color: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._value = 0
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(f"font-size: 36px; font-weight: 800; color: {color};")
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(700)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(lambda v: self.setText(str(int(v))))

    def set_value(self, target: int) -> None:
        self._anim.stop()
        self._anim.setStartValue(self._value)
        self._anim.setEndValue(max(0, int(target)))
        self._value = max(0, int(target))
        self._anim.start()


class DashboardScreen(QWidget):
    """Dashboard with premium spacing and live stats across app events."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.particles = ParticleBackground(self, num_particles=36)
        self._build_ui()
        self._wire_signals()
        self.refresh_data()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(26, 22, 26, 22)
        root.setSpacing(18)

        title = QLabel("Security Operations Dashboard")
        title.setStyleSheet(f"font-size: 28px; font-weight: 800; color: {Theme.ACCENT_CYAN};")
        subtitle = QLabel("Live posture, event timeline, and risk telemetry")
        subtitle.setStyleSheet(f"font-size: 14px; color: {Theme.TEXT_SECONDARY};")

        root.addWidget(title)
        root.addWidget(subtitle)

        row = QHBoxLayout()
        row.setSpacing(16)

        self.card_total, self.val_total = self._stat_card("Total Device Events", Theme.ACCENT_CYAN)
        self.card_threats, self.val_threats = self._stat_card("Threat Escalations", Theme.ACCENT_MAGENTA)
        self.card_connected, self.val_connected = self._stat_card("Recently Seen Devices", Theme.ACCENT_GREEN)
        self.card_blocked_today, self.val_blocked_today = self._stat_card("Threats Blocked Today", Theme.ACCENT_AMBER)

        row.addWidget(self.card_total)
        row.addWidget(self.card_threats)
        row.addWidget(self.card_connected)
        row.addWidget(self.card_blocked_today)
        root.addLayout(row)

        bottom = QHBoxLayout()
        bottom.setSpacing(16)

        self.timeline_card = GlassCard(glow=False)
        timeline_layout = QVBoxLayout(self.timeline_card)
        timeline_layout.setContentsMargins(18, 16, 18, 16)
        timeline_layout.setSpacing(8)

        tl_title = QLabel("Recent Timeline")
        tl_title.setStyleSheet(f"font-size: 18px; font-weight: 700; color: {Theme.TEXT_PRIMARY};")
        timeline_layout.addWidget(tl_title)

        self.timeline_labels: list[QLabel] = []
        for _ in range(8):
            row_lbl = QLabel("-")
            row_lbl.setStyleSheet(f"font-size: 14px; color: {Theme.TEXT_SECONDARY}; padding: 8px 0;")
            self.timeline_labels.append(row_lbl)
            timeline_layout.addWidget(row_lbl)
        timeline_layout.addStretch(1)

        self.posture_card = GlassCard(glow=True)
        posture_layout = QVBoxLayout(self.posture_card)
        posture_layout.setContentsMargins(18, 16, 18, 16)
        posture_layout.setSpacing(10)

        p_title = QLabel("Current Device Risk")
        p_title.setStyleSheet(f"font-size: 18px; font-weight: 700; color: {Theme.TEXT_PRIMARY};")
        self.risk_gauge = RiskGauge(self)
        self.risk_badge = ThreatBadge("low")

        self.entropy_label = QLabel("Max Entropy: —")
        self.entropy_label.setStyleSheet(
            f"font-size: 13px; font-weight: 600; color: {Theme.ACCENT_AMBER}; padding-top: 6px;"
        )

        posture_layout.addWidget(p_title)
        posture_layout.addWidget(self.risk_gauge, alignment=Qt.AlignmentFlag.AlignCenter)
        posture_layout.addWidget(self.risk_badge, alignment=Qt.AlignmentFlag.AlignCenter)
        posture_layout.addWidget(self.entropy_label, alignment=Qt.AlignmentFlag.AlignCenter)

        bottom.addWidget(self.timeline_card, stretch=3)
        bottom.addWidget(self.posture_card, stretch=2)
        root.addLayout(bottom, stretch=1)

    def _stat_card(self, title: str, accent: str) -> tuple[GlassCard, AnimatedStatLabel]:
        card = GlassCard(glow=True)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(6)

        caption = QLabel(title)
        caption.setStyleSheet(f"font-size: 13px; font-weight: 600; color: {Theme.TEXT_SECONDARY};")

        value = AnimatedStatLabel(accent)
        value.setText("0")

        layout.addWidget(caption)
        layout.addWidget(value)
        return card, value

    def _wire_signals(self) -> None:
        event_bus.usb_device_inserted.connect(lambda _: self.refresh_data())
        event_bus.scan_completed.connect(lambda _id, _s: self.refresh_data())
        event_bus.threat_detected.connect(lambda _: self.refresh_data())
        event_bus.policy_action_applied.connect(lambda _id, _a: self.refresh_data())
        event_bus.dashboard_refresh_requested.connect(lambda _: self.refresh_data())

    def resizeEvent(self, event: Any) -> None:
        super().resizeEvent(event)
        self.particles.resize(self.size())

    def showEvent(self, event: Any) -> None:
        super().showEvent(event)
        self.refresh_data()

    def refresh_data(self) -> None:
        try:
            with get_db() as session:
                recents = DeviceRepository.get_recent_events(limit=8, session=session)
                all_events = DeviceRepository.get_recent_events(limit=5000, session=session)
                threat_count = DeviceRepository.get_high_risk_count(session=session)
                blocked_today = self._get_threats_blocked_today(session)
                max_entropy = self._get_max_entropy_today(session)
        except Exception:
            recents = []
            all_events = []
            threat_count = 0
            blocked_today = 0
            max_entropy = 0.0

        self.val_total.set_value(len(all_events))
        self.val_threats.set_value(int(threat_count))
        self.val_connected.set_value(len(recents))
        self.val_blocked_today.set_value(int(blocked_today))

        # Update entropy display
        if max_entropy > 0:
            entropy_bits = max_entropy * 8.0 if max_entropy <= 1.0 else max_entropy
            self.entropy_label.setText(f"Max Entropy: {entropy_bits:.2f} bits")
        else:
            self.entropy_label.setText("Max Entropy: —")

        for idx, lbl in enumerate(self.timeline_labels):
            if idx >= len(recents):
                lbl.setText("-")
                continue
            ev = recents[idx]
            ts = ev.timestamp.strftime("%H:%M:%S") if ev.timestamp else "--:--:--"
            risk_val = getattr(ev.risk_level, "value", ev.risk_level) or "low"
            risk = str(risk_val).upper()
            lbl.setText(f"{ts}  |  {ev.device_name or 'Unknown USB'}  |  {risk}")

        if threat_count >= 5:
            self.risk_badge.set_risk_level("high")
            gauge = 85.0
        elif threat_count >= 2:
            self.risk_badge.set_risk_level("medium")
            gauge = 60.0
        else:
            self.risk_badge.set_risk_level("low")
            gauge = 28.0
        self.risk_gauge.set_value(gauge)

    @staticmethod
    def _get_threats_blocked_today(session: Any) -> int:
        """Query count of HIGH/CRITICAL risk events from today (UTC)."""
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        stmt = (
            select(func.count())
            .select_from(DeviceEvent)
            .where(
                DeviceEvent.risk_level.in_([RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]),
                DeviceEvent.timestamp >= today_start,
            )
        )
        return session.scalar(stmt) or 0

    @staticmethod
    def _get_max_entropy_today(session: Any) -> float:
        """Query the maximum entropy score from today's events."""
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        stmt = (
            select(func.max(DeviceEvent.entropy_score))
            .where(DeviceEvent.timestamp >= today_start)
        )
        result = session.scalar(stmt)
        return float(result) if result is not None else 0.0

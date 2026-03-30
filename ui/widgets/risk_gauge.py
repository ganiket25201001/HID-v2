"""
hid_shield.ui.widgets.risk_gauge
================================
Radial animated gauge displaying a 0-100% risk score.

Design
------
* Uses ``QPainter`` to draw smooth arcs and a sweeping needle.
* Smoothly animates value changes using ``QVariantAnimation``.
* Colour interpolates dynamically based on current value.
"""

from __future__ import annotations

import math
from typing import Any

from PySide6.QtCore import QEasingCurve, QRectF, Qt, QVariantAnimation
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QWidget

from ui.styles.theme import Theme


class RiskGauge(QWidget):
    """Large circular radial gauge indicating aggregate system risk.

    Parameters
    ----------
    parent : QWidget, optional
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(200, 200)

        # Logical value [0, 100]
        self._value: float = 0.0
        self._anim_value: float = 0.0

        # Animation setup
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(800)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._on_anim_step)

    def set_value(self, value: float) -> None:
        """Set the gauge target value and trigger the sweep animation.

        Parameters
        ----------
        value : float
            Risk percentage [0.0, 100.0].
        """
        val = max(0.0, min(100.0, float(value)))
        self._anim.stop()
        self._anim.setStartValue(self._anim_value)
        self._anim.setEndValue(val)
        self._value = val
        self._anim.start()

    def _on_anim_step(self, val: Any) -> None:
        self._anim_value = float(val)
        self.update()

    def _get_color_for_value(self, val: float) -> QColor:
        """Map [0, 100] to Green -> Amber -> Magenta."""
        if val < 30:
            return QColor(Theme.ACCENT_GREEN)
        elif val < 70:
            return QColor(Theme.ACCENT_AMBER)
        else:
            return QColor(Theme.ACCENT_MAGENTA)

    def paintEvent(self, event: Any) -> None:
        """Draw the track, swept arc, percentage text, and needle."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect()
        size = min(rect.width(), rect.height()) - 40
        
        # Center the gauge
        x = (rect.width() - size) / 2
        y = (rect.height() - size) / 2
        draw_rect = QRectF(x, y, size, size)

        # Gauge angles (Span uses 1/16th of a degree format in Qt)
        # Start at bottom-left (225 degrees), sweep 270 degrees clockwise to bottom-right (-45 degrees)
        start_angle = 225 * 16
        span_angle = -270 * 16  # Negative means clockwise sweep

        # 1. Background Track
        track_pen = QPen(QColor(Theme.BORDER))
        track_pen.setWidth(12)
        track_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(track_pen)
        painter.drawArc(draw_rect, start_angle, span_angle)

        # 2. Active Arc (interpolated colour and angle)
        current_color = self._get_color_for_value(self._anim_value)
        active_span = int((self._anim_value / 100.0) * span_angle)
        
        active_pen = QPen(current_color)
        active_pen.setWidth(12)
        active_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(active_pen)
        painter.drawArc(draw_rect, start_angle, active_span)

        # 3. Inner text (Value)
        painter.setPen(QPen(QColor(Theme.TEXT_PRIMARY)))
        font = QFont(Theme.FONT_FAMILY, 32, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(
            rect,
            Qt.AlignmentFlag.AlignCenter,
            f"{int(self._anim_value)}%"
        )

        # Subtext
        font_sub = QFont(Theme.FONT_FAMILY, 10)
        painter.setFont(font_sub)
        painter.setPen(QPen(QColor(Theme.TEXT_SECONDARY)))
        painter.drawText(
            QRectF(rect.x(), rect.y() + size * 0.35, rect.width(), rect.height()),
            Qt.AlignmentFlag.AlignCenter,
            "RISK LEVEL"
        )

        painter.end()

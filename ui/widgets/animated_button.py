"""
hid_shield.ui.widgets.animated_button
=====================================
Custom QPushButton with smooth hover transitions and ripple effect.

Design
------
* Inherits from ``QPushButton`` but implements a ``paintEvent`` with a
  ``QVariantAnimation`` to smoothly interpolate the background color rather
  than snapping instantly like standard CSS ``:hover``.
* Fits the cyberpunk vibe with neon accent glows on hover.
"""

from __future__ import annotations

from typing import Any, Optional

from PySide6.QtCore import QAbstractAnimation, QEasingCurve, Qt, QVariantAnimation
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QPushButton, QWidget

from ui.styles.theme import Theme


class AnimatedButton(QPushButton):
    """Button with a smooth 200ms colour transition on hover/leave.

    Use the ``accent_color`` parameter to define the hover target (e.g. cyan, magenta).
    """

    def __init__(
        self,
        text: str = "",
        parent: Optional[QWidget] = None,
        accent_color: str = Theme.ACCENT_CYAN,
    ) -> None:
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        self._base_color: QColor = QColor(Theme.BG_TERTIARY)
        self._accent_color: QColor = QColor(accent_color)
        self._current_color: QColor = self._base_color

        # QVariantAnimation for the smooth hover fade
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(200)  # 200ms easing
        self._anim.setEasingCurve(QEasingCurve.Type.InOutSine)
        self._anim.valueChanged.connect(self._on_color_interpolate)

    def _on_color_interpolate(self, clr: Any) -> None:
        """Callback fired by QVariantAnimation to update current frame colour."""
        if isinstance(clr, QColor):
            self._current_color = clr
            self.update()  # Request a repaint

    def enterEvent(self, event: Any) -> None:
        """Mouse entered bounding box — start fade to accent colour."""
        # Standard transparent/light hover version for cyberpunk buttons
        target = QColor(self._accent_color)
        target.setAlpha(40)  # semi-transparent fill on hover

        self._anim.stop()
        self._anim.setStartValue(self._current_color)
        self._anim.setEndValue(target)
        self._anim.start()
        super().enterEvent(event)

    def leaveEvent(self, event: Any) -> None:
        """Mouse left bounding box — fade back to base colour."""
        self._anim.stop()
        self._anim.setStartValue(self._current_color)
        self._anim.setEndValue(self._base_color)
        self._anim.start()
        super().leaveEvent(event)

    def paintEvent(self, event: Any) -> None:
        """Draw the animated button rect, border, and text."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect()
        rect.adjust(1, 1, -1, -1)

        path = QPainterPath()
        # Cyberpunk sharp/slightly rounded corners
        path.addRoundedRect(rect, 4, 4)

        # 1. Fill background (interpolated colour)
        painter.fillPath(path, self._current_color)

        # 2. Draw border
        border_col = QColor(Theme.BORDER_LIGHT)
        if self._anim.state() == QAbstractAnimation.State.Running or self.underMouse():
            border_col = self._accent_color
            
        pen = QPen(border_col)
        pen.setWidth(1)
        painter.setPen(pen)
        painter.drawPath(path)

        # 3. Draw text
        text_col = QColor(Theme.TEXT_PRIMARY)
        if self.underMouse():
            # slightly brighter or solid accent text on hover
            text_col = self._accent_color
            
        painter.setPen(QPen(text_col))
        painter.drawText(
            self.rect(),
            Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter,
            self.text(),
        )

        painter.end()

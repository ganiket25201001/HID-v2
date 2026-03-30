"""
hid_shield.ui.widgets.glass_card
================================
A container widget replicating glassmorphism / acrylic styling.

Design
------
* Inherits from ``QFrame`` so it can be styled easily or use a custom paintEvent.
* Instead of pure stylesheet (which can be slow/buggy with heavy transparency
  on older GPUs), it uses a lightweight ``QGraphicsDropShadowEffect`` combined
  with a semi-transparent background fill.
* Border radius: 12px.
* Optional subtle cyan glow based on the ``Theme`` palette.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QFrame, QGraphicsDropShadowEffect, QWidget

from ui.styles.theme import Theme


class GlassCard(QFrame):
    """A premium cyberpunk container with rounded corners and a subtle drop shadow.

    Use this as the base layer for dashboard panels and data tables.
    """

    def __init__(self, parent: QWidget | None = None, glow: bool = False) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.glow: bool = glow

        # Lightweight drop shadow for depth
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(20)
        shadow.setOffset(0, 8)
        
        # Cyberpunk ambient glow vs standard dark shadow
        if self.glow:
            shadow.setColor(QColor(0, 212, 255, 30))  # Theme.ACCENT_CYAN
            shadow.setBlurRadius(40)
        else:
            shadow.setColor(QColor(0, 0, 0, 80))
            
        self.setGraphicsEffect(shadow)

    def paintEvent(self, event: Any) -> None:
        """Draw the glass card background and border explicitly.

        This allows for better anti-aliasing on rounded corners than raw CSS.
        """
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Base rect
        rect = self.rect()
        rect.adjust(1, 1, -1, -1)  # inset to make room for border pen

        # Rounded path
        path = QPainterPath()
        path.addRoundedRect(rect, 12, 12)

        # Background fill (semi-transparent panel colour)
        bg_col = QColor(Theme.BG_SECONDARY)
        bg_col.setAlpha(240)  # Slight transparency for glass effect
        painter.fillPath(path, bg_col)

        # Border outline
        border_col = QColor(Theme.ACCENT_CYAN) if self.glow else QColor(Theme.BORDER)
        if self.glow:
            border_col.setAlpha(120)
        
        pen = QPen(border_col)
        pen.setWidth(1)
        painter.setPen(pen)
        painter.drawPath(path)

        painter.end()

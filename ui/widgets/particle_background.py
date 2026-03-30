"""
hid_shield.ui.widgets.particle_background
=========================================
Lightweight, animated neon particle canvas for premium aesthetics.

Design
------
* Inherits from ``QWidget``. Intended to be placed behind other widgets
  using absolute positioning or a ``QStackedWidget``.
* Maintains an array of 50 moving drifting coordinate points.
* A ``QTimer`` (16ms ~ 60fps) triggers ``update()`` which calls ``paintEvent()``.
* Very low CPU overhead because it only draws small ellipses without complex
  blending or QGraphicsScene overhead.
"""

from __future__ import annotations

import random
from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QWidget

from ui.styles.theme import Theme


class Particle:
    __slots__ = ["x", "y", "vx", "vy", "size", "alpha", "color"]

    def __init__(self, w: int, h: int) -> None:
        self.x: float = random.uniform(0, w)
        self.y: float = random.uniform(0, h)
        # Slow drift velocity
        self.vx: float = random.uniform(-0.3, 0.3)
        self.vy: float = random.uniform(-0.1, -0.6)  # Mostly drift up
        self.size: float = random.uniform(1.5, 3.5)
        self.alpha: int = random.randint(20, 100)
        
        # Mix of Cyan and Blue/White particles
        if random.random() > 0.7:
            c = QColor(Theme.ACCENT_CYAN)
        else:
            c = QColor(200, 240, 255)
        c.setAlpha(self.alpha)
        self.color: QColor = c

    def update(self, w: int, h: int) -> None:
        self.x += self.vx
        self.y += self.vy

        # Wrap around screen edges
        if self.x < 0: self.x = w
        if self.x > w: self.x = 0
        if self.y < 0: self.y = h
        if self.y > h: self.y = 0


class ParticleBackground(QWidget):
    """Animated background canvas rendering glowing drifting dots.

    Parameters
    ----------
    parent : QWidget, optional
    num_particles : int
        Number of points to simulate (default 50). Keep low for CPU efficiency.
    """

    def __init__(self, parent: QWidget | None = None, num_particles: int = 50) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent, False)
        
        self.particles: list[Particle] = []
        self._num = num_particles
        
        # 60fps timer
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._animate)
        self.timer.start(16)

    def _init_particles(self) -> None:
        """Seed the array geometry once the widget has a real size."""
        w, h = self.width(), self.height()
        if w > 0 and h > 0 and not self.particles:
            self.particles = [Particle(w, h) for _ in range(self._num)]

    def _animate(self) -> None:
        w, h = self.width(), self.height()
        if w == 0 or h == 0:
            return
            
        if not self.particles:
            self._init_particles()
            
        for p in self.particles:
            p.update(w, h)
            
        self.update()

    def paintEvent(self, event: Any) -> None:
        """Render all points efficiently using QPainter without anti-aliasing."""
        if not self.particles:
            return
            
        painter = QPainter(self)
        # Performance: For 50 tiny glowing dots, skipping AA is fine.
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        
        # Draw the subtle hex grid / lines if desired, or just solid dots
        for p in self.particles:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(p.color)
            painter.drawEllipse(int(p.x), int(p.y), int(p.size), int(p.size))

        painter.end()

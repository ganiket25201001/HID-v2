"""
hid_shield.ui.widgets.pipeline_widget
=====================================
Animated four-stage scan pipeline widget for the live USB detection takeover screen.

Design
------
* Uses ``QSequentialAnimationGroup`` and ``QPropertyAnimation`` to animate
  stage-by-stage reveal for:
    1) USB Ingest
    2) Shield Verification
    3) Sandbox Analysis
    4) Threat Classification
* Each stage fades in, scales up, then shows a glowing completion checkmark.
* Exposes ``set_progress`` and ``set_stage_completed`` methods so a real scanner
  can drive the UI in real time later.
"""

from __future__ import annotations

from typing import Any, Final

from PySide6.QtCore import (
    QEasingCurve,
    Property,
    QParallelAnimationGroup,
    QPropertyAnimation,
    QSequentialAnimationGroup,
    Qt,
)
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QSizePolicy,
    QWidget,
)

from ui.styles.theme import Theme


class _PipelineStageWidget(QWidget):
    """Single pipeline stage with icon badge, title, and animated check indicator."""

    def __init__(self, icon_text: str, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(180, 180)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        self._icon_text: str = icon_text
        self._title: str = title
        self._scale: float = 0.86
        self._check_glow: float = 0.0
        self._completed: bool = False
        self._active: bool = False

        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.opacity_effect.setOpacity(0.0)
        self.setGraphicsEffect(self.opacity_effect)

    # ------------------------------------------------------------------
    # Qt Properties (animated)
    # ------------------------------------------------------------------

    def get_scale(self) -> float:
        """Return the current stage scale factor used by paint transforms."""
        return self._scale

    def set_scale(self, value: float) -> None:
        """Set the current stage scale factor used by paint transforms."""
        self._scale = max(0.6, min(1.2, value))
        self.update()

    scale = Property(float, get_scale, set_scale)

    def get_check_glow(self) -> float:
        """Return checkmark glow intensity in the range 0.0..1.0."""
        return self._check_glow

    def set_check_glow(self, value: float) -> None:
        """Set checkmark glow intensity in the range 0.0..1.0."""
        self._check_glow = max(0.0, min(1.0, value))
        self.update()

    check_glow = Property(float, get_check_glow, set_check_glow)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_active(self, active: bool) -> None:
        """Highlight the stage as currently processing."""
        self._active = active
        self.update()

    def set_completed(self, completed: bool) -> None:
        """Mark the stage as complete and ensure checkmark is visible."""
        self._completed = completed
        self._check_glow = 1.0 if completed else 0.0
        self.update()

    # ------------------------------------------------------------------
    # Paint
    # ------------------------------------------------------------------

    def paintEvent(self, event: Any) -> None:  # noqa: ARG002 - Qt override
        """Custom stage renderer with neon circle, icon, title, and completion marker."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect()
        center_x = rect.center().x()
        center_y = rect.center().y() - 12

        painter.save()
        painter.translate(center_x, center_y)
        painter.scale(self._scale, self._scale)
        painter.translate(-center_x, -center_y)

        badge_size = min(rect.width(), rect.height()) * 0.54
        badge_x = center_x - (badge_size / 2)
        badge_y = center_y - (badge_size / 2)

        badge_rect = painter.viewport()
        badge_rect.setX(int(badge_x))
        badge_rect.setY(int(badge_y))
        badge_rect.setWidth(int(badge_size))
        badge_rect.setHeight(int(badge_size))

        # Soft cyan aura when active/completed to keep the pipeline dramatic.
        if self._active or self._completed:
            glow = QColor(Theme.ACCENT_CYAN if self._active else Theme.ACCENT_GREEN)
            glow.setAlpha(50)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(glow)
            aura = badge_rect.adjusted(-12, -12, 12, 12)
            painter.drawEllipse(aura)

        # Main badge.
        badge_fill = QColor(Theme.BG_TERTIARY)
        badge_fill.setAlpha(230)
        painter.setBrush(badge_fill)

        border = QColor(Theme.BORDER_LIGHT)
        if self._completed:
            border = QColor(Theme.ACCENT_GREEN)
        elif self._active:
            border = QColor(Theme.ACCENT_CYAN)

        pen = QPen(border)
        pen.setWidth(2)
        painter.setPen(pen)
        painter.drawEllipse(badge_rect)

        # Icon glyph.
        painter.setPen(QPen(QColor(Theme.TEXT_PRIMARY)))
        icon_font = painter.font()
        icon_font.setPointSize(22)
        icon_font.setBold(True)
        painter.setFont(icon_font)
        painter.drawText(badge_rect, Qt.AlignmentFlag.AlignCenter, self._icon_text)

        painter.restore()

        # Stage title under the badge.
        title_rect = rect.adjusted(6, rect.height() - 54, -6, -10)
        title_color = QColor(Theme.TEXT_PRIMARY if self._active or self._completed else Theme.TEXT_SECONDARY)
        painter.setPen(QPen(title_color))
        title_font = painter.font()
        title_font.setPointSize(11)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.drawText(title_rect, Qt.AlignmentFlag.AlignCenter, self._title)

        # Completion checkmark badge with neon glow.
        if self._completed:
            check_size = 28
            check_rect = title_rect
            check_rect.setX(int(center_x + (badge_size / 2) - (check_size * 0.8)))
            check_rect.setY(int(center_y - (badge_size / 2) - (check_size * 0.2)))
            check_rect.setWidth(check_size)
            check_rect.setHeight(check_size)

            glow_color = QColor(Theme.ACCENT_GREEN)
            glow_color.setAlpha(int(80 + 120 * self._check_glow))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(glow_color)
            painter.drawEllipse(check_rect.adjusted(-5, -5, 5, 5))

            painter.setBrush(QColor(Theme.ACCENT_GREEN))
            painter.drawEllipse(check_rect)

            painter.setPen(QPen(QColor(Theme.BG_PRIMARY), 2))
            check_font = painter.font()
            check_font.setPointSize(12)
            check_font.setBold(True)
            painter.setFont(check_font)
            painter.drawText(check_rect, Qt.AlignmentFlag.AlignCenter, "\u2713")


class PipelineWidget(QWidget):
    """Animated 4-stage USB scan pipeline.

    The widget supports two driving modes:
    1) Cinematic intro animation via ``start_intro_animation()``.
    2) Real-time scanner progress via ``set_progress()`` and
       ``set_stage_completed()``.
    """

    STAGE_THRESHOLD_PERCENT: Final[list[int]] = [10, 35, 70, 100]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._stages: list[_PipelineStageWidget] = []
        self._connector_progress: float = 0.0
        self._progress_percent: int = 0

        self._intro_group = QSequentialAnimationGroup(self)
        self._check_animations: list[QPropertyAnimation] = []

        self._build_ui()
        self._build_animations()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Create stage widgets and horizontal pipeline layout."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(14)

        stages = [
            ("USB", "USB Ingest"),
            ("SHD", "Shield Verify"),
            ("SBX", "Sandbox Run"),
            ("CLS", "Classification"),
        ]

        for icon, title in stages:
            stage = _PipelineStageWidget(icon, title, self)
            self._stages.append(stage)
            layout.addWidget(stage, stretch=1)

    def _build_animations(self) -> None:
        """Create sequential stage animations using fade + scale + check glow."""
        self._intro_group.clear()
        self._check_animations.clear()

        for stage in self._stages:
            stage_group = QParallelAnimationGroup(self)

            fade_anim = QPropertyAnimation(stage.opacity_effect, b"opacity", self)
            fade_anim.setDuration(380)
            fade_anim.setStartValue(0.0)
            fade_anim.setEndValue(1.0)
            fade_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

            scale_anim = QPropertyAnimation(stage, b"scale", self)
            scale_anim.setDuration(460)
            scale_anim.setStartValue(0.86)
            scale_anim.setEndValue(1.0)
            scale_anim.setEasingCurve(QEasingCurve.Type.OutBack)

            stage_group.addAnimation(fade_anim)
            stage_group.addAnimation(scale_anim)

            check_anim = QPropertyAnimation(stage, b"check_glow", self)
            check_anim.setDuration(280)
            check_anim.setStartValue(0.0)
            check_anim.setEndValue(1.0)
            check_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
            self._check_animations.append(check_anim)

            # Mark active at the start of each stage transition.
            stage_group.finished.connect(lambda s=stage: self._mark_stage_active(s))

            stage_sequence = QSequentialAnimationGroup(self)
            stage_sequence.addAnimation(stage_group)
            stage_sequence.addAnimation(check_anim)
            self._intro_group.addAnimation(stage_sequence)

        # Keep all stages marked completed when intro finishes.
        self._intro_group.finished.connect(self._finish_intro)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reset_pipeline(self) -> None:
        """Reset all stage visuals and clear progress state."""
        self._progress_percent = 0
        self._connector_progress = 0.0

        if self._intro_group.state() != self._intro_group.State.Stopped:
            self._intro_group.stop()

        for stage in self._stages:
            stage.opacity_effect.setOpacity(0.0)
            stage.set_scale(0.86)
            stage.set_completed(False)
            stage.set_active(False)

        self.update()

    def start_intro_animation(self) -> None:
        """Play the cinematic 4-stage reveal sequence."""
        self.reset_pipeline()
        if self._stages:
            self._stages[0].set_active(True)
        self._intro_group.start()

    def set_stage_completed(self, stage_index: int, completed: bool = True) -> None:
        """Externally mark a specific stage complete or incomplete.

        Parameters
        ----------
        stage_index:
            Zero-based stage index in the range ``[0, 3]``.
        completed:
            Whether the stage should be shown as complete.
        """
        if not 0 <= stage_index < len(self._stages):
            return

        stage = self._stages[stage_index]
        stage.opacity_effect.setOpacity(1.0)
        stage.set_scale(1.0)
        stage.set_completed(completed)

        # Keep the next stage highlighted to guide the user's eyes.
        for idx, candidate in enumerate(self._stages):
            candidate.set_active(idx == min(stage_index + 1, len(self._stages) - 1) and not completed)

        self.update()

    def set_progress(self, progress_percent: int) -> None:
        """Update the pipeline using a 0..100 scan progress value.

        This method is intended for real scanner integration where progress is
        streamed continuously from a worker thread.
        """
        self._progress_percent = max(0, min(100, int(progress_percent)))

        completed_count = 0
        for threshold in self.STAGE_THRESHOLD_PERCENT:
            if self._progress_percent >= threshold:
                completed_count += 1

        for idx, stage in enumerate(self._stages):
            is_completed = idx < completed_count
            is_active = idx == completed_count and completed_count < len(self._stages)

            stage.opacity_effect.setOpacity(1.0 if (is_completed or is_active) else 0.24)
            stage.set_scale(1.0 if (is_completed or is_active) else 0.9)
            stage.set_completed(is_completed)
            stage.set_active(is_active)

        # Connector progress is a subtle horizontal fill between all stages.
        self._connector_progress = self._progress_percent / 100.0
        self.update()

    # ------------------------------------------------------------------
    # Internal animation callbacks
    # ------------------------------------------------------------------

    def _mark_stage_active(self, stage: _PipelineStageWidget) -> None:
        """Transition active highlight to the next stage as intro progresses."""
        stage.set_active(False)
        stage.set_completed(True)

        stage_index = self._stages.index(stage)
        next_index = stage_index + 1
        if next_index < len(self._stages):
            self._stages[next_index].set_active(True)

        self._connector_progress = (stage_index + 1) / len(self._stages)
        self.update()

    def _finish_intro(self) -> None:
        """Finalize the intro state once all sequential stage animations end."""
        for stage in self._stages:
            stage.opacity_effect.setOpacity(1.0)
            stage.set_scale(1.0)
            stage.set_active(False)
            stage.set_completed(True)

        self._connector_progress = 1.0
        self._progress_percent = 100
        self.update()

    # ------------------------------------------------------------------
    # Connector rendering
    # ------------------------------------------------------------------

    def paintEvent(self, event: Any) -> None:  # noqa: ARG002 - Qt override
        """Draw connector rails behind the stage widgets with progress fill."""
        super().paintEvent(event)

        if len(self._stages) < 2:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        centers: list[tuple[int, int]] = []
        for stage in self._stages:
            geom = stage.geometry()
            centers.append((geom.center().x(), geom.center().y() - 8))

        # Base rail.
        base_pen = QPen(QColor(Theme.BORDER))
        base_pen.setWidth(4)
        painter.setPen(base_pen)
        for idx in range(len(centers) - 1):
            painter.drawLine(centers[idx][0], centers[idx][1], centers[idx + 1][0], centers[idx + 1][1])

        # Progress rail with neon cyan edge.
        progress_color = QColor(Theme.ACCENT_CYAN)
        progress_color.setAlpha(220)
        progress_pen = QPen(progress_color)
        progress_pen.setWidth(4)
        painter.setPen(progress_pen)

        total_length = 0.0
        for idx in range(len(centers) - 1):
            x1, y1 = centers[idx]
            x2, y2 = centers[idx + 1]
            segment = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
            total_length += segment

        target_length = total_length * self._connector_progress
        if total_length <= 0.0:
            return

        # Draw progress line incrementally up to target_length.
        remaining = target_length
        for idx in range(len(centers) - 1):
            x1, y1 = centers[idx]
            x2, y2 = centers[idx + 1]
            segment = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5

            if remaining <= 0:
                break

            if remaining >= segment:
                painter.drawLine(x1, y1, x2, y2)
                remaining -= segment
                continue

            ratio = remaining / segment
            px = int(x1 + (x2 - x1) * ratio)
            py = int(y1 + (y2 - y1) * ratio)
            painter.drawLine(x1, y1, px, py)
            break

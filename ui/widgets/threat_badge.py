"""
hid_shield.ui.widgets.threat_badge
==================================
A small pill-shaped badge displaying risk level text & colour.

Design
------
* Inherits from ``QLabel`` with custom padding and border-radius.
* Uses the exact neon colours defined in ``Theme``.
* Maps string risk levels (SAFE, LOW, MEDIUM, HIGH, CRITICAL) to colours.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QWidget

from ui.styles.theme import Theme


class ThreatBadge(QLabel):
    """Pill-shaped badge indicating device risk level.

    Parameters
    ----------
    risk_level : str
        The risk string ("safe", "low", "medium", "high", "critical").
    parent : QWidget, optional
    """

    def __init__(self, risk_level: str = "safe", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_risk_level(risk_level)

    def set_risk_level(self, risk_level: str) -> None:
        """Update the badge text and colour styling.

        Parameters
        ----------
        risk_level : str
            Risk classification string (case-insensitive).
        """
        level = risk_level.strip().lower()
        text = level.upper()

        # Map to Theme colours
        if level == "safe":
            bg_color = "rgba(0, 255, 136, 0.15)"
            border_color = Theme.ACCENT_GREEN
            text_color = Theme.ACCENT_GREEN
        elif level == "low":
            bg_color = "rgba(0, 212, 255, 0.15)"
            border_color = Theme.ACCENT_CYAN
            text_color = Theme.ACCENT_CYAN
        elif level == "medium":
            bg_color = "rgba(255, 184, 0, 0.15)"
            border_color = Theme.ACCENT_AMBER
            text_color = Theme.ACCENT_AMBER
        elif level in ("high", "critical", "dangerous"):
            bg_color = "rgba(255, 0, 110, 0.15)"
            border_color = Theme.ACCENT_MAGENTA
            text_color = Theme.ACCENT_MAGENTA
        else:
            bg_color = Theme.BG_TERTIARY
            border_color = Theme.BORDER
            text_color = Theme.TEXT_SECONDARY
            text = "UNKNOWN"

        self.setText(text)
        
        # Apply strict CSS for the pill shape
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {bg_color};
                border: 1px solid {border_color};
                color: {text_color};
                border-radius: 12px;
                padding: 4px 12px;
                font-weight: 700;
                font-size: 11px;
                letter-spacing: 1px;
            }}
        """)
        # Ensure it sizes to content
        self.setFixedSize(self.sizeHint())

"""Premium dialog to ask for a security key."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
)

from ui.styles.theme import Theme
from ui.widgets.animated_button import AnimatedButton
from ui.widgets.glass_card import GlassCard


class SecurityKeyDialog(QDialog):
    """Custom premium dialog for requesting a security key."""

    def __init__(self, parent: Any | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Authorization Required")
        self.setModal(True)
        self.setMinimumWidth(440)
        self.setStyleSheet(f"background-color: {Theme.BG_PRIMARY};")

        self.key_value = ""
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)
        root.setSpacing(16)

        title = QLabel("Security Key Required")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(f"font-size: 22px; font-weight: 800; color: {Theme.ACCENT_AMBER};")
        root.addWidget(title)

        subtitle = QLabel("Enter your Security Key to authorize this operator action.")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet(f"font-size: 13px; color: {Theme.TEXT_SECONDARY};")
        subtitle.setWordWrap(True)
        root.addWidget(subtitle)

        card = GlassCard(glow=True)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(18, 18, 18, 18)
        card_layout.setSpacing(12)

        self.input_field = QLineEdit(self)
        self.input_field.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_field.setPlaceholderText("Enter Security Key...")
        self.input_field.setMinimumHeight(42)
        self.input_field.setStyleSheet(f"""
            QLineEdit {{
                background: {Theme.BG_SECONDARY};
                color: {Theme.TEXT_PRIMARY};
                border: 1px solid {Theme.BORDER};
                border-radius: 6px;
                padding-left: 12px;
                font-size: 14px;
            }}
            QLineEdit:focus {{
                border: 1px solid {Theme.ACCENT_CYAN};
            }}
        """)

        card_layout.addWidget(self.input_field)
        root.addWidget(card)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(14)

        self.cancel_btn = AnimatedButton("Cancel", accent_color=Theme.TEXT_SECONDARY)
        self.submit_btn = AnimatedButton("Authorize", accent_color=Theme.ACCENT_CYAN)

        self.cancel_btn.setMinimumHeight(42)
        self.submit_btn.setMinimumHeight(42)

        self.cancel_btn.clicked.connect(self.reject)
        self.submit_btn.clicked.connect(self._on_submit)
        
        # Allow pressing Enter to submit
        self.input_field.returnPressed.connect(self._on_submit)

        btn_row.addWidget(self.cancel_btn)
        btn_row.addWidget(self.submit_btn)

        root.addLayout(btn_row)

    def _on_submit(self) -> None:
        self.key_value = self.input_field.text().strip()
        self.accept()

    @classmethod
    def get_key(cls, parent: Any | None = None) -> tuple[str, bool]:
        """Convenience method to show dialog and return the key."""
        dialog = cls(parent)
        result = dialog.exec_()
        return dialog.key_value, result == QDialog.DialogCode.Accepted

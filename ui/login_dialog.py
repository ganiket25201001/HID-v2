"""Login and signup dialog for HID Shield authentication."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
)

from security.auth_manager import AuthManager
from security.session_manager import SessionManager, UserMode
from ui.styles.theme import Theme
from ui.widgets.animated_button import AnimatedButton
from ui.widgets.glass_card import GlassCard


class LoginDialog(QDialog):
    """Modal login/signup dialog with optional security-key port unlock."""

    login_success = Signal(dict)

    def __init__(self, access_controller: Any | None = None, parent: QDialog | None = None) -> None:
        super().__init__(parent)
        self._access_controller = access_controller
        self._auth_manager = AuthManager()
        self._session_manager = SessionManager.instance()

        self.setWindowTitle("HID Shield Authentication")
        self.setModal(True)
        self.setMinimumWidth(620)
        self.setStyleSheet(f"background-color: {Theme.BG_PRIMARY};")

        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)
        root.setSpacing(12)

        title = QLabel("Secure Operator Login")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(
            f"font-size: 28px; font-weight: 800; color: {Theme.ACCENT_CYAN}; letter-spacing: 1px;"
        )

        subtitle = QLabel("Authenticate to access live USB controls")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet(f"font-size: 13px; color: {Theme.TEXT_SECONDARY};")

        root.addWidget(title)
        root.addWidget(subtitle)

        divider = QFrame(self)
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setStyleSheet(f"color: {Theme.BORDER}; background: {Theme.BORDER}; max-height: 1px;")
        root.addWidget(divider)

        card = GlassCard(glow=True)
        form = QFormLayout(card)
        form.setContentsMargins(18, 16, 18, 16)
        form.setHorizontalSpacing(18)
        form.setVerticalSpacing(12)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText("Username")
        self.username_input.setMinimumHeight(40)

        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMinimumHeight(40)

        self.security_key_input = QLineEdit(self)
        self.security_key_input.setPlaceholderText("Security Key (optional)")
        self.security_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.security_key_input.setMinimumHeight(40)

        for label_text in ("Username", "Password", "Security Key"):
            label = QLabel(label_text)
            label.setMinimumWidth(130)
            label.setStyleSheet(f"color: {Theme.TEXT_PRIMARY}; font-weight: 600;")
            if label_text == "Username":
                form.addRow(label, self.username_input)
            elif label_text == "Password":
                form.addRow(label, self.password_input)
            else:
                form.addRow(label, self.security_key_input)

        root.addWidget(card)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        self.login_btn = AnimatedButton("Login", accent_color=Theme.ACCENT_GREEN)
        self.signup_btn = AnimatedButton("Sign Up", accent_color=Theme.ACCENT_CYAN)
        self.unlock_btn = AnimatedButton("Unlock All Ports with Key", accent_color=Theme.ACCENT_AMBER)

        self.login_btn.setMinimumHeight(42)
        self.signup_btn.setMinimumHeight(42)
        self.unlock_btn.setMinimumHeight(42)

        self.login_btn.clicked.connect(self._on_login_clicked)
        self.signup_btn.clicked.connect(self._on_signup_clicked)
        self.unlock_btn.clicked.connect(self._on_unlock_clicked)

        btn_row.addWidget(self.login_btn)
        btn_row.addWidget(self.signup_btn)
        btn_row.addWidget(self.unlock_btn)

        root.addLayout(btn_row)

    def _on_login_clicked(self) -> None:
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Missing Credentials", "Username and password are required.")
            return

        try:
            ok = self._auth_manager.verify_credentials(username, password)
        except PermissionError as exc:
            QMessageBox.critical(self, "Account Locked", str(exc))
            return

        if not ok:
            QMessageBox.critical(self, "Login Failed", "Invalid username or password.")
            return

        self._session_manager.start_session(UserMode.ADMIN, operator_id=username)
        payload = {
            "username": username,
            "security_key": self.security_key_input.text().strip(),
        }
        self.login_success.emit(payload)
        self.accept()

    def _on_signup_clicked(self) -> None:
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Missing Credentials", "Enter username and password to sign up.")
            return

        try:
            self._auth_manager.sign_up(username=username, password=password)
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Input", str(exc))
            return

        QMessageBox.information(self, "Signup Complete", "Account saved. You can now log in.")

    def _on_unlock_clicked(self) -> None:
        key = self.security_key_input.text().strip()
        if not key:
            QMessageBox.warning(self, "Missing Key", "Enter the security key first.")
            return

        if self._access_controller is None:
            QMessageBox.warning(self, "Unavailable", "Access controller is not available.")
            return

        unlocked = bool(self._access_controller.unlock_all_ports_with_key(key))
        if unlocked:
            QMessageBox.information(self, "Ports Unlocked", "All USB ports have been unlocked successfully.")
        else:
            QMessageBox.critical(self, "Unlock Failed", "Security key verification failed.")

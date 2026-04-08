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
    QCheckBox,
    QMessageBox,
    QTabWidget,
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

        tabs = QTabWidget(self)

        login_card = GlassCard(glow=True)
        login_form = QFormLayout(login_card)
        login_form.setContentsMargins(18, 16, 18, 16)
        login_form.setHorizontalSpacing(18)
        login_form.setVerticalSpacing(12)
        login_form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        self.login_username_input = QLineEdit(self)
        self.login_username_input.setPlaceholderText("Username")
        self.login_username_input.setMinimumHeight(40)

        self.login_password_input = QLineEdit(self)
        self.login_password_input.setPlaceholderText("Password")
        self.login_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_password_input.setMinimumHeight(40)

        self.login_security_key_input = QLineEdit(self)
        self.login_security_key_input.setPlaceholderText("Security Key (optional)")
        self.login_security_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_security_key_input.setMinimumHeight(40)

        for label_text in ("Username", "Password", "Security Key"):
            label = QLabel(label_text)
            label.setMinimumWidth(130)
            label.setStyleSheet(f"color: {Theme.TEXT_PRIMARY}; font-weight: 600;")
            if label_text == "Username":
                login_form.addRow(label, self.login_username_input)
            elif label_text == "Password":
                login_form.addRow(label, self.login_password_input)
            else:
                login_form.addRow(label, self.login_security_key_input)
                
        self.login_remember_me = QCheckBox("Remember me for 3 days", self)
        self.login_remember_me.setStyleSheet(f"color: {Theme.TEXT_SECONDARY};")
        login_form.addRow("", self.login_remember_me)

        signup_card = GlassCard(glow=True)
        signup_form = QFormLayout(signup_card)
        signup_form.setContentsMargins(18, 16, 18, 16)
        signup_form.setHorizontalSpacing(18)
        signup_form.setVerticalSpacing(12)
        signup_form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        self.signup_username_input = QLineEdit(self)
        self.signup_username_input.setPlaceholderText("New Username")
        self.signup_username_input.setMinimumHeight(40)

        self.signup_password_input = QLineEdit(self)
        self.signup_password_input.setPlaceholderText("New Password")
        self.signup_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.signup_password_input.setMinimumHeight(40)

        self.signup_confirm_password_input = QLineEdit(self)
        self.signup_confirm_password_input.setPlaceholderText("Confirm Password")
        self.signup_confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.signup_confirm_password_input.setMinimumHeight(40)

        self.signup_security_key_input = QLineEdit(self)
        self.signup_security_key_input.setPlaceholderText("Security Key (required)")
        self.signup_security_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.signup_security_key_input.setMinimumHeight(40)

        signup_fields = (
            ("Username", self.signup_username_input),
            ("Password", self.signup_password_input),
            ("Confirm", self.signup_confirm_password_input),
            ("Security Key", self.signup_security_key_input),
        )
        for label_text, widget in signup_fields:
            label = QLabel(label_text)
            label.setMinimumWidth(130)
            label.setStyleSheet(f"color: {Theme.TEXT_PRIMARY}; font-weight: 600;")
            signup_form.addRow(label, widget)

        tabs.addTab(login_card, "Login")
        tabs.addTab(signup_card, "Sign Up")
        tabs.currentChanged.connect(self._on_tab_changed)
        root.addWidget(tabs)

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

        self.signup_btn.setVisible(False)

        root.addLayout(btn_row)

    def _on_tab_changed(self, index: int) -> None:
        if index == 0:
            self.login_btn.setVisible(True)
            self.signup_btn.setVisible(False)
        else:
            self.login_btn.setVisible(False)
            self.signup_btn.setVisible(True)

    def _on_login_clicked(self) -> None:
        username = self.login_username_input.text().strip()
        password = self.login_password_input.text().strip()

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
            "security_key": self.login_security_key_input.text().strip(),
        }
        self.login_success.emit(payload)
        self.accept()

    def _on_signup_clicked(self) -> None:
        username = self.signup_username_input.text().strip()
        password = self.signup_password_input.text().strip()
        confirm_password = self.signup_confirm_password_input.text().strip()
        security_key = self.signup_security_key_input.text().strip()

        if not username or not password or not confirm_password or not security_key:
            QMessageBox.warning(self, "Missing Credentials", "All sign-up fields are required.")
            return

        if password != confirm_password:
            QMessageBox.warning(self, "Invalid Input", "Password and confirmation do not match.")
            return

        if len(password) < 6:
            QMessageBox.warning(self, "Weak Password", "Password must be at least 6 characters.")
            return

        try:
            self._auth_manager.sign_up(
                username=username,
                password=password,
                security_key=security_key,
            )
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Input", str(exc))
            return

        QMessageBox.information(self, "Signup Complete", "Account saved. You can now log in.")

    def _on_unlock_clicked(self) -> None:
        key = self.login_security_key_input.text().strip()
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

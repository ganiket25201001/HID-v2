"""
HID Shield – Intelligent USB Security System
=============================================
Entry point for the desktop application.

Responsibilities
-----------------
1. Load configuration from ``config.yaml`` and ``.env``.
2. Bootstrap a PySide6 ``QApplication`` with the cyberpunk dark theme.
3. Display the main window with an "Exit" button.
4. Perform a first-run check (stub for later PIN-setup wizard).

Usage
-----
    python main.py
"""

from __future__ import annotations

import os
import sys
import ctypes
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QFont, QColor, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QGraphicsDropShadowEffect,
    QSizePolicy,
    QMessageBox,
)

from core.usb_monitor import USBEventEmitter
from database.db import init_db
from security.access_controller import AccessController
from ui.main_window import HIDShieldMainWindow

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Simulation mode — when True the app runs without admin rights or real
# USB device access.  Toggle to False for production deployments.
SIMULATION_MODE: bool = False

# Resolve paths relative to *this* file so it works whether launched from
# the repo root or from the hid_shield/ directory.
BASE_DIR: Path = Path(__file__).resolve().parent
CONFIG_PATH: Path = BASE_DIR / "config.yaml"
ENV_PATH: Path = BASE_DIR / ".env"


# ---------------------------------------------------------------------------
# Configuration Loader
# ---------------------------------------------------------------------------


def load_config(config_path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Read the YAML configuration file and return it as a dictionary.

    Falls back to sensible defaults when the file is missing so the app can
    still start during initial development.

    Parameters
    ----------
    config_path:
        Absolute path to the ``config.yaml`` file.

    Returns
    -------
    dict[str, Any]
        Parsed configuration dictionary.
    """
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as fh:
            config: dict[str, Any] = yaml.safe_load(fh) or {}
        return config

    # Minimal fallback so the app can always launch
    print(f"[WARNING] Config file not found at {config_path} — using defaults.")
    return {
        "app": {"name": "HID Shield", "version": "1.0.0", "window_width": 1280, "window_height": 800},
        "simulation_mode": False,
        "theme": {},
    }


def is_admin() -> bool:
    """Return True when process has administrator privileges on Windows."""
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# First-Run Check (stub)
# ---------------------------------------------------------------------------


def check_first_run(config: dict[str, Any]) -> None:
    """Detect whether this is the first launch of the application.

    In later prompts this will trigger the PIN-setup wizard and create the
    initial database.  For now it simply prints a message to the console.

    Parameters
    ----------
    config:
        The loaded application configuration dictionary.
    """
    # Placeholder: check for the existence of a local database / PIN hash.
    # These artefacts don't exist yet, so every run is a "first run" for now.
    admin_pin_hash: str = os.getenv("HID_SHIELD_ADMIN_PIN_HASH", "")
    if not admin_pin_hash:
        print("[INFO] First run setup will be handled in later step")


# ---------------------------------------------------------------------------
# Theme / Stylesheet Builder
# ---------------------------------------------------------------------------


def build_stylesheet(theme: dict[str, str]) -> str:
    """Generate a Qt stylesheet string from the theme palette.

    The stylesheet implements a cyberpunk dark aesthetic with neon accents,
    smooth hover transitions, and subtle glow effects.

    Parameters
    ----------
    theme:
        Dictionary of colour tokens loaded from ``config.yaml``.

    Returns
    -------
    str
        Complete Qt CSS stylesheet.
    """
    # Resolve palette with defaults matching the original design spec
    bg_primary: str = theme.get("bg_primary", "#0a0e17")
    bg_secondary: str = theme.get("bg_secondary", "#111827")
    bg_tertiary: str = theme.get("bg_tertiary", "#1a1f2e")
    accent_cyan: str = theme.get("accent_cyan", "#00d4ff")
    accent_magenta: str = theme.get("accent_magenta", "#ff006e")
    accent_green: str = theme.get("accent_green", "#00ff88")
    accent_amber: str = theme.get("accent_amber", "#ffb800")
    text_primary: str = theme.get("text_primary", "#e2e8f0")
    text_secondary: str = theme.get("text_secondary", "#94a3b8")
    text_disabled: str = theme.get("text_disabled", "#475569")
    border: str = theme.get("border", "#1e293b")

    return f"""
    /* ================================================================== */
    /*  HID Shield – Cyberpunk Dark Theme                                 */
    /* ================================================================== */

    /* --- Global -------------------------------------------------------- */
    * {{
        margin: 0;
        padding: 0;
    }}

    QMainWindow {{
        background-color: {bg_primary};
    }}

    QWidget {{
        background-color: transparent;
        color: {text_primary};
        font-family: "Segoe UI", "Inter", "Roboto", sans-serif;
        font-size: 14px;
    }}

    /* --- Labels -------------------------------------------------------- */
    QLabel {{
        color: {text_primary};
        background: transparent;
    }}

    QLabel#titleLabel {{
        font-size: 36px;
        font-weight: 700;
        color: {accent_cyan};
        letter-spacing: 2px;
    }}

    QLabel#subtitleLabel {{
        font-size: 15px;
        font-weight: 400;
        color: {text_secondary};
    }}

    QLabel#modeLabel {{
        font-size: 13px;
        font-weight: 600;
        color: {accent_green};
        padding: 6px 16px;
        border: 1px solid {accent_green};
        border-radius: 12px;
        background: rgba(0, 255, 136, 0.08);
    }}

    QLabel#versionLabel {{
        font-size: 12px;
        color: {text_disabled};
    }}

    /* --- Cards / Panels ----------------------------------------------- */
    QFrame#centralCard {{
        background-color: {bg_secondary};
        border: 1px solid {border};
        border-radius: 16px;
    }}

    /* --- Buttons ------------------------------------------------------ */
    QPushButton {{
        font-size: 14px;
        font-weight: 600;
        border: none;
        border-radius: 8px;
        padding: 12px 32px;
        color: {bg_primary};
    }}

    QPushButton#exitButton {{
        background: qlineargradient(
            x1:0, y1:0, x2:1, y2:1,
            stop:0 {accent_magenta}, stop:1 #cc005a
        );
        color: #ffffff;
        min-width: 140px;
    }}

    QPushButton#exitButton:hover {{
        background: qlineargradient(
            x1:0, y1:0, x2:1, y2:1,
            stop:0 #ff3388, stop:1 {accent_magenta}
        );
    }}

    QPushButton#exitButton:pressed {{
        background: #aa0044;
    }}

    /* --- Separator ----------------------------------------------------- */
    QFrame#separator {{
        background-color: {border};
        max-height: 1px;
    }}

    /* --- Scrollbar (future-proof) ------------------------------------- */
    QScrollBar:vertical {{
        background: {bg_secondary};
        width: 8px;
        border-radius: 4px;
    }}

    QScrollBar::handle:vertical {{
        background: {text_disabled};
        border-radius: 4px;
        min-height: 30px;
    }}

    QScrollBar::handle:vertical:hover {{
        background: {accent_cyan};
    }}
    """


# ---------------------------------------------------------------------------
# Main Window
# ---------------------------------------------------------------------------


class HIDShieldWindow(QMainWindow):
    """Primary application window.

    Shows the app title, simulation-mode badge, version info, and an Exit
    button.  Future prompts will populate this with the sidebar, dashboard
    panels, and device list.

    Parameters
    ----------
    config:
        The parsed ``config.yaml`` dictionary.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__()

        self._config: dict[str, Any] = config
        app_cfg: dict[str, Any] = config.get("app", {})
        theme_cfg: dict[str, str] = config.get("theme", {})

        # --- Window properties ------------------------------------------
        self.setWindowTitle(app_cfg.get("name", "HID Shield"))
        self.resize(
            app_cfg.get("window_width", 1280),
            app_cfg.get("window_height", 800),
        )
        self.setMinimumSize(
            QSize(
                app_cfg.get("min_window_width", 960),
                app_cfg.get("min_window_height", 640),
            )
        )

        # --- Central widget ---------------------------------------------
        central = QWidget(self)
        self.setCentralWidget(central)

        # Root vertical layout
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Fill the background
        central.setStyleSheet(
            f"background-color: {theme_cfg.get('bg_primary', '#0a0e17')};"
        )

        # --- Centred content card ---------------------------------------
        card = QFrame()
        card.setObjectName("centralCard")
        card.setFixedSize(620, 420)

        # Apply a subtle glow shadow to the card
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(60)
        shadow.setOffset(0, 0)
        shadow.setColor(QColor(0, 212, 255, 40))  # faint cyan glow
        card.setGraphicsEffect(shadow)

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(48, 40, 48, 40)
        card_layout.setSpacing(16)
        card_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # --- Shield icon placeholder ---
        shield_icon = QLabel("🛡️")
        shield_icon.setStyleSheet("font-size: 56px; background: transparent;")
        shield_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(shield_icon)

        # --- Title -------------------------------------------------------
        title = QLabel("HID Shield")
        title.setObjectName("titleLabel")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(title)

        # --- Subtitle ----------------------------------------------------
        subtitle = QLabel("Intelligent USB Security System")
        subtitle.setObjectName("subtitleLabel")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(subtitle)

        card_layout.addSpacing(8)

        # --- Simulation Mode Badge (only when active) --------------------
        sim_mode: bool = config.get("simulation_mode", SIMULATION_MODE)
        if sim_mode:
            mode_label = QLabel("⚡  SIMULATION MODE")
            mode_label.setObjectName("modeLabel")
            mode_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            mode_label.setSizePolicy(
                QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed
            )
            # Centre the badge horizontally
            badge_row = QHBoxLayout()
            badge_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
            badge_row.addWidget(mode_label)
            card_layout.addLayout(badge_row)

        card_layout.addSpacing(12)

        # --- Separator line ----------------------------------------------
        sep = QFrame()
        sep.setObjectName("separator")
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        card_layout.addWidget(sep)

        card_layout.addSpacing(12)

        # --- Exit button -------------------------------------------------
        exit_btn = QPushButton("⏻  Exit")
        exit_btn.setObjectName("exitButton")
        exit_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        exit_btn.clicked.connect(self.close)

        btn_row = QHBoxLayout()
        btn_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        btn_row.addWidget(exit_btn)
        card_layout.addLayout(btn_row)

        card_layout.addStretch()

        # --- Version label (bottom of card) ------------------------------
        version_label = QLabel(
            f"v{app_cfg.get('version', '1.0.0')}"
        )
        version_label.setObjectName("versionLabel")
        version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(version_label)

        # --- Place the card in the centre of the window -----------------
        root_layout.addStretch()
        card_row = QHBoxLayout()
        card_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_row.addWidget(card)
        root_layout.addLayout(card_row)
        root_layout.addStretch()


# ---------------------------------------------------------------------------
# Application Bootstrap
# ---------------------------------------------------------------------------


def main() -> None:
    """Application entry point.

    Performs the following steps in order:

    1. Load ``.env`` environment variables.
    2. Parse ``config.yaml``.
    3. Run the first-run check (stub).
    4. Create the Qt application, apply the theme, show the window.
    """
    # 1. Load .env (silently skip if the file doesn't exist yet)
    load_dotenv(dotenv_path=ENV_PATH)

    # Override SIMULATION_MODE from env if provided
    global SIMULATION_MODE
    env_sim: str = os.getenv("HID_SHIELD_SIMULATION_MODE", "").lower()
    if env_sim in ("true", "1", "yes"):
        SIMULATION_MODE = True
    elif env_sim in ("false", "0", "no"):
        SIMULATION_MODE = False

    # 2. Load YAML configuration
    config: dict[str, Any] = load_config()

    # Merge env-level simulation flag into the config dict
    if env_sim in ("true", "1", "yes"):
        config["simulation_mode"] = True
    elif env_sim in ("false", "0", "no"):
        config["simulation_mode"] = False
    else:
        config["simulation_mode"] = bool(config.get("simulation_mode", SIMULATION_MODE))

    # 3. First-run check
    check_first_run(config)

    # 4. Print startup banner
    sim_status: str = "SIMULATION_MODE" if config["simulation_mode"] else "LIVE MODE"
    print(f"HID Shield started in {sim_status}")
    print(f"  Version : {config.get('app', {}).get('version', '1.0.0')}")
    print(f"  Config  : {CONFIG_PATH}")

    # 5. Initialize database schema before the UI starts querying repositories.
    init_db()

    # 6. Create Qt application
    app = QApplication(sys.argv)
    app.setApplicationName("HID Shield")
    app.setApplicationVersion(config.get("app", {}).get("version", "1.0.0"))

    # Apply the cyberpunk dark theme globally
    theme_cfg: dict[str, str] = config.get("theme", {})
    app.setStyleSheet(build_stylesheet(theme_cfg))

    if not config["simulation_mode"] and not is_admin():
        warning_text = (
            "HID Shield is running without Administrator privileges.\n\n"
            "Real USB monitoring and USBSTOR registry enforcement may be limited.\n"
            "Run as Administrator for full real-mode protection."
        )
        print(f"[WARNING] {warning_text.replace(chr(10), ' ')}")
        QMessageBox.warning(None, "Administrator Rights Required", warning_text)

    # 7. Start USB monitor thread and initialize the integrated main window.
    usb_monitor = USBEventEmitter()
    usb_monitor.start()

    window = HIDShieldMainWindow()
    window.set_usb_monitor(usb_monitor)

    # 8. Bring up final enforcement orchestration and bind DecisionPanel controls.
    access_controller = AccessController()
    access_controller.attach_decision_panel(window.decision_panel)

    # Retain controller lifetime for the process duration.
    window._access_controller = access_controller  # type: ignore[attr-defined]

    app.aboutToQuit.connect(usb_monitor.stop)
    window.show()

    # 9. Enter the Qt event loop
    sys.exit(app.exec())


# ---------------------------------------------------------------------------
# Script guard
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()

"""Application entry point for HID Shield."""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from PySide6.QtWidgets import QApplication, QMessageBox

from core.event_bus import event_bus
from core.usb_monitor import USBEventEmitter
from database.db import init_db
from sandbox.file_scanner import FileScanner
from security.access_controller import AccessController
from ui.main_window import HIDShieldMainWindow
from ui.styles.theme import build_stylesheet, load_fonts

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.yaml"
ENV_PATH = BASE_DIR / ".env"


def load_config(config_path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Load runtime YAML config with production-safe defaults."""
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}

    return {
        "app": {
            "name": "HID Shield",
            "version": "1.0.0",
        },
        "policy": {
            "default_action": "prompt",
        },
    }


def is_admin() -> bool:
    """Return True when process has Administrator rights on Windows."""
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def enforce_live_mode() -> None:
    """Force production runtime mode for subsystems reading env flags."""
    os.environ["HID_SHIELD_SIMULATION_MODE"] = "false"


def main() -> None:
    """Start HID Shield desktop application."""
    load_dotenv(dotenv_path=ENV_PATH)
    config = load_config()
    enforce_live_mode()

    init_db()

    app = QApplication(sys.argv)
    app.setApplicationName(str(config.get("app", {}).get("name", "HID Shield")))
    app.setApplicationVersion(str(config.get("app", {}).get("version", "1.0.0")))

    load_fonts()
    app.setStyleSheet(build_stylesheet())

    if not is_admin():
        QMessageBox.warning(
            None,
            "Administrator Rights Recommended",
            (
                "HID Shield is running without Administrator privileges.\n\n"
                "Some real USB enforcement features may be limited."
            ),
        )

    usb_monitor = USBEventEmitter()
    usb_monitor.start()

    window = HIDShieldMainWindow()
    window.set_usb_monitor(usb_monitor)

    file_scanner = FileScanner()
    event_bus.usb_device_inserted.connect(file_scanner.scan_device)

    access_controller = AccessController()
    access_controller.attach_decision_panel(window.decision_panel)
    window._access_controller = access_controller  # type: ignore[attr-defined]

    app.aboutToQuit.connect(usb_monitor.stop)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

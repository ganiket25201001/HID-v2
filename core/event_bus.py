"""Global PySide6 event bus for decoupled HID Shield communication."""

from __future__ import annotations

import threading
from typing import Optional

from PySide6.QtCore import QObject, Signal


class AppEventBus(QObject):
    """Singleton event bus carrying app-wide runtime signals."""

    # Device lifecycle
    usb_device_inserted = Signal(dict)
    usb_device_removed = Signal(dict)

    # Scan lifecycle
    scan_started = Signal(int)
    scan_progress = Signal(int, int, str)  # event_id, progress(0-100), message
    scan_completed = Signal(int, dict)

    # Threat/policy/ai lifecycle
    threat_detected = Signal(dict)
    policy_action_applied = Signal(int, str)
    device_access_state_changed = Signal(int, str)  # event_id, block|allow|prompt
    ai_explanation_ready = Signal(dict)


    # Autonomous agent pipeline
    autonomous_report_ready = Signal(dict)
    autonomous_analysis_progress = Signal(int, int, str)  # event_id, progress, stage

    # UI sync helpers
    dashboard_refresh_requested = Signal(dict)
    threat_analysis_refresh_requested = Signal(dict)
    decision_panel_refresh_requested = Signal(dict)
    logs_refresh_requested = Signal(dict)

    # Runtime diagnostics
    error_occurred = Signal(str)

    _instance: Optional["AppEventBus"] = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> "AppEventBus":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return
        super().__init__()
        self._initialized = True


# Module-level singleton
event_bus: AppEventBus = AppEventBus()

"""
hid_shield.core.event_bus
=========================
Global PySide6 event bus for decoupled inter-component communication.

Design
------
* Inherits from ``QObject`` so it can declare and emit ``Signal`` objects.
* Acts as a singleton (``event_bus`` instance exported at module level).
* UI components connect to these signals instead of polling the database
  or holding direct references to background threads.
* All payloads involving devices use the ``DeviceInfo`` dataclass to ensure
  schema safety.
"""

from __future__ import annotations

import threading
from typing import Optional

from PySide6.QtCore import QObject, Signal


class AppEventBus(QObject):
    """Global event bus carrying signals between background workers and UI.

    Signals
    -------
    usb_device_inserted (dict)
        Fired when a new USB/HID device is connected. Payload is the
        ``DeviceInfo`` dataclass cast to a dictionary.
    usb_device_removed (dict)
        Fired when a USB device is disconnected. Payload is a dict with
        at least ``{'device_id': ...}``.
    scan_started (int)
        Fired when a file scan begins (payload = device_event_id).
    scan_completed (int, dict)
        Fired when a file scan finishes. Payload is event ID + summary dict.
    threat_detected (dict)
        Fired when the policy engine escalates a device to HIGH/CRITICAL.
        Payload is the raw event dictionary.
    policy_action_applied (int, str)
        Fired when an action (block/allow/quarantine) is successfully applied.
        Payload is (device_event_id, action_taken).
    """

    # --- Signal Declarations (must be class attributes on QObject) ---

    # Device lifecycle
    usb_device_inserted = Signal(dict)
    usb_device_removed = Signal(dict)

    # File scanning
    scan_started = Signal(int)
    scan_completed = Signal(int, dict)

    # Threats & Policy
    threat_detected = Signal(dict)
    policy_action_applied = Signal(int, str)

    # Internal state
    _instance: Optional[AppEventBus] = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> AppEventBus:
        """Singleton pattern enforcement."""
        with cls._lock:
            if cls._instance is None:
                # QObject requires calling super().__new__ without args
                obj = super().__new__(cls)
                cls._instance = obj
        return cls._instance

    def __init__(self) -> None:
        """Initialise the QObject parent (runs only once)."""
        if getattr(self, "_initialised", False):
            return
        super().__init__()
        self._initialised = True


# Global singleton instance mapped to the module level
event_bus: AppEventBus = AppEventBus()

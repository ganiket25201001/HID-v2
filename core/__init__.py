"""
hid_shield.core
===============
Core event bus and USB monitoring subsystem.

Exports:
* ``AppEventBus`` / ``event_bus`` – Global PySide6 signal bus.
* ``DeviceInfo``                  – Dataclass representing a parsed USB device.
* ``USBEventEmitter``             – Background QThread for device monitoring.
* ``PortLockdown``                – OS-level port control (simulation-aware).
"""

from core.device_info import DeviceInfo
from core.event_bus import AppEventBus, event_bus
from core.port_lockdown import PortLockdown
from core.usb_monitor import USBEventEmitter

__all__: list[str] = [
    "AppEventBus",
    "DeviceInfo",
    "PortLockdown",
    "USBEventEmitter",
    "event_bus",
]

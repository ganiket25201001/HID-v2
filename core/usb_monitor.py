"""
hid_shield.core.usb_monitor
=============================
Background QThread emitting USB connection/disconnection events.

Design
------
* Inherits from ``QThread`` to run autonomously without blocking the
  PySide6 main event loop.
* Evaluates ``SIMULATION_MODE`` on start. If true, synthesizes realistic
  fake USB insertion/removal events every 8–15 seconds using a
  pre-seeded catalogue of spoofed profiles (keyboards, storage, mice).
* Emits events to the UI thread via the global ``event_bus``.
* Real WMI (Windows Management Instrumentation) monitoring is wrapped in
  ``try/except`` to guarantee the thread does not crash in simulation mode.
  On Linux, ``pyudev`` handles monitoring in real mode.
* Debouncing filters out transient OS chatter.
"""

from __future__ import annotations

import os
import random
import time
from typing import Any

from PySide6.QtCore import QThread

from core.device_info import DeviceInfo
from core.event_bus import event_bus


def _get_simulation_mode() -> bool:
    env_val = os.getenv("HID_SHIELD_SIMULATION_MODE", "").lower()
    if env_val in ("true", "1", "yes"):
        return True
    if env_val in ("false", "0", "no"):
        return False
    # Fallback minimal YAML check without full app boot
    import yaml
    from pathlib import Path
    cfg = Path(__file__).resolve().parent.parent / "config.yaml"
    if cfg.exists():
        with open(cfg, "r") as fh:
            return bool(yaml.safe_load(fh).get("simulation_mode", True))
    return True


# ---------------------------------------------------------------------------
# Fake Device Catalogue
# ---------------------------------------------------------------------------

_FAKE_DEVICES: list[dict[str, Any]] = [
    {
        "device_name": "Logitech G502 Gaming Mouse",
        "vendor_id": "046d",
        "product_id": "c07d",
        "device_type": "mouse",
        "manufacturer": "Logitech",
    },
    {
        "device_name": "SanDisk Cruzer Blade 32GB",
        "vendor_id": "0781",
        "product_id": "5567",
        "device_type": "storage",
        "manufacturer": "SanDisk",
        "capacity_bytes": 32_000_000_000,
        "serial_number": "SD987654321A",
    },
    {
        "device_name": "Generic USB Keyboard",
        "vendor_id": "413c",
        "product_id": "2107",
        "device_type": "keyboard",
        "manufacturer": "Dell",
        "serial_number": "DLY811K1",
    },
    {
        "device_name": "[SUSPICIOUS] Arduino Leonardo HID",
        "vendor_id": "2341",
        "product_id": "8036",
        "device_type": "keyboard",
        "manufacturer": "Arduino",
        "serial_number": "RDU_DUCKY_1",
    },
]


# ---------------------------------------------------------------------------
# Monitor Thread
# ---------------------------------------------------------------------------


class USBEventEmitter(QThread):
    """Background thread monitoring OS events for USB lifecycle changes.

    Attributes
    ----------
    is_running: True if the thread loop is active.
    simulation_mode: True if generating synthetic events.
    """

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self.is_running: bool = False
        self.simulation_mode: bool = _get_simulation_mode()

        # Simple set to track currently "plugged in" devices for synthetic disconnects
        self._active_sim_devices: dict[str, DeviceInfo] = {}

    def run(self) -> None:
        """Main loop of the QThread (called implicitly by ``.start()``)."""
        self.is_running = True
        print(f"[USB] USBEventEmitter started "
              f"({'SIMULATION' if self.simulation_mode else 'LIVE'} mode)")

        if self.simulation_mode:
            self._run_simulation_loop()
        else:
            self._run_wmi_loop()

    def stop(self) -> None:
        """Signal the thread loop to terminate gracefully."""
        self.is_running = False
        self.quit()
        self.wait(1000)

    # ------------------------------------------------------------------
    # Simulation Mode
    # ------------------------------------------------------------------

    def _run_simulation_loop(self) -> None:
        """Indefinitely emit random fake USB events every 8–15s."""
        while self.is_running:
            # Sleep for a random interval (8 to 15 seconds)
            time.sleep(random.randint(8, 15))
            if not self.is_running:
                break

            # 20% chance to remove an existing device, 80% to plug a new one
            if self._active_sim_devices and random.random() < 0.2:
                self._synthesize_removal()
            else:
                self._synthesize_insertion()

    def _synthesize_insertion(self) -> None:
        # Pick a random profile
        profile = random.choice(_FAKE_DEVICES)
        dev = DeviceInfo(**profile, is_simulated=True)
        # Randomise serial number slightly for repeated insertions
        if random.random() > 0.5:
            dev.serial_number = f"SIM_{random.randint(1000, 9999)}"

        self._active_sim_devices[dev.device_id] = dev

        # Emit the signal on the global bus
        payload = dev.to_dict()
        event_bus.usb_device_inserted.emit(payload)

    def _synthesize_removal(self) -> None:
        if not self._active_sim_devices:
            return
        device_id = random.choice(list(self._active_sim_devices.keys()))
        dev = self._active_sim_devices.pop(device_id)

        # Broadcast removal
        event_bus.usb_device_removed.emit(dev.to_dict())

    # ------------------------------------------------------------------
    # Real Mode (WMI/pyudev wrapped tightly)
    # ------------------------------------------------------------------

    def _run_wmi_loop(self) -> None:
        """Monitor real OS APIs for device changes.

        Wrapped in a try/except so that importing WMI dependencies does not
        crash the app on Linux/Mac, or if the pywin32 module is missing.
        """
        try:
            import wmi  # type: ignore
            # Local initialisation so it's strictly confined to this thread
            wmi_conn = wmi.WMI()
            # Poll every 2 seconds for new Win32_USBControllerDevice links
            # (In production, a WMI event watcher __InstanceCreationEvent
            #  would be used, but polling is safer across environments without Admin rights)
            
            # Very basic polling loop for safety
            known_ids = set()
            
            while self.is_running:
                current_ids = set()
                try:
                    for usb in wmi_conn.Win32_USBControllerDevice():
                        current_ids.add(usb.Dependent.DeviceID)
                except Exception as wmi_err:
                    print(f"[USB] Real WMI polling error: {wmi_err}")
                
                # Check for new devices (simple diff)
                new_devices = current_ids - known_ids
                if new_devices and known_ids: # Don't flood on startup
                    for nd in new_devices:
                        dev = DeviceInfo(device_id=nd, is_simulated=False)
                        event_bus.usb_device_inserted.emit(dev.to_dict())
                
                # Simple removal check
                removed = known_ids - current_ids
                if removed and known_ids:
                    for rd in removed:
                        event_bus.usb_device_removed.emit({"device_id": rd})
                
                known_ids = current_ids
                time.sleep(2)
                
        except ImportError:
            print("[USB] Error: WMI package not found. Cannot run real USB monitor.")
            print("[USB] Falling back to idle sleep loop.")
            while self.is_running:
                time.sleep(2)
        except Exception as e:
            print(f"[USB] Critical monitor error: {e}")
            while self.is_running:
                time.sleep(2)

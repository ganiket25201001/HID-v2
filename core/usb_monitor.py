"""Background USB monitor thread using real OS device events."""

from __future__ import annotations

import os
import platform
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
            return bool(yaml.safe_load(fh).get("simulation_mode", False))
    return False


# ---------------------------------------------------------------------------
# Monitor Thread
# ---------------------------------------------------------------------------


class USBEventEmitter(QThread):
    """Background thread monitoring real USB lifecycle changes."""

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self.is_running: bool = False
        self.simulation_mode: bool = _get_simulation_mode()
        self._known_devices: dict[str, DeviceInfo] = {}

    def run(self) -> None:
        """Main loop of the QThread (called implicitly by ``.start()``)."""
        self.is_running = True
        print(f"[USB] USBEventEmitter started "
              f"({'SIMULATION FLAG ON' if self.simulation_mode else 'LIVE'} mode)")

        if platform.system().lower() != "windows":
            print("[USB] Real USB watcher currently supports Windows WMI only.")
            self._idle_loop()
            return

        self._run_wmi_loop()

    def stop(self) -> None:
        """Signal the thread loop to terminate gracefully."""
        self.is_running = False
        self.quit()
        self.wait(1000)

    # ------------------------------------------------------------------
    # Real Mode (WMI/pyudev wrapped tightly)
    # ------------------------------------------------------------------

    def _run_wmi_loop(self) -> None:
        """Monitor real USB events via Win32_USBHub WMI watchers."""
        try:
            import wmi  # type: ignore

            wmi_conn = wmi.WMI()
            self._seed_known_devices(wmi_conn)

            insertion_watcher = wmi_conn.Win32_USBHub.watch_for(
                notification_type="Creation",
                delay_secs=1,
            )
            removal_watcher = wmi_conn.Win32_USBHub.watch_for(
                notification_type="Deletion",
                delay_secs=1,
            )

            while self.is_running:
                handled_event = False

                try:
                    created = insertion_watcher(timeout_ms=1200)
                    handled_event = True
                    self._handle_inserted_device(wmi_conn, created)
                except wmi.x_wmi_timed_out:
                    pass
                except Exception as watch_err:
                    print(f"[USB] WMI insertion watcher error: {watch_err}")

                try:
                    deleted = removal_watcher(timeout_ms=200)
                    handled_event = True
                    self._handle_removed_device(deleted)
                except wmi.x_wmi_timed_out:
                    pass
                except Exception as watch_err:
                    print(f"[USB] WMI removal watcher error: {watch_err}")

                if not handled_event:
                    time.sleep(0.2)

        except ImportError:
            print("[USB] Missing dependency: install 'WMI' to enable real USB monitoring.")
            self._idle_loop()
        except Exception as e:
            print(f"[USB] Critical monitor error: {e}")
            self._idle_loop()

    def _seed_known_devices(self, wmi_conn: Any) -> None:
        """Capture currently connected USB hubs to avoid startup event floods."""
        try:
            for usb_hub in wmi_conn.Win32_USBHub():
                pnp_device_id = str(getattr(usb_hub, "PNPDeviceID", "") or "")
                if not pnp_device_id:
                    continue
                mount_point = self._resolve_mount_point(wmi_conn, pnp_device_id)
                device = DeviceInfo.from_wmi_usbhub(
                    usb_hub,
                    mount_point=mount_point,
                    is_simulated=self.simulation_mode,
                )
                self._known_devices[device.device_id] = device
        except Exception as seed_err:
            print(f"[USB] Failed to seed known devices: {seed_err}")

    def _handle_inserted_device(self, wmi_conn: Any, usb_hub: Any) -> None:
        """Normalize and emit a real USB insertion event."""
        pnp_device_id = str(getattr(usb_hub, "PNPDeviceID", "") or "")
        mount_point = self._resolve_mount_point(wmi_conn, pnp_device_id)

        # Fallback: if strict PNP-based resolution failed, detect any
        # newly-appeared removable drives not yet in the known set.
        if mount_point is None:
            mount_point = self._detect_new_removable_drive(wmi_conn)

        device = DeviceInfo.from_wmi_usbhub(
            usb_hub,
            mount_point=mount_point,
            is_simulated=self.simulation_mode,
        )

        if device.device_id in self._known_devices:
            return

        self._known_devices[device.device_id] = device
        event_bus.usb_device_inserted.emit(device.to_dict())

    def _handle_removed_device(self, usb_hub: Any) -> None:
        """Emit USB removal events using the most recent known device snapshot."""
        removed_id = str(
            getattr(usb_hub, "DeviceID", "")
            or getattr(usb_hub, "PNPDeviceID", "")
            or ""
        )
        if not removed_id:
            return

        existing = self._known_devices.pop(removed_id, None)
        if existing is not None:
            event_bus.usb_device_removed.emit(existing.to_dict())
            return

        # Fallback if WMI returns an ID shape different from insertion payload.
        event_bus.usb_device_removed.emit({"device_id": removed_id})

    def _resolve_mount_point(self, wmi_conn: Any, pnp_device_id: str, retries: int = 6, delay: float = 0.5) -> str | None:
        """Map a USB PNP ID to a Windows logical drive, if one exists."""
        if not pnp_device_id:
            return None

        normalized = pnp_device_id.replace("\\\\", "\\").upper()
        removable_drives: list[str] = []
        
        for attempt in range(retries):
            try:
                for disk in wmi_conn.Win32_DiskDrive():
                    disk_pnp = str(getattr(disk, "PNPDeviceID", "") or "").replace("\\\\", "\\").upper()
                    if normalized not in disk_pnp and disk_pnp not in normalized:
                        continue

                    for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                        for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                            device_id = str(getattr(logical_disk, "DeviceID", "") or "")
                            if device_id:
                                return f"{device_id}\\"
                
                # Fetch fallback removable drives if deep mapping failed
                removable_drives = [str(ld.DeviceID) + "\\" for ld in wmi_conn.Win32_LogicalDisk(DriveType=2)]
            except Exception as mount_err:
                print(f"[USB] Could not resolve mount point during attempt {attempt+1}: {mount_err}")
            
            if attempt < retries - 1:
                time.sleep(delay)

        # Fallback: if strict mapping failed but exactly one removable drive is connected, safely assume it's the one
        if len(removable_drives) == 1:
            return removable_drives[0]

        return None

    def _detect_new_removable_drive(self, wmi_conn: Any) -> str | None:
        """Detect newly-appeared removable drives not in the known device set."""
        try:
            known_mounts = {
                d.mount_point
                for d in self._known_devices.values()
                if d.mount_point
            }
            for ld in wmi_conn.Win32_LogicalDisk(DriveType=2):
                drive = str(getattr(ld, "DeviceID", "") or "") + "\\"
                if drive not in known_mounts and len(drive) > 1:
                    return drive
        except Exception as e:
            print(f"[USB] Could not detect new removable drive: {e}")
        return None

    def _idle_loop(self) -> None:
        """Keep thread alive safely when real monitoring is unavailable."""
        while self.is_running:
            time.sleep(1)

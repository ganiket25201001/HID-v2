"""
hid_shield.core.port_lockdown
=============================
OS-level control layer for blocking and unblocking USB ports/interfaces.

Design
------
* Abstract class interface offering ``lock_all_usb_ports()``, ``unlock_port()``,
  and ``apply_policy(device, action)``.
* Respects ``SIMULATION_MODE``. When in simulation, absolutely no OS registry
  calls are made; all actions are cleanly logged to the console/UI.
* For Windows, implements the standard USBSTOR registry toggle
  (HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR : Start = 4).
* The ``apply_policy`` method routes high-level actions ("block", "quarantine")
  down to the actual system primitives or simulation stubs.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
import threading
from typing import Any


def _get_simulation_mode() -> bool:
    env_val = os.getenv("HID_SHIELD_SIMULATION_MODE", "").lower()
    if env_val in ("true", "1", "yes"):
        return True
    if env_val in ("false", "0", "no"):
        return False
    import yaml
    from pathlib import Path
    cfg = Path(__file__).resolve().parent.parent / "config.yaml"
    if cfg.exists():
        with open(cfg, "r") as fh:
            return bool(yaml.safe_load(fh).get("simulation_mode", False))
    return False


class PortLockdown:
    """Manages system-level USB restrictions (blocking devices globally or individually).

    Examples
    --------
    .. code-block:: python

        from core.port_lockdown import PortLockdown
        from core.device_info import DeviceInfo

        manager = PortLockdown()
        manager.apply_policy(device_id="USB\\...", action="block")
    """

    def __init__(self) -> None:
        self.simulation_mode = _get_simulation_mode()
        self._mount_lock = threading.RLock()
        self._isolated_mounts: dict[str, dict[str, str]] = {}

    # ------------------------------------------------------------------
    # Policy Router
    # ------------------------------------------------------------------

    def apply_policy(self, device_id: str, action: str, extra: dict[str, Any] | None = None) -> bool:
        """Route a high-level policy action to the OS subsystem.

        Parameters
        ----------
        device_id:
            The unique identifier of the device (WMI DeviceID / HWID).
        action:
            One of the string literals from ``database.models.PolicyAction``
            (e.g., "block", "allow", "quarantine").
        extra:
            Context dictionary.

        Returns
        -------
        bool
            ``True`` if the requested action was successfully executed by the OS
            (or successfully simulated).
        """
        if self.simulation_mode:
            print(f"[LOCKDOWN] SIMULATION: applied '{action}' to device {device_id}")
            return True

        # Live dispatch
        action_norm = action.lower()
        if action_norm in ("block", "quarantine"):
            return self._disable_device_live(device_id)
        elif action_norm == "allow":
            enabled = self._enable_device_live(device_id)
            mount_restored = self._restore_mount_for_device(device_id)
            return bool(enabled or mount_restored)
        
        # PROMPT / MONITOR don't require OS-level interference
        return True

    def isolate_mount_point(self, device_id: str, mount_point: str) -> str | None:
        """Detach a removable drive letter and return its stable volume GUID path.

        The returned path has the ``\\\\?\\Volume{GUID}\\`` shape and remains
        accessible to privileged services while removing easy host-user access
        through Explorer and standard drive-letter navigation.
        """
        if self.simulation_mode:
            print(
                f"[LOCKDOWN] SIMULATION: isolate_mount_point({device_id}, {mount_point})"
            )
            return mount_point

        if platform.system().lower() != "windows":
            return None

        drive_root = self._normalize_drive_root(mount_point)
        if not drive_root:
            return None

        volume_guid = self._query_volume_guid(drive_root)
        if not volume_guid:
            return None

        if not self._detach_drive_letter(drive_root):
            return None

        with self._mount_lock:
            self._isolated_mounts[str(device_id)] = {
                "volume_guid": volume_guid,
                "drive_root": drive_root,
            }

        print(
            "[LOCKDOWN] LIVE: Detached drive letter "
            f"{drive_root} for device {device_id}; isolated path={volume_guid}"
        )
        return volume_guid

    def restore_mount_point(self, device_id: str) -> bool:
        """Restore a previously detached drive letter for an allowed device."""
        if self.simulation_mode:
            print(f"[LOCKDOWN] SIMULATION: restore_mount_point({device_id})")
            return True
        return self._restore_mount_for_device(device_id)

    # ------------------------------------------------------------------
    # Global Controls
    # ------------------------------------------------------------------

    def lock_all_usb_storage(self) -> bool:
        """Globally disable USB Mass Storage class devices via the Windows Registry.
        
        This prevents any new USB drives from mounting.
        """
        if self.simulation_mode:
            print("[LOCKDOWN] SIMULATION: lock_all_usb_storage() triggered.")
            return True

        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\USBSTOR",
                0,
                winreg.KEY_SET_VALUE
            )
            # 4 = Disabled, 3 = Manual/Enabled
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 4)
            winreg.CloseKey(key)
            print("[LOCKDOWN] LIVE: USB Mass Storage globally DISABLED (Registry: USBSTOR=4)")
            return True
        except PermissionError:
            print("[LOCKDOWN] Error: Missing Admin privileges to write USBSTOR registry key.")
            return False
        except Exception as e:
            print(f"[LOCKDOWN] Error tweaking USBSTOR: {e}")
            return False

    def unlock_all_usb_storage(self) -> bool:
        """Globally re-enable USB Mass Storage (undoes ``lock_all_usb_storage``)."""
        if self.simulation_mode:
            print("[LOCKDOWN] SIMULATION: unlock_all_usb_storage() triggered.")
            return True

        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\USBSTOR",
                0,
                winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 3)
            winreg.CloseKey(key)
            print("[LOCKDOWN] LIVE: USB Mass Storage globally ENABLED (Registry: USBSTOR=3)")
            return True
        except PermissionError:
            return False
        except Exception as e:
            print(f"[LOCKDOWN] Error tweaking USBSTOR: {e}")
            return False

    # ------------------------------------------------------------------
    # Fine-grained Live Device Isolation
    # Integrated from: USB-Physical-Security — device-level port control
    # Primary method: DevCon CLI ('devcon disable HWID')
    # Fallback: WMI Win32_PnPEntity.Disable()
    # ------------------------------------------------------------------

    def _disable_device_live(self, device_id: str) -> bool:
        """Disable a specific USB device using DevCon CLI or WMI fallback.

        Parameters
        ----------
        device_id:
            The Hardware ID or DeviceID string (e.g., ``USB\\VID_1234&PID_5678\\...``).

        Returns
        -------
        bool
            ``True`` if the device was successfully disabled.
        """
        print(f"[LOCKDOWN] LIVE: Attempting to disable device: {device_id}")

        # --- Attempt 1: DevCon CLI ---
        if self._devcon_disable(device_id):
            return True

        # --- Attempt 2: WMI Win32_PnPEntity ---
        if self._wmi_disable(device_id):
            return True

        # --- Both methods failed ---
        print(
            f"[LOCKDOWN] ERROR: Could not disable device {device_id}. "
            "Neither DevCon CLI nor WMI method succeeded. "
            "Ensure DevCon is installed or run with administrator privileges."
        )
        return False

    def _enable_device_live(self, device_id: str) -> bool:
        """Re-enable a previously disabled USB device.

        Parameters
        ----------
        device_id:
            The Hardware ID or DeviceID string.

        Returns
        -------
        bool
            ``True`` if the device was successfully re-enabled.
        """
        print(f"[LOCKDOWN] LIVE: Attempting to re-enable device: {device_id}")

        # --- Attempt 1: DevCon CLI ---
        if self._devcon_enable(device_id):
            return True

        # --- Attempt 2: WMI ---
        if self._wmi_enable(device_id):
            return True

        print(
            f"[LOCKDOWN] ERROR: Could not re-enable device {device_id}. "
            "Neither DevCon CLI nor WMI method succeeded."
        )
        return False

    # ------------------------------------------------------------------
    # DevCon CLI helpers
    # Integrated from: USB-Physical-Security — subprocess batch approach
    # ------------------------------------------------------------------

    def _devcon_disable(self, device_id: str) -> bool:
        """Disable device via devcon.exe subprocess call."""
        import shutil
        import subprocess

        devcon_path = shutil.which("devcon") or shutil.which("devcon.exe")
        if not devcon_path:
            print("[LOCKDOWN] DevCon CLI not found on PATH — skipping devcon method.")
            return False

        try:
            result = subprocess.run(
                [devcon_path, "disable", f"@{device_id}"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                print(f"[LOCKDOWN] DEVCON: Device disabled successfully: {device_id}")
                return True
            print(
                f"[LOCKDOWN] DEVCON: disable returned code {result.returncode}: "
                f"{result.stdout.strip()} {result.stderr.strip()}"
            )
            return False
        except FileNotFoundError:
            print("[LOCKDOWN] DEVCON: devcon.exe not found.")
            return False
        except subprocess.TimeoutExpired:
            print("[LOCKDOWN] DEVCON: disable command timed out.")
            return False
        except Exception as e:
            print(f"[LOCKDOWN] DEVCON: Unexpected error — {e}")
            return False

    def _devcon_enable(self, device_id: str) -> bool:
        """Enable device via devcon.exe subprocess call."""
        import shutil
        import subprocess

        devcon_path = shutil.which("devcon") or shutil.which("devcon.exe")
        if not devcon_path:
            return False

        try:
            result = subprocess.run(
                [devcon_path, "enable", f"@{device_id}"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                print(f"[LOCKDOWN] DEVCON: Device enabled successfully: {device_id}")
                return True
            return False
        except Exception:
            return False

    # ------------------------------------------------------------------
    # WMI fallback helpers
    # ------------------------------------------------------------------

    def _wmi_disable(self, device_id: str) -> bool:
        """Disable device via WMI Win32_PnPEntity.Disable()."""
        try:
            import wmi  # type: ignore[import-untyped]

            conn = wmi.WMI()
            devices = conn.Win32_PnPEntity(DeviceID=device_id)
            if not devices:
                # Try partial match on PNPDeviceID
                devices = [
                    d for d in conn.Win32_PnPEntity()
                    if device_id.lower() in str(getattr(d, "DeviceID", "")).lower()
                ]
            if not devices:
                print(f"[LOCKDOWN] WMI: Device not found: {device_id}")
                return False

            target = devices[0]
            result = target.Disable()
            ret_code = result[0] if isinstance(result, (tuple, list)) else result
            if ret_code == 0:
                print(f"[LOCKDOWN] WMI: Device disabled: {device_id}")
                return True
            print(f"[LOCKDOWN] WMI: Disable returned error code {ret_code}")
            return False
        except ImportError:
            print("[LOCKDOWN] WMI: wmi module not available.")
            return False
        except Exception as e:
            print(f"[LOCKDOWN] WMI: Error disabling device — {e}")
            return False

    def _wmi_enable(self, device_id: str) -> bool:
        """Enable device via WMI Win32_PnPEntity.Enable()."""
        try:
            import wmi  # type: ignore[import-untyped]

            conn = wmi.WMI()
            devices = conn.Win32_PnPEntity(DeviceID=device_id)
            if not devices:
                devices = [
                    d for d in conn.Win32_PnPEntity()
                    if device_id.lower() in str(getattr(d, "DeviceID", "")).lower()
                ]
            if not devices:
                print(f"[LOCKDOWN] WMI: Device not found: {device_id}")
                return False

            target = devices[0]
            result = target.Enable()
            ret_code = result[0] if isinstance(result, (tuple, list)) else result
            if ret_code == 0:
                print(f"[LOCKDOWN] WMI: Device enabled: {device_id}")
                return True
            print(f"[LOCKDOWN] WMI: Enable returned error code {ret_code}")
            return False
        except ImportError:
            return False
        except Exception as e:
            print(f"[LOCKDOWN] WMI: Error enabling device — {e}")
            return False

    # ------------------------------------------------------------------
    # Drive-letter isolation helpers
    # ------------------------------------------------------------------

    def _normalize_drive_root(self, mount_point: str) -> str | None:
        text = str(mount_point or "").strip()
        if not text:
            return None

        if re.match(r"^[A-Za-z]:$", text):
            return text.upper()
        if re.match(r"^[A-Za-z]:\\$", text):
            return text[:2].upper()
        return None

    def _query_volume_guid(self, drive_root: str) -> str | None:
        try:
            result = subprocess.run(
                ["mountvol", drive_root, "/L"],
                capture_output=True,
                text=True,
                timeout=8,
            )
        except Exception as exc:
            print(f"[LOCKDOWN] mountvol /L failed for {drive_root}: {exc}")
            return None

        if result.returncode != 0:
            return None

        for line in result.stdout.splitlines():
            candidate = line.strip()
            if candidate.upper().startswith(r"\\?\VOLUME{"):
                if not candidate.endswith("\\"):
                    candidate = candidate + "\\"
                return candidate
        return None

    def _detach_drive_letter(self, drive_root: str) -> bool:
        try:
            result = subprocess.run(
                ["mountvol", drive_root, "/D"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except Exception as exc:
            print(f"[LOCKDOWN] mountvol /D failed for {drive_root}: {exc}")
            return False

    def _attach_drive_letter(self, drive_root: str, volume_guid: str) -> bool:
        try:
            result = subprocess.run(
                ["mountvol", drive_root, volume_guid],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except Exception as exc:
            print(
                f"[LOCKDOWN] mountvol attach failed for {drive_root} <- {volume_guid}: {exc}"
            )
            return False

    def _restore_mount_for_device(self, device_id: str) -> bool:
        with self._mount_lock:
            tracked = self._isolated_mounts.get(str(device_id))

        if not tracked:
            return False

        drive_root = tracked.get("drive_root", "")
        volume_guid = tracked.get("volume_guid", "")
        if not drive_root or not volume_guid:
            return False

        restored = self._attach_drive_letter(drive_root, volume_guid)
        if restored:
            with self._mount_lock:
                self._isolated_mounts.pop(str(device_id), None)
            print(
                f"[LOCKDOWN] LIVE: Restored drive letter {drive_root} for device {device_id}"
            )
        return restored

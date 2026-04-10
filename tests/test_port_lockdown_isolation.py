"""Unit tests for host mount isolation helpers in PortLockdown."""

from __future__ import annotations

from core.port_lockdown import PortLockdown


def test_isolate_mount_point_tracks_volume(monkeypatch):
    lockdown = PortLockdown()
    lockdown.simulation_mode = False

    monkeypatch.setattr("core.port_lockdown.platform.system", lambda: "Windows")
    monkeypatch.setattr(lockdown, "_query_volume_guid", lambda _drive: r"\\?\Volume{abc-def}\\")
    monkeypatch.setattr(lockdown, "_detach_drive_letter", lambda _drive: True)

    isolated = lockdown.isolate_mount_point(device_id="USB_DEVICE_1", mount_point="E:\\")

    assert isolated == r"\\?\Volume{abc-def}\\"
    assert lockdown._isolated_mounts["USB_DEVICE_1"]["drive_root"] == "E:"


def test_restore_mount_point_for_allowed_device(monkeypatch):
    lockdown = PortLockdown()
    lockdown.simulation_mode = False

    lockdown._isolated_mounts["USB_DEVICE_2"] = {
        "drive_root": "F:",
        "volume_guid": r"\\?\Volume{xyz}\\",
    }

    attached = {"called": False}

    def _fake_attach(drive_root: str, volume_guid: str) -> bool:
        attached["called"] = True
        assert drive_root == "F:"
        assert volume_guid == r"\\?\Volume{xyz}\\"
        return True

    monkeypatch.setattr(lockdown, "_attach_drive_letter", _fake_attach)

    assert lockdown.restore_mount_point("USB_DEVICE_2") is True
    assert attached["called"] is True
    assert "USB_DEVICE_2" not in lockdown._isolated_mounts


def test_normalize_drive_root_variants():
    lockdown = PortLockdown()

    assert lockdown._normalize_drive_root("G:") == "G:"
    assert lockdown._normalize_drive_root("g:\\") == "G:"
    assert lockdown._normalize_drive_root(r"\\?\Volume{xyz}\\") is None

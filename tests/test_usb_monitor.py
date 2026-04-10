"""Tests for core.usb_monitor — USB event detection with mocked WMI."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch, MagicMock


class TestUSBEventEmitter:
    """Test USBEventEmitter with mocked WMI layer."""

    def test_emitter_creates_without_crash(self):
        """USBEventEmitter should instantiate without errors."""
        # WMI is only imported inside _run_wmi_loop(), not at construction time
        from core.usb_monitor import USBEventEmitter
        emitter = USBEventEmitter()
        assert emitter is not None
        assert hasattr(emitter, "is_running")
        assert emitter.is_running is False

    def test_device_connect_event_fires(self):
        """Simulated insertion event should trigger usb_device_inserted signal."""
        from core.event_bus import event_bus

        fired = {"count": 0}

        def on_insert(payload):
            fired["count"] += 1

        event_bus.usb_device_inserted.connect(on_insert)

        fake_device_payload = {
            "device_name": "Test USB Keyboard",
            "vendor_id": "046d",
            "product_id": "c534",
            "device_type": "keyboard",
        }
        event_bus.usb_device_inserted.emit(fake_device_payload)

        assert fired["count"] == 1, "USB insertion signal should have fired once"
        event_bus.usb_device_inserted.disconnect(on_insert)

    def test_device_disconnect_event_fires(self):
        """Simulated removal event should trigger usb_device_removed signal."""
        from core.event_bus import event_bus

        fired = {"count": 0}

        def on_remove(payload):
            fired["count"] += 1

        event_bus.usb_device_removed.connect(on_remove)

        fake_remove_payload = {
            "device_name": "Test USB Mouse",
            "vendor_id": "1234",
            "product_id": "5678",
        }
        event_bus.usb_device_removed.emit(fake_remove_payload)

        assert fired["count"] == 1, "USB removal signal should have fired once"
        event_bus.usb_device_removed.disconnect(on_remove)

    def test_emitter_has_simulation_mode_attr(self):
        """USBEventEmitter should expose simulation_mode attribute."""
        from core.usb_monitor import USBEventEmitter
        emitter = USBEventEmitter()
        assert hasattr(emitter, "simulation_mode")
        assert isinstance(emitter.simulation_mode, bool)

    def test_insert_event_payload_reflects_pre_isolated_mount(self, monkeypatch):
        """Mount should be isolated before insertion payload emission."""
        from core.usb_monitor import USBEventEmitter
        from core.event_bus import event_bus

        emitter = USBEventEmitter()
        emitter.simulation_mode = False
        emitter._isolate_on_insert = True

        monkeypatch.setattr(
            emitter,
            "_resolve_mount_point",
            lambda _conn, _pnp: "E:\\",
        )
        monkeypatch.setattr(
            emitter,
            "_detect_new_removable_drive",
            lambda _conn: None,
        )
        monkeypatch.setattr(
            emitter,
            "_close_explorer_for_drive_async",
            lambda _drive: None,
        )
        monkeypatch.setattr(
            emitter._lockdown,
            "isolate_mount_point",
            lambda device_id, mount_point: r"\\?\Volume{abc-def}\\",
        )

        usb_hub = MagicMock()
        usb_hub.PNPDeviceID = "USB\\VID_1234&PID_5678\\SERIAL123"
        usb_hub.DeviceID = "USB\\VID_1234&PID_5678\\SERIAL123"
        usb_hub.Name = "USB Flash Device"
        usb_hub.Caption = "USB Flash Device"
        usb_hub.Manufacturer = "TestVendor"

        received: list[dict] = []

        def _on_insert(payload):
            received.append(dict(payload))

        event_bus.usb_device_inserted.connect(_on_insert)
        try:
            emitter._handle_inserted_device(MagicMock(), usb_hub)
        finally:
            event_bus.usb_device_inserted.disconnect(_on_insert)

        assert received, "Expected one insertion payload"
        payload = received[0]
        assert payload["mount_point"] == r"\\?\Volume{abc-def}\\"
        assert payload["original_mount_point"] == "E:\\"
        assert payload["host_isolated"] is True


class TestDeviceInfo:
    """Test DeviceInfo dataclass parsing."""

    def test_device_info_to_dict(self):
        """DeviceInfo.to_dict() should return a complete dictionary."""
        from core.device_info import DeviceInfo
        info = DeviceInfo(
            device_id="USB\\VID_046D&PID_C534\\1234",
            device_name="Test Keyboard",
            vendor_id="046d",
            product_id="c534",
            serial_number="SN123",
            manufacturer="Logitech",
            device_type="keyboard",
        )
        d = info.to_dict()
        assert d["device_name"] == "Test Keyboard"
        assert d["vendor_id"] == "046d"
        assert d["product_id"] == "c534"
        assert d["serial_number"] == "SN123"

    def test_device_info_unknown_defaults(self):
        """Default DeviceInfo should have sensible defaults."""
        from core.device_info import DeviceInfo
        info = DeviceInfo(device_id="USB\\unknown")
        d = info.to_dict()
        assert "device_id" in d
        assert d["device_id"] == "USB\\unknown"

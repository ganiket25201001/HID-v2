"""Data models representing USB devices discovered from OS APIs."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Optional
import re


@dataclass
class DeviceInfo:
    """Represents a physical USB device detected by the OS monitor."""

    device_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    device_name: str = "Unknown Device"
    vendor_id: Optional[str] = None
    product_id: Optional[str] = None
    serial_number: Optional[str] = None
    manufacturer: Optional[str] = None
    device_type: str = "unknown"
    is_simulated: bool = False
    capacity_bytes: int = 0
    mount_point: Optional[str] = None
    raw_properties: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        """Compatibility alias used by legacy tests and console scripts."""
        return self.device_name

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary for event-bus payloads."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceInfo:
        """Reconstruct DeviceInfo from a dictionary payload."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def get_hardware_id(self) -> str:
        """Return the standard Windows-style HWID string."""
        vid = (self.vendor_id or "0000").upper()
        pid = (self.product_id or "0000").upper()
        return f"USB\\VID_{vid}&PID_{pid}"

    @classmethod
    def from_wmi_usbhub(
        cls,
        usb_hub: Any,
        *,
        mount_point: Optional[str] = None,
        is_simulated: bool = False,
    ) -> "DeviceInfo":
        """Build a device record from a Win32_USBHub WMI object."""
        pnp_device_id = str(getattr(usb_hub, "PNPDeviceID", "") or "")
        device_id = str(getattr(usb_hub, "DeviceID", "") or pnp_device_id or uuid.uuid4().hex)
        device_name = str(getattr(usb_hub, "Name", "") or getattr(usb_hub, "Caption", "") or "Unknown USB Device")
        manufacturer = cls._optional_text(getattr(usb_hub, "Manufacturer", None))

        vid, pid = cls._extract_vid_pid(device_id + " " + pnp_device_id)
        serial = cls._extract_serial(pnp_device_id)
        dev_type = cls._infer_device_type(device_name=device_name, pnp_device_id=pnp_device_id, mount_point=mount_point)

        raw_properties = {
            "device_id": device_id,
            "pnp_device_id": pnp_device_id,
            "description": cls._optional_text(getattr(usb_hub, "Description", None)),
            "status": cls._optional_text(getattr(usb_hub, "Status", None)),
            "class_code": cls._optional_text(getattr(usb_hub, "ClassCode", None)),
            "subclass_code": cls._optional_text(getattr(usb_hub, "SubClassCode", None)),
            "protocol_code": cls._optional_text(getattr(usb_hub, "ProtocolCode", None)),
        }

        return cls(
            device_id=device_id,
            device_name=device_name,
            vendor_id=vid,
            product_id=pid,
            serial_number=serial,
            manufacturer=manufacturer,
            device_type=dev_type,
            is_simulated=is_simulated,
            mount_point=mount_point,
            raw_properties={k: v for k, v in raw_properties.items() if v is not None},
        )

    @staticmethod
    def _optional_text(value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _extract_vid_pid(raw_text: str) -> tuple[Optional[str], Optional[str]]:
        match = re.search(r"VID_([0-9A-Fa-f]{4}).*PID_([0-9A-Fa-f]{4})", raw_text)
        if not match:
            return None, None
        return match.group(1).lower(), match.group(2).lower()

    @staticmethod
    def _extract_serial(pnp_device_id: str) -> Optional[str]:
        if not pnp_device_id:
            return None
        parts = pnp_device_id.split("\\")
        if len(parts) < 3:
            return None
        serial = parts[-1].strip()
        return serial or None

    @staticmethod
    def _infer_device_type(
        *,
        device_name: str,
        pnp_device_id: str,
        mount_point: Optional[str],
    ) -> str:
        if mount_point:
            return "storage"

        value = f"{device_name} {pnp_device_id}".lower()
        if any(token in value for token in ("keyboard", "kbd", "hid keyboard")):
            return "keyboard"
        if any(token in value for token in ("mouse", "touchpad", "hid-compliant mouse")):
            return "mouse"
        if any(token in value for token in ("storage", "disk", "mass storage", "flash", "thumb drive", "pendrive")):
            return "storage"
        if "composite" in value:
            return "composite"
        return "unknown"

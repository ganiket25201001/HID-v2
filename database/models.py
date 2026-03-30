"""
hid_shield.database.models
===========================
SQLAlchemy ORM models for HID Shield.

Models
------
* ``DeviceEvent``    – Represents a USB/HID device plug/unplug or policy action.
* ``FileScanResult`` – File-hash scan result associated with a device event.
* ``UserAction``     – Audit log of operator decisions (allow / block / etc.).
* ``SystemAlert``    – Application-level alerts sent to the UI or admin.

Relationships
-------------
``DeviceEvent`` → ``FileScanResult``  (one-to-many)
``DeviceEvent`` → ``UserAction``      (one-to-many)
``DeviceEvent`` → ``SystemAlert``     (one-to-many, optional)

The ``Base`` class lives in ``database.db`` to avoid circular imports.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.db import Base


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class RiskLevel(str, enum.Enum):
    """Risk level assigned to a device or scan result.

    Uses ``str`` mixin so values serialise cleanly to JSON / log strings.
    """
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DeviceType(str, enum.Enum):
    """Broad category of the USB/HID device."""
    KEYBOARD = "keyboard"
    MOUSE = "mouse"
    COMPOSITE = "composite"
    STORAGE = "storage"
    AUDIO = "audio"
    NETWORK = "network"
    UNKNOWN = "unknown"


class PolicyAction(str, enum.Enum):
    """Action that was applied (or requested) for a device event."""
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    PROMPT = "prompt"
    MONITOR = "monitor"


class AlertSeverity(str, enum.Enum):
    """Severity level for a system alert."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertCategory(str, enum.Enum):
    """Functional category for a system alert."""
    DEVICE = "device"
    FILE_SCAN = "file_scan"
    POLICY = "policy"
    SYSTEM = "system"
    AUTH = "auth"


# ---------------------------------------------------------------------------
# Helper: UTC timestamp default
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    """Return the current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Model: DeviceEvent
# ---------------------------------------------------------------------------


class DeviceEvent(Base):
    """Represents a significant event involving a USB/HID device.

    Recorded whenever a device is connected, disconnected, blocked, or
    otherwise acted upon by the policy engine.

    Columns
    -------
    id              : Integer primary key (auto-increment).
    timestamp       : UTC datetime of the event (default: now).
    device_name     : Human-readable device name from the OS descriptor.
    vendor_id       : USB Vendor ID (e.g. "046d" for Logitech).
    product_id      : USB Product ID.
    serial          : Device serial number (may be empty/null).
    manufacturer    : Manufacturer string from the USB descriptor.
    device_type     : ``DeviceType`` enum value.
    risk_level      : ``RiskLevel`` enum value assigned by the analyser.
    entropy_score   : Keystroke-entropy score (0.0 – 1.0, nullable).
    keystroke_rate  : Observed keystrokes-per-second (nullable).
    action_taken    : ``PolicyAction`` applied to this event.
    is_simulated    : True when generated in simulation mode.
    notes           : Free-text notes (analyst comments, rule name, etc.).
    """

    __tablename__ = "device_events"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # When
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        server_default=func.now(),
        nullable=False,
        index=True,
        comment="UTC timestamp of the event",
    )

    # Device identity
    device_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="Unknown Device",
        comment="Human-readable device name from OS descriptor",
    )
    vendor_id: Mapped[Optional[str]] = mapped_column(
        String(8),
        nullable=True,
        comment="USB Vendor ID (4-hex-digit string, e.g. '046d')",
    )
    product_id: Mapped[Optional[str]] = mapped_column(
        String(8),
        nullable=True,
        comment="USB Product ID (4-hex-digit string)",
    )
    serial: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        comment="Device serial number from USB descriptor",
    )
    manufacturer: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Manufacturer string from USB descriptor",
    )

    # Classification
    device_type: Mapped[str] = mapped_column(
        Enum(DeviceType, native_enum=False),
        nullable=False,
        default=DeviceType.UNKNOWN.value,
        comment="Broad category of the USB device",
    )
    risk_level: Mapped[str] = mapped_column(
        Enum(RiskLevel, native_enum=False),
        nullable=False,
        default=RiskLevel.LOW.value,
        index=True,
        comment="Risk level assigned by the threat analyser",
    )

    # Behavioural metrics
    entropy_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="Keystroke-entropy score in range [0.0, 1.0]; higher = more suspicious",
    )
    keystroke_rate: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="Observed keystrokes per second at time of detection",
    )

    # Policy outcome
    action_taken: Mapped[str] = mapped_column(
        Enum(PolicyAction, native_enum=False),
        nullable=False,
        default=PolicyAction.PROMPT.value,
        comment="Policy action applied to this event",
    )

    # Provenance
    is_simulated: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="True when this event was generated by the simulation engine",
    )
    notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Free-text analyst notes or triggering rule name",
    )

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    #: File-hash scan results associated with this event.
    file_scans: Mapped[list[FileScanResult]] = relationship(
        "FileScanResult",
        back_populates="device_event",
        cascade="all, delete-orphan",
        lazy="select",
    )

    #: Operator actions recorded in response to this event.
    user_actions: Mapped[list[UserAction]] = relationship(
        "UserAction",
        back_populates="device_event",
        cascade="all, delete-orphan",
        lazy="select",
    )

    #: System alerts triggered by this event.
    alerts: Mapped[list[SystemAlert]] = relationship(
        "SystemAlert",
        back_populates="device_event",
        cascade="all, delete-orphan",
        lazy="select",
    )

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"<DeviceEvent id={self.id!r} device={self.device_name!r} "
            f"risk={self.risk_level!r} action={self.action_taken!r}>"
        )

    def __str__(self) -> str:
        ts: str = (
            self.timestamp.isoformat() if self.timestamp else "no-timestamp"
        )
        return (
            f"[{ts}] DeviceEvent#{self.id}: {self.device_name} "
            f"({self.device_type}) – risk={self.risk_level}, "
            f"action={self.action_taken}"
        )


# ---------------------------------------------------------------------------
# Model: FileScanResult
# ---------------------------------------------------------------------------


class FileScanResult(Base):
    """Hash-based file scan result associated with a device event.

    When a storage device is connected, its payload is scanned and each
    file's hash is checked against a known-malware database.

    Columns
    -------
    id              : Integer primary key.
    device_event_id : FK → ``device_events.id``.
    timestamp       : UTC datetime of the scan.
    file_path       : Path to the scanned file (as seen on the device).
    file_name       : Basename of the file.
    file_size_bytes : File size in bytes.
    sha256_hash     : SHA-256 hex digest of the file contents.
    md5_hash        : MD5 hex digest (legacy compatibility).
    is_malicious    : True if the hash matched a known-bad signature.
    threat_name     : Name of the matched threat (e.g. "Trojan.BadUSB").
    scan_engine     : Name/version of the scan engine used.
    risk_level      : Risk level assigned to this specific file.
    is_simulated    : True in simulation mode.
    notes           : Additional analyst notes.
    """

    __tablename__ = "file_scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Foreign key to the parent device event
    device_event_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("device_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="FK to the device_events table",
    )

    # When the scan ran
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    # File identity
    file_path: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
        comment="Full path to the scanned file on the device",
    )
    file_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Basename of the scanned file",
    )
    file_size_bytes: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Size of the file in bytes",
    )

    # Cryptographic hashes
    sha256_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        comment="SHA-256 hex digest of the file",
    )
    md5_hash: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
        comment="MD5 hex digest (legacy; prefer sha256_hash)",
    )

    # Threat intelligence
    is_malicious: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="True if hash matched a known-threat signature",
    )
    threat_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Matched threat / malware family name",
    )
    scan_engine: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        comment="Scan engine identifier and version string",
    )

    # Risk
    risk_level: Mapped[str] = mapped_column(
        Enum(RiskLevel, native_enum=False),
        nullable=False,
        default=RiskLevel.SAFE.value,
        comment="Risk level for this individual file",
    )

    # Provenance
    is_simulated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ------------------------------------------------------------------
    # Relationship (back-reference)
    # ------------------------------------------------------------------

    device_event: Mapped[DeviceEvent] = relationship(
        "DeviceEvent",
        back_populates="file_scans",
    )

    def __repr__(self) -> str:
        return (
            f"<FileScanResult id={self.id!r} file={self.file_name!r} "
            f"malicious={self.is_malicious!r} risk={self.risk_level!r}>"
        )

    def __str__(self) -> str:
        threat: str = self.threat_name or "none"
        return (
            f"FileScanResult#{self.id}: {self.file_name} "
            f"– malicious={self.is_malicious}, threat={threat}, "
            f"risk={self.risk_level}"
        )


# ---------------------------------------------------------------------------
# Model: UserAction
# ---------------------------------------------------------------------------


class UserAction(Base):
    """Audit log entry capturing an operator decision.

    Every time a human operator allows, blocks, or quarantines a device (or
    overrides the automatic policy) a ``UserAction`` row is created.

    Columns
    -------
    id              : Integer primary key.
    device_event_id : FK → ``device_events.id``.
    timestamp       : UTC datetime of the action.
    action          : ``PolicyAction`` chosen by the operator.
    operator_id     : Identifier of the operator (username / PIN hash prefix).
    reason          : Optional reason / justification text.
    was_override    : True if the action overrode an automatic decision.
    previous_action : The automatic action that was overridden (if any).
    ip_address      : Source IP if administered remotely (audit trail).
    notes           : Free-text audit notes.
    """

    __tablename__ = "user_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    device_event_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("device_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    action: Mapped[str] = mapped_column(
        Enum(PolicyAction, native_enum=False),
        nullable=False,
        comment="Policy action chosen by the operator",
    )

    operator_id: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        comment="Identifier for the human operator (username or PIN prefix)",
    )

    reason: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Justification text entered by the operator",
    )

    was_override: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="True if the operator overrode the automatic policy decision",
    )

    previous_action: Mapped[Optional[str]] = mapped_column(
        Enum(PolicyAction, native_enum=False),
        nullable=True,
        comment="The automatic action that was overridden (when was_override=True)",
    )

    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),   # IPv4 or IPv6
        nullable=True,
        comment="Source IP address for remote administration audit",
    )

    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ------------------------------------------------------------------
    # Relationship
    # ------------------------------------------------------------------

    device_event: Mapped[DeviceEvent] = relationship(
        "DeviceEvent",
        back_populates="user_actions",
    )

    def __repr__(self) -> str:
        return (
            f"<UserAction id={self.id!r} action={self.action!r} "
            f"operator={self.operator_id!r} override={self.was_override!r}>"
        )

    def __str__(self) -> str:
        ts: str = (
            self.timestamp.isoformat() if self.timestamp else "no-timestamp"
        )
        return (
            f"[{ts}] UserAction#{self.id}: operator={self.operator_id} "
            f"→ {self.action}"
            + (" (override)" if self.was_override else "")
        )


# ---------------------------------------------------------------------------
# Model: SystemAlert
# ---------------------------------------------------------------------------


class SystemAlert(Base):
    """Application-level alert surfaced to the UI or sent to an admin.

    Alerts summarise significant threat or policy events so the operator can
    review them in the notification centre without reading raw event logs.

    Columns
    -------
    id              : Integer primary key.
    device_event_id : Optional FK → ``device_events.id``.
    timestamp       : UTC datetime of the alert.
    title           : Short, human-readable alert title.
    message         : Detailed alert body text.
    severity        : ``AlertSeverity`` level.
    category        : ``AlertCategory`` functional area.
    is_read         : True after the operator has acknowledged the alert.
    is_dismissed    : True after the operator has dismissed the alert from UI.
    is_simulated    : True in simulation mode.
    source          : Name of the subsystem that raised the alert.
    """

    __tablename__ = "system_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Optional link to a device event
    device_event_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("device_events.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Optional FK to the triggering device event",
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    # Content
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Short alert title shown in the notification centre",
    )
    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Full alert message body",
    )

    # Classification
    severity: Mapped[str] = mapped_column(
        Enum(AlertSeverity, native_enum=False),
        nullable=False,
        default=AlertSeverity.INFO.value,
        index=True,
    )
    category: Mapped[str] = mapped_column(
        Enum(AlertCategory, native_enum=False),
        nullable=False,
        default=AlertCategory.SYSTEM.value,
        index=True,
    )

    # State
    is_read: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False,
        comment="True after operator acknowledges the alert",
    )
    is_dismissed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False,
        comment="True after operator dismisses the alert from UI",
    )

    # Provenance
    is_simulated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    source: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        comment="Name of the subsystem that raised this alert",
    )

    # ------------------------------------------------------------------
    # Relationship
    # ------------------------------------------------------------------

    device_event: Mapped[Optional[DeviceEvent]] = relationship(
        "DeviceEvent",
        back_populates="alerts",
    )

    def __repr__(self) -> str:
        return (
            f"<SystemAlert id={self.id!r} title={self.title!r} "
            f"severity={self.severity!r} read={self.is_read!r}>"
        )

    def __str__(self) -> str:
        ts: str = (
            self.timestamp.isoformat() if self.timestamp else "no-timestamp"
        )
        return (
            f"[{ts}] SystemAlert#{self.id} [{self.severity.upper()}] "
            f"{self.title}"
        )

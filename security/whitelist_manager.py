"""Thread-safe serial-number whitelist manager for HID Shield."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from database.db import get_db
from database.models import AlertCategory, AlertSeverity
from database.repository import AlertRepository
from security.session_manager import SessionManager, UserMode


@dataclass(slots=True)
class WhitelistEntry:
    """Immutable representation of a whitelisted device serial."""

    serial_number: str
    added_at: str
    label: str | None
    added_by: str | None


class WhitelistManager:
    """Manage persistent serial whitelist records.

    Persistence model:
    - Entries are persisted in SQLite through `AlertRepository` records.
    - Each whitelist mutation writes an append-only log event.
    - Current state is reconstructed by replaying logs in timestamp order.

    This avoids schema migrations while keeping storage durable.
    """

    _SOURCE_TAG: str = "security.whitelist_manager"
    _TITLE_ADD: str = "WHITELIST_ADD"
    _TITLE_REMOVE: str = "WHITELIST_REMOVE"

    def __init__(self) -> None:
        """Initialize whitelist cache and synchronization primitives."""
        self._lock = threading.RLock()
        self._entries: dict[str, WhitelistEntry] = {}
        self._loaded: bool = False

    def add_device(
        self,
        serial_number: str,
        *,
        label: str | None = None,
        added_by: str | None = None,
    ) -> bool:
        """Add a device serial number to whitelist.

        Requires ADMIN session to prevent unauthorized trust escalation.

        Parameters
        ----------
        serial_number:
            Hardware serial string.
        label:
            Optional friendly device label.
        added_by:
            Optional operator identifier.

        Returns
        -------
        bool
            True if added, False if already present, invalid, or unauthorized.
        """
        if not SessionManager.instance().require_auth(UserMode.ADMIN):
            print("[WHITELIST] Unauthorized: ADMIN session required to add devices.")
            return False

        normalized = self._normalize_serial(serial_number)
        if not normalized:
            return False

        with self._lock:
            self._ensure_loaded_locked()
            if normalized in self._entries:
                return False

            payload = {
                "serial_number": normalized,
                "label": label,
                "added_by": added_by,
                "timestamp": self._utc_now_iso(),
            }
            self._append_log_event(title=self._TITLE_ADD, payload=payload)

            self._entries[normalized] = WhitelistEntry(
                serial_number=normalized,
                added_at=payload["timestamp"],
                label=label,
                added_by=added_by,
            )
            return True

    def remove_device(self, serial_number: str, *, removed_by: str | None = None) -> bool:
        """Remove a device serial number from whitelist.

        Requires ADMIN session to prevent unauthorized trust modification.
        """
        if not SessionManager.instance().require_auth(UserMode.ADMIN):
            print("[WHITELIST] Unauthorized: ADMIN session required to remove devices.")
            return False

        normalized = self._normalize_serial(serial_number)
        if not normalized:
            return False

        with self._lock:
            self._ensure_loaded_locked()
            if normalized not in self._entries:
                return False

            payload = {
                "serial_number": normalized,
                "removed_by": removed_by,
                "timestamp": self._utc_now_iso(),
            }
            self._append_log_event(title=self._TITLE_REMOVE, payload=payload)
            self._entries.pop(normalized, None)
            return True

    def is_whitelisted(self, serial_number: str) -> bool:
        """Check whether a serial number is currently whitelisted."""
        normalized = self._normalize_serial(serial_number)
        if not normalized:
            return False

        with self._lock:
            self._ensure_loaded_locked()
            return normalized in self._entries

    def list_entries(self) -> list[WhitelistEntry]:
        """Return all current whitelist entries sorted by serial number."""
        with self._lock:
            self._ensure_loaded_locked()
            return sorted(self._entries.values(), key=lambda item: item.serial_number)

    def refresh(self) -> None:
        """Force a full reload from persistent repository logs."""
        with self._lock:
            self._entries = {}
            self._loaded = False
            self._ensure_loaded_locked()

    # ------------------------------------------------------------------
    # Internal persistence helpers
    # ------------------------------------------------------------------

    def _ensure_loaded_locked(self) -> None:
        """Replay repository log events and populate in-memory whitelist cache."""
        if self._loaded:
            return

        events = self._load_whitelist_events()
        rebuilt: dict[str, WhitelistEntry] = {}

        # Replay in ascending timestamp order for deterministic state.
        for title, payload in events:
            serial = self._normalize_serial(payload.get("serial_number", ""))
            if not serial:
                continue

            if title == self._TITLE_ADD:
                rebuilt[serial] = WhitelistEntry(
                    serial_number=serial,
                    added_at=str(payload.get("timestamp") or self._utc_now_iso()),
                    label=self._as_optional_str(payload.get("label")),
                    added_by=self._as_optional_str(payload.get("added_by")),
                )
            elif title == self._TITLE_REMOVE:
                rebuilt.pop(serial, None)

        self._entries = rebuilt
        self._loaded = True

    def _append_log_event(self, *, title: str, payload: dict[str, Any]) -> None:
        """Persist one whitelist mutation event through `AlertRepository`."""
        with get_db() as session:
            AlertRepository.create_alert(
                session,
                title=title,
                message=json.dumps(payload, separators=(",", ":")),
                severity=AlertSeverity.INFO,
                category=AlertCategory.SYSTEM,
                device_event_id=None,
                is_simulated=True,
                source=self._SOURCE_TAG,
            )

    def _load_whitelist_events(self) -> list[tuple[str, dict[str, Any]]]:
        """Load and parse persisted whitelist log events from repository."""
        with get_db() as session:
            alerts = AlertRepository.get_recent_alerts(limit=5000, session=session)

        parsed: list[tuple[str, dict[str, Any], datetime]] = []
        for alert in alerts:
            if str(alert.source or "") != self._SOURCE_TAG:
                continue
            if str(alert.title or "") not in {self._TITLE_ADD, self._TITLE_REMOVE}:
                continue

            payload = self._parse_json_message(str(alert.message or ""))
            timestamp = alert.timestamp or datetime.now(timezone.utc)
            parsed.append((str(alert.title), payload, timestamp))

        parsed.sort(key=lambda row: row[2])
        return [(title, payload) for title, payload, _ in parsed]

    # ------------------------------------------------------------------
    # Small utilities
    # ------------------------------------------------------------------

    def _normalize_serial(self, serial_number: str) -> str:
        """Normalize serial format to uppercase trimmed canonical form."""
        return str(serial_number or "").strip().upper()

    def _parse_json_message(self, raw_message: str) -> dict[str, Any]:
        """Safely parse alert message JSON payload to dictionary."""
        try:
            value = json.loads(raw_message)
            return value if isinstance(value, dict) else {}
        except json.JSONDecodeError:
            return {}

    def _as_optional_str(self, value: Any) -> str | None:
        """Normalize value to optional stripped string."""
        if value is None:
            return None
        text = str(value).strip()
        return text if text else None

    def _utc_now_iso(self) -> str:
        """Return current UTC timestamp as ISO-8601 string."""
        return datetime.now(timezone.utc).isoformat()

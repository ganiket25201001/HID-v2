"""
hid_shield.security.session_manager
=====================================
Session state management for the authenticated user.

Design
------
* ``SessionManager`` is a **singleton** — only one instance exists per
  process.  Call ``SessionManager()`` or ``SessionManager.instance()`` to
  get the same object every time.
* The active session is tracked in memory only (not persisted to disk) so a
  process restart always requires re-authentication.
* Session timeout is configurable via ``config.yaml`` → ``security.session_timeout_minutes``
  (default: 15 minutes).
* Lightweight callback lists replace PySide6 ``Signal`` to keep this module
  importable in non-Qt test contexts.  The UI layer can register callbacks
  via ``on_session_change()``.
* Thread-safe: a ``threading.RLock`` guards all state mutations.

Modes
-----
GUEST    – Not authenticated; read-only access.
USER     – Authenticated with PIN; standard monitoring access.
ADMIN    – Authenticated with master password or elevated PIN; full access.
"""

from __future__ import annotations

import os
import threading
import time
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Optional

import yaml


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

_HERE: Path = Path(__file__).resolve().parent
_PROJECT_ROOT: Path = _HERE.parent
_CONFIG_PATH: Path = _PROJECT_ROOT / "config.yaml"


def _load_config() -> dict[str, Any]:
    if _CONFIG_PATH.exists():
        with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    return {}


# ---------------------------------------------------------------------------
# User mode enumeration
# ---------------------------------------------------------------------------


class UserMode(str, Enum):
    """Privilege level of the active session."""
    GUEST = "GUEST"    # Not authenticated
    USER = "USER"      # Authenticated via PIN
    ADMIN = "ADMIN"    # Authenticated via master password / elevated rights


# ---------------------------------------------------------------------------
# SessionManager (singleton)
# ---------------------------------------------------------------------------

_SESSION_TIMEOUT_MINUTES_DEFAULT: int = 15


class SessionManager:
    """Singleton managing the current operator session.

    Usage
    -----
    .. code-block:: python

        sm = SessionManager()            # Returns existing or new singleton
        sm.start_session(UserMode.USER)  # Mark as authenticated
        sm.is_authenticated()            # True
        sm.refresh_session()             # Reset the inactivity timer

    Callbacks registered via ``on_session_change()`` are invoked whenever
    the session mode changes (e.g. login, logout, timeout).
    """

    # Singleton holder
    _instance: Optional[SessionManager] = None
    _instance_lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Singleton constructor
    # ------------------------------------------------------------------

    def __new__(cls) -> "SessionManager":
        """Return the existing singleton instance, or create a new one."""
        with cls._instance_lock:
            if cls._instance is None:
                obj = super().__new__(cls)
                obj._initialised = False
                cls._instance = obj
        return cls._instance

    def __init__(self) -> None:
        # Guard against re-initialisation on subsequent __new__ calls
        if getattr(self, "_initialised", False):
            return

        config: dict[str, Any] = _load_config()
        security_cfg: dict[str, Any] = config.get("security", {})
        self._timeout_minutes: int = int(
            security_cfg.get("session_timeout_minutes", _SESSION_TIMEOUT_MINUTES_DEFAULT)
        )

        self._lock: threading.RLock = threading.RLock()

        # Session state
        self._mode: UserMode = UserMode.GUEST
        self._session_start: float = 0.0       # monotonic epoch of login
        self._last_activity: float = 0.0       # monotonic epoch of last action
        self._operator_id: Optional[str] = None

        # Callback lists for UI integration (replaces Qt signals here)
        self._on_change_callbacks: list[Callable[[UserMode], None]] = []

        self._initialised = True

    # ------------------------------------------------------------------
    # Singleton class method
    # ------------------------------------------------------------------

    @classmethod
    def instance(cls) -> "SessionManager":
        """Return the singleton ``SessionManager`` instance.

        Equivalent to calling ``SessionManager()`` directly.
        """
        return cls()

    @classmethod
    def reset(cls) -> None:
        """Destroy the singleton (for unit testing only).

        .. warning::
            Do **not** call this in production code.
        """
        with cls._instance_lock:
            cls._instance = None

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def start_session(
        self,
        mode: UserMode,
        operator_id: Optional[str] = None,
    ) -> None:
        """Start or elevate an authenticated session.

        Parameters
        ----------
        mode:
            The ``UserMode`` level for this session.
        operator_id:
            Optional identifier for the operator (username / PIN fragment).
        """
        with self._lock:
            now: float = time.monotonic()
            old_mode: UserMode = self._mode
            self._mode = mode
            self._session_start = now
            self._last_activity = now
            self._operator_id = operator_id

        print(
            f"[SESSION] Session started — mode={mode.value}, "
            f"operator={operator_id or 'anonymous'}, "
            f"timeout={self._timeout_minutes} min"
        )

        if mode != old_mode:
            self._notify_callbacks(mode)

    def end_session(self) -> None:
        """Log out and revert to GUEST mode.

        Clears all session state and notifies registered callbacks.
        """
        with self._lock:
            prev: UserMode = self._mode
            self._mode = UserMode.GUEST
            self._session_start = 0.0
            self._last_activity = 0.0
            self._operator_id = None

        print("[SESSION] Session ended — reverted to GUEST.")

        if prev != UserMode.GUEST:
            self._notify_callbacks(UserMode.GUEST)

    def refresh_session(self) -> None:
        """Reset the inactivity timer (call on any user interaction).

        Has no effect when no session is active (GUEST mode).
        """
        with self._lock:
            if self._mode != UserMode.GUEST:
                self._last_activity = time.monotonic()

    def check_timeout(self) -> bool:
        """Check whether the session has timed out and end it if so.

        Returns
        -------
        bool
            ``True`` if the session was active and just timed out;
            ``False`` if the session is still valid or was already in GUEST.
        """
        with self._lock:
            if self._mode == UserMode.GUEST:
                return False
            elapsed_minutes: float = (
                time.monotonic() - self._last_activity
            ) / 60.0
            if elapsed_minutes >= self._timeout_minutes:
                # Capture the mode before clearing
                print(
                    f"[SESSION] Session timed out after "
                    f"{elapsed_minutes:.1f} min — reverting to GUEST."
                )

        if elapsed_minutes >= self._timeout_minutes:
            self.end_session()
            return True
        return False

    # ------------------------------------------------------------------
    # Privilege checks
    # ------------------------------------------------------------------

    def is_authenticated(self) -> bool:
        """Return ``True`` if a non-GUEST session is active and not timed out.

        Also triggers a timeout check as a side effect.
        """
        self.check_timeout()
        with self._lock:
            return self._mode != UserMode.GUEST

    def is_admin(self) -> bool:
        """Return ``True`` if the active session has ADMIN privileges.

        Also triggers a timeout check as a side effect.
        """
        self.check_timeout()
        with self._lock:
            return self._mode == UserMode.ADMIN

    def require_auth(self, minimum_mode: UserMode = UserMode.USER) -> bool:
        """Return ``True`` if the current session meets the minimum mode.

        Can be used as a guard at the start of privileged operations.

        Parameters
        ----------
        minimum_mode:
            The minimum ``UserMode`` required.  Defaults to ``USER``.

        Returns
        -------
        bool
            ``True`` if the session mode is >= ``minimum_mode``.
        """
        self.check_timeout()
        mode_rank: dict[UserMode, int] = {
            UserMode.GUEST: 0,
            UserMode.USER: 1,
            UserMode.ADMIN: 2,
        }
        with self._lock:
            current_rank: int = mode_rank.get(self._mode, 0)
        required_rank: int = mode_rank.get(minimum_mode, 1)
        return current_rank >= required_rank

    # ------------------------------------------------------------------
    # State queries
    # ------------------------------------------------------------------

    def get_current_mode(self) -> str:
        """Return the current ``UserMode`` value as a plain string.

        Returns
        -------
        str
            One of ``"GUEST"``, ``"USER"``, or ``"ADMIN"``.
        """
        with self._lock:
            return self._mode.value

    def get_operator_id(self) -> Optional[str]:
        """Return the identifier of the currently logged-in operator.

        Returns
        -------
        str or None
        """
        with self._lock:
            return self._operator_id

    def session_age_seconds(self) -> float:
        """Return the total age of the current session in seconds.

        Returns
        -------
        float
            Seconds since ``start_session`` was called, or ``0.0`` if GUEST.
        """
        with self._lock:
            if self._session_start == 0.0:
                return 0.0
            return time.monotonic() - self._session_start

    def inactivity_seconds(self) -> float:
        """Return seconds since the last ``refresh_session`` call.

        Returns
        -------
        float
            0.0 when in GUEST mode.
        """
        with self._lock:
            if self._last_activity == 0.0:
                return 0.0
            return time.monotonic() - self._last_activity

    def timeout_remaining_seconds(self) -> float:
        """Return the seconds until inactivity timeout (0 if GUEST).

        Returns
        -------
        float
            Remaining seconds before automatic logout.
        """
        with self._lock:
            if self._mode == UserMode.GUEST:
                return 0.0
            elapsed = time.monotonic() - self._last_activity
            remaining = (self._timeout_minutes * 60) - elapsed
            return max(0.0, remaining)

    def set_timeout_minutes(self, timeout_minutes: int) -> None:
        """Update session inactivity timeout with a safe bounded value.

        Parameters
        ----------
        timeout_minutes:
            Timeout value in minutes. Values are clamped into [1, 240].
        """
        bounded = max(1, min(240, int(timeout_minutes)))
        with self._lock:
            self._timeout_minutes = bounded

    # ------------------------------------------------------------------
    # Callback registration (UI integration)
    # ------------------------------------------------------------------

    def on_session_change(self, callback: Callable[[UserMode], None]) -> None:
        """Register a callback invoked when the session mode changes.

        The callback receives the new ``UserMode`` as its sole argument.
        Multiple callbacks can be registered; they are called in order.

        Parameters
        ----------
        callback:
            A callable that accepts a single ``UserMode`` argument.

        Example
        -------
        .. code-block:: python

            def handle_mode_change(mode: UserMode) -> None:
                print(f"Session mode changed to {mode.value}")

            sm = SessionManager()
            sm.on_session_change(handle_mode_change)
        """
        if callback not in self._on_change_callbacks:
            self._on_change_callbacks.append(callback)

    def remove_session_callback(self, callback: Callable[[UserMode], None]) -> None:
        """Unregister a previously registered session-change callback.

        Parameters
        ----------
        callback:
            The callback to remove.
        """
        if callback in self._on_change_callbacks:
            self._on_change_callbacks.remove(callback)

    def _notify_callbacks(self, mode: UserMode) -> None:
        """Invoke all registered session-change callbacks.

        Parameters
        ----------
        mode:
            The new ``UserMode`` to pass to each callback.
        """
        for cb in list(self._on_change_callbacks):
            try:
                cb(mode)
            except Exception as exc:  # noqa: BLE001
                print(f"[SESSION] Callback error: {exc}")

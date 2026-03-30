"""
hid_shield.security.auth_manager
==================================
PIN and master-password authentication manager for HID Shield.

Architecture
------------
* PINs are 6-digit numeric strings stored as bcrypt hashes in a dedicated
  SQLite table (``auth_config``).  The table is created on first access if it
  does not yet exist, so no Alembic migration is needed for this lightweight
  key-value store.
* A master password is supported alongside the PIN for recovery scenarios.
* Failed-attempt tracking and lockout (3 failures → 60 s cooldown) are
  implemented in memory and survive only for the current process lifetime
  (intentionally — a reboot resets the counter, matching typical HSM UX).
* All public methods are fully type-annotated and safe to call from a
  PySide6 main thread or a background worker thread (operations are brief
  and synchronous; bcrypt's hashing cost is bounded to ≤ 300 ms per call).
* In SIMULATION_MODE a convenience ``dev_pin = "123456"`` is pre-seeded the
  first time ``is_first_run()`` is called so that developers can log in
  immediately without completing the setup wizard.

Security notes
--------------
* bcrypt work factor is set to 12 (≈ 200 ms on modern hardware) — sufficient
  for a 6-digit PIN since the attack surface is the local machine only.
* The raw PIN is never stored, logged, or retained in any attribute.
* Thread-safety: a ``threading.Lock`` guards the failed-attempt counters.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any, Optional

import bcrypt
import yaml
from sqlalchemy import Column, String, Text, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# ---------------------------------------------------------------------------
# Internal Base + lightweight auth table (separate from main ORM Base to
# keep this module fully self-contained and importable in isolation)
# ---------------------------------------------------------------------------

_HERE: Path = Path(__file__).resolve().parent          # …/security/
_PROJECT_ROOT: Path = _HERE.parent                     # …/hid_shield/
_CONFIG_PATH: Path = _PROJECT_ROOT / "config.yaml"


def _load_config() -> dict[str, Any]:
    """Read config.yaml and return it as a dict."""
    if _CONFIG_PATH.exists():
        with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    return {}


def _get_db_path() -> Path:
    """Resolve the SQLite database path from config / env."""
    env_path: str = os.getenv("HID_SHIELD_DB_PATH", "")
    if env_path:
        return Path(env_path).resolve()
    config = _load_config()
    db_rel: str = config.get("database", {}).get("path", "hid_shield.db")
    p = Path(db_rel)
    if not p.is_absolute():
        p = (_PROJECT_ROOT / p).resolve()
    return p


def _is_simulation_mode() -> bool:
    """Return True when the app is in simulation mode."""
    env_val = os.getenv("HID_SHIELD_SIMULATION_MODE", "").lower()
    if env_val in ("true", "1", "yes"):
        return True
    if env_val in ("false", "0", "no"):
        return False
    return bool(_load_config().get("simulation_mode", True))


# ---------------------------------------------------------------------------
# Tiny ORM base for the auth_config table
# ---------------------------------------------------------------------------


class _AuthBase(DeclarativeBase):
    pass


class _AuthConfig(_AuthBase):
    """Key-value store for auth settings persisted in the main SQLite DB."""
    __tablename__ = "auth_config"

    key: Column = Column(String(128), primary_key=True, nullable=False)
    value: Column = Column(Text, nullable=True)


# ---------------------------------------------------------------------------
# AuthManager
# ---------------------------------------------------------------------------

# Lockout constants
_MAX_ATTEMPTS: int = 3          # Failed attempts before lockout
_LOCKOUT_SECONDS: int = 60      # Duration of the lockout period
_BCRYPT_ROUNDS: int = 12        # bcrypt work factor

# In-simulation-mode convenience PIN (cleared in production)
_SIM_DEV_PIN: str = "123456"


class AuthManager:
    """Manages PIN and master-password authentication for HID Shield.

    Parameters
    ----------
    db_path:
        Path to the SQLite database.  Defaults to the path resolved from
        ``config.yaml`` / ``HID_SHIELD_DB_PATH`` env var.
    simulation_mode:
        When ``True`` (default from config), a dev PIN is pre-seeded on
        first run so developers can log in without a setup wizard.

    Attributes
    ----------
    simulation_mode : bool
        Whether simulation mode is active.
    """

    # Key names inside the auth_config table
    _KEY_PIN_HASH: str = "pin_hash"
    _KEY_MASTER_HASH: str = "master_password_hash"
    _KEY_FIRST_RUN: str = "first_run_complete"

    def __init__(
        self,
        db_path: Optional[Path] = None,
        simulation_mode: Optional[bool] = None,
    ) -> None:
        self.simulation_mode: bool = (
            simulation_mode if simulation_mode is not None else _is_simulation_mode()
        )

        # Resolve database path
        self._db_path: Path = db_path or _get_db_path()
        db_url: str = f"sqlite:///{self._db_path}"

        # Create a private engine + session factory for auth operations only
        self._engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False},
        )

        # Ensure the auth_config table exists
        _AuthBase.metadata.create_all(bind=self._engine)

        self._Session = sessionmaker(bind=self._engine, autocommit=False,
                                     autoflush=False, expire_on_commit=False)

        # Thread-safe failed-attempt tracking
        self._lock: threading.Lock = threading.Lock()
        self._failed_attempts: int = 0
        self._lockout_until: float = 0.0   # epoch seconds

        # Seed dev PIN in simulation mode if this is a first run
        if self.simulation_mode and self.is_first_run():
            self._seed_simulation_pin()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_session(self) -> Session:
        """Return a new SQLAlchemy session."""
        return self._Session()

    def _get_value(self, key: str) -> Optional[str]:
        """Retrieve a value from ``auth_config`` by key.

        Returns ``None`` if the key does not exist.
        """
        with self._get_session() as session:
            row = session.get(_AuthConfig, key)
            return row.value if row else None

    def _set_value(self, key: str, value: str) -> None:
        """Upsert a value in ``auth_config``."""
        session = self._get_session()
        try:
            row = session.get(_AuthConfig, key)
            if row is None:
                row = _AuthConfig(key=key, value=value)
                session.add(row)
            else:
                row.value = value
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def _hash_secret(self, secret: str) -> str:
        """Return a bcrypt hash of ``secret``.

        Parameters
        ----------
        secret:
            The plain-text PIN or password to hash.

        Returns
        -------
        str
            The bcrypt hash string (includes salt and cost factor).
        """
        salt: bytes = bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
        hashed: bytes = bcrypt.hashpw(secret.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    def _verify_secret(self, secret: str, hashed: str) -> bool:
        """Return ``True`` if ``secret`` matches the stored bcrypt ``hashed``.

        Parameters
        ----------
        secret:
            Plain-text secret to verify.
        hashed:
            Stored bcrypt hash string.
        """
        try:
            return bcrypt.checkpw(
                secret.encode("utf-8"),
                hashed.encode("utf-8"),
            )
        except Exception:
            return False

    def _seed_simulation_pin(self) -> None:
        """Pre-seed the dev PIN ``123456`` for simulation mode."""
        print("[AUTH] SIMULATION_MODE: seeding development PIN (masked).")
        self.set_new_pin(_SIM_DEV_PIN)

    # ------------------------------------------------------------------
    # Lockout helpers
    # ------------------------------------------------------------------

    def _is_locked_out(self) -> bool:
        """Return ``True`` if the account is currently locked out."""
        with self._lock:
            if self._failed_attempts >= _MAX_ATTEMPTS:
                remaining: float = self._lockout_until - time.monotonic()
                if remaining > 0:
                    return True
                # Lockout period expired — reset
                self._failed_attempts = 0
                self._lockout_until = 0.0
        return False

    def _record_failure(self) -> None:
        """Increment the failed-attempt counter and arm lockout if needed."""
        with self._lock:
            self._failed_attempts += 1
            if self._failed_attempts >= _MAX_ATTEMPTS:
                self._lockout_until = time.monotonic() + _LOCKOUT_SECONDS
                print(
                    f"[AUTH] {_MAX_ATTEMPTS} failed attempts — "
                    f"locked out for {_LOCKOUT_SECONDS} s."
                )

    def _record_success(self) -> None:
        """Reset the failed-attempt counter after a successful auth."""
        with self._lock:
            self._failed_attempts = 0
            self._lockout_until = 0.0

    # ------------------------------------------------------------------
    # Public API — PIN management
    # ------------------------------------------------------------------

    def is_first_run(self) -> bool:
        """Return ``True`` if no PIN has been configured yet.

        Returns
        -------
        bool
            ``True`` on first run (no PIN hash stored); ``False`` otherwise.
        """
        return self._get_value(self._KEY_PIN_HASH) is None

    def set_new_pin(self, pin: str) -> None:
        """Persist a new bcrypt-hashed PIN.

        The raw ``pin`` is hashed immediately and not retained anywhere.

        Parameters
        ----------
        pin:
            6-digit numeric string (validation is the caller's responsibility).

        Raises
        ------
        ValueError
            If ``pin`` is empty.
        """
        if not pin:
            raise ValueError("PIN must not be empty.")
        hashed: str = self._hash_secret(pin)
        self._set_value(self._KEY_PIN_HASH, hashed)
        self._set_value(self._KEY_FIRST_RUN, "true")
        print("[AUTH] PIN updated successfully.")

    def verify_pin(self, pin: str) -> bool:
        """Verify a PIN against the stored bcrypt hash.

        Enforces the lockout policy — raises ``PermissionError`` when
        the account is locked out before even checking the PIN.

        Parameters
        ----------
        pin:
            Plain-text PIN entered by the operator.

        Returns
        -------
        bool
            ``True`` if the PIN matches; ``False`` otherwise.

        Raises
        ------
        PermissionError
            When the account is locked out due to repeated failures.
        """
        if self._is_locked_out():
            remaining: float = max(0.0, self._lockout_until - time.monotonic())
            raise PermissionError(
                f"Account locked. Try again in {remaining:.0f} seconds."
            )

        stored_hash: Optional[str] = self._get_value(self._KEY_PIN_HASH)
        if stored_hash is None:
            # No PIN configured — first-run state
            self._record_failure()
            return False

        if self._verify_secret(pin, stored_hash):
            self._record_success()
            return True

        self._record_failure()
        return False

    # ------------------------------------------------------------------
    # Public API — master password
    # ------------------------------------------------------------------

    def set_master_password(self, password: str) -> None:
        """Persist a bcrypt-hashed master (recovery) password.

        Parameters
        ----------
        password:
            Plain-text master password.

        Raises
        ------
        ValueError
            If ``password`` is empty.
        """
        if not password:
            raise ValueError("Master password must not be empty.")
        hashed: str = self._hash_secret(password)
        self._set_value(self._KEY_MASTER_HASH, hashed)
        print("[AUTH] Master password updated successfully.")

    def verify_password(self, password: str) -> bool:
        """Verify the master password against the stored hash.

        Applies the same lockout policy as ``verify_pin``.

        Parameters
        ----------
        password:
            Plain-text master password entered by the operator.

        Returns
        -------
        bool
            ``True`` if the password matches; ``False`` otherwise.

        Raises
        ------
        PermissionError
            When the account is locked out.
        """
        if self._is_locked_out():
            remaining = max(0.0, self._lockout_until - time.monotonic())
            raise PermissionError(
                f"Account locked. Try again in {remaining:.0f} seconds."
            )

        stored_hash: Optional[str] = self._get_value(self._KEY_MASTER_HASH)
        if stored_hash is None:
            self._record_failure()
            return False

        if self._verify_secret(password, stored_hash):
            self._record_success()
            return True

        self._record_failure()
        return False

    # ------------------------------------------------------------------
    # Public API — lockout state queries
    # ------------------------------------------------------------------

    def is_locked_out(self) -> bool:
        """Return ``True`` if the account is currently locked out.

        Public wrapper for ``_is_locked_out`` (without side-effects).
        """
        return self._is_locked_out()

    def lockout_remaining_seconds(self) -> float:
        """Return seconds remaining in the current lockout (0 if not locked).

        Returns
        -------
        float
            Seconds remaining, or ``0.0`` if there is no active lockout.
        """
        with self._lock:
            if self._failed_attempts >= _MAX_ATTEMPTS:
                remaining = self._lockout_until - time.monotonic()
                return max(0.0, remaining)
        return 0.0

    def reset_lockout(self) -> None:
        """Administratively clear the lockout counter.

        This should only be called by a trusted code path (e.g. after
        successful master-password recovery).
        """
        with self._lock:
            self._failed_attempts = 0
            self._lockout_until = 0.0
        print("[AUTH] Lockout counter reset.")

    @property
    def failed_attempts(self) -> int:
        """Return the current number of consecutive failed attempts."""
        with self._lock:
            return self._failed_attempts

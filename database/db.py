"""
hid_shield.database.db
======================
SQLAlchemy engine, session factory, and database lifecycle helpers.

Design decisions
----------------
* Uses **SQLite** via the synchronous SQLAlchemy API (Alembic-compatible).
* The database path is resolved from ``config.yaml`` → ``database.path``.
  An environment variable ``HID_SHIELD_DB_PATH`` can override it at runtime.
* ``SIMULATION_MODE`` does **not** disable the database — a real SQLite file is
  always used so that the full application code path can be exercised in tests.
  A log message makes this visible during development.
* ``get_db()`` is a standard context-manager pattern; it can be used with
  ``with get_db() as session:`` anywhere in the application.
* ``init_db()`` creates all tables the first time it is called.  It is
  idempotent (``checkfirst=True`` equivalent via ``create_all``).
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

import yaml
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_HERE: Path = Path(__file__).resolve().parent          # …/hid_shield/database/
_PROJECT_ROOT: Path = _HERE.parent                     # …/hid_shield/
_CONFIG_PATH: Path = _PROJECT_ROOT / "config.yaml"


# ---------------------------------------------------------------------------
# Declarative Base (shared by all models)
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    """SQLAlchemy 2.x declarative base.

    All ORM model classes inherit from this.  Keeping it here (rather than in
    ``models.py``) prevents circular imports between ``db`` and ``models``.
    """


# ---------------------------------------------------------------------------
# Configuration Loader (private)
# ---------------------------------------------------------------------------


def _load_config() -> dict[str, Any]:
    """Read config.yaml and return it as a dict.

    Returns an empty dict if the file is missing so the module can still be
    imported in minimal test environments.
    """
    if _CONFIG_PATH.exists():
        with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    return {}


def _resolve_db_url() -> str:
    """Return the SQLite connection URL for the application database.

    Resolution order (highest priority first):

    1. ``HID_SHIELD_DB_PATH`` environment variable
    2. ``database.path`` key in ``config.yaml``
    3. Hard-coded default: ``hid_shield.db`` next to the project root

    The returned URL is always an absolute ``sqlite:///`` URL so SQLAlchemy
    does not depend on the current working directory.
    """
    # 1. Environment variable override
    env_path: str = os.getenv("HID_SHIELD_DB_PATH", "")
    if env_path:
        return f"sqlite:///{Path(env_path).resolve()}"

    # 2. config.yaml
    config: dict[str, Any] = _load_config()
    db_path_str: str = (
        config.get("database", {}).get("path", "") or "hid_shield.db"
    )

    # 3. Resolve the path relative to the project root
    db_path: Path = Path(db_path_str)
    if not db_path.is_absolute():
        db_path = (_PROJECT_ROOT / db_path).resolve()

    return f"sqlite:///{db_path}"


def _is_simulation_mode() -> bool:
    """Return True when the app is running in simulation mode."""
    env_val: str = os.getenv("HID_SHIELD_SIMULATION_MODE", "").lower()
    if env_val in ("true", "1", "yes"):
        return True
    if env_val in ("false", "0", "no"):
        return False
    config: dict[str, Any] = _load_config()
    return bool(config.get("simulation_mode", False))


def _is_db_echo_enabled() -> bool:
    """Return True when SQLAlchemy SQL echoing should be enabled."""
    env_val: str = os.getenv("HID_SHIELD_DB_ECHO", "").lower()
    if env_val in ("true", "1", "yes"):
        return True
    if env_val in ("false", "0", "no"):
        return False
    config: dict[str, Any] = _load_config()
    return bool(config.get("database", {}).get("echo", False))


# ---------------------------------------------------------------------------
# Engine Creation
# ---------------------------------------------------------------------------


def _create_engine_instance() -> Engine:
    """Instantiate and configure the SQLAlchemy synchronous engine.

    SQLite-specific pragmas are applied via an ``event`` listener so that
    foreign-key enforcement and WAL mode are active for every connection.
    """
    db_url: str = _resolve_db_url()
    simulation: bool = _is_simulation_mode()
    echo: bool = _is_db_echo_enabled()

    if simulation:
        print(
            "[DB] SIMULATION_MODE: using real SQLite DB for testing."
        )
    else:
        # VULN-011 FIX: Log only the database filename, not the full path.
        from pathlib import Path as _P
        _db_name = _P(db_url.replace("sqlite:///", "")).name if "sqlite" in db_url else "database"
        print(f"[DB] Database ready: {_db_name}")

    eng: Engine = create_engine(
        db_url,
        echo=echo,
        # Allow the same connection to be used across threads (safe for
        # SQLite because we use scoped sessions in the app).
        connect_args={"check_same_thread": False},
        # Keep a pool of connections; SQLite is single-file so the pool is
        # tiny but it still improves performance over constant re-opens.
        pool_size=5,
        max_overflow=10,
    )

    # Apply SQLite pragmas on every new connection
    @event.listens_for(eng, "connect")
    def _set_sqlite_pragmas(dbapi_conn: Any, _connection_record: Any) -> None:
        """Enable foreign-key enforcement and WAL journal mode."""
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("PRAGMA journal_mode = WAL")
        cursor.close()

    return eng


# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------

#: The global SQLAlchemy engine.  Initialised once when this module is first
#: imported.
engine: Engine = _create_engine_instance()

#: Session factory bound to the module-level engine.
SessionLocal: sessionmaker[Session] = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,   # Avoid detached-instance errors after commit
)


# ---------------------------------------------------------------------------
# Session Context Manager
# ---------------------------------------------------------------------------


@contextmanager
def get_db() -> Generator[Session, None, None]:
    """Yield a transactional SQLAlchemy ``Session``.

    Usage
    -----
    .. code-block:: python

        from database.db import get_db

        with get_db() as session:
            events = session.query(DeviceEvent).all()

    The session is automatically committed on clean exit and rolled back on
    exception.  It is always closed when the ``with`` block exits.

    Yields
    ------
    Session
        An active SQLAlchemy ``Session`` object.
    """
    session: Session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Database Initialisation
# ---------------------------------------------------------------------------


def init_db() -> None:
    """Create all ORM-mapped tables in the database (idempotent).

    This function must be called **after** all model modules have been
    imported so that the ``Base`` metadata is fully populated.

    It is safe to call multiple times — ``create_all`` skips tables that
    already exist.
    """
    # Import models here (inside the function) to avoid circular imports at
    # module level; the import has the side effect of registering the table
    # metadata on ``Base``.
    import database.models as _models  # noqa: F401 (side-effect import)

    print("[DB] Initialising database schema …")
    Base.metadata.create_all(bind=engine)

    # Verify the connection is healthy
    with engine.connect() as conn:
        result = conn.execute(text("SELECT sqlite_version()"))
        sqlite_ver: str = result.scalar() or "unknown"
        print(f"[DB] SQLite version: {sqlite_ver}")

    print("[DB] Database schema ready.")

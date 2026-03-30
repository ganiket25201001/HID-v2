"""
hid_shield.database
===================
Database package for HID Shield.

Exports the public surface used throughout the application:

* ``Base``          – SQLAlchemy declarative base (all models inherit from it)
* ``engine``        – SQLAlchemy Engine instance (created on first import)
* ``SessionLocal``  – Session factory (call to get a raw session)
* ``get_db``        – Context manager yielding a scoped ``Session``
* ``init_db``       – Creates all tables (run once at startup)

Models are importable from ``database.models`` directly.
"""

from database.db import Base, SessionLocal, engine, get_db, init_db

__all__: list[str] = [
    "Base",
    "SessionLocal",
    "engine",
    "get_db",
    "init_db",
]

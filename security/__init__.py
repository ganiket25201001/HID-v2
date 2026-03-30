"""
hid_shield.security
====================
Security package for HID Shield.

Exports the three main security subsystem classes used throughout the app:

* ``AuthManager``    – PIN / password verification and lockout logic.
* ``SessionManager`` – Singleton tracking the active user session.
* ``PolicyEngine``   – Rule-based device risk evaluator loaded from config.
"""

from security.auth_manager import AuthManager
from security.policy_engine import PolicyEngine
from security.session_manager import SessionManager

__all__: list[str] = [
    "AuthManager",
    "PolicyEngine",
    "SessionManager",
]

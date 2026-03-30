"""
hid_shield.ui
=============
User Interface package for HID Shield.

Exports:
* ``HIDShieldMainWindow`` – The primary application shell.
* Custom widgets from ``ui.widgets``.
"""

from ui.main_window import HIDShieldMainWindow

__all__: list[str] = [
    "HIDShieldMainWindow",
]

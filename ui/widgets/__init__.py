"""
hid_shield.ui.widgets
=====================
Custom PySide6 widgets for the HID Shield UI.

Exports:
* ``GlassCard``      – Container widget with glassmorphism styling.
* ``AnimatedButton`` – Button with ripple and smooth colour transitions.
"""

from ui.widgets.animated_button import AnimatedButton
from ui.widgets.glass_card import GlassCard

__all__: list[str] = [
    "AnimatedButton",
    "GlassCard",
]

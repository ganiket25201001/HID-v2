"""
hid_shield.ui.styles.theme
==========================
Theme constants and stylesheet builder.

Design
------
* Centralises the cyberpunk dark palette defined in ``config.yaml``.
* Loads fonts from ``assets/fonts/`` if available.
* ``build_stylesheet()`` merges the Python constants into the main ``base.qss``
  file so we get the best of both worlds (QSS separation + dynamic colours).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from PySide6.QtGui import QFontDatabase

# ---------------------------------------------------------------------------
# Paths and config loader
# ---------------------------------------------------------------------------

_HERE: Path = Path(__file__).resolve().parent          # ui/styles/
_PROJECT_ROOT: Path = _HERE.parent.parent              # hid_shield/
_CONFIG_PATH: Path = _PROJECT_ROOT / "config.yaml"
_ASSETS_DIR: Path = _PROJECT_ROOT / "assets"
_FONTS_DIR: Path = _ASSETS_DIR / "fonts"


def _load_config() -> dict[str, Any]:
    if _CONFIG_PATH.exists():
        with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    return {}


# ---------------------------------------------------------------------------
# Theme Constants (Cyberpunk Dark Palette)
# ---------------------------------------------------------------------------

# These defaults match the exact project specification. They are overridden
# by config.yaml → theme if present.
class Theme:
    BG_PRIMARY: str = "#0a0e17"       # Deep space background (Window)
    BG_SECONDARY: str = "#111827"     # Card / panel background
    BG_TERTIARY: str = "#1a1f2e"      # Elevated surfaces / hovers
    
    ACCENT_CYAN: str = "#00d4ff"      # Primary accent (Neon cyan)
    ACCENT_MAGENTA: str = "#ff006e"   # Danger / Block / Exit (Neon magenta)
    ACCENT_GREEN: str = "#00ff88"     # Success / Safe / Sim mode (Neon green)
    ACCENT_AMBER: str = "#ffb800"     # Warning (Amber)
    
    TEXT_PRIMARY: str = "#e2e8f0"     # Main body text
    TEXT_SECONDARY: str = "#94a3b8"   # Muted subtitles / metadata
    TEXT_DISABLED: str = "#475569"    # Disabled controls
    
    BORDER: str = "#1e293b"           # Subtle borders
    BORDER_LIGHT: str = "#334155"     # Active borders
    
    GLOW_CYAN: str = "rgba(0, 212, 255, 0.15)"
    GLOW_MAGENTA: str = "rgba(255, 0, 110, 0.15)"
    
    FONT_FAMILY: str = "Segoe UI"
    FONT_SIZE_BASE: int = 14

# Initialize from config immediately
_cfg = _load_config().get("theme", {})
Theme.BG_PRIMARY = _cfg.get("bg_primary", Theme.BG_PRIMARY)
Theme.BG_SECONDARY = _cfg.get("bg_secondary", Theme.BG_SECONDARY)
Theme.BG_TERTIARY = _cfg.get("bg_tertiary", Theme.BG_TERTIARY)
Theme.ACCENT_CYAN = _cfg.get("accent_cyan", Theme.ACCENT_CYAN)
Theme.ACCENT_MAGENTA = _cfg.get("accent_magenta", Theme.ACCENT_MAGENTA)
Theme.ACCENT_GREEN = _cfg.get("accent_green", Theme.ACCENT_GREEN)
Theme.ACCENT_AMBER = _cfg.get("accent_amber", Theme.ACCENT_AMBER)
Theme.TEXT_PRIMARY = _cfg.get("text_primary", Theme.TEXT_PRIMARY)
Theme.TEXT_SECONDARY = _cfg.get("text_secondary", Theme.TEXT_SECONDARY)
Theme.TEXT_DISABLED = _cfg.get("text_disabled", Theme.TEXT_DISABLED)
Theme.BORDER = _cfg.get("border", Theme.BORDER)
Theme.FONT_FAMILY = _cfg.get("font_family", Theme.FONT_FAMILY)


# ---------------------------------------------------------------------------
# Font Manager
# ---------------------------------------------------------------------------

def load_fonts() -> None:
    """Load all TTF/OTF fonts in the assets/fonts directory into QFontDatabase.
    
    Called once during app startup.
    """
    if not _FONTS_DIR.exists():
        return
        
    for font_file in _FONTS_DIR.iterdir():
        if font_file.suffix.lower() in (".ttf", ".otf"):
            font_id = QFontDatabase.addApplicationFont(str(font_file))
            if font_id != -1:
                families = QFontDatabase.applicationFontFamilies(font_id)
                if families:
                    # Automatically upgrade the base font if "Inter" or "Roboto" is found
                    if "Inter" in families[0] or "Roboto" in families[0]:
                        Theme.FONT_FAMILY = families[0]


# ---------------------------------------------------------------------------
# Stylesheet Builder
# ---------------------------------------------------------------------------

def build_stylesheet() -> str:
    """Read base.qss and replace all `{{VAR}}` placeholders with Theme constants.
    
    Returns
    -------
    str
        The fully compiled QSS string ready for ``app.setStyleSheet()``.
    """
    qss_path: Path = _HERE / "base.qss"
    
    # Fallback minimal stylesheet if base.qss is missing
    if not qss_path.exists():
        return f"QMainWindow {{ background-color: {Theme.BG_PRIMARY}; }}"
        
    with open(qss_path, "r", encoding="utf-8") as fh:
        raw_qss = fh.read()
        
    # Replace tokens
    replacements = {
        "{{BG_PRIMARY}}": Theme.BG_PRIMARY,
        "{{BG_SECONDARY}}": Theme.BG_SECONDARY,
        "{{BG_TERTIARY}}": Theme.BG_TERTIARY,
        "{{ACCENT_CYAN}}": Theme.ACCENT_CYAN,
        "{{ACCENT_MAGENTA}}": Theme.ACCENT_MAGENTA,
        "{{ACCENT_GREEN}}": Theme.ACCENT_GREEN,
        "{{ACCENT_AMBER}}": Theme.ACCENT_AMBER,
        "{{TEXT_PRIMARY}}": Theme.TEXT_PRIMARY,
        "{{TEXT_SECONDARY}}": Theme.TEXT_SECONDARY,
        "{{TEXT_DISABLED}}": Theme.TEXT_DISABLED,
        "{{BORDER}}": Theme.BORDER,
        "{{BORDER_LIGHT}}": Theme.BORDER_LIGHT,
        "{{FONT_FAMILY}}": f'"{Theme.FONT_FAMILY}", "Segoe UI", sans-serif',
    }
    
    compiled = raw_qss
    for token, value in replacements.items():
        compiled = compiled.replace(token, str(value))
        
    return compiled

# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

project_dir = Path(SPECPATH).resolve()
assets_dir = project_dir / "assets"
icon_path = project_dir / "assets" / "icon.ico"

# Bundle assets (including fonts) and required package data.
datas = []
if assets_dir.exists():
    datas.append((str(assets_dir), "assets"))

datas += collect_data_files("reportlab")
datas += collect_data_files("PySide6")

hiddenimports = [
    # Core runtime
    "yaml",
    "dotenv",
    "wmi",
    "win32api",
    "win32con",
    "win32com",
    "win32com.client",
    "pythoncom",
    "pywintypes",
    "bcrypt",
    "bcrypt._bcrypt",
    # Report generation
    "reportlab",
    "reportlab.lib.colors",
    "reportlab.lib.pagesizes",
    "reportlab.lib.styles",
    "reportlab.lib.units",
    "reportlab.platypus",
    # Qt modules used across UI
    "PySide6.QtCore",
    "PySide6.QtGui",
    "PySide6.QtWidgets",
    "PySide6.QtPrintSupport",
    "PySide6.QtSvg",
    "PySide6.QtXml",
]

# Collect dynamic submodules for robust production packaging.
hiddenimports += collect_submodules("sqlalchemy")
hiddenimports += collect_submodules("reportlab")
hiddenimports += collect_submodules("PySide6")


analysis = Analysis(
    ["main.py"],
    pathex=[str(project_dir)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(analysis.pure, analysis.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.zipfiles,
    analysis.datas,
    [],
    name="HID Shield",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=(str(icon_path) if icon_path.exists() else None),
    uac_admin=True,
)

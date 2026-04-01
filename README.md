# HID Shield

HID Shield is a Windows desktop security application built with PySide6 for real-time USB/HID monitoring, threat analysis, and operator-controlled policy enforcement.

The project combines:
- Live USB event monitoring
- File and device threat scoring with a LightGBM-based classifier
- Authentication and session controls
- Risk-aware decision workflows
- Persistent SQLite event history and PDF reporting

## Features

- Real USB mode with WMI-backed event monitoring
- Hybrid ML pipeline: LightGBM probability model + deterministic safety rules
- Device-level escalation logic from file-level findings
- Policy recommendations integrated into classification output
- Analyst UI for dashboard, live detection, threat analysis, logs, and settings
- Report generation via PDF export

## Requirements

- Windows 10 or Windows 11
- Python 3.11+
- Administrator privileges recommended for full real-device enforcement

## Quick Start

```bash
pip install -r requirements.txt
python main.py
```

## Default Access

Bootstrap credentials are seeded for first-run initialization.

- Username: `admin`
- Password: `admin`
- Security key: `admin`

Change these credentials immediately before real deployment.

## ML Pipeline

Runtime classifier:
- `ml/lightgbm_classifier.py`
- Model artifact: `ml/models/hid_shield_model.txt`

Re-train model locally:

```bash
python ml/train_model.py
```

## Configuration

Primary runtime config is `config.yaml`.

Key sections:
- `app`
- `policy`
- `database`
- `logging`
- `theme`

Production default is real USB mode (`simulation_mode: false`).

## Build

```bash
pyinstaller build.spec
```

Output executable:
- `dist/HID Shield.exe`

## Repository Notes

- Build artifacts and local runtime files are excluded by `.gitignore`.
- Do not commit `dist/`, `build/`, local DB files, or virtual environments.

## License

Add a `LICENSE` file before publishing publicly.

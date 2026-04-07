# HID Shield

HID Shield is a Windows desktop USB/HID security platform built with PySide6. It monitors device insertion in real time, scans mounted content in a sandbox, applies hybrid ML + heuristic risk analysis, and enforces operator-driven access policies.

## What It Does

- Detects USB/HID insert and removal events through WMI.
- Scans files from attached media with entropy, PE header, and suspicious import checks.
- Runs an ensemble threat pipeline (LightGBM + RandomForest).
- Computes device-level risk from file-level outcomes.
- Applies policy actions such as allow safe only, manage suspicious files, or block/eject.
- Stores audit history in SQLite and supports report export.

## Runtime Architecture

1. main.py loads config and environment, initializes DB, and starts the Qt app.
2. core/usb_monitor.py emits insertion/removal events via core/event_bus.py.
3. sandbox/file_scanner.py performs staged file analysis in isolated sandbox folders.
4. ml/classifier.py classifies threats and produces device-level conclusions.
5. security/access_controller.py and security/policy_engine.py determine enforcement.
6. ui/main_window.py and related screens render detection, analysis, logs, and decisions.

## Key Modules

- core/: USB monitoring, device abstraction, event signaling, port lockdown logic.
- sandbox/: file discovery, entropy analysis, PE analysis, HID behavior analysis.
- ml/: feature extraction, LightGBM classifier, RandomForest classifier, training script.
- security/: authentication/session handling, policy engine, whitelist and access control.
- database/: SQLAlchemy models, engine setup, repository layer.
- ui/: dashboard, USB detection, threat analysis, decision panel, logs, settings.
- reports/: PDF export.

## Requirements

- Windows 10 or Windows 11
- Python 3.11+
- Administrator privileges recommended for full USB enforcement behavior

## Quick Start

```bash
pip install -r requirements.txt
python main.py
```

## Makefile Commands

```bash
make install-deps
make run
make test
make build-exe
make clean
```

- install-deps: installs dependencies from requirements.txt
- run: launches the desktop app
- test: runs pytest in quiet mode
- build-exe: builds with PyInstaller using build.spec
- clean: removes build, cache, and common artifact files

## Build Executable

```bash
pyinstaller build.spec
```

Expected output:
- dist/HID Shield.exe

## Configuration

Runtime configuration lives in config.yaml.

Important sections:
- app: metadata and window sizing
- policy: entropy and keystroke thresholds, default action, confidence thresholds
- database: sqlite path
- logging: file path and retention settings
- theme: UI colors and typography

Note: main.py forces HID_SHIELD_SIMULATION_MODE=false at startup for live mode behavior.

## ML Pipeline

- LightGBM model artifact: ml/models/hid_shield_model.txt
- RandomForest model artifact: ml/models/rf_threat_model.joblib
- Ensemble merge logic is implemented in ml/classifier.py

Retrain model artifacts:

```bash
python ml/train_model.py
```

## Testing

Test suite is in tests/ and includes:
- classifier and ensemble behavior
- entropy analyzer
- PE analyzer
- USB monitor flows
- integration scenarios

Run all tests:

```bash
make test
```

## First Run Credentials

Bootstrap credentials used by the login flow:
- Username: admin
- Password: admin
- Security key: admin

Change these credentials immediately in production deployments.

## Packaging and Installer Assets

- PyInstaller spec: build.spec
- Inno Setup script: installer/HIDShield.iss
- Installer automation scripts: installer/Build-Installer.ps1 and installer/Install-HIDShield.ps1

## License

Project is currently marked as Proprietary in pyproject.toml.

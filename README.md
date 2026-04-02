# HID Shield

HID Shield is a production-focused Windows desktop security platform built with PySide6 for USB/HID monitoring, file threat analysis, operator approval workflows, and controlled access enforcement.

## Core Capabilities

- Real-time USB detection and event lifecycle tracking
- Hybrid file risk inference with LightGBM plus deterministic rule safeguards
- Device-level risk escalation from file-level outcomes
- Approval-gated access decisions before device exposure
- Security-focused dashboard, threat analysis, and logs/reporting views
- SQLite-backed event history and PDF report export

## Requirements

- Windows 10 or Windows 11
- Python 3.11+
- Administrator privileges recommended for full policy enforcement

## Installation

```bash
pip install -r requirements.txt
```

## Run (Direct)

```bash
python main.py
```

## Makefile Usage

The project includes a production-ready Makefile with standard development and packaging commands.

```bash
make install-deps
make run
make test
make build-exe
make clean
```

Available targets:
- `install-deps`: install all Python dependencies from `requirements.txt`
- `run`: start HID Shield desktop application
- `test`: execute automated tests with pytest
- `build-exe`: build distributable executable using `build.spec`
- `clean`: remove build and cache artifacts

## Build Output

```bash
pyinstaller build.spec
```

Generated executable:
- `dist/HID Shield.exe`

## Default Access (First Run)

Bootstrap credentials are seeded for first initialization:
- Username: `admin`
- Password: `admin`
- Security key: `admin`

Change these credentials immediately for production deployment.

## Configuration

Primary runtime configuration is stored in `config.yaml`.

Key sections:
- `app`
- `policy`
- `database`
- `logging`
- `theme`

## ML Model

Runtime classifier module:
- `ml/lightgbm_classifier.py`

Expected model artifact:
- `ml/models/hid_shield_model.txt`

Train or refresh the model locally:

```bash
python ml/train_model.py
```

## Repository Hygiene

The repository excludes local and generated artifacts via `.gitignore`, including:
- `build/`, `dist/`
- local database/log files
- virtual environments and editor caches

## License

Add a `LICENSE` file before publishing publicly.

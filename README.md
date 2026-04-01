# HID Shield - Intelligent USB Security System

HID Shield is a Windows-focused PySide6 desktop application for monitoring, analyzing, and controlling USB and HID device activity.

It is designed as an analyst workflow tool that combines:
- Live USB detection and eventing
- Risk scoring and policy enforcement
- Threat analysis screens and operator decisions
- Authentication and session control
- Event history and PDF incident reporting

## Table of Contents
- System Requirements
- Quick Start
- First-Run Authentication
- How the App Works
- Architecture Overview
- Configuration
- Project Structure
- Packaging as EXE
- Troubleshooting
- Development Notes
- Security Notes
- License

## System Requirements

- OS: Windows 10 or Windows 11
- Python: 3.11+ (3.14 tested in this repository)
- RAM: 8 GB minimum
- Disk: at least 1 GB free for runtime data and build outputs
- Optional: Administrator rights for device-control paths

## Quick Start

1. Clone the repository.
2. Open a terminal in the `hid_shield` root.
3. Install dependencies.
4. Run the app.

~~~bash
pip install -r requirements.txt
python main.py
~~~

## First-Run Authentication

On first run, the app seeds default bootstrap credentials in local auth storage.

Default bootstrap values:
- Username: `admin`
- Password: `admin`
- Security key: `admin`

Important:
- Change these values immediately for any real environment.
- Do not use defaults in production or shared environments.

## How the App Works

Typical operator flow:

1. Launch app and sign in.
2. USB insertion event appears in Live USB screen.
3. Scan pipeline runs (simulation-safe by default flow).
4. Threat Analysis presents risk and file details.
5. Operator applies decision/policy.
6. Events and alerts are written to SQLite.
7. Reports can be exported from Logs and Reports.

Core screens:
- Dashboard: high-level posture and recent activity
- Live USB: detection, progress, device intelligence
- Threat Analysis: file-level and device-level risk summary
- Logs and Reports: history, filtering, PDF export
- Settings: policy, account, notifications, storage

## Architecture Overview

~~~text
UI Layer (PySide6)
  -> Event Bus (Qt signals)
     -> Core monitoring and policy modules
     -> ML classification pipeline (deterministic mock backend)
     -> Database repositories (SQLite via SQLAlchemy)
     -> Reporting/export services
~~~

Major module responsibilities:
- `core/`: USB monitoring, device info, event bus, optional lockdown helpers
- `security/`: auth, session, policy engine, access control, whitelist
- `ml/`: feature extraction and classifier orchestration
- `database/`: models, DB bootstrap, repositories
- `ui/`: screens, styles, custom widgets
- `reports/`: PDF export pipeline

## Configuration

Primary configuration file: `config.yaml`

Key groups:
- `app`: app metadata, default window sizing
- `simulation_mode`: simulation-safe behavior toggle
- `policy`: default action, entropy threshold, keystroke limits
- `database`: database path and SQL echo
- `logging`: level, rotation, retention
- `theme`: colors, typography, visual tokens

Example run-mode switch:
- Set `simulation_mode: false` in `config.yaml` for production-oriented behavior.

## Project Structure

Top-level highlights:
- `main.py`: application entry point
- `build.spec`: PyInstaller build spec
- `run_as_admin.bat`: elevated EXE launcher helper
- `requirements.txt`: pinned dependencies
- `config.yaml`: runtime settings

UI-related paths:
- `ui/main_window.py`: app shell and navigation
- `ui/styles/base.qss`: global stylesheet
- `ui/usb_detection.py`: live detection screen
- `ui/threat_analysis.py`: post-scan analysis
- `ui/logs_screen.py`: logs and PDF operations

## Packaging as EXE

Build command:

~~~bash
pyinstaller build.spec
~~~

Expected output:
- `dist/HID Shield.exe`

Run elevated:
- Double-click `run_as_admin.bat`
- Or right-click `dist/HID Shield.exe` and choose Run as administrator

Important GitHub note:
- Do not commit `dist/` or `build/` artifacts to a normal GitHub repository because large EXE/PKG files can exceed GitHub limits.
- Publish release binaries via GitHub Releases or Git LFS.

## Troubleshooting

### App starts but UI looks broken
- Confirm `assets/` exists and is available in project root.
- Confirm stylesheet loads from `ui/styles/base.qss`.

### EXE build fails on missing Windows modules
- Ensure dependencies are installed:

~~~bash
pip install -r requirements.txt
pip install pywin32 pyinstaller
~~~

### Push to GitHub rejected for large files
- Remove build artifacts from commit history.
- Keep only source files in branch commits.
- Rebuild locally as needed instead of committing binaries.

## Development Notes

- Default local DB file: `hid_shield.db`
- Runtime may generate `hid_shield.db-wal` and `hid_shield.db-shm`
- Python cache folders and build outputs should stay out of source commits

Recommended local smoke test:
1. Run `python main.py`
2. Login successfully
3. Trigger or simulate USB detection
4. Verify Threat Analysis data rendering
5. Export a PDF report from Logs and Reports

## Security Notes

- Bootstrap credentials are for initialization convenience only.
- Replace defaults immediately and treat any generated local auth data as sensitive.
- Review policy defaults in `config.yaml` before real deployment.
- Run with least privilege where possible; use elevation only for required enforcement operations.

## License

This repository is currently treated as proprietary/internal unless a formal `LICENSE` file is added.

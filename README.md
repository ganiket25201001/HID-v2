# HID Shield - Intelligent USB Security System

HID Shield is a PySide6 desktop application for monitoring, analyzing, and controlling USB/HID device activity with a modern analyst workflow.

The project combines:
- Live USB detection
- Sandbox file analysis
- Deterministic ML threat classification
- Policy-based access control
- Operator decision workflow
- Forensic logs and PDF reporting

## System Requirements

- OS: Windows 10 or Windows 11 (recommended)
- Python: 3.11+
- RAM: 8 GB minimum, 16 GB recommended
- Disk: 1 GB free for app, logs, and SQLite data
- Optional: Administrator privileges for future real USB enforcement modes

## Installation

1. Clone or download the project.
2. Open a terminal in the hid_shield folder.
3. Create and activate a virtual environment.
4. Install dependencies:

~~~bash
pip install -r requirements.txt
~~~

## First-Run Setup

On first launch, configure authentication:
- Create a 6-digit operator PIN.
- Optionally configure a master recovery password.
- In simulation mode, a development PIN may be pre-seeded for convenience.

Security recommendation:
- Replace development credentials immediately for non-demo use.

## Run the Application

~~~bash
python main.py
~~~

## Architecture Overview

~~~text
+---------------------------- HID SHIELD APPLICATION ----------------------------+
|                                                                                |
|   +---------------- UI Layer ----------------+                                 |
|   | Dashboard | USB Detection | Threat View |                                 |
|   | Decision Panel | Logs/Reports | Settings|                                 |
|   +-----------------------+------------------+                                 |
|                           |                                                    |
|                           v                                                    |
|                    +-------------+                                             |
|                    |  Event Bus  |  (Qt signals for decoupled modules)         |
|                    +------+------+                                             |
|                           |                                                    |
|     +---------------------+----------------------+                             |
|     |                     |                      |                             |
|     v                     v                      v                             |
| +--------+         +-------------+        +------------------+                 |
| | USB    |         | Sandbox +   |        | ML Classifier +  |                 |
| |Monitor | ------> | FileScanner | -----> | Feature Extractor|                 |
| +--------+         +-------------+        +------------------+                 |
|                                 |                   |                          |
|                                 v                   v                          |
|                          +-----------------------------------+                  |
|                          | Policy Engine + Access Controller |                  |
|                          +----------------+------------------+                  |
|                                           |                                     |
|                                           v                                     |
|                             +-----------------------------+                     |
|                             | SQLite (events/scans/alerts)|                     |
|                             +-----------------------------+                     |
+--------------------------------------------------------------------------------+
~~~

## Feature Summary

### Core Security
- Live USB insert/remove monitoring with simulation-safe operation.
- Device risk assessment with policy thresholds.
- File sandboxing and deep scan pipeline (entropy, PE checks, heuristics).
- Deterministic ML threat scoring for file and device-level classification.

### Analyst Workflow
- Threat Analysis screen with file tree, details, and risk visuals.
- Decision Panel with action modes:
  - Allow Safe Only
  - Manage Suspicious
  - Block and Eject
  - Grant Full Access
- Whitelist management by hardware serial.

### Operations and Reporting
- Event logs and historical analysis views.
- PDF export for incident reports.
- Settings screen for runtime policy/account/logging controls.

## Settings and Configuration

Main settings source:
- config.yaml

Configurable areas include:
- Policy thresholds (entropy, keystroke rate, default action)
- Session timeout and account controls
- Notification behavior
- Log level, rotation, retention

## Known Limitations

- Current default flow is simulation-first for safe development.
- Real USB mount/eject and low-level control actions are intentionally not executed in simulation mode.
- Some hard enforcement paths require admin rights and additional OS-specific integration.
- ML engine currently uses a deterministic mock classifier for demo stability.

## Switching from Mock AI to a Real Model

Current state:
- Deterministic fallback classifier under ml/mock_classifier.py.
- Public classification API under ml/classifier.py.

To integrate a real model:
1. Implement a production classifier backend (for example, ONNX, scikit-learn, or PyTorch inference).
2. Keep the same feature vector contract from ml/feature_extractor.py.
3. Add model loading, inference, and confidence outputs in the classifier backend.
4. Wire backend selection in ml/classifier.py based on configuration flag.
5. Keep mock mode available for deterministic CI/demo paths.

Suggested config flag example:
- ml.backend: mock | onnx | sklearn

## Screenshots (Placeholders)

Add screenshots to the repository under:
- assets/screenshots/

Suggested files:
- assets/screenshots/dashboard.png
- assets/screenshots/live_usb_detection.png
- assets/screenshots/threat_analysis.png
- assets/screenshots/decision_panel.png
- assets/screenshots/logs_reports.png
- assets/screenshots/settings_screen.png

README placement guidance:
- Insert each screenshot under its corresponding feature section.
- Keep image widths consistent for a premium presentation.

## Testing Notes

Recommended smoke flow:
1. Start app with python main.py.
2. Verify simulated USB event appears.
3. Confirm scan, classification, and decision workflow.
4. Export a PDF from Logs screen.
5. Save settings from Settings screen and confirm no runtime errors.

## License

This repository is currently distributed as proprietary/internal software unless replaced by a formal open-source license file.

If you intend public release, add a dedicated LICENSE file and update this section accordingly.

## Packaging for Production (Single EXE)

Build target:
- Windows single-file executable: HID Shield.exe
- UAC elevation requested automatically on launch
- GUI mode (no console window)

### 1) Install packager

~~~bash
pip install pyinstaller
~~~

### 2) Build executable

~~~bash
pyinstaller build.spec
~~~

Expected artifact:
- dist/HID Shield.exe

### 3) Run as Administrator

Option A:
- Double-click run_as_admin.bat

Option B:
- Right-click dist/HID Shield.exe and choose Run as administrator

### 4) Included runtime assets

The build.spec bundles:
- assets/ (including assets/fonts/)
- PySide6 runtime modules
- reportlab data files
- SQLAlchemy/reporting submodules and Windows USB dependencies (WMI/pywin32 hidden imports)

### 5) Final pendrive verification flow

1. Launch HID Shield.exe as Administrator.
2. Login with admin / admin.
3. Insert real pendrive.
4. Confirm Live USB detection, Dashboard live updates, and Threat Analysis hierarchy.
5. Verify Logs tab actions:
  - Apply Date Filter
  - Clear Old Logs
  - Export PDF
6. Enter security key "admin" and confirm immediate unlock action.

If any module import is missing in the packaged build, add it to hiddenimports in build.spec and rebuild.

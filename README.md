# HID Shield

HID Shield is a Windows desktop USB/HID security platform built with PySide6. It monitors device insertion in real time, isolates USB storage from host drive-letter access, analyzes staged content through Windows Sandbox, and enforces operator-driven access policies.

## What It Does

- Detects USB/HID insert and removal events through WMI.
- Detaches removable drive letters immediately on insertion to reduce host-level exposure.
- Stages USB files into a controlled host path and runs analysis inside Windows Sandbox.
- Scans files inside Windows Sandbox with fail-closed blocking when sandbox output is unavailable.
- Runs an ensemble threat pipeline (LightGBM + RandomForest).
- Computes device-level risk from file-level outcomes.
- Applies policy actions such as allow safe only, manage suspicious files, or block/eject.
- Stores audit history in SQLite and supports report export.

## Runtime Architecture

1. main.py loads config and environment, initializes DB, and starts the Qt app.
2. core/usb_monitor.py isolates removable mount letters and emits insertion/removal events via core/event_bus.py.
3. sandbox/file_scanner.py detaches drive letters, stages content, and prefers Windows Sandbox analysis.
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

For strict isolation mode, run these once from elevated PowerShell first:

```powershell
powershell -ExecutionPolicy Bypass -File .\installer\Enable-WindowsSandbox.ps1
powershell -ExecutionPolicy Bypass -File .\installer\Apply-USBIsolationPolicy.ps1
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
./.venv/Scripts/python.exe -m PyInstaller --clean --noconfirm build.spec
```

Expected output:

- dist/HID Shield.exe

## Configuration

Runtime configuration lives in config.yaml.

Important sections:

- app: metadata and window sizing
- policy: entropy and keystroke thresholds, default action, confidence thresholds
- windows_sandbox: sandbox-first scan settings, host staging root, timeout, mount isolation toggle, close behavior
- database: sqlite path
- logging: file path and retention settings
- theme: UI colors and typography

Note: main.py forces HID_SHIELD_SIMULATION_MODE=false at startup for live mode behavior.

## Updated Isolation Design

HID Shield now follows a sandbox-first isolation pipeline:

1. USB insertion is detected via WMI.
2. The scanner isolates the removable drive by detaching its drive letter (`mountvol X: /D`).
3. Files are staged into a restricted host folder under `C:/ProgramData/HIDShield/sandbox_bridge`.
4. Windows Sandbox is launched with networking and clipboard redirection disabled.
5. A startup PowerShell script runs analysis inside the sandbox and emits JSON output.
6. HID Shield ingests sandbox results, computes final risk, and applies access decisions.

If strict mode is enabled (`windows_sandbox.require_windows_sandbox: true`), HID Shield blocks the device when sandbox output is unavailable. You can switch to permissive mode by setting this value to `false`.

## Windows Sandbox Setup Guide

1. Enable Windows Sandbox feature (admin PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File .\installer\Enable-WindowsSandbox.ps1
```

1. Reboot if requested by the script.

1. Apply host hardening policy:

```powershell
powershell -ExecutionPolicy Bypass -File .\installer\Apply-USBIsolationPolicy.ps1
```

1. Verify runtime config in `config.yaml`:

- `windows_sandbox.enabled: true`
- `windows_sandbox.isolate_drive_letter_on_insert: true`
- `windows_sandbox.require_windows_sandbox: true`

1. Start HID Shield:

```powershell
python main.py
```

## USB Data Flow Into Sandbox (Secure Relay)

Windows Sandbox does not support direct generic USB passthrough. HID Shield uses a secure relay model:

1. Host process reads USB content only through a privileged service context.
2. USB drive letter is detached so users cannot browse mounted content directly.
3. Files are copied into controlled staging folders mapped into Sandbox.
4. Sandbox script analyzes mapped input and writes only JSON results back to host output mapping.
5. Staged artifacts are deleted unless `windows_sandbox.keep_artifacts` is enabled.

Reference `.wsb` template: `installer/HIDShield-USB-Analysis.wsb`.

## Automation and Near-Silent Execution

Automation in this build is implemented by `sandbox/windows_sandbox_bridge.py`:

- Generates per-session script and `.wsb` config.
- Launches `WindowsSandbox.exe` automatically.
- Waits for result JSON with timeout control.
- Instructs sandbox VM to shut down after writing results.

Notes:

- Windows Sandbox always opens a visible window; true fully hidden mode is not supported by Microsoft.
- This implementation is near-silent (auto-start + auto-close) but not truly headless.

## Security Considerations and Limitations

- Direct USB passthrough into Windows Sandbox is not available for generic storage devices.
- A host-side staging path is required as a relay boundary.
- Drive-letter detachment reduces user-space exposure but does not replace hardware USB firewalls.
- For strongest assurance, run HID Shield with Administrator rights and enforce endpoint GPO baselines.

## Assumptions

- HID Shield runs with administrative privileges in production.
- Windows Sandbox feature is enabled on supported Windows 10/11 editions.
- Microsoft Defender is available in the sandbox guest for inline malware scan invocation.
- Operators accept near-silent sandbox windows rather than fully invisible execution.

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

## AI Agent (Gemma 4)

HID Shield includes an optional Gen AI Agent for rich threat explanations. This feature requires **Ollama** to be installed and running on the host system.

### Setup Instructions:

1. **Install Ollama**: Download and install from [ollama.com](https://ollama.com).
2. **Pull Gemma 4 Model**:
   ```bash
   ollama pull gemma4:e2b
   ```
3. **Enable in Settings**: Open HID Shield, navigate to `Settings` -> `AI Integration`, and toggle `Enable AI Explanations`.

The agent runs asynchronously after the ML classification is complete, providing natural language insights into why a specific risk score was assigned.

## Packaging and Installer Assets

- PyInstaller spec: build.spec
- Inno Setup script: installer/HIDShield.iss
- Installer automation scripts: installer/Build-Installer.ps1 and installer/Install-HIDShield.ps1

## License

Project is currently marked as Proprietary in pyproject.toml.

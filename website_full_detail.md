# HID Shield v1.0.0 — Comprehensive Security Audit & Reference Document

> **Audit Date:** 2026-04-15  
> **Auditor:** Automated Security Engineering Pipeline  
> **Classification:** CONFIDENTIAL — Internal Use Only  

---

## Table of Contents

1. [Project Structure](#1-project-structure)
2. [Module Analysis](#2-module-analysis)
3. [Dependency Inventory](#3-dependency-inventory)
4. [Security Posture Assessment](#4-security-posture-assessment)
5. [Vulnerability Catalogue](#5-vulnerability-catalogue)
6. [Remediation Priority Matrix](#6-remediation-priority-matrix)

---

## 1. Project Structure

```
HID-v2/
├── main.py                          # Application entry point
├── config.yaml                      # Runtime configuration (thresholds, AI, sandbox)
├── .env.example                     # Environment variable template
├── requirements.txt                 # Python dependencies
├── pyproject.toml                   # Project metadata & build config
├── Makefile                         # Build automation commands
├── build.spec                       # PyInstaller packaging spec
├── run_as_admin.bat                 # Windows UAC elevation launcher
├── README.md                        # Project documentation
├── .gitignore                       # Git exclusion rules
│
├── core/                            # Core runtime subsystems
│   ├── __init__.py                  # Package init & exports
│   ├── usb_monitor.py               # Real-time USB device event watcher (WMI)
│   ├── device_info.py               # USB device metadata normalization
│   ├── event_bus.py                 # Global Qt signal event bus (singleton)
│   └── port_lockdown.py             # OS-level USB port blocking (registry/devcon/WMI)
│
├── security/                        # Authentication & policy enforcement
│   ├── __init__.py                  # Package init
│   ├── access_controller.py         # Final scan→decision orchestrator
│   ├── auth_manager.py              # PIN/password authentication (bcrypt)
│   ├── policy_engine.py             # Rule-based risk evaluator
│   ├── session_manager.py           # Session lifecycle (singleton, timeout)
│   └── whitelist_manager.py         # Serial-number device whitelist
│
├── sandbox/                         # File analysis & sandboxing
│   ├── __init__.py                  # Lazy-import package init
│   ├── file_scanner.py              # Multi-stage async scan pipeline
│   ├── entropy_analyzer.py          # Shannon entropy computation
│   ├── pe_analyzer.py               # PE header & import analysis
│   ├── hid_descriptor_analyzer.py   # HID behavioral anomaly detection
│   ├── sandbox_manager.py           # Per-scan sandbox folder lifecycle
│   └── windows_sandbox_bridge.py    # Windows Sandbox isolated analysis
│
├── ml/                              # Machine learning threat classification
│   ├── __init__.py                  # Package init & exports
│   ├── classifier.py                # Ensemble classifier (LightGBM + RF)
│   ├── feature_extractor.py         # 10-feature vector extraction
│   ├── lightgbm_classifier.py       # LightGBM binary threat scoring
│   ├── random_forest_classifier.py  # RandomForest 3-class classifier
│   ├── train_model.py               # Offline model training utility
│   └── models/                      # Persisted model files
│       ├── hid_shield_model.txt     # LightGBM model artifact
│       └── rf_threat_model.joblib   # RandomForest model artifact
│
├── database/                        # Persistence layer
│   ├── __init__.py                  # Public API exports
│   ├── db.py                        # SQLAlchemy engine, session factory, init
│   ├── models.py                    # ORM models (DeviceEvent, FileScan, etc.)
│   └── repository.py               # CRUD helper classes
│
├── ai_agent/                        # Advisory AI integration (Ollama)
│   ├── __init__.py                  # Package stub
│   ├── config.py                    # AI settings loader/saver
│   ├── explanation_agent.py         # Async QThread advisory worker
│   ├── advisory_service.py          # Ollama text/vision model service
│   ├── file_analysis.py             # AI-powered file forensics
│   └── retrieval.py                 # Embedding-based case retrieval
│
├── ui/                              # PySide6 desktop GUI
│   ├── __init__.py                  # Package init
│   ├── main_window.py               # Main window shell & navigation
│   ├── dashboard.py                 # Real-time threat dashboard
│   ├── decision_panel.py            # USB action decision panel
│   ├── login_dialog.py              # Authentication dialog
│   ├── logs_screen.py               # Event log viewer
│   ├── settings_screen.py           # Configuration editor
│   ├── threat_analysis.py           # Threat analysis detail view
│   ├── usb_detection.py             # USB detection status panel
│   ├── styles/                      # QSS theme system
│   └── widgets/                     # Reusable UI components
│
├── tests/                           # Test suite
│   ├── __init__.py
│   ├── test_classifier.py           # ML classifier tests
│   ├── test_entropy_analyzer.py     # Entropy analysis tests
│   ├── test_pe_analyzer.py          # PE header analysis tests
│   ├── test_integration.py          # Integration tests
│   ├── test_usb_monitor.py          # USB monitor tests
│   ├── test_ai_advisory_service.py  # AI service tests
│   ├── test_ai_file_analysis.py     # AI file analysis tests
│   ├── test_port_lockdown_isolation.py  # Port lockdown tests
│   └── test_windows_sandbox_bridge.py   # Sandbox bridge tests
│
├── installer/                       # NSIS/deployment packaging
├── reports/                         # Generated PDF/HTML reports
└── assets/                          # Icons, images, branding
```

---

## 2. Module Analysis

### 2.1 `main.py` — Application Entry Point
- **Purpose:** Bootstrap PySide6 app, init DB, start USB monitor thread, wire event bus.
- **Security Role:** Forces `SIMULATION_MODE=false` for production; checks admin privileges.
- **Issues Found:** Private attribute injection (`window._access_controller`); no startup integrity check.

### 2.2 `core/usb_monitor.py` — USB Event Watcher
- **Purpose:** WMI-based background thread detecting USB insertion/removal on Windows.
- **Security Role:** First line of defense — detects new USB devices and triggers scan pipeline.
- **Issues Found:** Uses `ctypes.windll.user32` for Explorer window closing (unsafe FFI); no input validation on WMI payloads; `_close_explorer_for_drive_async` uses `PostMessageW` with hardcoded WM_CLOSE.

### 2.3 `core/port_lockdown.py` — USB Port Control
- **Purpose:** OS-level device disable/enable via DevCon CLI, WMI, and Registry USBSTOR toggle.
- **Security Role:** Enforcement layer — blocks/unblocks USB devices at the OS level.
- **Issues Found:** `subprocess.run()` with device ID in shell arguments (command injection risk); no input sanitization on `device_id`; `_devcon_disable` passes user-controllable strings to subprocess.

### 2.4 `core/event_bus.py` — Global Event Bus
- **Purpose:** Singleton Qt signal hub for inter-component communication.
- **Security Role:** Message broker — no authentication on signal emitters.
- **Issues Found:** Any connected component can emit arbitrary signals (no authorization).

### 2.5 `security/auth_manager.py` — Authentication
- **Purpose:** PIN and password management with bcrypt hashing and lockout policy.
- **Security Role:** Primary authentication gate.
- **Issues Found:**
  - **CRITICAL:** Default credentials hardcoded (`admin/admin/admin` for username/password/security key).
  - **HIGH:** PIN `123456` pre-seeded in simulation mode — simulation flag defaults to `True` in `_is_simulation_mode()` fallback.
  - **MEDIUM:** Lockout counter is in-memory only; process restart clears it.
  - **MEDIUM:** `_DEFAULT_ADMIN_PASSWORD = "admin"` and `_DEFAULT_SECURITY_KEY = "admin"` in source code.

### 2.6 `security/session_manager.py` — Session Lifecycle
- **Purpose:** Singleton session state with timeout and mode transitions.
- **Security Role:** Privilege gating (GUEST → USER → ADMIN).
- **Issues Found:**
  - **HIGH:** `check_timeout()` has a variable scoping bug — `elapsed_minutes` used outside `with self._lock:` block (line 236), creating a race condition.
  - **MEDIUM:** No CSRF-like protection on mode transitions; any code path can call `start_session(UserMode.ADMIN)`.

### 2.7 `security/policy_engine.py` — Risk Evaluator
- **Purpose:** Rule-based device risk classification with configurable thresholds.
- **Security Role:** Risk score computation driving block/allow decisions.
- **Issues Found:** `entropy_threshold` defaults to `0.65` which may be too permissive; `config.yaml` sets it to `0.9` which is near-critical threshold.

### 2.8 `security/access_controller.py` — Enforcement Orchestrator
- **Purpose:** Connects scan results → ML classification → policy engine → OS enforcement.
- **Security Role:** Final decision maker for device access.
- **Issues Found:** `unlock_all_ports_with_key()` accepts any string as security key — combined with default key `"admin"` this is a full bypass.

### 2.9 `security/whitelist_manager.py` — Device Whitelist
- **Purpose:** Serial-number-based device trust list persisted via system alerts.
- **Security Role:** Trust bypass for known-good devices.
- **Issues Found:** No authorization check on `add_device()`; any code path can whitelist a device serial.

### 2.10 `sandbox/file_scanner.py` — File Scan Pipeline
- **Purpose:** Multi-stage analysis (entropy, PE, heuristics, Windows Sandbox).
- **Security Role:** Core threat detection engine.
- **Issues Found:** `hashlib.md5()` used (weak hash, marked `noqa: S324`); reads entire file into memory (`file_path.read_bytes()`) with no size limit — memory exhaustion risk on large files.

### 2.11 `sandbox/entropy_analyzer.py` — Shannon Entropy
- **Purpose:** Byte-frequency entropy computation with classification.
- **Security Role:** Detects packed/encrypted payloads.
- **Issues Found:** No issues — well-bounded and deterministic.

### 2.12 `sandbox/pe_analyzer.py` — PE Analysis
- **Purpose:** PE header parsing and suspicious API detection.
- **Security Role:** Identifies injection-capable executables.
- **Issues Found:** Mock analysis in simulation mode can mask real threats if simulation flag is misconfigured.

### 2.13 `sandbox/hid_descriptor_analyzer.py` — HID Behavioral Analysis
- **Purpose:** Keystroke injection rate detection and composite device fingerprinting.
- **Security Role:** Rubber Ducky / BadUSB detection.
- **Issues Found:** `descriptor_hash` uses only SHA256[:16] (truncated) — collision risk for fingerprint tracking.

### 2.14 `sandbox/windows_sandbox_bridge.py` — Windows Sandbox Integration
- **Purpose:** Launch Windows Sandbox with analysis script, collect JSON results.
- **Security Role:** Isolated file analysis in throwaway VM.
- **Issues Found:**
  - **HIGH:** WSB config disables networking but `<Networking>Disable</Networking>` is inside the sandbox — files are still copied from host with `shutil.copy2` without integrity verification.
  - **MEDIUM:** Sandbox script uses `-ExecutionPolicy Bypass` — intentional but should be documented as accepted risk.
  - **LOW:** Timeout polling loop (`time.sleep(1)`) is CPU-wasteful.

### 2.15 `sandbox/sandbox_manager.py` — Sandbox Lifecycle
- **Purpose:** Create per-scan temp folders, copy files, cleanup.
- **Security Role:** Isolation boundary for file analysis.
- **Issues Found:** `discover_device_files()` falls back to scanning `*.py` files from the sandbox module itself when no mount point is found — information leak of source code to analysis pipeline.

### 2.16 `ml/lightgbm_classifier.py` — LightGBM Classifier
- **Purpose:** Production binary threat scoring with hybrid rule + model pipeline.
- **Security Role:** ML-based threat detection.
- **Issues Found:** Rule-only mode silently activated on Python ≥3.13 — may reduce detection accuracy without operator awareness.

### 2.17 `ml/random_forest_classifier.py` — RandomForest Classifier
- **Purpose:** Secondary 3-class classifier for ensemble detection.
- **Security Role:** Ensemble redundancy for threat detection.
- **Issues Found:** Trains on synthetic data at runtime if no model file exists — not production-safe (synthetic model quality is unvalidated).

### 2.18 `ml/classifier.py` — Ensemble Classifier
- **Purpose:** Orchestrates LightGBM + RandomForest with merge rules.
- **Security Role:** Final ML verdict for file/device risk.
- **Issues Found:** `_merge_levels` has a redundant branch (line 151) — both sides of a conditional return the same value.

### 2.19 `database/db.py` — Database Engine
- **Purpose:** SQLAlchemy engine creation, session factory, SQLite configuration.
- **Security Role:** Data persistence layer.
- **Issues Found:**
  - **MEDIUM:** `check_same_thread=False` disables SQLite thread safety check — documented as intentional but requires careful session management.
  - **LOW:** Database URL printed to console including path (`print(f"[DB] Using database: {db_url}")`) — information disclosure in logs.

### 2.20 `ai_agent/` — Advisory AI Integration
- **Purpose:** Local Ollama-powered threat explanations and file analysis.
- **Security Role:** Advisory only — does not make enforcement decisions.
- **Issues Found:** `advisory_service.py` sends scan data to local Ollama API — if Ollama is remotely accessible, this is a data exfiltration path.

---

## 3. Dependency Inventory

| Package | Version Spec | Purpose | Security Notes |
|---------|-------------|---------|----------------|
| `bcrypt` | ≥4.2.1 | Password/PIN hashing | ✅ Industry standard |
| `joblib` | ≥1.3.0 | ML model serialization | ⚠️ Pickle-based deserialization (RCE if model files tampered) |
| `lightgbm` | ≥4.6.0 | Gradient boosting classifier | ✅ Native C++ inference |
| `numpy` | ≥2.2.2 | Numerical computation | ✅ Stable |
| `pefile` | ≥2023.2.7 | PE header parsing | ⚠️ Parses untrusted binary headers |
| `PySide6` | ≥6.8.0 | Desktop GUI framework | ✅ Qt wrapper |
| `python-dotenv` | ≥1.0.1 | Environment variable loading | ✅ Low risk |
| `PyYAML` | ≥6.0.2 | YAML configuration parsing | ✅ Uses `safe_load` throughout |
| `reportlab` | ≥4.2.5 | PDF report generation | ✅ Low risk |
| `scikit-learn` | ≥1.3.0 | RandomForest classifier | ✅ Established ML library |
| `scipy` | ≥1.15.1 | Scientific computing | ✅ Math utilities |
| `SQLAlchemy` | ≥2.0.36 | ORM / database engine | ✅ Industry standard |
| `WMI` | ≥1.5.1 | Windows Management Instrumentation | ⚠️ Windows-only; requires admin |
| `pyinstaller` | ≥6.4.0 | Application packaging | ✅ Build-time only |
| `pytest` | ≥8.3.4 | Test framework | ✅ Dev-time only |
| `ollama` | ≥0.4.0 | Local LLM API client | ⚠️ Network communication to local API |

---

## 4. Security Posture Assessment

### 4.1 Strengths ✅

| Area | Assessment |
|------|-----------|
| **Password Storage** | bcrypt with cost factor 12 — resistant to brute force |
| **YAML Parsing** | `yaml.safe_load()` used consistently — no deserialization attacks |
| **Session Timeout** | Configurable inactivity timeout with automatic GUEST revert |
| **Lockout Policy** | 3-attempt lockout with 60s cooldown on authentication |
| **Database** | SQLite WAL mode, foreign keys enforced, parameterized queries via ORM |
| **Sandbox Isolation** | Windows Sandbox with networking disabled, VGPU disabled, clipboard disabled |
| **Drive Isolation** | Pre-scan drive letter detachment reduces host exposure |
| **ML Ensemble** | Dual-model voting with conservative merge (both must agree for SAFE) |
| **Entropy Detection** | Spec-aligned thresholds (7.2 suspicious, 7.8 packed/encrypted) |
| **PE Analysis** | MZ/PE signature validation with suspicious API detection |
| **HID Detection** | Keystroke rate thresholds (20 KPS suspicious, 80 KPS malicious) |
| **Audit Trail** | All actions logged to database with operator ID and timestamp |

### 4.2 Weaknesses ❌

| Area | Severity | Assessment |
|------|----------|-----------|
| **Default Credentials** | 🔴 CRITICAL | `admin/admin` username/password and `admin` security key |
| **Session Race Condition** | 🔴 HIGH | Variable scope bug in `check_timeout()` |
| **Command Injection** | 🟠 HIGH | Unsanitized device IDs passed to `subprocess.run()` |
| **No Input Validation** | 🟠 HIGH | VID/PID/serial not validated against expected format |
| **Simulation Mode Default** | 🟠 HIGH | `_is_simulation_mode()` fallback returns `True` in auth_manager |
| **Source Code Leak** | 🟡 MEDIUM | Sandbox fallback scans own Python source files |
| **Memory Exhaustion** | 🟡 MEDIUM | File scanner reads entire files without size cap |
| **Truncated Hash** | 🟡 MEDIUM | HID descriptor fingerprint uses SHA256[:16] |
| **Model Tampering** | 🟡 MEDIUM | No integrity check on ML model files (joblib/pickle) |
| **Info Disclosure** | 🟢 LOW | Database paths printed to console/logs |

---

## 5. Vulnerability Catalogue

### VULN-001: Hardcoded Default Credentials
- **Severity:** 🔴 CRITICAL (CVSS 9.8)
- **Location:** `security/auth_manager.py:141-143`
- **Description:** Default admin credentials (`admin/admin/admin`) are hardcoded and auto-seeded on first run. Combined with the security key unlock in `access_controller.py:159-193`, an attacker knowing the default key `"admin"` can unlock all USB ports.
- **Impact:** Full USB port bypass; complete security control override.
- **Remediation:** Force credential change on first run; remove hardcoded defaults; generate random initial security key.

### VULN-002: Session Manager Race Condition
- **Severity:** 🔴 HIGH (CVSS 7.5)
- **Location:** `security/session_manager.py:214-239`
- **Description:** `check_timeout()` reads `elapsed_minutes` inside `with self._lock:` but uses it outside the lock block (line 236). This creates a TOCTOU race condition where concurrent threads could observe inconsistent session state.
- **Impact:** Session timeout bypass; privilege persistence beyond configured timeout.
- **Remediation:** Move the timeout comparison and `end_session()` call inside the lock scope.

### VULN-003: Command Injection via Device ID
- **Severity:** 🟠 HIGH (CVSS 8.1)
- **Location:** `core/port_lockdown.py:287-288`
- **Description:** `_devcon_disable()` passes `device_id` directly into a subprocess command list as `f"@{device_id}"`. While Python's list-based `subprocess.run()` provides some protection against shell injection, a maliciously crafted device ID string from a USB device descriptor could still cause unexpected behavior in DevCon argument parsing.
- **Impact:** Potential command injection or denial of service.
- **Remediation:** Validate device IDs against a strict regex pattern (`^[A-Za-z0-9_\\\\&]+$`); reject any containing shell metacharacters.

### VULN-004: Simulation Mode Defaults to True
- **Severity:** 🟠 HIGH (CVSS 7.0)
- **Location:** `security/auth_manager.py:82`
- **Description:** The `_is_simulation_mode()` fallback returns `True` when the config key `simulation_mode` is not found. This means if `config.yaml` is missing or corrupted, the auth manager enters simulation mode with pre-seeded development PIN `123456`.
- **Impact:** Authentication bypass in degraded deployment scenarios.
- **Remediation:** Default to `False` (production) when config is unavailable.

### VULN-005: No Input Validation on USB Device Fields
- **Severity:** 🟠 HIGH (CVSS 7.0)
- **Location:** Multiple (device_info.py, usb_monitor.py, file_scanner.py)
- **Description:** Vendor ID, Product ID, serial number, and device name fields from USB descriptors are used throughout the application without format validation. Malicious USB devices can set arbitrary strings in these fields.
- **Impact:** Log injection, display manipulation, potential XSS in reports, command injection in downstream operations.
- **Remediation:** Validate VID/PID as 4-hex-digit strings; sanitize serial numbers and device names; enforce max lengths.

### VULN-006: Unbounded File Read in Scanner
- **Severity:** 🟡 MEDIUM (CVSS 5.3)
- **Location:** `sandbox/file_scanner.py:379`
- **Description:** `_analyze_single_file()` calls `file_path.read_bytes()` without any size limit. A USB device containing a multi-gigabyte file could exhaust system memory.
- **Impact:** Denial of service via memory exhaustion.
- **Remediation:** Enforce a configurable max file size (e.g., 100 MB); skip or stream files exceeding the limit.

### VULN-007: Source Code Exposure in Sandbox Fallback
- **Severity:** 🟡 MEDIUM (CVSS 5.0)
- **Location:** `sandbox/sandbox_manager.py:88-91`
- **Description:** When no USB mount point is detected, `discover_device_files()` falls back to scanning the sandbox package's own Python source files. This exposes application source code to the analysis pipeline and potentially to logs/reports.
- **Impact:** Information disclosure of application internals.
- **Remediation:** Return an empty list instead of scanning own source; raise an explicit error.

### VULN-008: ML Model Integrity Not Verified
- **Severity:** 🟡 MEDIUM (CVSS 6.0)
- **Location:** `ml/random_forest_classifier.py:131-132`, `ml/lightgbm_classifier.py:188`
- **Description:** ML model files (`joblib`, LightGBM text format) are loaded without integrity verification. The joblib format uses pickle under the hood, which allows arbitrary code execution if the model file is tampered with.
- **Impact:** Remote code execution if an attacker can replace model files.
- **Remediation:** Compute and verify SHA-256 checksums of model files at load time; store expected hashes in a signed manifest.

### VULN-009: No Authorization on Whitelist Operations
- **Severity:** 🟡 MEDIUM (CVSS 5.5)
- **Location:** `security/whitelist_manager.py:47-93`
- **Description:** `add_device()` and `remove_device()` perform no authorization check. Any code path with access to the `WhitelistManager` instance can whitelist arbitrary device serial numbers, bypassing security controls.
- **Impact:** Unauthorized device trust escalation.
- **Remediation:** Require `SessionManager.require_auth(UserMode.ADMIN)` before whitelist mutations.

### VULN-010: Truncated Descriptor Hash
- **Severity:** 🟢 LOW (CVSS 3.0)
- **Location:** `sandbox/hid_descriptor_analyzer.py:218-219`
- **Description:** Device descriptor fingerprint uses `sha256(...)[:16]` (8 bytes / 64 bits), which has significantly reduced collision resistance compared to the full hash.
- **Impact:** Potential fingerprint collision allowing a malicious device to impersonate a known-good device.
- **Remediation:** Use at minimum SHA256[:32] (128-bit) for device fingerprinting.

### VULN-011: Database Path Information Disclosure
- **Severity:** 🟢 LOW (CVSS 2.0)
- **Location:** `database/db.py:142-145`
- **Description:** Full database file path is printed to stdout during initialization.
- **Impact:** Information disclosure of filesystem layout.
- **Remediation:** Use structured logging at DEBUG level only; mask paths in production.

---

## 6. Remediation Priority Matrix

| Priority | Vulnerability | Effort | Phase |
|----------|--------------|--------|-------|
| **P0** | VULN-001: Hardcoded Default Credentials | Medium | Phase 2 |
| **P0** | VULN-002: Session Race Condition | Low | Phase 2 |
| **P0** | VULN-004: Simulation Mode Defaults | Low | Phase 2 |
| **P1** | VULN-003: Command Injection | Medium | Phase 2 |
| **P1** | VULN-005: Input Validation | Medium | Phase 2 |
| **P1** | VULN-008: Model Integrity | Medium | Phase 2 |
| **P2** | VULN-006: Unbounded File Read | Low | Phase 2 |
| **P2** | VULN-007: Source Code Exposure | Low | Phase 2 |
| **P2** | VULN-009: Whitelist Auth | Low | Phase 2 |
| **P3** | VULN-010: Truncated Hash | Low | Phase 2 |
| **P3** | VULN-011: Info Disclosure | Low | Phase 2 |

---

> **Next Steps:** Proceed to Phase 2 — Security-First Code Fixes, addressing all vulnerabilities in priority order.

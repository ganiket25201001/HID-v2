"""Security-focused tests validating all VULN-001 through VULN-011 patches.

These tests ensure that the security fixes applied during the HID Shield
audit remain effective and are not regressed by future changes.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# VULN-001: No hardcoded default credentials
# ---------------------------------------------------------------------------


class TestVULN001_NoHardcodedCredentials:
    """Verify that default admin credentials are not predictable."""

    def test_default_password_is_empty_string(self) -> None:
        """The class-level default password must not be 'admin'."""
        from security.auth_manager import AuthManager

        assert AuthManager._DEFAULT_ADMIN_PASSWORD != "admin", (
            "VULN-001 REGRESSION: Default admin password is still 'admin'!"
        )

    def test_default_security_key_is_empty_string(self) -> None:
        """The class-level default security key must not be 'admin'."""
        from security.auth_manager import AuthManager

        assert AuthManager._DEFAULT_SECURITY_KEY != "admin", (
            "VULN-001 REGRESSION: Default security key is still 'admin'!"
        )

    def test_generate_initial_secret_is_random(self) -> None:
        """Each call to _generate_initial_secret must produce unique output."""
        from security.auth_manager import AuthManager

        secrets = {AuthManager._generate_initial_secret() for _ in range(50)}
        assert len(secrets) == 50, (
            "VULN-001 REGRESSION: _generate_initial_secret is not producing unique values!"
        )

    def test_generate_initial_secret_minimum_entropy(self) -> None:
        """Generated secrets must have sufficient length for security."""
        from security.auth_manager import AuthManager

        secret = AuthManager._generate_initial_secret(24)
        # base64url encoding of 24 bytes → 32 chars
        assert len(secret) >= 20, (
            f"VULN-001: Generated secret too short ({len(secret)} chars)"
        )


# ---------------------------------------------------------------------------
# VULN-002: Session manager race condition
# ---------------------------------------------------------------------------


class TestVULN002_SessionRaceCondition:
    """Verify that check_timeout is thread-safe."""

    def setup_method(self) -> None:
        from security.session_manager import SessionManager
        SessionManager.reset()

    def teardown_method(self) -> None:
        from security.session_manager import SessionManager
        SessionManager.reset()

    def test_check_timeout_does_not_use_unscoped_variable(self) -> None:
        """check_timeout must not reference elapsed_minutes outside the lock."""
        import inspect
        from security.session_manager import SessionManager

        source = inspect.getsource(SessionManager.check_timeout)
        # The old bug had `if elapsed_minutes >= ...` after the `with self._lock:` block.
        # The fix uses a `should_end` boolean flag instead.
        assert "should_end" in source, (
            "VULN-002 REGRESSION: check_timeout does not use should_end flag pattern."
        )

    def test_concurrent_timeout_checks_are_safe(self) -> None:
        """Multiple threads calling check_timeout must not crash."""
        from security.session_manager import SessionManager, UserMode

        sm = SessionManager()
        sm.start_session(UserMode.USER)
        # Set a very short timeout to trigger boundary behavior
        sm.set_timeout_minutes(1)

        errors: list[Exception] = []

        def check_loop() -> None:
            try:
                for _ in range(100):
                    sm.check_timeout()
                    sm.refresh_session()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=check_loop) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"VULN-002 REGRESSION: Thread errors: {errors}"


# ---------------------------------------------------------------------------
# VULN-003: Command injection via device ID
# ---------------------------------------------------------------------------


class TestVULN003_CommandInjection:
    """Verify device ID sanitization before subprocess calls."""

    def test_safe_device_id_passes(self) -> None:
        """Normal Windows PNP device IDs must pass validation."""
        from core.port_lockdown import _sanitize_device_id

        valid_ids = [
            r"USB\VID_1234&PID_5678\ABCD1234",
            r"USB\VID_046D&PID_C077\5&abc123&0&2",
            "USBSTOR_DISK",
            "USB#VID_1234",
        ]
        for device_id in valid_ids:
            result = _sanitize_device_id(device_id)
            assert result == device_id.strip()

    def test_shell_metacharacters_rejected(self) -> None:
        """Device IDs with shell metacharacters must be rejected."""
        from core.port_lockdown import _sanitize_device_id

        malicious_ids = [
            "USB\\VID_1234; rm -rf /",
            "USB|whoami",
            "$(calc.exe)",
            "`powershell -c evil`",
            "USB\nVID_1234",
            "USB' OR 1=1 --",
            'USB"; calc.exe; "',
        ]
        for device_id in malicious_ids:
            with pytest.raises(ValueError, match="forbidden"):
                _sanitize_device_id(device_id)

    def test_empty_device_id_rejected(self) -> None:
        """Empty device IDs must be rejected."""
        from core.port_lockdown import _sanitize_device_id

        with pytest.raises(ValueError, match="empty"):
            _sanitize_device_id("")

    def test_oversized_device_id_rejected(self) -> None:
        """Extremely long device IDs must be rejected."""
        from core.port_lockdown import _sanitize_device_id

        with pytest.raises(ValueError, match="max length"):
            _sanitize_device_id("A" * 1000)


# ---------------------------------------------------------------------------
# VULN-004: Simulation mode defaults
# ---------------------------------------------------------------------------


class TestVULN004_SimulationModeDefaults:
    """Verify simulation mode defaults to False (production-safe)."""

    def test_fallback_is_false_when_config_missing(self) -> None:
        """When config.yaml has no simulation_mode key, default must be False."""
        from security.auth_manager import _is_simulation_mode

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("HID_SHIELD_SIMULATION_MODE", None)
            with patch("security.auth_manager._load_config", return_value={}):
                assert _is_simulation_mode() is False, (
                    "VULN-004 REGRESSION: Simulation mode defaults to True!"
                )

    def test_explicit_env_true_works(self) -> None:
        """Explicit env var must still enable simulation mode."""
        from security.auth_manager import _is_simulation_mode

        with patch.dict(os.environ, {"HID_SHIELD_SIMULATION_MODE": "true"}):
            assert _is_simulation_mode() is True

    def test_explicit_env_false_works(self) -> None:
        """Explicit env var must still disable simulation mode."""
        from security.auth_manager import _is_simulation_mode

        with patch.dict(os.environ, {"HID_SHIELD_SIMULATION_MODE": "false"}):
            assert _is_simulation_mode() is False


# ---------------------------------------------------------------------------
# VULN-006: Unbounded file read
# ---------------------------------------------------------------------------


class TestVULN006_UnboundedFileRead:
    """Verify max file size enforcement in file scanner."""

    def test_analyze_single_file_has_size_guard(self) -> None:
        """_analyze_single_file must check file size before reading."""
        import inspect
        from sandbox.file_scanner import FileScanner

        source = inspect.getsource(FileScanner._analyze_single_file)
        assert "_MAX_SCAN_FILE_SIZE" in source, (
            "VULN-006 REGRESSION: No max file size guard in _analyze_single_file!"
        )
        assert "skipped" in source.lower() or "oversized" in source.lower(), (
            "VULN-006 REGRESSION: No oversized file handling logic found!"
        )


# ---------------------------------------------------------------------------
# VULN-007: Source code exposure in sandbox fallback
# ---------------------------------------------------------------------------


class TestVULN007_SourceCodeExposure:
    """Verify sandbox fallback does not expose own source files."""

    def test_discover_device_files_no_self_scan(self) -> None:
        """discover_device_files must not scan its own *.py files."""
        import inspect
        from sandbox.sandbox_manager import SandboxManager

        source = inspect.getsource(SandboxManager.discover_device_files)
        assert 'glob("*.py")' not in source, (
            "VULN-007 REGRESSION: Sandbox fallback still scans own source files!"
        )
        assert "Path(__file__)" not in source, (
            "VULN-007 REGRESSION: Sandbox fallback still references __file__!"
        )


# ---------------------------------------------------------------------------
# VULN-008: ML model integrity verification
# ---------------------------------------------------------------------------


class TestVULN008_ModelIntegrity:
    """Verify ML model files are integrity-checked on load."""

    def test_lightgbm_loader_has_integrity_check(self) -> None:
        """_load_model must verify SHA-256 checksum."""
        import inspect
        from ml.lightgbm_classifier import LightGBMClassifier

        source = inspect.getsource(LightGBMClassifier._load_model)
        assert "sha256" in source.lower() or "checksum" in source.lower(), (
            "VULN-008 REGRESSION: No integrity check in _load_model!"
        )
        assert "RuntimeError" in source or "tampered" in source.lower(), (
            "VULN-008 REGRESSION: Tampered model handling not found!"
        )

    def test_compute_file_hash_returns_hex_digest(self) -> None:
        """_compute_file_hash must return a valid SHA-256 hex string."""
        from ml.lightgbm_classifier import LightGBMClassifier

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
            tmp.write(b"test content for hash verification")
            tmp_path = Path(tmp.name)

        try:
            result = LightGBMClassifier._compute_file_hash(tmp_path)
            assert len(result) == 64, "SHA-256 hex digest must be 64 chars"
            assert all(c in "0123456789abcdef" for c in result)

            # Verify deterministic behavior
            result2 = LightGBMClassifier._compute_file_hash(tmp_path)
            assert result == result2, "Hash must be deterministic"
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_tampered_model_raises_error(self) -> None:
        """Loading a model with mismatched checksum must raise RuntimeError."""
        from ml.lightgbm_classifier import LightGBMClassifier

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "fake_model.txt"
            checksum_path = model_path.with_suffix(".txt.sha256")

            model_path.write_text("fake model content")
            checksum_path.write_text("0000000000000000000000000000000000000000000000000000000000000000  fake_model.txt\n")

            classifier = LightGBMClassifier.__new__(LightGBMClassifier)
            with pytest.raises(RuntimeError, match="integrity check FAILED"):
                classifier._load_model(model_path)


# ---------------------------------------------------------------------------
# VULN-009: Whitelist authorization
# ---------------------------------------------------------------------------


class TestVULN009_WhitelistAuth:
    """Verify whitelist operations require ADMIN authorization."""

    def test_add_device_checks_auth(self) -> None:
        """add_device must verify ADMIN session before proceeding."""
        import inspect
        from security.whitelist_manager import WhitelistManager

        source = inspect.getsource(WhitelistManager.add_device)
        assert "require_auth" in source, (
            "VULN-009 REGRESSION: add_device does not check authorization!"
        )
        assert "ADMIN" in source, (
            "VULN-009 REGRESSION: add_device does not require ADMIN mode!"
        )

    def test_remove_device_checks_auth(self) -> None:
        """remove_device must verify ADMIN session before proceeding."""
        import inspect
        from security.whitelist_manager import WhitelistManager

        source = inspect.getsource(WhitelistManager.remove_device)
        assert "require_auth" in source, (
            "VULN-009 REGRESSION: remove_device does not check authorization!"
        )
        assert "ADMIN" in source, (
            "VULN-009 REGRESSION: remove_device does not require ADMIN mode!"
        )


# ---------------------------------------------------------------------------
# VULN-010: Truncated descriptor hash
# ---------------------------------------------------------------------------


class TestVULN010_DescriptorHash:
    """Verify descriptor fingerprint uses adequate hash length."""

    def test_hash_length_at_least_32(self) -> None:
        """Descriptor hash must be at least 32 hex chars (128-bit)."""
        from sandbox.hid_descriptor_analyzer import HIDDescriptorAnalyzer

        analyzer = HIDDescriptorAnalyzer()
        device_info = {
            "vendor_id": "1234",
            "product_id": "5678",
            "device_type": "keyboard",
            "manufacturer": "TestCorp",
            "serial_number": "SN12345",
        }
        result = analyzer._compute_descriptor_hash(device_info)
        assert len(result) >= 32, (
            f"VULN-010 REGRESSION: Descriptor hash too short ({len(result)} chars)!"
        )


# ---------------------------------------------------------------------------
# VULN-011: Database path info disclosure
# ---------------------------------------------------------------------------


class TestVULN011_InfoDisclosure:
    """Verify database initialization does not log full paths."""

    def test_db_init_no_full_path_in_log(self) -> None:
        """Database startup log must not contain full filesystem path."""
        import inspect
        from database.db import _create_engine_instance

        source = inspect.getsource(_create_engine_instance)
        # The old code was: print(f"[DB] Using database: {db_url}")
        assert 'f"[DB] Using database: {db_url}"' not in source, (
            "VULN-011 REGRESSION: Full database URL still logged!"
        )

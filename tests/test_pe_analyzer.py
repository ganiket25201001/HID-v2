"""Tests for sandbox.pe_analyzer — PE header detection and analysis."""

import sys
import os

# Ensure project root is on sys.path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from sandbox.pe_analyzer import PEHeaderAnalyzer


class TestIsPEExecutable:
    """Test the raw MZ + PE\\0\\0 byte-level detection."""

    def test_mz_header_detected(self):
        """Valid PE: MZ at offset 0, PE\\0\\0 at offset pointed by 0x3C."""
        # Build a minimal valid PE header
        data = bytearray(256)
        data[0:2] = b"\x4D\x5A"          # MZ signature
        # PE header offset stored at 0x3C (little-endian) = 0x80
        data[0x3C:0x40] = (0x80).to_bytes(4, byteorder="little")
        data[0x80:0x84] = b"PE\x00\x00"  # PE signature at offset 0x80
        assert PEHeaderAnalyzer.is_pe_executable(bytes(data)) is True

    def test_non_pe_data_rejected(self):
        """Normal text/binary content should NOT be detected as PE."""
        data = b"This is a normal HID descriptor payload with no PE content at all." * 3
        assert PEHeaderAnalyzer.is_pe_executable(data) is False

    def test_too_short_data_rejected(self):
        """Data shorter than 64 bytes cannot contain a PE header."""
        data = b"\x4D\x5A" + b"\x00" * 30  # 32 bytes, too short
        assert PEHeaderAnalyzer.is_pe_executable(data) is False

    def test_mz_only_no_pe_signature(self):
        """MZ present at offset 0 but PE\\0\\0 missing at the resolved offset."""
        data = bytearray(256)
        data[0:2] = b"\x4D\x5A"
        data[0x3C:0x40] = (0x80).to_bytes(4, byteorder="little")
        data[0x80:0x84] = b"\x00\x00\x00\x00"  # NOT PE\0\0
        assert PEHeaderAnalyzer.is_pe_executable(bytes(data)) is False

    def test_no_mz_at_all(self):
        """No MZ magic at offset 0."""
        data = bytearray(256)
        data[0:2] = b"\x00\x00"
        assert PEHeaderAnalyzer.is_pe_executable(bytes(data)) is False

    def test_pe_offset_out_of_bounds(self):
        """PE offset at 0x3C points beyond the data length."""
        data = bytearray(128)
        data[0:2] = b"\x4D\x5A"
        # Point to offset 0x1000, which is way beyond 128 bytes
        data[0x3C:0x40] = (0x1000).to_bytes(4, byteorder="little")
        assert PEHeaderAnalyzer.is_pe_executable(bytes(data)) is False


class TestPEHeaderAnalyzer:
    """Test the full analyze_file pipeline with simulation mode."""

    def test_simulation_mode_returns_dict(self):
        """In simulation mode, analyze_file should return a well-formed dict."""
        analyzer = PEHeaderAnalyzer(simulation_mode=True)
        # Create a temporary file with fake PE-like content
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"\x4D\x5A" + b"\x00" * 254)
            tmp_path = f.name

        try:
            from pathlib import Path
            result = analyzer.analyze_file(Path(tmp_path))
            assert isinstance(result, dict)
            assert "suspicious_apis" in result
            assert "threat_indicators" in result
        finally:
            os.unlink(tmp_path)

    def test_suspicious_apis_list_type(self):
        """Suspicious APIs should always be a list."""
        analyzer = PEHeaderAnalyzer(simulation_mode=True)
        import tempfile
        from pathlib import Path
        with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as f:
            f.write(b"\x00" * 256)
            tmp_path = f.name
        try:
            result = analyzer.analyze_file(Path(tmp_path))
            assert isinstance(result.get("suspicious_apis"), list)
        finally:
            os.unlink(tmp_path)

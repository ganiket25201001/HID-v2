"""Integration tests — end-to-end threat classification scenarios."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from sandbox.entropy_analyzer import ShannonEntropyAnalyzer
from sandbox.pe_analyzer import PEHeaderAnalyzer
from sandbox.hid_descriptor_analyzer import HIDDescriptorAnalyzer
from ml.lightgbm_classifier import LightGBMClassifier, ThreatLevel
from security.policy_engine import PolicyEngine, DeviceSnapshot


class TestRubberDuckyProfile:
    """Simulate a USB Rubber Ducky — should be classified as MALICIOUS."""

    def test_rubber_ducky_high_keystroke_rate(self):
        """Rubber Ducky: keystroke rate > 80 KPS → MALICIOUS."""
        hid = HIDDescriptorAnalyzer()
        result = hid.analyze_device({
            "device_name": "USB Rubber Ducky",
            "device_type": "keyboard",
            "vendor_id": None,
            "product_id": None,
            "keystroke_rate": 200.0,
        })
        assert result.keystroke_label == "MALICIOUS"
        assert result.is_anomalous is True

    def test_rubber_ducky_policy_critical(self):
        """Policy engine should flag Rubber Ducky profile as HIGH or CRITICAL."""
        engine = PolicyEngine()
        snapshot = DeviceSnapshot(
            device_name="USB Rubber Ducky",
            device_type="keyboard",
            keystroke_rate=200.0,
            entropy_score=0.95,
        )
        result = engine.evaluate(snapshot)
        assert result.risk_level in ("high", "critical"), (
            f"Rubber Ducky risk_level={result.risk_level}, expected high or critical"
        )

    def test_rubber_ducky_ml_classification(self):
        """ML classifier should flag Rubber Ducky features as non-SAFE."""
        clf = LightGBMClassifier()
        features = {
            "entropy": 7.5,
            "file_size": 180000,
            "extension_mismatch": 0,
            "has_pe_header": 0,
            "suspicious_imports_count": 1,
            "yara_matches": 2,
            "is_script": 1,
            "is_hidden": 1,
            "has_autorun_ref": 1,
            "is_dual_hid": 1,
        }
        result = clf.classify_features(features)
        assert result.level != ThreatLevel.SAFE, (
            f"BadUSB vector got SAFE — expected SUSPICIOUS or higher"
        )


class TestStandardMouse:
    """Simulate a standard USB mouse — should be classified as SAFE."""

    def test_standard_mouse_low_entropy(self):
        """Normal device data should have low entropy."""
        analyzer = ShannonEntropyAnalyzer()
        # Mouse descriptor is small structured binary
        data = b"\x05\x01\x09\x02\xA1\x01" * 100
        result = analyzer.analyze_bytes(data)
        entropy = float(result["entropy"])
        assert entropy < 5.0, f"Mouse descriptor entropy {entropy} should be < 5.0"

    def test_standard_mouse_not_pe(self):
        """Normal device data should not be detected as PE."""
        data = b"\x05\x01\x09\x02\xA1\x01" * 50
        assert PEHeaderAnalyzer.is_pe_executable(data) is False

    def test_standard_mouse_policy_safe(self):
        """Policy engine should allow a normal mouse."""
        engine = PolicyEngine()
        snapshot = DeviceSnapshot(
            device_name="Logitech M590",
            device_type="mouse",
            vendor_id="046d",
            product_id="4069",
            serial="SN100",
            keystroke_rate=0.0,
            entropy_score=0.1,
        )
        result = engine.evaluate(snapshot)
        assert result.risk_level in ("safe", "low"), (
            f"Normal mouse risk={result.risk_level}, expected safe or low"
        )

    def test_standard_mouse_hid_safe(self):
        """HID analyzer should not flag a normal mouse."""
        hid = HIDDescriptorAnalyzer()
        result = hid.analyze_device({
            "device_name": "Logitech M590",
            "device_type": "mouse",
            "vendor_id": "046d",
            "product_id": "4069",
            "keystroke_rate": 0.0,
        })
        assert result.keystroke_label == "SAFE"


class TestUSBDriveAsHID:
    """Simulate USB drive presenting as HID — should be SUSPICIOUS."""

    def test_storage_with_hid_name_suspicious(self):
        """Storage device with HID-like name should be flagged."""
        hid = HIDDescriptorAnalyzer()
        result = hid.analyze_device({
            "device_name": "Generic HID Keyboard Device",
            "device_type": "storage",
            "vendor_id": None,
            "product_id": None,
            "keystroke_rate": 0.0,
        })
        assert result.is_anomalous is True
        assert any("HID" in reason or "keyboard" in reason for reason in result.anomaly_reasons)

    def test_composite_device_flagged(self):
        """Composite device should be flagged as anomalous."""
        hid = HIDDescriptorAnalyzer()
        result = hid.analyze_device({
            "device_name": "USB Composite Device",
            "device_type": "composite",
            "vendor_id": "0000",
            "product_id": "0000",
            "keystroke_rate": 25.0,
        })
        assert result.is_composite is True
        assert result.is_anomalous is True

    def test_suspicious_keystroke_rate(self):
        """Keystroke rate between 20-80 KPS → SUSPICIOUS."""
        hid = HIDDescriptorAnalyzer()
        result = hid.analyze_device({
            "device_name": "Unknown USB Device",
            "device_type": "keyboard",
            "vendor_id": "1234",
            "product_id": "5678",
            "keystroke_rate": 45.0,
        })
        assert result.keystroke_label == "SUSPICIOUS"


class TestPolicyEngineThresholds:
    """Verify the policy engine uses spec thresholds."""

    def test_entropy_threshold_triggers_high(self):
        """Entropy >= config threshold (0.9) → HIGH risk."""
        engine = PolicyEngine()
        snapshot = DeviceSnapshot(
            device_name="Suspicious Device",
            entropy_score=0.92,
        )
        result = engine.evaluate(snapshot)
        assert result.risk_level in ("high", "critical")

    def test_entropy_critical_threshold(self):
        """Entropy >= 0.90 → CRITICAL risk."""
        engine = PolicyEngine()
        snapshot = DeviceSnapshot(
            device_name="Crypted Device",
            entropy_score=0.95,
        )
        result = engine.evaluate(snapshot)
        assert result.risk_level == "critical"

    def test_malicious_files_escalate(self):
        """Multiple malicious files → risk escalation."""
        engine = PolicyEngine()
        snapshot = DeviceSnapshot(
            device_name="Infected Drive",
            device_type="storage",
            malicious_file_count=5,
            total_file_count=10,
        )
        result = engine.evaluate(snapshot)
        assert result.risk_level == "critical"

    def test_no_serial_low_risk(self):
        """Device without serial → LOW risk (not escalated alone)."""
        engine = PolicyEngine()
        snapshot = DeviceSnapshot(
            device_name="Generic USB",
            serial=None,
        )
        result = engine.evaluate(snapshot)
        assert result.risk_level in ("safe", "low")

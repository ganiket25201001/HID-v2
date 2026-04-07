"""Tests for ml.classifier — EnsembleClassifier and LightGBM/RF integration."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from ml.lightgbm_classifier import LightGBMClassifier, ThreatLevel


class TestLightGBMClassifier:
    """Test the primary LightGBM backend."""

    def setup_method(self):
        self.clf = LightGBMClassifier()

    def test_safe_device_passes(self):
        """Normal mouse/keyboard features should classify as SAFE."""
        features = {
            "entropy": 1.5,
            "file_size": 2000,
            "extension_mismatch": 0,
            "has_pe_header": 0,
            "suspicious_imports_count": 0,
            "yara_matches": 0,
            "is_script": 0,
            "is_hidden": 0,
            "has_autorun_ref": 0,
            "is_dual_hid": 0,
        }
        result = self.clf.classify_features(features)
        assert result.level == ThreatLevel.SAFE, (
            f"Normal device got {result.level.value}, expected SAFE"
        )

    def test_malicious_device_flagged(self):
        """High-risk ransomware-style vector should NOT be SAFE."""
        features = {
            "entropy": 7.9,
            "file_size": 3200000,
            "extension_mismatch": 1,
            "has_pe_header": 1,
            "suspicious_imports_count": 6,
            "yara_matches": 3,
            "is_script": 0,
            "is_hidden": 1,
            "has_autorun_ref": 1,
            "is_dual_hid": 0,
        }
        result = self.clf.classify_features(features)
        assert result.level != ThreatLevel.SAFE, (
            f"Ransomware vector classified as SAFE — expected DANGEROUS or CRITICAL"
        )
        assert result.score >= 50.0, (
            f"Malicious score {result.score} should be >= 50.0"
        )

    def test_confidence_threshold(self):
        """Borderline vector — verify confidence is computed and in [0, 1]."""
        features = {
            "entropy": 6.5,
            "file_size": 90000,
            "extension_mismatch": 1,
            "has_pe_header": 0,
            "suspicious_imports_count": 1,
            "yara_matches": 1,
            "is_script": 1,
            "is_hidden": 0,
            "has_autorun_ref": 0,
            "is_dual_hid": 0,
        }
        result = self.clf.classify_features(features)
        assert 0.0 <= result.confidence <= 1.0, (
            f"Confidence {result.confidence} should be in [0.0, 1.0]"
        )

    def test_classify_device_empty_files(self):
        """Device with no file results should default to SAFE."""
        result = self.clf.classify_device([])
        assert result["device_level"] == ThreatLevel.SAFE.value

    def test_classify_device_with_dangerous_file(self):
        """Device with one DANGEROUS file should escalate device risk."""
        file_results = [
            {"level": "DANGEROUS", "score": 75.0},
            {"level": "SAFE", "score": 10.0},
        ]
        result = self.clf.classify_device(file_results)
        assert result["device_level"] == ThreatLevel.DANGEROUS.value

    def test_classify_features_returns_explanation(self):
        """Result must include an explanation string."""
        features = {
            "entropy": 3.0,
            "file_size": 5000,
            "extension_mismatch": 0,
            "has_pe_header": 0,
            "suspicious_imports_count": 0,
            "yara_matches": 0,
            "is_script": 0,
            "is_hidden": 0,
            "has_autorun_ref": 0,
            "is_dual_hid": 0,
        }
        result = self.clf.classify_features(features)
        assert isinstance(result.explanation, str)
        assert len(result.explanation) > 0


class TestRandomForestClassifier:
    """Test the RF secondary model."""

    def setup_method(self):
        from ml.random_forest_classifier import RandomForestThreatClassifier
        self.rf = RandomForestThreatClassifier()

    def test_safe_device_classified_safe(self):
        """Normal keyboard features → SAFE."""
        from ml.random_forest_classifier import RFThreatLabel
        features = {
            "entropy": 2.0,
            "pe_flag": 0,
            "hid_type_encoded": 1.0,
            "descriptor_hash_encoded": 0.2,
            "keystroke_rate": 5.0,
            "vendor_id_encoded": 0.5,
            "product_id_encoded": 0.4,
            "is_composite": 0,
        }
        result = self.rf.classify(features)
        assert result.label == RFThreatLabel.SAFE

    def test_malicious_device_detected(self):
        """Rubber Ducky profile → MALICIOUS or SUSPICIOUS."""
        from ml.random_forest_classifier import RFThreatLabel
        features = {
            "entropy": 7.8,
            "pe_flag": 1,
            "hid_type_encoded": 1.0,
            "descriptor_hash_encoded": 0.95,
            "keystroke_rate": 200.0,
            "vendor_id_encoded": 0.0,
            "product_id_encoded": 0.0,
            "is_composite": 1,
        }
        result = self.rf.classify(features)
        assert result.label != RFThreatLabel.SAFE, (
            f"Rubber Ducky profile classified as SAFE — expected MALICIOUS or SUSPICIOUS"
        )

    def test_confidence_in_range(self):
        """Confidence score must be in [0.0, 1.0]."""
        features = {
            "entropy": 5.0,
            "pe_flag": 0,
            "hid_type_encoded": 2.0,
            "descriptor_hash_encoded": 0.5,
            "keystroke_rate": 10.0,
            "vendor_id_encoded": 0.3,
            "product_id_encoded": 0.3,
            "is_composite": 0,
        }
        result = self.rf.classify(features)
        assert 0.0 <= result.confidence <= 1.0

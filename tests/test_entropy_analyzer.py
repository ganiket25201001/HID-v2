"""Tests for sandbox.entropy_analyzer — Shannon entropy computation and classification."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from sandbox.entropy_analyzer import ShannonEntropyAnalyzer


class TestShannonEntropy:
    """Core entropy computation tests."""

    def setup_method(self):
        self.analyzer = ShannonEntropyAnalyzer()

    def test_high_entropy_detected(self):
        """Random bytes should produce entropy >= 7.2 bits (SUSPICIOUS threshold)."""
        import random
        random.seed(42)
        data = bytes(random.randint(0, 255) for _ in range(4096))
        result = self.analyzer.analyze_bytes(data)
        entropy = float(result["entropy"])
        assert entropy >= 7.2, f"Random data entropy {entropy} should be >= 7.2"

    def test_low_entropy_safe(self):
        """Repeated single-byte data should have very low entropy (< 1.0)."""
        data = b"\xAA" * 4096
        result = self.analyzer.analyze_bytes(data)
        entropy = float(result["entropy"])
        assert entropy < 1.0, f"Repeated byte entropy {entropy} should be < 1.0"

    def test_boundary_value_7_2(self):
        """Crafted payload near the 7.2 boundary — verify classification label."""
        # Use mostly random bytes to get close to 7.2+
        import random
        random.seed(99)
        data = bytes(random.randint(0, 255) for _ in range(8192))
        result = self.analyzer.analyze_bytes(data)
        entropy = float(result["entropy"])
        classification = str(result["classification"])
        # Random 8KB data should have entropy > 7.2 → packed or encrypted
        assert entropy >= 7.0, f"Expected near-max entropy, got {entropy}"
        assert classification in ("packed", "encrypted"), (
            f"Classification '{classification}' should be 'packed' or 'encrypted' for entropy {entropy}"
        )

    def test_is_suspicious_true_for_high(self):
        """is_suspicious should return True when entropy >= 7.2."""
        assert self.analyzer.is_suspicious(7.2) is True
        assert self.analyzer.is_suspicious(7.9) is True

    def test_is_suspicious_false_for_low(self):
        """is_suspicious should return False when entropy < 7.2."""
        assert self.analyzer.is_suspicious(7.1) is False
        assert self.analyzer.is_suspicious(4.0) is False
        assert self.analyzer.is_suspicious(0.0) is False

    def test_empty_data_returns_zero(self):
        """Empty bytes should return 0.0 entropy without crashing."""
        result = self.analyzer.analyze_bytes(b"")
        entropy = float(result["entropy"])
        assert entropy == 0.0

    def test_analyze_returns_required_keys(self):
        """Result dict must contain entropy, classification, and explanation."""
        result = self.analyzer.analyze_bytes(b"Hello World" * 100)
        assert "entropy" in result
        assert "classification" in result
        assert "explanation" in result

    def test_plain_text_classification(self):
        """Low-entropy structured text should classify as plain_text."""
        data = b"AAABBBCCC" * 500
        result = self.analyzer.analyze_bytes(data)
        classification = str(result["classification"])
        entropy = float(result["entropy"])
        assert entropy < 4.2, f"Structured text entropy {entropy} should be < 4.2"
        assert classification == "plain_text"

    def test_threshold_constants_match_spec(self):
        """Verify class-level threshold constants match the security spec."""
        assert self.analyzer.ENTROPY_SUSPICIOUS_THRESHOLD == 7.2
        assert self.analyzer.ENTROPY_PACKED_THRESHOLD == 7.8

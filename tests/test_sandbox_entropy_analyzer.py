import tempfile
import unittest
from pathlib import Path

from sandbox.entropy_analyzer import ShannonEntropyAnalyzer


class EntropyAnalyzerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.analyzer = ShannonEntropyAnalyzer()

    def test_empty_payload_entropy_is_zero(self) -> None:
        result = self.analyzer.analyze_bytes(b"")

        self.assertEqual(result["entropy"], 0.0)
        self.assertEqual(result["classification"], "plain_text")

    def test_repetitive_payload_has_low_entropy(self) -> None:
        result = self.analyzer.analyze_bytes(b"A" * 4096)

        self.assertLess(result["entropy"], 1.0)
        self.assertEqual(result["classification"], "plain_text")

    def test_invalid_max_bytes_returns_unreadable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "payload.bin"
            path.write_bytes(b"abc")

            result = self.analyzer.analyze_file(path, max_bytes=0)

        self.assertEqual(result["classification"], "unreadable")
        self.assertIn("max_bytes", result["explanation"])


if __name__ == "__main__":
    unittest.main()

import unittest
from pathlib import Path

from sandbox.pe_analyzer import PEHeaderAnalyzer


class PEAnalyzerTests(unittest.TestCase):
    def test_non_pe_extension_is_skipped(self) -> None:
        analyzer = PEHeaderAnalyzer(simulation_mode=True)

        result = analyzer.analyze_file(Path("notes.txt"))

        self.assertFalse(result["is_pe"])
        self.assertEqual(result["analysis_mode"], "skipped_non_pe")

    def test_simulation_detects_suspicious_filename_patterns(self) -> None:
        analyzer = PEHeaderAnalyzer(simulation_mode=True)

        result = analyzer.analyze_file(Path("payload_loader.exe"))

        self.assertTrue(result["is_pe"])
        self.assertEqual(result["analysis_mode"], "simulation")
        self.assertIn("VirtualAlloc", result["suspicious_apis"])


if __name__ == "__main__":
    unittest.main()

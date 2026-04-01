import unittest
from pathlib import Path

from database.models import RiskLevel
from sandbox.file_scanner import FileScanner


class FileScannerAdvancedTests(unittest.TestCase):
    def setUp(self) -> None:
        # Bypass runtime-heavy constructor; these tests target pure scoring helpers.
        self.scanner = FileScanner.__new__(FileScanner)

    def test_score_threat_boundary_medium_at_28(self) -> None:
        risk, threat, notes = self.scanner._score_threat(
            file_path=Path("sample.bin"),
            entropy_info={"entropy": 7.2},
            pe_info={"suspicious_apis": []},
            heuristics={
                "yara_hits": [],
                "script_like": False,
                "hidden_path": False,
                "autorun_reference": False,
            },
        )

        self.assertEqual(risk, RiskLevel.MEDIUM.value)
        self.assertEqual(threat, "Anomalous.File")
        self.assertIn("Entropy very high", notes)

    def test_score_threat_critical_for_compound_indicators(self) -> None:
        risk, threat, notes = self.scanner._score_threat(
            file_path=Path("payload_loader.exe"),
            entropy_info={"entropy": 7.85},
            pe_info={"suspicious_apis": ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"]},
            heuristics={
                "yara_hits": ["SuspiciousFilenameRule", "ThreadInjectionRule"],
                "script_like": True,
                "hidden_path": True,
                "autorun_reference": True,
            },
        )

        self.assertEqual(risk, RiskLevel.CRITICAL.value)
        self.assertEqual(threat, "Trojan.BadUSB.Loader")
        self.assertIn("Suspicious PE APIs", notes)
        self.assertIn("YARA-like hit", notes)

    def test_run_heuristics_detects_script_and_injection_markers(self) -> None:
        heuristics = self.scanner._run_heuristics(
            file_path=Path(".hidden/dropper.ps1"),
            file_bytes=b"powershell Invoke-Expression; CreateRemoteThread",
            mime_type="text/plain",
        )

        self.assertTrue(heuristics["script_like"])
        self.assertTrue(heuristics["hidden_path"])
        self.assertIn("PowerShellExecutionRule", heuristics["yara_hits"])
        self.assertIn("ThreadInjectionRule", heuristics["yara_hits"])

    def test_build_summary_counts_levels_and_max_entropy(self) -> None:
        rows = [
            {"risk_level": RiskLevel.SAFE.value, "entropy": 1.0},
            {"risk_level": RiskLevel.LOW.value, "entropy": 2.2},
            {"risk_level": RiskLevel.MEDIUM.value, "entropy": 6.4},
            {"risk_level": RiskLevel.HIGH.value, "entropy": 7.7},
            {"risk_level": RiskLevel.CRITICAL.value, "entropy": 7.9},
        ]
        summary = self.scanner._build_summary({"device_name": "USB"}, rows)

        self.assertEqual(summary["total_files"], 5)
        self.assertEqual(summary["safe_files"], 2)
        self.assertEqual(summary["medium_risk_files"], 1)
        self.assertEqual(summary["high_risk_files"], 2)
        self.assertEqual(summary["max_entropy"], 7.9)


if __name__ == "__main__":
    unittest.main()

"""Unit tests for WindowsSandboxBridge helpers."""

from __future__ import annotations

import json
from pathlib import Path

from sandbox.windows_sandbox_bridge import WindowsSandboxBridge


class _BridgeForTest(WindowsSandboxBridge):
    def _load_config(self):
        return {
            "windows_sandbox": {
                "enabled": True,
                "timeout_seconds": 3,
                "keep_artifacts": False,
                "host_staging_root": str(Path.cwd() / "_tmp_bridge_root"),
            }
        }


def test_wsb_config_contains_hardening_controls():
    bridge = _BridgeForTest()

    wsb = bridge._build_wsb_config(
        host_input=Path("C:/tmp/input"),
        host_output=Path("C:/tmp/output"),
        host_scripts=Path("C:/tmp/scripts"),
    )

    assert "<Networking>Disable</Networking>" in wsb
    assert "<ClipboardRedirection>Disable</ClipboardRedirection>" in wsb
    assert "run_hidshield_scan.ps1" in wsb


def test_wait_for_results_parses_json(tmp_path):
    bridge = _BridgeForTest()
    output = tmp_path / "sandbox_result.json"
    payload = {"status": "ok", "files": [{"sandbox_name": "x.bin", "risk_level": "safe"}]}
    output.write_text(json.dumps(payload), encoding="utf-8")

    rows = bridge._wait_for_results(output)

    assert len(rows) == 1
    assert rows[0]["sandbox_name"] == "x.bin"


def test_scan_script_avoids_forced_shutdown_popup_pattern():
    bridge = _BridgeForTest()
    script = bridge._build_scan_script()

    assert "Stop-Computer -Force" not in script

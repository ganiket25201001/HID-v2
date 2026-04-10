"""Windows Sandbox bridge for isolated USB file analysis."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import yaml


class WindowsSandboxBridge:
    """Launch Windows Sandbox, run analysis script, and collect JSON results."""

    def __init__(self) -> None:
        cfg = self._load_config().get("windows_sandbox", {})

        self.enabled: bool = bool(cfg.get("enabled", False))
        self.timeout_seconds: int = int(cfg.get("timeout_seconds", 240))
        self.keep_artifacts: bool = bool(cfg.get("keep_artifacts", False))
        self.close_after_analysis: bool = bool(cfg.get("close_after_analysis", False))

        configured_root = str(cfg.get("host_staging_root", "")).strip()
        if configured_root:
            self._root = Path(configured_root)
        else:
            program_data = os.getenv("ProgramData") or str(Path.home())
            self._root = Path(program_data) / "HIDShield" / "sandbox_bridge"

        self._root.mkdir(parents=True, exist_ok=True)
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        self._sandbox_exe = system_root / "System32" / "WindowsSandbox.exe"

    def is_available(self) -> bool:
        """Return True when Windows Sandbox is configured and available."""
        return bool(
            self.enabled
            and platform.system().lower() == "windows"
            and self._sandbox_exe.exists()
        )

    def analyze_staged_files(self, *, session_id: str, staged_files: list[Path]) -> list[dict[str, Any]]:
        """Analyze staged files in Windows Sandbox and return per-file JSON rows."""
        if not staged_files:
            return []
        if not self.is_available():
            return []

        run_id = f"{session_id}_{uuid.uuid4().hex[:8]}"
        run_root = self._root / run_id
        input_dir = run_root / "input"
        output_dir = run_root / "output"
        scripts_dir = run_root / "scripts"

        input_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        scripts_dir.mkdir(parents=True, exist_ok=True)

        output_file = output_dir / "sandbox_result.json"

        for source in staged_files:
            if not source.exists() or not source.is_file():
                continue
            target = input_dir / source.name
            shutil.copy2(source, target)

        script_path = scripts_dir / "run_hidshield_scan.ps1"
        wsb_path = scripts_dir / "hidshield_scan.wsb"

        script_path.write_text(self._build_scan_script(), encoding="utf-8")
        wsb_path.write_text(
            self._build_wsb_config(
                host_input=input_dir,
                host_output=output_dir,
                host_scripts=scripts_dir,
            ),
            encoding="utf-8",
        )

        try:
            sandbox_proc = subprocess.Popen(
                [str(self._sandbox_exe), str(wsb_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as exc:
            print(f"[SANDBOX] Failed to launch Windows Sandbox: {exc}")
            self._cleanup_run_dir(run_root)
            return []

        rows = self._wait_for_results(output_file)

        if self.close_after_analysis:
            self._close_sandbox_process(sandbox_proc)

        if not self.keep_artifacts:
            self._cleanup_run_dir(run_root)
        return rows

    def _close_sandbox_process(self, sandbox_proc: subprocess.Popen[Any]) -> None:
        """Close Windows Sandbox process tree after analysis if configured."""
        try:
            if sandbox_proc.poll() is not None:
                return

            sandbox_proc.terminate()
            sandbox_proc.wait(timeout=8)
        except Exception:
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(sandbox_proc.pid), "/T", "/F"],
                    capture_output=True,
                    text=True,
                    timeout=8,
                )
            except Exception:
                return

    def _wait_for_results(self, output_file: Path) -> list[dict[str, Any]]:
        deadline = time.time() + max(30, self.timeout_seconds)

        while time.time() < deadline:
            if output_file.exists() and output_file.stat().st_size > 2:
                try:
                    payload = json.loads(output_file.read_text(encoding="utf-8"))
                    rows = payload.get("files", []) if isinstance(payload, dict) else []
                    if isinstance(rows, list):
                        return [dict(row) for row in rows if isinstance(row, dict)]
                except json.JSONDecodeError:
                    pass
                except Exception:
                    return []
            time.sleep(1)

        print("[SANDBOX] Timed out waiting for Windows Sandbox results.")
        return []

    def _cleanup_run_dir(self, run_root: Path) -> None:
        try:
            shutil.rmtree(run_root, ignore_errors=True)
        except Exception:
            return

    def _build_wsb_config(self, *, host_input: Path, host_output: Path, host_scripts: Path) -> str:
        input_path = str(host_input.resolve())
        output_path = str(host_output.resolve())
        scripts_path = str(host_scripts.resolve())

        return f"""<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Disable</Networking>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{input_path}</HostFolder>
      <SandboxFolder>C:\\HIDShield\\Input</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{output_path}</HostFolder>
      <SandboxFolder>C:\\HIDShield\\Output</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{scripts_path}</HostFolder>
      <SandboxFolder>C:\\HIDShield\\Scripts</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\HIDShield\\Scripts\\run_hidshield_scan.ps1 -InputDir C:\\HIDShield\\Input -OutputFile C:\\HIDShield\\Output\\sandbox_result.json</Command>
  </LogonCommand>
</Configuration>
"""

    def _build_scan_script(self) -> str:
        return r"""
param(
    [Parameter(Mandatory = $true)][string]$InputDir,
    [Parameter(Mandatory = $true)][string]$OutputFile
)

$ErrorActionPreference = "Stop"

function Get-Entropy {
    param([byte[]]$Bytes)

    if (-not $Bytes -or $Bytes.Length -eq 0) {
        return 0.0
    }

    $counts = @{}
    foreach ($b in $Bytes) {
        if ($counts.ContainsKey($b)) {
            $counts[$b] += 1
        } else {
            $counts[$b] = 1
        }
    }

    $entropy = 0.0
    foreach ($count in $counts.Values) {
        $p = [double]$count / [double]$Bytes.Length
        if ($p -gt 0) {
            $entropy += -1.0 * $p * ([Math]::Log($p, 2))
        }
    }

    return [Math]::Round($entropy, 4)
}

$scriptExt = @(".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta")
$exeExt = @(".exe", ".dll", ".sys", ".scr", ".com")

try {
    Start-MpScan -ScanType CustomScan -ScanPath $InputDir | Out-Null
} catch {
    # Defender scan may be unavailable in some hardened sandbox images.
}

$results = @()
$files = Get-ChildItem -Path $InputDir -File -Recurse -Force -ErrorAction SilentlyContinue

foreach ($file in $files) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
        $entropy = Get-Entropy -Bytes $bytes
        $sha256 = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
        $relativePath = $file.FullName.Substring($InputDir.Length).TrimStart('\\')
        $ext = $file.Extension.ToLowerInvariant()

        $risk = "safe"
        $notes = @()

        if ($scriptExt -contains $ext) {
            $risk = "medium"
            $notes += "Script extension detected"
        }

        if ($exeExt -contains $ext) {
            if ($risk -eq "safe") {
                $risk = "medium"
            }
            $notes += "Executable extension detected"
        }

        if ($entropy -ge 7.8) {
            $risk = "critical"
            $notes += "Entropy >= 7.8"
        } elseif ($entropy -ge 7.2) {
            if ($risk -ne "critical") {
                $risk = "high"
            }
            $notes += "Entropy >= 7.2"
        } elseif ($entropy -ge 6.5 -and $risk -eq "safe") {
            $risk = "low"
            $notes += "Entropy elevated"
        }

        if ($bytes.Length -gt 0) {
            $sampleLength = [Math]::Min($bytes.Length, 4096)
            $sampleText = [System.Text.Encoding]::ASCII.GetString($bytes, 0, $sampleLength).ToLowerInvariant()

            if ($sampleText.Contains("powershell") -or $sampleText.Contains("invoke-expression")) {
                if ($risk -in @("safe", "low", "medium")) {
                    $risk = "high"
                }
                $notes += "PowerShell execution indicators"
            }

            if ($sampleText.Contains("createremotethread") -or $sampleText.Contains("virtualalloc")) {
                $risk = "critical"
                $notes += "Injection API indicators"
            }
        }

        $results += [PSCustomObject]@{
            sandbox_name = $file.Name
            relative_path = $relativePath
            size = [int64]$file.Length
            sha256 = $sha256
            entropy = [double]$entropy
            risk_level = $risk
            threat_name = $null
            notes = ($notes -join "; ")
        }
    } catch {
        $results += [PSCustomObject]@{
            sandbox_name = $file.Name
            relative_path = $file.Name
            size = [int64]$file.Length
            sha256 = $null
            entropy = 0.0
            risk_level = "medium"
            threat_name = $null
            notes = "Sandbox analysis error: $($_.Exception.Message)"
        }
    }
}

$payload = [PSCustomObject]@{
    status = "ok"
    engine = "windows_sandbox_defender"
    files = $results
    created_at = (Get-Date).ToString("o")
}

$payload | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputFile -Encoding UTF8
""".strip() + "\n"

    def _load_config(self) -> dict[str, Any]:
        config_path = Path(__file__).resolve().parent.parent / "config.yaml"
        if not config_path.exists():
            return {}
        with config_path.open("r", encoding="utf-8") as stream:
            return yaml.safe_load(stream) or {}

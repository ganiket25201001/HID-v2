"""Portable Executable header analysis helpers for threat triage."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def _is_simulation_mode() -> bool:
    """Return simulation mode from environment variable fallback logic."""
    raw_value = os.getenv("HID_SHIELD_SIMULATION_MODE", "").strip().lower()
    if raw_value in {"1", "true", "yes"}:
        return True
    if raw_value in {"0", "false", "no"}:
        return False
    return True


class PEHeaderAnalyzer:
    """Inspect PE imports and suspicious API usage from executable files.

    In simulation mode or when `pefile` is unavailable, deterministic mock analysis
    is used so the sandbox pipeline remains fully operational.
    """

    # Integrated from: Malware-Analysis-Report-Tool — PE signature constants
    _MZ_SIGNATURE: bytes = b"\x4D\x5A"  # MZ header at offset 0
    _PE_SIGNATURE: bytes = b"PE\x00\x00"  # PE\0\0 at the offset stored at 0x3C

    SUSPICIOUS_APIS: tuple[str, ...] = (
        "VirtualAlloc",
        "VirtualProtect",
        "CreateRemoteThread",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "NtCreateThreadEx",
        "LoadLibraryA",
        "LoadLibraryW",
        "GetProcAddress",
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "RegSetValueExA",
        "RegSetValueExW",
    )

    # Integrated from: Malware-Analysis-Report-Tool — raw MZ + PE\0\0 validation
    @staticmethod
    def is_pe_executable(data: bytes) -> bool:
        """Check if raw bytes represent a PE executable using signature bytes.

        Validates:
        1. MZ header (0x4D 0x5A) at offset 0.
        2. PE\\0\\0 signature at the offset stored in the DWORD at 0x3C.

        Parameters
        ----------
        data:
            Raw file bytes (at least 64 bytes required for header inspection).

        Returns
        -------
        bool
            ``True`` when both MZ and PE signatures are present at the
            expected offsets.
        """
        if len(data) < 64:
            return False
        # Check MZ magic at offset 0
        if data[:2] != PEHeaderAnalyzer._MZ_SIGNATURE:
            return False
        # Read the PE header offset from the DWORD at 0x3C (little-endian)
        pe_offset = int.from_bytes(data[0x3C:0x40], byteorder="little")
        if pe_offset < 0 or pe_offset + 4 > len(data):
            return False
        # Validate PE\0\0 signature at the resolved offset
        return data[pe_offset : pe_offset + 4] == PEHeaderAnalyzer._PE_SIGNATURE

    def __init__(self, simulation_mode: bool | None = None) -> None:
        """Create analyzer and conditionally load `pefile` at runtime."""
        self._simulation_mode = (
            _is_simulation_mode() if simulation_mode is None else simulation_mode
        )
        self._pe_module: Any | None = None
        if not self._simulation_mode:
            try:
                import pefile  # type: ignore[import-not-found]

                self._pe_module = pefile
            except Exception:
                # Fall back gracefully when pefile is not installed.
                self._pe_module = None

    def analyze_file(self, file_path: Path) -> dict[str, object]:
        """Analyze PE metadata and suspicious import behavior.

        Parameters
        ----------
        file_path:
            Candidate executable path.

        Returns
        -------
        dict[str, object]
            Analysis summary including import list and indicators.
        """
        extension = file_path.suffix.lower()
        if extension not in {".exe", ".dll", ".sys", ".scr", ".ocx", ".com"}:
            return {
                "is_pe": False,
                "imports": [],
                "suspicious_apis": [],
                "threat_indicators": [],
                "analysis_mode": "skipped_non_pe",
            }

        if self._simulation_mode or self._pe_module is None:
            return self._mock_analysis(file_path)

        try:
            pe = self._pe_module.PE(str(file_path), fast_load=True)
            pe.parse_data_directories(
                directories=[self._pe_module.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )

            imports: list[str] = []
            suspicious: list[str] = []
            indicators: list[str] = []

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode(errors="ignore") if entry.dll else "unknown"
                    for imp in entry.imports:
                        if not imp.name:
                            continue
                        fn_name = imp.name.decode(errors="ignore")
                        full_name = f"{dll_name}:{fn_name}"
                        imports.append(full_name)
                        if fn_name in self.SUSPICIOUS_APIS:
                            suspicious.append(fn_name)

            if suspicious:
                indicators.append("Suspicious process injection or execution APIs imported")

            entropy_hint = ""
            if hasattr(pe, "sections") and pe.sections:
                high_entropy_sections = 0
                for section in pe.sections:
                    try:
                        if float(section.get_entropy()) >= 7.2:
                            high_entropy_sections += 1
                    except Exception:
                        continue
                if high_entropy_sections >= 2:
                    entropy_hint = "Multiple high-entropy PE sections detected"
                    indicators.append(entropy_hint)

            return {
                "is_pe": True,
                "imports": sorted(set(imports))[:250],
                "suspicious_apis": sorted(set(suspicious)),
                "threat_indicators": indicators,
                "analysis_mode": "pefile",
                "entropy_hint": entropy_hint,
            }
        except Exception as exc:
            return {
                "is_pe": True,
                "imports": [],
                "suspicious_apis": [],
                "threat_indicators": ["PE parse error"],
                "analysis_mode": "error",
                "error": str(exc),
            }

    def _mock_analysis(self, file_path: Path) -> dict[str, object]:
        """Generate deterministic simulated PE findings from file naming cues."""
        stem = file_path.stem.lower()
        base_imports = [
            "KERNEL32.dll:GetModuleHandleA",
            "KERNEL32.dll:GetProcAddress",
            "KERNEL32.dll:LoadLibraryA",
            "USER32.dll:MessageBoxA",
        ]
        suspicious: list[str] = []
        indicators: list[str] = []

        if any(tag in stem for tag in ("loader", "inject", "rat", "dropper", "payload")):
            suspicious.extend(["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"])
            indicators.append("Filename pattern resembles loader/injector behavior")

        if "macro" in stem or "script" in stem:
            suspicious.append("WinExec")
            indicators.append("Potential script-to-binary staging behavior")

        imports = base_imports + [f"KERNEL32.dll:{api}" for api in suspicious]
        return {
            "is_pe": True,
            "imports": imports,
            "suspicious_apis": sorted(set(suspicious)),
            "threat_indicators": indicators,
            "analysis_mode": "simulation" if self._simulation_mode else "mock_no_pefile",
        }

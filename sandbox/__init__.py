"""Sandbox and file-analysis engine package for HID Shield."""

__all__ = [
    "SandboxManager",
    "SandboxSession",
    "ShannonEntropyAnalyzer",
    "PEHeaderAnalyzer",
    "FileScanner",
    "WindowsSandboxBridge",
]


def __getattr__(name: str):
    if name == "SandboxManager" or name == "SandboxSession":
        from sandbox.sandbox_manager import SandboxManager, SandboxSession

        return {"SandboxManager": SandboxManager, "SandboxSession": SandboxSession}[name]

    if name == "ShannonEntropyAnalyzer":
        from sandbox.entropy_analyzer import ShannonEntropyAnalyzer

        return ShannonEntropyAnalyzer

    if name == "PEHeaderAnalyzer":
        from sandbox.pe_analyzer import PEHeaderAnalyzer

        return PEHeaderAnalyzer

    if name == "FileScanner":
        from sandbox.file_scanner import FileScanner

        return FileScanner

    if name == "WindowsSandboxBridge":
        from sandbox.windows_sandbox_bridge import WindowsSandboxBridge

        return WindowsSandboxBridge

    raise AttributeError(f"module 'sandbox' has no attribute {name!r}")

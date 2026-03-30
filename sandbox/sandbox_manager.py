"""Thread-safe sandbox lifecycle manager for isolated USB file analysis."""

from __future__ import annotations

import os
import shutil
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class SandboxSession:
    """Metadata container describing one sandbox session."""

    session_id: str
    sandbox_path: Path
    created_at: float


class SandboxManager:
    """Create, populate, and cleanup per-scan sandbox directories.

    The manager stores each session in `%APPDATA%/HIDShield/sandbox/<session_id>`
    and protects session state with a re-entrant lock for safe multi-thread usage.
    """

    def __init__(self) -> None:
        """Prepare root sandbox path and thread-safe session registry."""
        appdata_root = os.getenv("APPDATA")
        if appdata_root:
            self._root = Path(appdata_root) / "HIDShield" / "sandbox"
        else:
            self._root = Path.home() / ".hidshield" / "sandbox"

        self._root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._sessions: dict[str, SandboxSession] = {}

    def create_session(self) -> SandboxSession:
        """Create a new sandbox session directory with obfuscated style name."""
        with self._lock:
            nonce = uuid.uuid4().hex
            timestamp = f"{int(time.time())}"
            session_id = f"sess_{timestamp}_{nonce[:12]}"
            sandbox_path = self._root / session_id
            sandbox_path.mkdir(parents=True, exist_ok=False)

            session = SandboxSession(
                session_id=session_id,
                sandbox_path=sandbox_path,
                created_at=time.time(),
            )
            self._sessions[session_id] = session
            return session

    def shadow_copy_files(
        self,
        session_id: str,
        source_files: list[Path],
    ) -> list[Path]:
        """Shadow-copy source files into the session folder.

        Parameters
        ----------
        session_id:
            Existing sandbox session identifier.
        source_files:
            Concrete source file paths to copy.

        Returns
        -------
        list[Path]
            Paths of copied files inside sandbox.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise KeyError(f"Unknown sandbox session: {session_id}")

            copied: list[Path] = []
            for source in source_files:
                if not source.exists() or not source.is_file():
                    continue

                safe_name = f"{uuid.uuid4().hex[:8]}_{source.name}"
                target = session.sandbox_path / safe_name
                shutil.copy2(source, target)
                copied.append(target)

            return copied

    def create_mock_files(self, session_id: str, count: int) -> list[Path]:
        """Generate realistic synthetic file set for simulation-mode scanning."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise KeyError(f"Unknown sandbox session: {session_id}")

            templates = self._simulation_templates()
            created_files: list[Path] = []

            for index in range(max(1, count)):
                template = templates[index % len(templates)]
                file_name = template["name"].format(i=index + 1)
                file_bytes = template["bytes"]
                target = session.sandbox_path / file_name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(file_bytes)
                created_files.append(target)

            return created_files

    def cleanup_session(self, session_id: str) -> bool:
        """Delete the sandbox folder for a specific session."""
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is None:
                return False

            shutil.rmtree(session.sandbox_path, ignore_errors=True)
            return True

    def cleanup_all(self) -> None:
        """Remove all active session folders known to this manager instance."""
        with self._lock:
            session_ids = list(self._sessions.keys())

        for session_id in session_ids:
            self.cleanup_session(session_id)

    def _simulation_templates(self) -> list[dict[str, bytes | str]]:
        """Return byte templates that mimic mixed benign and malicious USB content."""
        return [
            {
                "name": "docs/employee_handbook_{i}.pdf",
                "bytes": b"%PDF-1.6\n" + b"A" * 2048,
            },
            {
                "name": "media/launch_promo_{i}.mp4",
                "bytes": os.urandom(8192),
            },
            {
                "name": "scripts/startup_sync_{i}.ps1",
                "bytes": b"Start-Process powershell -WindowStyle Hidden\n" + b"B" * 768,
            },
            {
                "name": "bin/firmware_updater_{i}.exe",
                "bytes": b"MZ" + os.urandom(12288),
            },
            {
                "name": "autorun.inf",
                "bytes": b"[autorun]\nopen=bin/firmware_updater_1.exe\naction=Run updater\n",
            },
            {
                "name": ".hidden/.cache_payload_{i}.dat",
                "bytes": os.urandom(4096),
            },
            {
                "name": "docs/macrosheet_{i}.docm",
                "bytes": b"PK\x03\x04" + b"macro" * 300,
            },
            {
                "name": "bin/loader_inject_{i}.dll",
                "bytes": b"MZ" + os.urandom(10240),
            },
        ]

"""Thread-safe sandbox lifecycle manager for isolated USB file analysis."""

from __future__ import annotations

import os
import shutil
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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

    def shadow_copy_from_device(
        self,
        session_id: str,
        device_payload: dict[str, Any],
        *,
        max_files: int = 500,
    ) -> list[Path]:
        """Copy real files from the detected USB mount path into the sandbox."""
        source_files = self.discover_device_files(device_payload, max_files=max_files)
        return self.shadow_copy_files(session_id=session_id, source_files=source_files)

    def discover_device_files(
        self,
        device_payload: dict[str, Any],
        *,
        max_files: int = 500,
    ) -> list[Path]:
        """Return file paths discovered from the connected USB volume."""
        mount_root = self._resolve_mount_root(device_payload)
        if mount_root is None:
            return []

        discovered: list[Path] = []
        for file_path in mount_root.rglob("*"):
            if len(discovered) >= max_files:
                break
            if not file_path.is_file():
                continue
            if self._is_ignored_path(file_path):
                continue
            discovered.append(file_path)
        return discovered

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

    def _resolve_mount_root(self, device_payload: dict[str, Any]) -> Path | None:
        """Resolve a usable mount root from USB monitor payload fields."""
        candidates = [
            device_payload.get("mount_point"),
            device_payload.get("drive_letter"),
            device_payload.get("device_path"),
            device_payload.get("path"),
        ]

        for candidate in candidates:
            if not candidate:
                continue
            try:
                path = Path(str(candidate))
                if path.exists() and path.is_dir():
                    return path
            except OSError:
                continue
        return None

    def _is_ignored_path(self, file_path: Path) -> bool:
        """Filter out OS metadata and inaccessible system files."""
        lowered = file_path.name.lower()
        if lowered in {"thumbs.db", "desktop.ini"}:
            return True
        if lowered.startswith("$"):
            return True
        return False

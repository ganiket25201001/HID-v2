import tempfile
import unittest
from pathlib import Path

from sandbox.sandbox_manager import SandboxManager


class SandboxManagerAdvancedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = SandboxManager()

    def test_cleanup_unknown_session_returns_false(self) -> None:
        self.assertFalse(self.manager.cleanup_session("missing-session"))

    def test_shadow_copy_skips_missing_files(self) -> None:
        session = self.manager.create_session()
        missing = Path("Z:/definitely/not/found.bin")

        copied = self.manager.shadow_copy_files(session.session_id, [missing])
        self.manager.cleanup_session(session.session_id)

        self.assertEqual(copied, [])

    def test_discover_returns_empty_for_invalid_mount_point(self) -> None:
        files = self.manager.discover_device_files({"mount_point": "Z:/does/not/exist"})
        self.assertEqual(files, [])

    def test_cleanup_all_removes_active_sessions(self) -> None:
        sessions = [self.manager.create_session() for _ in range(3)]

        for session in sessions:
            self.assertTrue(session.sandbox_path.exists())

        self.manager.cleanup_all()

        for session in sessions:
            self.assertFalse(session.sandbox_path.exists())

    def test_shadow_copy_keeps_original_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "sample.txt"
            source.write_text("payload", encoding="utf-8")

            session = self.manager.create_session()
            copied = self.manager.shadow_copy_files(session.session_id, [source])

            self.assertEqual(source.read_text(encoding="utf-8"), "payload")
            self.assertEqual(copied[0].read_text(encoding="utf-8"), "payload")

            self.manager.cleanup_session(session.session_id)


if __name__ == "__main__":
    unittest.main()

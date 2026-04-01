import tempfile
import unittest
from pathlib import Path

from sandbox.sandbox_manager import SandboxManager


class SandboxManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = SandboxManager()

    def test_discover_device_files_ignores_noise_and_respects_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.txt").write_text("a", encoding="utf-8")
            (root / "b.txt").write_text("b", encoding="utf-8")
            (root / "thumbs.db").write_text("cache", encoding="utf-8")
            (root / "$tmp.sys").write_text("ignored", encoding="utf-8")
            (root / "sub").mkdir()
            (root / "sub" / "c.txt").write_text("c", encoding="utf-8")

            files = self.manager.discover_device_files({"mount_point": str(root)}, max_files=2)

        self.assertEqual(len(files), 2)
        names = {p.name.lower() for p in files}
        self.assertNotIn("thumbs.db", names)
        self.assertFalse(any(name.startswith("$") for name in names))

    def test_shadow_copy_files_creates_namespaced_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "payload.exe"
            source.write_bytes(b"binary")

            session = self.manager.create_session()
            copied = self.manager.shadow_copy_files(session.session_id, [source])
            self.manager.cleanup_session(session.session_id)

        self.assertEqual(len(copied), 1)
        self.assertNotEqual(copied[0].name, source.name)
        self.assertTrue(copied[0].name.endswith(source.name))


if __name__ == "__main__":
    unittest.main()

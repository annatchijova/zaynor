import tempfile
import unittest
from pathlib import Path

from zaynor.sandbox import SandboxConfig, SandboxError, hash_evidence, read_evidence, run_worker_command


class SandboxContractTests(unittest.TestCase):
    def test_hash_precedes_read_and_returns_stable_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "event.json").write_bytes(b'{"event":"synthetic"}')
            data, digest = read_evidence(root, "event.json")
            _, second_digest, size = hash_evidence(root, "event.json")
            self.assertEqual(data, b'{"event":"synthetic"}')
            self.assertEqual(digest, second_digest)
            self.assertEqual(size, len(data))

    def test_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root.parent / "outside-zaynor-evidence.txt"
            outside.write_text("not evidence", encoding="utf-8")
            try:
                with self.assertRaises(SandboxError):
                    hash_evidence(root, "../outside-zaynor-evidence.txt")
            finally:
                outside.unlink()

    def test_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.txt"
            target.write_text("secret", encoding="utf-8")
            link = root / "link.txt"
            link.symlink_to(target)
            with self.assertRaises(SandboxError):
                hash_evidence(root, "link.txt")

    def test_worker_command_requires_explicit_allowlist(self):
        with self.assertRaises(SandboxError):
            run_worker_command(["/bin/true"])
        returncode, stdout, stderr = run_worker_command(
            ["/bin/true"], SandboxConfig(allowed_commands=("/bin/true",))
        )
        self.assertEqual((returncode, stdout, stderr), (0, b"", b""))


if __name__ == "__main__":
    unittest.main()

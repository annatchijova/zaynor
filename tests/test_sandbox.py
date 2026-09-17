import tempfile
import time
from pathlib import Path

import pytest

from zaynor.sandbox import SandboxConfig, SandboxError, hash_evidence, read_evidence, run_worker_command


def test_hash_precedes_read_and_returns_stable_identity():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "event.json").write_bytes(b'{"event":"synthetic"}')
        data, digest = read_evidence(root, "event.json")
        _, second_digest, size = hash_evidence(root, "event.json")
        assert data == b'{"event":"synthetic"}'
        assert digest == second_digest
        assert size == len(data)


def test_path_traversal_is_rejected():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        outside = root.parent / "outside-zaynor-evidence.txt"
        outside.write_text("not evidence", encoding="utf-8")
        try:
            with pytest.raises(SandboxError):
                hash_evidence(root, "../outside-zaynor-evidence.txt")
        finally:
            outside.unlink()


def test_symlink_is_rejected():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        target = root / "target.txt"
        target.write_text("secret", encoding="utf-8")
        link = root / "link.txt"
        link.symlink_to(target)
        with pytest.raises(SandboxError):
            hash_evidence(root, "link.txt")


def test_worker_command_requires_explicit_allowlist():
    with pytest.raises(SandboxError):
        run_worker_command(["/bin/true"])
    returncode, stdout, stderr = run_worker_command(["/bin/true"], SandboxConfig(allowed_commands=("/bin/true",)))
    assert (returncode, stdout, stderr) == (0, b"", b"")


def test_oversized_output_raises_sandbox_error_not_process_lookup_error():
    """Regression for the bug found by induction during review: the
    original implementation buffered the full output via communicate()
    before checking max_output_bytes, and the kill-on-overflow path then
    crashed with ProcessLookupError because the process had already
    exited. Both are fixed: the read is bounded while streaming, and
    killing an already-exited process is not an error.
    """
    cfg = SandboxConfig(
        allowed_commands=("/usr/bin/python3",), max_output_bytes=1000, timeout_seconds=10
    )
    command = [
        "/usr/bin/python3",
        "-c",
        "import sys; sys.stdout.buffer.write(b'A' * 5_000_000)",
    ]
    with pytest.raises(SandboxError, match="output exceeded"):
        run_worker_command(command, cfg)


def test_oversized_output_does_not_wait_for_full_buffering():
    """The bound is enforced while reading, not after the child exits —
    a command that keeps writing past the limit gets cut off instead of
    running to completion first.
    """
    cfg = SandboxConfig(
        allowed_commands=("/usr/bin/python3",), max_output_bytes=1000, timeout_seconds=10
    )
    command = [
        "/usr/bin/python3",
        "-c",
        "import sys,time\n"
        "while True:\n"
        "    sys.stdout.buffer.write(b'A' * 65536)\n"
        "    sys.stdout.flush()\n",
    ]
    with pytest.raises(SandboxError, match="output exceeded"):
        run_worker_command(command, cfg)


def test_evidence_read_rejects_symlink_swapped_after_validation():
    """The O_NOFOLLOW + fstat fix: even a path that resolves cleanly at
    validation time is rejected if what actually gets opened is not a
    regular file.
    """
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        real = root / "real.txt"
        real.write_text("ok", encoding="utf-8")
        # A regular file passes _confined_regular_file's checks; swap it
        # for a symlink right before the open to simulate the TOCTOU window.
        from zaynor import sandbox as sandbox_module

        original_open = sandbox_module._open_confined

        def swap_then_open(path):
            outside = root.parent / "swap-target.txt"
            outside.write_text("secret", encoding="utf-8")
            path.unlink()
            path.symlink_to(outside)
            try:
                return original_open(path)
            finally:
                outside.unlink(missing_ok=True)

        sandbox_module._open_confined = swap_then_open
        try:
            with pytest.raises(SandboxError):
                read_evidence(root, "real.txt")
        finally:
            sandbox_module._open_confined = original_open


def test_worker_output_limit_is_enforced_during_collection():
    config = SandboxConfig(
        allowed_commands=("/bin/sh",), max_output_bytes=4096, timeout_seconds=10
    )
    started = time.monotonic()
    with pytest.raises(SandboxError, match="output exceeded"):
        run_worker_command(
            ["/bin/sh", "-c", "head -c 2000000 /dev/zero; sleep 30"], config
        )
    assert time.monotonic() - started < 6


def test_worker_timeout_is_enforced_while_child_is_running():
    config = SandboxConfig(allowed_commands=("/bin/sh",), timeout_seconds=1)
    started = time.monotonic()
    with pytest.raises(SandboxError, match="exceeded its timeout"):
        run_worker_command(["/bin/sh", "-c", "printf hi; sleep 6"], config)
    assert time.monotonic() - started < 4

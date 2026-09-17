"""Bounded evidence-worker primitives for ZAYNOR.

ADAPTED from Codex's `zaynor/sandbox.py` (PR #1, `samuel` branch), moved
under `src/zaynor/` to match this package's existing layout (avoids two
competing top-level `zaynor` packages), with three fixes found and
confirmed by induction during review:

1. `run_worker_command` used `subprocess.communicate()`, which only
   returns after the child has already exited and has already buffered
   its *entire* stdout/stderr in the parent process's memory — so
   `max_output_bytes` was checked only after the bytes it was meant to
   cap were already fully collected. A command emitting far more than the
   configured limit ballooned parent memory before being "rejected".
   Fixed by reading both pipes incrementally (`selectors`) and cutting the
   process off the moment either stream crosses the limit, instead of
   after the fact.
2. The over-limit path then called `os.killpg(process.pid, 9)` on a
   process that, in the `communicate()` version, had by definition already
   exited (communicate() waits for exit) — confirmed by induction: this
   raised an unhandled `ProcessLookupError` instead of `SandboxError`.
   Fixed by treating "already exited" as success, not an error.
3. Evidence files were opened with plain `Path.open("rb")` — a
   check-then-open gap between the symlink/allowlist validation and the
   actual read. Fixed with `os.open(..., os.O_NOFOLLOW)` plus an fstat
   check that the opened descriptor is still a regular file, mirroring
   `path_guard.py`'s `safe_open`.

This module is for the isolated evidence worker only. The API process must
not import it to inspect artifact bytes. It hashes before reading, confines
paths to the per-job evidence directory, rejects symlinks, and bounds reads
and worker commands. It does not parse, render, OCR, decompress, or infer
from artifacts.
"""

from __future__ import annotations

import hashlib
import os
import resource
import selectors
import stat
import subprocess
import time
import contextlib
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


class SandboxError(RuntimeError):
    """A worker request cannot be performed within the declared contract."""


@dataclass(frozen=True)
class SandboxConfig:
    allowed_commands: tuple[str, ...] = ()
    max_read_bytes: int = 10 * 1024 * 1024
    max_output_bytes: int = 10 * 1024 * 1024
    max_cpu_seconds: int = 30
    max_memory_bytes: int = 512 * 1024 * 1024
    timeout_seconds: int = 35


def _confined_regular_file(evidence_dir: Path, requested: str) -> Path:
    root = evidence_dir.resolve(strict=True)
    raw_candidate = root / requested
    try:
        relative = raw_candidate.relative_to(root)
    except ValueError as exc:
        raise SandboxError("evidence path must be relative to the job directory") from exc
    current = root
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            raise SandboxError("evidence path contains a symlink")
    candidate = raw_candidate.resolve(strict=True)
    if root == candidate or root not in candidate.parents:
        raise SandboxError("evidence path escapes the job directory")
    if candidate.is_symlink() or not candidate.is_file():
        raise SandboxError("evidence path is not a regular, non-symlink file")
    return candidate


def _open_confined(path: Path):
    """Open a validated path with O_NOFOLLOW and an fstat re-check, so a
    file swapped for a symlink between validation and open is rejected at
    open time rather than silently followed.
    """
    try:
        if hasattr(os, "O_NOFOLLOW"):
            fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
        else:  # pragma: no cover - no non-POSIX target for this project
            fd = os.open(str(path), os.O_RDONLY)
    except OSError as exc:
        raise SandboxError(f"evidence path could not be opened safely: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SandboxError("evidence path is not a regular file")
        return os.fdopen(fd, "rb")
    except Exception:
        os.close(fd)
        raise


_DEFAULT_SANDBOX_CONFIG = SandboxConfig()


def hash_evidence(evidence_dir: Path, requested: str, config: SandboxConfig | None = None) -> tuple[Path, str, int]:
    """Hash one bounded evidence file before any caller receives its bytes."""
    resolved = _DEFAULT_SANDBOX_CONFIG if config is None else config
    path = _confined_regular_file(evidence_dir, requested)
    digest = hashlib.sha256()
    size = 0
    with _open_confined(path) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            if size > resolved.max_read_bytes:
                raise SandboxError("evidence file exceeds the read limit")
            digest.update(chunk)
    return path, digest.hexdigest(), size


def read_evidence(evidence_dir: Path, requested: str, config: SandboxConfig | None = None) -> tuple[bytes, str]:
    """Return bytes only after hashing the same bounded file."""
    resolved = _DEFAULT_SANDBOX_CONFIG if config is None else config
    path = _confined_regular_file(evidence_dir, requested)
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    total = 0
    with _open_confined(path) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(chunk)
            if total > resolved.max_read_bytes:
                raise SandboxError("evidence file exceeds the read limit")
            digest.update(chunk)
            chunks.append(chunk)
    return b"".join(chunks), digest.hexdigest()


def _limit_resources(config: SandboxConfig) -> None:
    resource.setrlimit(resource.RLIMIT_AS, (config.max_memory_bytes, config.max_memory_bytes))
    resource.setrlimit(resource.RLIMIT_CPU, (config.max_cpu_seconds, config.max_cpu_seconds + 2))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (config.max_output_bytes, config.max_output_bytes))


def _kill_process_group(pid: int) -> None:
    """Best-effort kill. The process may already have exited (it finished
    on its own, or a prior check already killed it) — that is success, not
    an error, so ProcessLookupError is swallowed here rather than left to
    crash the caller.
    """
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pid, 9)


def _stop_process(process: subprocess.Popen) -> None:
    """Stop a worker promptly and reap it without waiting on descendants."""
    _kill_process_group(process.pid)
    try:
        process.kill()
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()


def _read_bounded_pipes(
    process: subprocess.Popen, config: SandboxConfig
) -> tuple[bytes, bytes]:
    """Read stdout/stderr incrementally, enforcing `max_output_bytes` and
    `timeout_seconds` DURING collection — not after `communicate()` has
    already buffered everything.
    """
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    open_streams = {"stdout", "stderr"}
    deadline = time.monotonic() + config.timeout_seconds

    try:
        while open_streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process_group(process.pid)
                raise subprocess.TimeoutExpired(process.args, config.timeout_seconds)

            for key, _ in selector.select(timeout=min(remaining, 0.5)):
                name = key.data
                # BufferedReader.read() may wait for the requested size even
                # after select reports the pipe readable. read1() consumes
                # only bytes currently available, preserving the deadline.
                chunk = key.fileobj.read1(65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    open_streams.discard(name)
                    continue
                buffers[name].extend(chunk)
                if len(buffers[name]) > config.max_output_bytes:
                    _stop_process(process)
                    raise SandboxError("worker output exceeded its limit")
    except subprocess.TimeoutExpired:
        _stop_process(process)
        raise
    finally:
        selector.close()

    remaining = deadline - time.monotonic()
    try:
        process.wait(timeout=max(remaining, 0))
    except subprocess.TimeoutExpired:
        _stop_process(process)
        raise

    return bytes(buffers["stdout"]), bytes(buffers["stderr"])


def run_worker_command(command: Sequence[str], config: SandboxConfig | None = None) -> tuple[int, bytes, bytes]:
    """Run an already-allowlisted worker command with POSIX resource limits
    and a real streaming bound on its output.

    Command allowlisting, filesystem isolation, and network isolation are
    the worker launcher contract; this function supplies process-level
    bounds plus the output-size/timeout enforcement.
    """
    resolved = _DEFAULT_SANDBOX_CONFIG if config is None else config
    if not command or any("\x00" in part for part in command):
        raise SandboxError("worker command must be non-empty and NUL-free")
    if not resolved.allowed_commands or command[0] not in resolved.allowed_commands:
        raise SandboxError("worker command is not in the explicit allowlist")

    process = subprocess.Popen(
        list(command),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        preexec_fn=lambda: _limit_resources(resolved),
        close_fds=True,
    )
    try:
        stdout, stderr = _read_bounded_pipes(process, resolved)
    except subprocess.TimeoutExpired as exc:
        _stop_process(process)
        raise SandboxError("worker command exceeded its timeout") from exc

    return process.returncode, stdout, stderr

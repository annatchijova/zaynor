"""Bounded evidence-worker primitives for ZAYNOR.

This module is for the isolated evidence worker only. The API process must not
import it to inspect artifact bytes. It hashes before reading, confines paths to
the per-job evidence directory, rejects symlinks, and bounds reads and worker
commands. It does not parse, render, OCR, decompress, or infer from artifacts.
"""

from __future__ import annotations

import hashlib
import os
import resource
import selectors
import stat
import subprocess
import time
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
    """Open a validated evidence path without following a replacement symlink."""
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(path), flags)
    except OSError as exc:
        raise SandboxError(f"evidence path could not be opened safely: {exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise SandboxError("evidence path is not a regular file")
        return os.fdopen(fd, "rb")
    except Exception:
        os.close(fd)
        raise


def hash_evidence(evidence_dir: Path, requested: str, config: SandboxConfig = SandboxConfig()) -> tuple[Path, str, int]:
    """Hash one bounded evidence file before any caller receives its bytes."""
    path = _confined_regular_file(evidence_dir, requested)
    digest = hashlib.sha256()
    total = 0
    with _open_confined(path) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(chunk)
            if total > config.max_read_bytes:
                raise SandboxError("evidence file exceeds the read limit")
            digest.update(chunk)
    return path, digest.hexdigest(), total


def read_evidence(evidence_dir: Path, requested: str, config: SandboxConfig = SandboxConfig()) -> tuple[bytes, str]:
    """Return bytes only after hashing the same bounded file."""
    path = _confined_regular_file(evidence_dir, requested)
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    total = 0
    with _open_confined(path) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(chunk)
            if total > config.max_read_bytes:
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
    try:
        os.killpg(pid, 9)
    except ProcessLookupError:
        pass


def _close_process_pipes(process: subprocess.Popen) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()


def _read_bounded_pipes(process: subprocess.Popen, config: SandboxConfig) -> tuple[bytes, bytes]:
    """Collect worker output incrementally under size and time bounds."""
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
                chunk = key.fileobj.read1(65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    open_streams.discard(name)
                    continue
                buffers[name].extend(chunk)
                if len(buffers[name]) > config.max_output_bytes:
                    _kill_process_group(process.pid)
                    raise SandboxError("worker output exceeded its limit")
    except BaseException:
        _kill_process_group(process.pid)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _kill_process_group(process.pid)
            process.wait()
        _close_process_pipes(process)
        raise
    finally:
        selector.close()

    remaining = deadline - time.monotonic()
    try:
        process.wait(timeout=max(remaining, 0))
    except subprocess.TimeoutExpired:
        _kill_process_group(process.pid)
        process.wait(timeout=5)
        raise
    _close_process_pipes(process)
    return bytes(buffers["stdout"]), bytes(buffers["stderr"])


def run_worker_command(command: Sequence[str], config: SandboxConfig = SandboxConfig()) -> tuple[int, bytes, bytes]:
    """Run an allowlisted worker with POSIX resource and output limits."""
    if not command or any("\x00" in part for part in command):
        raise SandboxError("worker command must be non-empty and NUL-free")
    if not config.allowed_commands or command[0] not in config.allowed_commands:
        raise SandboxError("worker command is not in the explicit allowlist")
    process = subprocess.Popen(
        list(command),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        preexec_fn=lambda: _limit_resources(config),
        close_fds=True,
    )
    try:
        stdout, stderr = _read_bounded_pipes(process, config)
    except subprocess.TimeoutExpired as exc:
        raise SandboxError("worker command exceeded its timeout") from exc
    return process.returncode, stdout, stderr

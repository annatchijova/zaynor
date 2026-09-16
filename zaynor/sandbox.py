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


def hash_evidence(evidence_dir: Path, requested: str, config: SandboxConfig = SandboxConfig()) -> tuple[Path, str, int]:
    """Hash one bounded evidence file before any caller receives its bytes."""
    path = _confined_regular_file(evidence_dir, requested)
    size = path.stat().st_size
    if size > config.max_read_bytes:
        raise SandboxError("evidence file exceeds the read limit")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return path, digest.hexdigest(), size


def read_evidence(evidence_dir: Path, requested: str, config: SandboxConfig = SandboxConfig()) -> tuple[bytes, str]:
    """Return bytes only after hashing the same bounded file."""
    path = _confined_regular_file(evidence_dir, requested)
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    total = 0
    with path.open("rb") as stream:
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


def run_worker_command(command: Sequence[str], config: SandboxConfig = SandboxConfig()) -> tuple[int, bytes, bytes]:
    """Run an already-allowlisted worker command with POSIX resource limits.

    Command allowlisting, filesystem isolation, and network isolation are the
    worker launcher contract; this function supplies only process-level bounds.
    """
    if not command or any("\x00" in part for part in command):
        raise SandboxError("worker command must be non-empty and NUL-free")
    if not config.allowed_commands or command[0] not in config.allowed_commands:
        raise SandboxError("worker command is not in the explicit allowlist")
    start = time.monotonic()
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
        stdout, stderr = process.communicate(timeout=config.timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        os.killpg(process.pid, 9)
        process.wait()
        raise SandboxError("worker command exceeded its timeout") from exc
    if len(stdout) > config.max_output_bytes or len(stderr) > config.max_output_bytes:
        os.killpg(process.pid, 9)
        raise SandboxError("worker output exceeded its limit")
    if time.monotonic() - start > config.timeout_seconds:
        raise SandboxError("worker command exceeded its wall-clock limit")
    return process.returncode, stdout, stderr

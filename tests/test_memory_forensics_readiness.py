"""Confirms the memory/Volatility3 path Mode 1 actually uses is
operationally ready, without a real memory dump (sourcing one from Digital
Corpora is separate, deferred work — see docs/implementation-plan.en.md).

Corrects a claim from an earlier pass (red-team round 5, 2026-09-16): this
used to check `vigia.sift.memory_forensics.Volatility3Interface`, but that
module is never actually invoked by Mode 1. The root `sift_orchestrator.py`
shim `vigia_agent.py` imports does its own direct Volatility3 subprocess
call (`_analyze_memory_vol3`/`_vol3_run`, `vol -f <path> <plugin>`) for
memory, in every evidence combination — confirmed by reading its
`analyze()`. This test exercises that real mechanism instead: the binary
resolution gap it has (`vol` vs the fallback name `"vol3"`) and ZAYNOR's
fix for it (`ensure_vol3_alias_on_path` in `zaynor_mode1_executor.py`).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from zaynor.zaynor_mode1_executor import ensure_vol3_alias_on_path

from zaynor.vendored_engine import VENDORED_ENGINE_PATH

VIGIA_REPO_PATH = VENDORED_ENGINE_PATH

pytestmark = pytest.mark.skipif(
    not VIGIA_REPO_PATH.is_dir(),
    reason="vendored VIGÍA engine (vendor/vigia_engine/) is missing",
)


def test_real_vol_binary_is_installed():
    """The binary VIGÍA's Mode-1 memory path ultimately needs — regardless
    of which name it resolves it under — must actually be present.
    """
    assert shutil.which("vol") is not None


def test_vol3_alias_makes_vigias_fallback_name_resolve_and_run():
    """Reproduces the real gap and confirms the fix, by induction, not by
    reading code: `sift_orchestrator.py::_vol3_run` invokes the bare name
    `"vol3"` when its sibling-of-interpreter check fails (the case in this
    environment, since `pip install --user volatility3` puts the `vol`
    console script in the user site's bin, not next to `sys.executable`).
    Before the fix, `subprocess.run(["vol3", ...])` raises
    `FileNotFoundError` — VIGÍA catches it generically and returns a silent
    zero-signal result. After `ensure_vol3_alias_on_path`, the same
    subprocess call must actually run the real `vol` binary.
    """
    env = dict(os.environ)
    with tempfile.TemporaryDirectory() as shim_parent:
        ensure_vol3_alias_on_path(env, Path(shim_parent))
        result = subprocess.run(
            ["vol3", "-h"], env=env, capture_output=True, text=True, timeout=30
        )
    assert result.returncode == 0
    assert "usage" in result.stdout.lower()


def test_vol3_alias_is_a_noop_when_vol3_already_resolves(tmp_path):
    """If a real `vol3` were ever on PATH, the shim must not shadow it with
    a `vol`-pointing alias — `ensure_vol3_alias_on_path` checks
    `shutil.which("vol3")` before creating anything.
    """
    real_vol3 = tmp_path / "vol3"
    real_vol3.write_text("#!/bin/sh\necho REAL_VOL3\n")
    real_vol3.chmod(0o755)

    env = dict(os.environ)
    env["PATH"] = f"{tmp_path}{os.pathsep}{env.get('PATH', '')}"
    with tempfile.TemporaryDirectory() as shim_parent:
        ensure_vol3_alias_on_path(env, Path(shim_parent))
        result = subprocess.run(
            ["vol3"], env=env, capture_output=True, text=True, timeout=30
        )
    assert result.stdout.strip() == "REAL_VOL3"

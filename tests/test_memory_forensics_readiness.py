"""Confirms the memory/Volatility3 path is operationally ready, without a
real memory dump (sourcing one from Digital Corpora is separate, deferred
work — see docs/implementation-plan.en.md).

No new ZAYNOR code exists for this path on purpose (AGENTS.md §2.1): once
a `.raw`/`.vmem`/`.mem`/`.dmp` file sits in a case's evidence directory,
`zaynor_mode1_executor.run_vigia_mode1` already routes it through the same
mechanism confirmed for registry/prefetch/browser/event-log — it just sets
`VIGIA_ALLOWED_DUMP_PATHS` to the evidence root the same way it does
`VIGIA_ALLOWED_REGISTRY_PATHS`. This test only confirms the external
dependency (the `vol` binary) that mechanism relies on is actually present
and runnable — not that a real analysis succeeds, which needs real data.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

VIGIA_REPO_PATH = Path("/home/labestiadevigia/vigia-repo")

pytestmark = pytest.mark.skipif(
    not VIGIA_REPO_PATH.is_dir(),
    reason="vigia-repo checkout not present on this machine",
)


def test_volatility3_binary_is_installed_and_runnable():
    """`Volatility3Interface()`'s constructor itself runs `vol --version`
    and would raise `RuntimeError` if the binary were missing or timed out
    — constructing it without raising is the real, meaningful check here.

    `interface.version` legitimately comes back "unknown" in this
    environment: `vol --version` exits 2 ("unrecognized arguments:
    --version") on the installed Volatility3 2.28.0 (confirmed via
    `pip show volatility3`) — this specific CLI build doesn't support that
    flag, so the regex in `_detect_version()` has nothing to match. That's
    VIGÍA's own graceful degradation (catches only TimeoutExpired/
    FileNotFoundError, returns "unknown" otherwise), not a bug being
    reported here — real plugin invocation (`vol -f <dump> <plugin>`, what
    `_run_plugin` actually uses) doesn't depend on `--version` at all.
    """
    sys.path.insert(0, str(VIGIA_REPO_PATH))
    try:
        from vigia.sift.memory_forensics import Volatility3Interface
    finally:
        sys.path.remove(str(VIGIA_REPO_PATH))

    interface = Volatility3Interface()  # would raise if `vol` were missing
    assert interface.version == "unknown"  # documents the known CLI-flag gap above

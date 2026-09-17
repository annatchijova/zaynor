"""Optional HMAC-keyed anchor for ZAYNOR's hash chains.

A plain SHA-256 hash chain (`audit_log.py`, `investigation_log.py`) proves
the chain is internally consistent — each entry references the one before
it — but says nothing about who could have produced it. Anyone with write
access to the log file can recompute an entirely new, internally-consistent
chain from scratch in milliseconds; a bare SHA-256 chain cannot tell that
apart from the real history. An HMAC keyed with a secret only the real
writer holds closes that gap: recomputing the chain without the key
produces `entry_hmac` values that do not match, so a forged chain is
distinguishable from the genuine one even by an attacker who can rewrite
every hash in it.

Same pattern already used by VIGÍA's own `vigia/core/tool_log_chain.py`
(`entry_hmac`/`chain_tip_hmac`, gated on `VIGIA_HMAC_KEY[_FILE]`) — this
module is ZAYNOR's own analogous, independently-written implementation,
not an import of VIGÍA's (AGENTS.md §2.1: this is ZAYNOR's own audit
trail, a different concern from the VIGÍA-integration boundary that
section governs).

Deliberately no ephemeral key: a chain signed with a key nobody can
reproduce is indistinguishable from a tampered one. Without a configured
key, the chain operates hash-only — documented as a caveat, never
silently upgraded to "verified" and never a hard failure either.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
from pathlib import Path

_HMAC_KEY_ENV = "ZAYNOR_HMAC_KEY"
_HMAC_KEY_FILE_ENV = "ZAYNOR_HMAC_KEY_FILE"


def resolve_hmac_key() -> bytes | None:
    """Resolve the HMAC key from the environment: `ZAYNOR_HMAC_KEY` (hex)
    or `ZAYNOR_HMAC_KEY_FILE` (path to raw key bytes). `None` if neither is
    configured — the caller must treat that as "hash-only mode", not an
    error.
    """
    key_hex = os.environ.get(_HMAC_KEY_ENV, "").strip()
    if key_hex:
        try:
            return bytes.fromhex(key_hex)
        except ValueError:
            pass
    key_file = os.environ.get(_HMAC_KEY_FILE_ENV, "").strip()
    if key_file:
        path = Path(key_file)
        if path.is_file():
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                raise ValueError("HMAC key file must not be readable by group or other users")
            return path.read_bytes().strip()
    return None


def compute_entry_hmac(key: bytes, entry_hash: str) -> str:
    """HMAC-SHA256 of one entry's own (unkeyed) hash."""
    return hmac.new(key, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()

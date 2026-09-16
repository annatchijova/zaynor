"""SHA-256 streaming hash — reimplemented small rather than pulled from
VIGÍA's `generate_forensic_hash` (ADR: that tool is an MCP-registered
function coupled to the SIFT bridge's session/mount state; this is a few
lines of stdlib with no such coupling, and it is used only for byte
identity/integrity under a manifest, never presented as proof of truth,
authorship, or completeness).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

_CHUNK_SIZE = 1024 * 1024


def sha256_file(path: str | Path) -> str:
    """Return the hex SHA-256 digest of a file's bytes, read in chunks so
    the whole file never has to fit in memory at once.
    """
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()

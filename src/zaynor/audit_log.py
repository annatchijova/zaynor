"""Append-only, hash-chained JSONL audit log.

REIMPLEMENTED SMALL rather than adapted from VIGÍA's
`vigia/core/tool_log_chain.py` / `execution_logger.py`: those carry a
schema (Peirce-layer fields, epistemic-check events, an `output_boundary`
module) built for VIGÍA's own investigation semantics, which ZAYNOR does
not have yet at this stage of the pipeline (see AGENTS.md "Scope: the
hybrid pipeline" — stages 1-4). What's reused is the *pattern*: each entry
hashes the previous entry, so modifying, reordering, or dropping a past
entry breaks the chain from that point forward. A separate tail-anchor
file (VIGÍA's `chain_tip_sha256` pattern, `vigia/core/tool_log_chain.py`)
closes the truncation gap that plain hash-chaining leaves open: deleting
the last N lines of an append-only file leaves everything *remaining*
internally consistent, since nothing inside the array itself references
what came after it. Confirmed by induction during the red-team pass on
this module (see docs/red-team) before this anchor was added — `verify()`
returned `True` against a log with its last entry deleted.

`entry_hmac`/`chain_tip_hmac` (see `hmac_chain.py`) close the remaining
gap: plain SHA-256, even with the tail anchor, only proves the chain is
*internally consistent* — anyone with write access to the log file can
recompute an entirely new, consistent chain from scratch. HMAC-SHA256
keyed with `ZAYNOR_HMAC_KEY[_FILE]` cannot be reproduced without that key,
so a wholesale-forged chain is distinguishable from the genuine one.
Optional, same as VIGÍA's own `VIGIA_HMAC_KEY`: absent, the log operates
in hash-only mode, reported as a caveat by `verify_with_report`, never a
silent "verified."
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from zaynor.hmac_chain import compute_entry_hmac, resolve_hmac_key

_GENESIS_HASH = "0" * 64


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    action: str
    detail: dict[str, Any]
    prev_hash: str
    entry_hash: str
    entry_hmac: str | None = None


class AuditLog:
    """Appends entries to a JSONL file, each one hash-chained to the last.

    Not thread-safe and not process-safe by design: this is a single-writer
    audit trail for one investigation run, not a shared service.
    """

    def __init__(self, log_path: str | Path, *, hmac_key: bytes | None = None):
        self._path = Path(log_path)
        self._tail_path = self._path.with_suffix(self._path.suffix + ".tail")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._hmac_key = hmac_key if hmac_key is not None else resolve_hmac_key()
        self._seq, self._prev_hash = self._resume()

    def _resume(self) -> tuple[int, str]:
        if not self._path.exists():
            return 0, _GENESIS_HASH
        seq = 0
        prev_hash = _GENESIS_HASH
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                seq = record["seq"]
                prev_hash = record["entry_hash"]
        return seq, prev_hash

    def append(self, action: str, detail: dict[str, Any]) -> AuditEntry:
        seq = self._seq + 1
        body = {"seq": seq, "action": action, "detail": detail, "prev_hash": self._prev_hash}
        entry_hash = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
        record = {**body, "entry_hash": entry_hash}
        tail_anchor: dict[str, Any] = {"seq": seq, "entry_hash": entry_hash}
        if self._hmac_key is not None:
            entry_hmac = compute_entry_hmac(self._hmac_key, entry_hash)
            record["entry_hmac"] = entry_hmac
            tail_anchor["chain_tip_hmac"] = compute_entry_hmac(self._hmac_key, entry_hash)

        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(_canonical(record) + "\n")

        # Tail anchor, written OUTSIDE the truncatable array: an attacker
        # who deletes the last line(s) of the JSONL file must also update
        # this sidecar to the *new* last entry, or verify() catches the
        # mismatch. Overwritten (not appended) — it always holds only the
        # current tip. `chain_tip_hmac`, when a key is configured, closes
        # the residual gap plain SHA-256 leaves: recomputable by anyone
        # with write access, same limit as `entry_hash` without
        # `entry_hmac`.
        self._tail_path.write_text(_canonical(tail_anchor), encoding="utf-8")

        self._seq = seq
        self._prev_hash = entry_hash
        return AuditEntry(**record)

    @staticmethod
    def verify(log_path: str | Path, *, hmac_key: bytes | None = None) -> bool:
        """Recompute every entry's hash from its own fields, confirm each
        one references the true previous entry, and confirm the sidecar
        tail-anchor file (if present) matches the JSONL's actual last entry
        — this is what catches a tail-truncation attack that plain
        hash-chaining alone does not.

        A missing tail-anchor file is backward-compatible (a log written
        before this anchor existed), not a failure: the gap is reported as
        a caveat via `verify_with_report`, not silently treated as valid
        when the caller actually needs the truncation guarantee.

        `hmac_key` defaults to `resolve_hmac_key()` (the same environment
        resolution `AuditLog.__init__` uses) — pass an explicit key or
        `b""`-truthy-check-avoiding sentinel only to override that.
        """
        ok, _ = AuditLog.verify_with_report(log_path, hmac_key=hmac_key)
        return ok

    @staticmethod
    def verify_with_report(
        log_path: str | Path, *, hmac_key: bytes | None = None
    ) -> tuple[bool, str]:
        path = Path(log_path)
        if not path.exists():
            return True, "no log file"
        key = hmac_key if hmac_key is not None else resolve_hmac_key()

        prev_hash = _GENESIS_HASH
        last_seq = 0
        last_hash = _GENESIS_HASH
        saw_any = False
        saw_any_hmac = False
        saw_any_missing_hmac = False
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                saw_any = True
                record = json.loads(line)
                if record["prev_hash"] != prev_hash:
                    return False, f"chain break before seq={record['seq']}"
                body = {
                    "seq": record["seq"],
                    "action": record["action"],
                    "detail": record["detail"],
                    "prev_hash": record["prev_hash"],
                }
                expected_hash = hashlib.sha256(
                    _canonical(body).encode("utf-8")
                ).hexdigest()
                if expected_hash != record["entry_hash"]:
                    return False, f"entry_hash mismatch at seq={record['seq']}"
                entry_hmac = record.get("entry_hmac")
                if entry_hmac is not None:
                    saw_any_hmac = True
                    if key is not None and not hmac.compare_digest(
                        compute_entry_hmac(key, expected_hash), entry_hmac
                    ):
                        return False, f"entry_hmac mismatch at seq={record['seq']} (wrong key or forged chain)"
                else:
                    saw_any_missing_hmac = True
                    if key is not None and saw_any_hmac:
                        return False, f"missing entry_hmac at seq={record['seq']}"
                prev_hash = record["entry_hash"]
                last_seq = record["seq"]
                last_hash = record["entry_hash"]

        tail_path = path.with_suffix(path.suffix + ".tail")
        if not tail_path.exists():
            if saw_any:
                return True, "chain valid; no tail anchor present (truncation not covered)"
            return True, "empty log"

        tail = json.loads(tail_path.read_text(encoding="utf-8"))
        if tail["seq"] != last_seq or tail["entry_hash"] != last_hash:
            return False, "tail anchor does not match the log's actual last entry (truncation)"
        tail_hmac = tail.get("chain_tip_hmac")
        if tail_hmac is not None and key is not None:
            if not hmac.compare_digest(compute_entry_hmac(key, last_hash), tail_hmac):
                return False, "tail anchor entry_hmac mismatch (wrong key or forged tail)"

        caveats = []
        if not saw_any_hmac:
            if key is not None and saw_any:
                return False, "HMAC key supplied but chain has no entry_hmac values"
            caveats.append("hash-only mode: no HMAC anchor on this chain")
        else:
            if key is None:
                caveats.append("entry_hmac present but not verified (no key supplied)")
            if saw_any_missing_hmac:
                return False, "chain mixes HMAC and non-HMAC entries"

        message = "chain valid; tail anchor matches"
        if caveats:
            message += " (" + "; ".join(caveats) + ")"
        return True, message

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

Genesis is bound to `case_id` (Anna, adapting Mneme's
`custody.py::genesis_hash` design — same idea, one project down: a
per-memory chain there, a per-case chain here): `genesis = sha256(b"ZAYNOR_AUDIT_GENESIS:" + case_id)`,
not a shared constant. A chain for case A cannot be grafted onto case B
even if every entry after the graft point is internally consistent — the
graft fails at seq 1, because case B's verifier computes a different
genesis than case A's chain was built on. A shared genesis constant (the
original design here, and Cronos's `chain.py`) only binds the case
identity *inside* each hashed entry, which a verifier must be told to
check; binding it into genesis makes the check unconditional — the chain
cannot even begin to verify against the wrong case.

`action` is a closed vocabulary (`_ACTIONS`), same discipline as Mneme's
`EVENT_TYPES`: an unreasoned or unknown-shaped audit event should fail to
append, not silently record whatever a caller happened to pass. Scoped to
what ZAYNOR's own pipeline actually does today (case-freeze, snapshot
materialization, engine invocation, result sealing) — extending it is a
protocol change, not a call-site choice.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from zaynor.argentina_time import format_argentina
from zaynor.hmac_chain import compute_entry_hmac, resolve_hmac_key

_GENESIS_PREFIX = b"ZAYNOR_AUDIT_GENESIS:"

_ACTIONS = frozenset(
    {
        # Case lifecycle (freeze -> analyze), one entry per real pipeline step.
        "CASE_FROZEN",
        "SNAPSHOT_MATERIALIZED",
        "ENGINE_INVOKED",
        "RESULT_SEALED",
        # Read-only tool calls (tools.py::audited_tool / ReadOnlyToolRegistry),
        # one TOOL_INVOKED per call, followed by exactly one of the other two.
        "TOOL_INVOKED",
        "TOOL_SUCCEEDED",
        "TOOL_FAILED",
    }
)


def genesis_hash(case_id: str) -> str:
    """Per-case genesis — binding case_id here, not just inside each entry,
    is what makes chain grafting (case A's audit trail presented as case
    B's) structurally impossible rather than merely detectable by a
    verifier that remembered to check.
    """
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("case_id must be a non-empty string")
    return hashlib.sha256(_GENESIS_PREFIX + case_id.encode("utf-8")).hexdigest()


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    case_id: str
    action: str
    detail: dict[str, Any]
    reason: str
    created_at: str
    prev_hash: str
    entry_hash: str
    entry_hmac: str | None = None


class AuditLog:
    """Appends entries to a JSONL file, each one hash-chained to the last.

    Not thread-safe and not process-safe by design: this is a single-writer
    audit trail for one investigation run, not a shared service.
    """

    def __init__(self, log_path: str | Path, *, case_id: str, hmac_key: bytes | None = None):
        self._path = Path(log_path)
        self._tail_path = self._path.with_suffix(self._path.suffix + ".tail")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._case_id = case_id
        self._genesis = genesis_hash(case_id)
        self._hmac_key = hmac_key if hmac_key is not None else resolve_hmac_key()
        self._seq, self._prev_hash = self._resume()

    @property
    def case_id(self) -> str:
        """The case this log is bound to — same value `genesis_hash` was
        computed from. Exposed read-only so a caller (telemetry, a future
        MCP consumer) can key off it without threading `case_id` through a
        second parameter everywhere an `AuditLog` is already in scope.
        """
        return self._case_id

    def _resume(self) -> tuple[int, str]:
        if not self._path.exists():
            return 0, self._genesis
        seq = 0
        prev_hash = self._genesis
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if record.get("case_id") != self._case_id:
                    raise ValueError(
                        f"audit log at {self._path} belongs to case "
                        f"{record.get('case_id')!r}, not {self._case_id!r} — refusing to graft"
                    )
                seq = record["seq"]
                prev_hash = record["entry_hash"]
        return seq, prev_hash

    def append(self, action: str, detail: dict[str, Any], *, reason: str) -> AuditEntry:
        if action not in _ACTIONS:
            raise ValueError(f"unknown audit action {action!r}; the vocabulary is closed: {sorted(_ACTIONS)}")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("reason must be a non-empty string — an unreasoned audit event cannot exist")
        seq = self._seq + 1
        body = {
            "seq": seq,
            "case_id": self._case_id,
            "action": action,
            "detail": detail,
            "reason": reason,
            "created_at": format_argentina(),
            "prev_hash": self._prev_hash,
        }
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
    def load_entries(log_path: str | Path) -> list[dict[str, Any]]:
        """Read every entry from a JSONL audit log, in file order.

        Deliberately does not verify anything -- a caller displaying these
        entries must call `verify_with_report` separately and show its own
        result, so "read successfully" is never mistaken for "chain intact"
        (CLAUDE.md 5.3: a degraded read must never look like a correct one).
        """
        path = Path(log_path)
        if not path.exists():
            return []
        entries: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    @staticmethod
    def verify(log_path: str | Path, *, case_id: str, hmac_key: bytes | None = None) -> bool:
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
        ok, _ = AuditLog.verify_with_report(log_path, case_id=case_id, hmac_key=hmac_key)
        return ok

    @staticmethod
    def verify_with_report(
        log_path: str | Path, *, case_id: str, hmac_key: bytes | None = None
    ) -> tuple[bool, str]:
        path = Path(log_path)
        if not path.exists():
            return True, "no log file"
        key = hmac_key if hmac_key is not None else resolve_hmac_key()
        genesis = genesis_hash(case_id)

        prev_hash = genesis
        last_seq = 0
        last_hash = genesis
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
                if record.get("case_id") != case_id:
                    return False, f"entry at seq={record.get('seq')} belongs to case {record.get('case_id')!r}, not {case_id!r} — chain grafted"
                if record.get("action") not in _ACTIONS:
                    return False, f"entry at seq={record['seq']} has unknown action {record.get('action')!r}"
                if not isinstance(record.get("reason"), str) or not record["reason"].strip():
                    return False, f"entry at seq={record['seq']} has no reason — unreasoned audit event"
                if record["prev_hash"] != prev_hash:
                    return False, f"chain break before seq={record['seq']}"
                body = {
                    "seq": record["seq"],
                    "case_id": record["case_id"],
                    "action": record["action"],
                    "detail": record["detail"],
                    "reason": record["reason"],
                    "created_at": record["created_at"],
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

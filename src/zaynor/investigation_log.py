"""Investigation log: what the (optional) LLM investigator was thinking.

ADAPTED from ANNACONDA's `agent/mission.py` — the hypothesis/open-question/
sealed-journal subset only. Dropped: `record_collection`/`tried_hunts` (the
"hunts" concept is ANNACONDA's own recon-tooling domain), `schedule_next_
action`/`escalate`/`acknowledge_escalation`/`stand_down`/`begin_cycle`/
`is_due` (the whole autonomous cron-wakeup loop — ZAYNOR's investigator, if
used, runs synchronously within one case's investigation, not across weeks
of asynchronous sweeps), and `load_mission`/`attach` (migration logic tied
to ANNACONDA's own case-store shape). `_canonicalize` is reimplemented
small (plain sorted-key JSON) instead of importing ANNACONDA's
`core.canonicalize` module.

Two properties carried over unchanged, because they are exactly what
AGENTS.md §2.3 needs from the optional investigator:

1. **Tamper-evident.** Every mutation appends a journal entry sealed over
   the previous one (SHA-256 over canonical JSON). `verify_log` proves
   nobody rewrote the investigator's own history.
2. **It cannot reach authoritative state.** Nothing here produces or alters
   a `CORROBORATED`/`CONTRADICTED`/`INSUFFICIENT` claim. This is
   AGENTS.md's own line: "The LLM's internal hypothesis state is not the
   ledger's claim state — don't conflate the two." A hypothesis here is
   `open` / `supported` / `refuted`; only the (not yet built) VIGÍA-backed
   gate can assign an authoritative claim state.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from zaynor.hmac_chain import compute_entry_hmac

GENESIS_HASH = "0" * 64

_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"

# An investigator may move a hypothesis between these; it may not invent a
# state (a typo'd status is refused, not silently stored).
HYPOTHESIS_STATES = frozenset({"open", "supported", "refuted"})

# Bounded so a long investigation's working summary cannot grow without
# limit; settled entries are dropped before open ones, oldest before
# newest, and how many were dropped is recorded so a reader never mistakes
# the working view for the whole record.
HYPOTHESIS_LIMIT = 100
QUESTION_LIMIT = 50


class InvestigationLogError(ValueError):
    """Invalid input reached the investigation-log boundary."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime(_TS_FMT)


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _seal(obj: dict) -> str:
    return hashlib.sha256(_canonical_json(obj).encode("utf-8")).hexdigest()


def _text(value: Any, field: str, *, limit: int = 2000) -> str:
    """Accept a non-empty string, bounded — unbounded text is memory that
    grows without a stop condition.
    """
    if not isinstance(value, str) or not value.strip():
        raise InvestigationLogError(f"{field} must be a non-empty string")
    out = value.strip()
    if len(out) > limit:
        raise InvestigationLogError(f"{field} exceeds {limit} characters")
    return out


def _mint_id(log: dict, counter: str, prefix: str) -> str:
    """A monotonically increasing id, seeded from the highest id already
    present so a log written before the counter existed keeps handing out
    fresh ids rather than replaying old ones.
    """
    seen = log.get(counter)
    if not isinstance(seen, int):
        field = {"_next_hypothesis": "hypotheses", "_next_question": "open_questions"}[counter]
        seen = 0
        for item in log.get(field) or []:
            raw = str(item.get("id", ""))[len(prefix):]
            if raw.isdigit():
                seen = max(seen, int(raw))
    seen += 1
    log[counter] = seen
    return f"{prefix}{seen}"


def _trim(log: dict) -> None:
    dropped = log.setdefault("summarized_away", {"hypotheses": 0, "open_questions": 0})

    def cap(items: list, limit: int, is_settled) -> list:
        excess = len(items) - limit
        if excess <= 0:
            return items
        order = sorted(range(len(items)), key=lambda i: (0 if is_settled(items[i]) else 1, i))
        drop = set(order[:excess])
        return [item for i, item in enumerate(items) if i not in drop]

    for key, limit, is_settled in (
        ("hypotheses", HYPOTHESIS_LIMIT, lambda h: h.get("status") != "open"),
        ("open_questions", QUESTION_LIMIT, lambda q: bool(q.get("resolved"))),
    ):
        before = len(log[key])
        log[key] = cap(log[key], limit, is_settled)
        dropped[key] += before - len(log[key])


def new_investigation_log(case_id: str) -> dict:
    """An empty investigation log for a fresh case."""
    return {
        "case_id": case_id,
        "hypotheses": [],
        "open_questions": [],
        "journal": [],
        "memory_head": GENESIS_HASH,
    }


def record(
    log: dict, *, actor: str, action: str, detail: dict, hmac_key: bytes | None = None
) -> dict:
    """Append one sealed entry. Every mutation in this module goes through
    here, so the journal is the complete history of the investigator's own
    reasoning about this case — chained, so a later edit is detectable.

    `hmac_key` (optional, same rationale and env convention as
    `audit_log.py`'s `entry_hmac`/`chain_tip_hmac`, see `hmac_chain.py`):
    plain SHA-256 chaining only proves internal consistency — anyone who
    can edit `log` can recompute a whole new, consistent chain from
    scratch. A caller holding a key can't be forged by one that doesn't.
    This module stays pure (no env reads, no I/O) — a caller wanting the
    default `ZAYNOR_HMAC_KEY[_FILE]` resolution calls
    `hmac_chain.resolve_hmac_key()` itself and passes the result in.
    """
    actor = _text(actor, "actor", limit=120)
    action = _text(action, "action", limit=120)
    if not isinstance(detail, dict):
        raise InvestigationLogError("detail must be a dict")

    body = {
        "seq": len(log["journal"]),
        "actor": actor,
        "action": action,
        "detail": detail,
        "recorded_utc": _now(),
        "prev_hash": log.get("memory_head", GENESIS_HASH),
    }
    entry_hash = _seal(body)
    entry = dict(body, entry_hash=entry_hash)
    if hmac_key is not None:
        entry["entry_hmac"] = compute_entry_hmac(hmac_key, entry_hash)
        log["memory_head_hmac"] = compute_entry_hmac(hmac_key, entry_hash)
    log["journal"].append(entry)
    log["memory_head"] = entry_hash
    return entry


def _journal_backing(log: dict) -> list[str]:
    """Every id in the working-state summary must be traceable to a sealed
    journal entry — one-directional, since `_trim` legitimately drops
    entries the journal still keeps.

    This catches an entry added to the summary with no journal mutation
    behind it, and a journal-backed entry whose fields were changed without
    a matching mutation entry.
    """
    errors = []
    journal = [e for e in log.get("journal", []) if isinstance(e, dict)]

    def details(action: str) -> list[dict]:
        return [e.get("detail") or {} for e in journal if e.get("action") == action]

    for field, actions, label in (
        ("hypotheses", ("add_hypothesis", "update_hypothesis"), "hypothesis"),
        ("open_questions", ("note_open_question", "resolve_open_question"), "open question"),
    ):
        latest: dict[str, dict] = {}
        for action in actions:
            for detail in details(action):
                if isinstance(detail.get("id"), str):
                    latest[detail["id"]] = detail
        for item in log.get(field) or []:
            item_id = item.get("id")
            if item_id not in latest:
                errors.append(
                    f"{label} {item.get('id')!r} appears in the summary but the "
                    f"journal never recorded it"
                )
            elif item != latest[item_id]:
                errors.append(f"{label} {item_id!r} summary differs from its last journal state")
    return errors


def verify_log(log: dict, *, hmac_key: bytes | None = None) -> dict:
    """Re-derive the journal chain, then check the working state against
    it. The chain alone proves nobody rewrote history; it says nothing
    about whether the summary lists (`hypotheses`, `open_questions`) match
    what the chain actually recorded — `_journal_backing` closes that gap.

    `hmac_key`: verifies `entry_hmac`/`memory_head_hmac` when present (see
    `record`'s docstring). A missing key, or entries recorded before one
    was configured, are caveats in the returned dict, never `log_ok=False`
    on their own — only a mismatched HMAC (wrong key, or a wholesale
    recomputed chain) is a real failure.

    Reports every break found, not just the first.
    """
    errors: list[str] = []
    caveats: list[str] = []
    saw_any_hmac = False
    saw_any_missing_hmac = False
    prev = GENESIS_HASH
    for i, entry in enumerate(log.get("journal", [])):
        if not isinstance(entry, dict):
            errors.append(f"entry {i} is not an object")
            continue
        if entry.get("seq") != i:
            errors.append(f"entry {i} has seq {entry.get('seq')!r} — an entry was inserted, dropped, or reordered")
        if entry.get("prev_hash") != prev:
            errors.append(f"entry {i} does not chain onto its predecessor")
        body = {k: v for k, v in entry.items() if k not in ("entry_hash", "entry_hmac")}
        entry_hash = entry.get("entry_hash")
        if _seal(body) != entry_hash:
            errors.append(f"entry {i} was altered after it was sealed")
        entry_hmac = entry.get("entry_hmac")
        if entry_hmac is not None:
            saw_any_hmac = True
            if hmac_key is not None and compute_entry_hmac(hmac_key, entry_hash) != entry_hmac:
                errors.append(f"entry {i} entry_hmac mismatch (wrong key or forged chain)")
        else:
            saw_any_missing_hmac = True
        prev = entry_hash if entry_hash is not None else prev

    head_ok = prev == log.get("memory_head", GENESIS_HASH)
    if not head_ok:
        errors.append("memory_head does not match the end of the journal")
    memory_head_hmac = log.get("memory_head_hmac")
    if memory_head_hmac is not None:
        saw_any_hmac = True
        if hmac_key is not None and compute_entry_hmac(hmac_key, prev) != memory_head_hmac:
            errors.append("memory_head_hmac mismatch (wrong key or forged tail)")
    errors.extend(_journal_backing(log))

    if not saw_any_hmac:
        caveats.append("hash-only mode: no HMAC anchor on this journal")
    else:
        if hmac_key is None:
            caveats.append("entry_hmac present but not verified (no key supplied)")
        if saw_any_missing_hmac:
            caveats.append("some entries predate HMAC key configuration and lack entry_hmac")

    return {
        "log_ok": not errors,
        "journal_entries": len(log.get("journal", [])),
        "memory_head": log.get("memory_head", GENESIS_HASH),
        "errors": errors,
        "caveats": caveats,
    }


# --- what the investigator may write ----------------------------------------
# Every function below is a bounded, typed mutation that ends in a sealed
# journal entry. There is deliberately no function here that writes a
# CORROBORATED/CONTRADICTED/INSUFFICIENT claim: those exist only in
# ZaynorAuthoritativeResult, reached through the VIGÍA adapter, never
# through this log.

def add_hypothesis(log: dict, *, actor: str, text: str) -> dict:
    """Open a line of inquiry. Returns the stored hypothesis (with its id)."""
    hypothesis = {
        "id": _mint_id(log, "_next_hypothesis", "H"),
        "text": _text(text, "hypothesis text"),
        "status": "open",
        "rationale": None,
    }
    log["hypotheses"].append(hypothesis)
    record(log, actor=actor, action="add_hypothesis", detail=dict(hypothesis))
    _trim(log)
    return hypothesis


def update_hypothesis(log: dict, *, actor: str, hypothesis_id: str, status: str, rationale: str) -> dict:
    """Move a hypothesis to supported or refuted, with the reasoning that
    moved it. Refuted hypotheses are kept, never deleted — the ground a
    later reader needs is the ground that was discarded and why.
    """
    if status not in HYPOTHESIS_STATES:
        raise InvestigationLogError(f"status must be one of {sorted(HYPOTHESIS_STATES)}, not {status!r}")
    for h in log["hypotheses"]:
        if h["id"] == hypothesis_id:
            h["status"] = status
            h["rationale"] = _text(rationale, "rationale")
            record(log, actor=actor, action="update_hypothesis", detail=dict(h))
            _trim(log)
            return h
    raise InvestigationLogError(f"unknown hypothesis {hypothesis_id!r}")


def note_open_question(log: dict, *, actor: str, question: str, what_would_resolve: str) -> dict:
    """Record something the investigator could not settle, and what would
    settle it. Idempotent on the question text, so re-asking the same
    question does not accumulate duplicate entries.
    """
    question = _text(question, "question")
    for q in log["open_questions"]:
        if q["question"] == question:
            return q
    entry = {
        "id": _mint_id(log, "_next_question", "Q"),
        "question": question,
        "what_would_resolve": _text(what_would_resolve, "what_would_resolve"),
        "resolved": False,
    }
    log["open_questions"].append(entry)
    record(log, actor=actor, action="note_open_question", detail=dict(entry))
    _trim(log)
    return entry


def resolve_open_question(log: dict, *, actor: str, question_id: str, how: str) -> dict:
    for q in log["open_questions"]:
        if q["id"] == question_id:
            q["resolved"] = True
            q["resolved_how"] = _text(how, "how")
            record(log, actor=actor, action="resolve_open_question", detail=dict(q))
            return q
    raise InvestigationLogError(f"unknown question {question_id!r}")

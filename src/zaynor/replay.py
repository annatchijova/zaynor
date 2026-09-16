"""Stage 1: deterministic replay of a synthetic telemetry fixture.

This is a replayed/generated event stream, never a live collector — see
AGENTS.md, "Scope: the hybrid pipeline". `event_id` is derived from the
event's own content, not from wall-clock time or read order, so replaying
the same fixture twice produces identical ids in identical order.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path

from zaynor.schemas import TelemetryEvent


def _canonical_json(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _event_id(logical_time: int, event_type: str, fields: dict) -> str:
    payload = _canonical_json(
        {"logical_time": logical_time, "event_type": event_type, "fields": fields}
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def replay(fixture_path: str | Path) -> Iterator[TelemetryEvent]:
    """Yield events from a JSONL fixture, in file order, with a logical clock.

    There is no `time.sleep` here: file order *is* the emission order. A
    presentation layer that wants a paced demo effect adds its own delay
    around the iterator; it must never be load-bearing for correctness.
    """
    path = Path(fixture_path)
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            logical_time = int(record["logical_time"])
            event_type = str(record["event_type"])
            fields = dict(record.get("fields", {}))
            yield TelemetryEvent(
                event_id=_event_id(logical_time, event_type, fields),
                logical_time=logical_time,
                event_type=event_type,
                fields=fields,
            )

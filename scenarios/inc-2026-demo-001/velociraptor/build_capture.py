#!/usr/bin/env python3
"""Generate the byte-stable capture for the INC-2026-DEMO-001 Velociraptor lab.

Reads the synthetic lab state written by `simulate_endpoint_activity.py` and
produces `captured-collection.json` — the same record shape a live hunt
export produces (one entry per VQL artifact: columns + row value lists).
`tools.velociraptor.adapter.MockTransport` replays this capture through the
identical normalization/window path as a live collection.

Usage:
    python3 build_capture.py \
        --lab-root /tmp/kilo/zaynor-lab \
        --output captured-collection.json
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


def read_auth_events(lab_root: Path) -> list[dict]:
    target = lab_root / "auth_events.jsonl"
    events = []
    for line in target.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def build_capture(lab_root: Path) -> list[dict]:
    events = read_auth_events(lab_root)
    auth_columns = ["ref", "event", "account", "account_role", "device", "success", "timestamp"]
    auth_rows = [
        [event.get(column) for column in auth_columns] for event in events
    ]

    lab_files = lab_root / "lab_files"
    files = []
    for path in sorted(lab_root.rglob("lab_files/*")):
        if not path.is_file():
            continue
        stat = path.stat()
        modified_ms = int(stat.st_mtime * 1000)
        birth_ms = max(modified_ms, int(stat.st_ctime * 1000))
        files.append({"path": path.as_posix(), "size_bytes": stat.st_size,
                      "modified_time_ms": modified_ms, "birth_time_ms": birth_ms})
    files_columns = ["path", "size_bytes", "modified_time_ms", "birth_time_ms"]
    files_rows = [[f[c] for c in files_columns] for f in files]

    note_columns = ["note_line"]
    note_lines = (lab_root / "operator_note.txt").read_text(encoding="utf-8").splitlines()
    note_rows = [[line] for line in note_lines]

    return [
        {"artifact_id": "sim-auth-events", "columns": auth_columns, "rows": auth_rows},
        {"artifact_id": "sim-lab-files", "columns": files_columns, "rows": files_rows},
        {"artifact_id": "sim-operator-note", "columns": ["note_line"], "rows": note_rows},
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--lab-root", type=Path, default=Path("/tmp/kilo/zaynor-lab"))
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "captured-collection.json")
    args = parser.parse_args(argv)

    capture = build_capture(args.lab_root)
    args.output.write_text(json.dumps(capture, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    total = sum(len(entry["rows"]) for entry in capture)
    print(f"capture written: {args.output} ({total} rows)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

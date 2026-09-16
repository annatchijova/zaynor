"""Chain-of-custody log for evidence captured by the case freezer.

ADAPTED, almost verbatim, from ANNACONDA's `core/chain_of_custody.py`
(itself from VIGÍA), translated to English. Dropped: the `acquire()`
compatibility shim for SIFT disk-forensics modules (`$MFT` parsing, etc.)
— that is VIGÍA/ANNACONDA's own acquisition domain, out of scope for a
synthetic-fixture case freezer. Kept: the record shape and
`export_for_bundle`, since the manifest this produces is exactly what the
case-freeze step needs to hand downstream. No legal chain-of-custody claim
is made anywhere in this module or its callers — see AGENTS.md's SHA-256
scope note ("byte identity/integrity under the manifest", not proof of
truth, authorship, or completeness).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class CustodyRecord:
    operation: str
    timestamp: str
    actor: str
    artifact_hash: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ChainOfCustody:
    """An append-in-memory log of operations performed on one case's
    evidence, exported alongside the manifest — not a legal chain of
    custody, just a record of what this system did and when.
    """

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.records: list[CustodyRecord] = []

    def add_record(
        self,
        operation: str,
        actor: str = "zaynor_case_freezer",
        artifact_hash: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CustodyRecord:
        record = CustodyRecord(
            operation=operation,
            timestamp=datetime.now(timezone.utc).isoformat(),
            actor=actor,
            artifact_hash=artifact_hash,
            metadata=metadata or {},
        )
        self.records.append(record)
        return record

    def export_for_manifest(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "n_records": len(self.records),
            "records": [
                {
                    "operation": r.operation,
                    "timestamp": r.timestamp,
                    "actor": r.actor,
                    "artifact_hash": r.artifact_hash,
                    "metadata": r.metadata,
                }
                for r in self.records
            ],
        }

    def __len__(self) -> int:
        return len(self.records)

"""Static, read-only binary triage import boundary (ADR-0005)."""

from tools.binary_static.importer import import_binary_static, triage_bytes
from tools.offline_evidence import (
    OfflineEvidenceError,
    StagedEvidence,
    combine_staged_evidence,
    freeze_staged_evidence,
)

__all__ = [
    "OfflineEvidenceError",
    "StagedEvidence",
    "combine_staged_evidence",
    "freeze_staged_evidence",
    "import_binary_static",
    "triage_bytes",
]

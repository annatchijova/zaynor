"""VQL artifact templates for ZAYNOR's DFIR demo collections.

Each template targets a built-in Velociraptor capability (no custom server
artifact packs required to run the demo) and declares:

- `artifact_id`: stable identifier used by the adapter, the mapping layer,
  and the window manifest.
- `vql`: the VQL source. Templates only QUERY local endpoint state; the
  sim_* artifacts read the synthetic lab activity written by the lab
  script under /tmp/zaynor-lab/, so a demo client does not need any
  pre-existing "malicious" state on the host.
- `evidence_type`: the normalized evidence type the adapter tags the rows
  with. This is an observation label (what kind of thing was collected),
  not a score or a verdict.

Keep the window-to-profile mapping in `mappings.py` aligned with these
ids: it is the only place that maps a collected artifact onto a ZAYNOR
evidence profile.
"""

from __future__ import annotations

from dataclasses import dataclass

LAB_ROOT = "/tmp/kilo/zaynor-lab"


@dataclass(frozen=True)
class VqlArtifact:
    """One collectible VQL artifact in the demo catalog."""

    artifact_id: str
    vql: str
    evidence_type: str
    description: str


_PROCESS_LIST = """\
SELECT Pid AS pid, Name AS name, CommandLine AS command,
       Exe AS exe, Username AS username,
       CreateTime AS create_time
FROM pslist()"""

_SIM_AUTH_EVENTS = """\
SELECT ref, event, account, account_role, device, success, timestamp
FROM parse_jsonl(filename="CATEGORY_UPLOAD/auth_events.jsonl")"""

_SIM_LAB_FILES = """\
SELECT FullPath AS path, Size AS size_bytes,
       Mtime.UnixMilli AS modified_time_ms,
       Btime.UnixMilli AS birth_time_ms
FROM glob(globs="LAB_ROOT/lab_files/**")"""

_SIM_OPERATOR_NOTE = """\
SELECT Line AS note_line
FROM parse_lines(filename="LAB_ROOT/operator_note.txt", accessor="file")"""


def _materialize(vql: str) -> str:
    return vql.replace("CATEGORY_UPLOAD", LAB_ROOT).replace("LAB_ROOT", LAB_ROOT)


CATALOG: tuple[VqlArtifact, ...] = tuple(
    VqlArtifact(
        artifact_id=a.artifact_id,
        vql=_materialize(a.vql),
        evidence_type=a.evidence_type,
        description=a.description,
    )
    for a in (
        VqlArtifact(
            artifact_id="windows-processes",
            vql=_PROCESS_LIST,
            evidence_type="process",
            description="Running process inventory (built-in pslist source).",
        ),
        VqlArtifact(
            artifact_id="sim-auth-events",
            vql=_SIM_AUTH_EVENTS,
            evidence_type="log_entry",
            description=(
                "Synthetic authentication log (VPN login, SSH session starts) "
                "recorded by the lab activity script."
            ),
        ),
        VqlArtifact(
            artifact_id="sim-lab-files",
            vql=_SIM_LAB_FILES,
            evidence_type="file_metadata",
            description=(
                "Filesystem metadata for the lab evidence directory "
                "(the collection.zip story)."
            ),
        ),
        VqlArtifact(
            artifact_id="sim-operator-note",
            vql=_SIM_OPERATOR_NOTE,
            evidence_type="log_entry",
            description=(
                "Operator follow-up note copied by the lab activity script; "
                "content is treated strictly as evidence (it may contain "
                "investigator-manipulation attempts)."
            ),
        ),
    )
)

CATALOG_BY_ID: dict[str, VqlArtifact] = {a.artifact_id: a for a in CATALOG}

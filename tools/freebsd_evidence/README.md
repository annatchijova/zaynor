# FreeBSD offline evidence importer

`tools.freebsd_evidence` imports files that were already acquired from an
authorized FreeBSD lab. It never contacts a guest, executes an artifact,
loads a kernel module, or decides whether an observation is malicious.

The importer stages:

- the exact original bytes under `originals/freebsd_evidence/`;
- one versioned JSON record per typed observation under
  `observations/freebsd_evidence/`; and
- a canonical copy of the complete input package plus an explicit
  `analysis_unsupported` metadata record.

Call `freeze_staged_evidence()` to pass those files through ZAYNOR's existing
case freezer. To place this module and scanner reports in one case, stage them
separately, call `combine_staged_evidence()`, and freeze the combined result
once.

## Input contract

The Python API is:

```python
from pathlib import Path

from tools.freebsd_evidence import import_freebsd_evidence

staged = import_freebsd_evidence(package, Path("acquisition"), Path("staging"))
```

The checkout-local command-line entrypoint accepts the same contract and can
optionally freeze it immediately:

```bash
python3 -m tools.freebsd_evidence \
  --package acquisition/freebsd-package.json \
  --source-root acquisition \
  --staging-root work/freebsd-stage \
  --cases-root cases
```

Omit `--cases-root` to validate and stage without freezing. The command prints
a JSON summary and exits nonzero on invalid input. Package JSON is limited to
1 MiB and 32 nested levels; duplicate keys, non-standard numeric constants,
symlinks, and mutation while reading fail closed. The validated package is
canonicalized into `metadata/freebsd_evidence-input-package.json`, which is
included in the frozen manifest and referenced by every observation.

`package` is a schema-version `1` object:

```json
{
  "schema_version": 1,
  "module": "freebsd_evidence",
  "case_id": "INC-FREEBSD-001",
  "target": {
    "os": "FreeBSD",
    "release": "14.3-RELEASE",
    "arch": "amd64",
    "kernel_build": "GENERIC-14.3-p1"
  },
  "acquisition": {
    "acquisition_id": "acq-external-disk-001",
    "vantage": "external_disk",
    "lineage_id": "lineage:disk-capture-001",
    "captured_at": "2026-09-30T12:00:00Z",
    "capture_time_source": "hypervisor-record"
  },
  "artifacts": [
    {
      "logical_path": "/boot/loader.conf",
      "kind": "loader_configuration",
      "collection_status": "collected",
      "source_path": "files/boot/loader.conf",
      "sha256": "<lowercase SHA-256>"
    }
  ]
}
```

`target.os` must be exactly `FreeBSD`. The shared header lets each importer
declare which target systems it accepts; this importer parses FreeBSD-specific
files and keeps the FreeBSD-only default even though the binary importers
of ADR-0005 also accept `Linux` and `Windows`.

`source_path` is relative to the acquisition directory. `logical_path` is the
path recorded for the target and is never opened by the importer. Supported
kinds are `boot_file`, `kernel_module`, `loader_configuration`,
`startup_configuration`, `system_log`, `bsm_audit_trail`, and `guest_report`.

Declared collection statuses are:

- `collected`: requires `source_path` and `sha256`;
- `not_collected` and `unreadable`: require `reason`, with no source bytes;
- `observed_absent`: requires both `reason` and a documented `search_scope`.

`observed_absent` means only that the declared complete scope did not contain
the item. `not_collected`, `unreadable`, and parse failure never become
absence.

## Normalization limits

Simple UTF-8 `name=value` entries in loader and startup configuration files
become typed configuration observations. UTF-8 system logs and guest reports
become line observations without interpreting their content. Unknown active
configuration syntax stays in the frozen original and adds a limitation.

Boot files and module files receive inventory observations only. A module file
does not establish that the module was loaded. BSM audit bytes are preserved,
but this increment has no version-validated BSM parser, so the package records
`bsm_parser_unavailable`.

Each file is limited to 16 MiB, a package to 64 MiB and 256 files, staged
observations to 10,000, and a normalized text line to 16,384 characters.
Oversized lines stay available in the frozen original and add a limitation.
Inputs reject path traversal, symlinks, digest mismatch, mutation while reading,
malformed provenance, duplicate paths, and binary floating-point values. These
bounds deliberately exclude full disk and memory images pending a separate
storage and parser decision.

## Authority boundary

Every observation preserves the upstream `lineage_id`. Different files or
normalizers from one acquisition do not gain independent lineages. Evidence
text remains data even when it resembles an instruction.

The module does not feed VIGIA yet. Its metadata says
`analysis_unsupported` and `vigia_input_contract_not_validated`; callers must
not invent scores to force the observations into the current case-corpus
contract. A later adapter change requires calibrated benign and positive
controls and a separate review.

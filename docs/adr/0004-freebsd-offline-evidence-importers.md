# ADR 0004: Import FreeBSD evidence and scanner reports without verdict authority

- Status: Accepted for the P1 import boundary
- Date: 2026-09-30

## Context

ZAYNOR needs to preserve evidence acquired after an authorized experiment in a
disposable FreeBSD VM. The requested inputs include selected files and boot or
startup configuration, system logs, BSM audit bytes, and reports already
produced by chkrootkit or Rootkit Hunter.

The current VIGIA case-corpus path expects calibrated scoring fields and does
not yet demonstrate a lossless contract for unscored FreeBSD observations,
`UNKNOWN` states, source hashes, and acquisition lineage. Treating a scanner
warning as a finding or inventing static scores would create a second forensic
authority outside VIGIA. Running scanners, samples, or live collection from
ZAYNOR would also cross the repository's postmortem and bounded-acquisition
scope.

## Decision

Add two read-only offline importers under `tools/`:

- `freebsd_evidence` validates provenance and acquired files, preserves the
  original bytes, and emits typed configuration, text-line, inventory,
  missing-source, and parse-failure observations.
- `rootkit_scanner_reports` preserves raw chkrootkit/rkhunter reports and emits
  narrowly parsed tool-reported statuses for exact supported dialects.

Both use the common `tools.offline_evidence` staging contract. Independent
module stages may be combined for the same `case_id`, then originals,
observations, a canonical copy of each complete input package, and limitation
metadata cross the existing `freeze_case()` boundary together. Each
observation retains its upstream `lineage_id` and references its frozen package
record. Both importers provide checkout-local `python -m` entrypoints; these
stage by default and freeze only when `--cases-root` is supplied.

The result is explicitly `analysis_unsupported`. No VIGIA case-corpus artifact,
score, finding, framework mapping, seal, or LLM narrative is produced from
these records in this increment.

## Security and epistemic constraints

- Inputs are bounded, digest-verified regular files. Absolute paths, `..`,
  symlinks, byte mutation during read, duplicate paths, malformed provenance,
  and binary floating-point values fail closed.
- Package JSON has a separate 1 MiB and 32-level bound. Duplicate object keys
  and non-standard numeric constants fail closed instead of being normalized
  silently by the JSON decoder.
- File content and scanner output are untrusted evidence data. Text that looks
  like an instruction has no control authority.
- `reported_alert` and `reported_clear` describe only a named scanner test and
  its recorded run. Silence, a skipped test, an unsupported dialect, and an
  unavailable source never become a clean result.
- A filename, parser, or second scanner does not establish independent
  acquisition. Independence continues to use the upstream `lineage_id`.
- Boot and module files do not prove execution or residence. BSM bytes are
  inventory-only until a version-validated parser exists. Full disk and memory
  images remain outside the 64 MiB import boundary.
- SHA-256 binds staged bytes to the supplied acquisition manifest. It does not
  prove that guest-produced content is truthful or complete.

## Consequences

The project gains a usable P1 evidence bundle and an honest coverage statement
without weakening the ZAYNOR/VIGIA or deterministic/LLM authority boundaries.
Analysts can audit exactly which originals, observations, unknowns, and
limitations were frozen.

The importers alone cannot answer whether a rootkit was present. P2 requires a
separately reviewed VIGIA adapter and calibration against benign and controlled
positive acquisitions. Memory-resident process, module, connection, hook, or
kernel-code claims remain P3 work requiring a build-matched offline parser and
independent validation.

## Amendment (2026-10-04)

The shared header in `tools/offline_evidence.py` now takes a per-importer
target-system allowlist (`allowed_os`). Its default is FreeBSD-only, so both
importers of this ADR behave exactly as decided here. The format-level binary
importers of [ADR-0005](./0005-binary-static-triage-and-analysis-reports.md)
opt in to `FreeBSD`, `Linux` and `Windows`. No decision of this ADR changes.

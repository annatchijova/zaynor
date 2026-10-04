# Static binary triage importer

`tools.binary_static` measures and parses binaries that were already acquired
from an authorized lab. It never executes, loads, relocates, disassembles or
emulates them, and it never decides whether a binary is malicious, packed,
benign or clean. It is the static slice that
[ADR-0003](../../docs/adr/0003-binary-and-bootkit-analysis-out-of-scope.md)
cleared for ZAYNOR: hashing, ELF/PE header parsing and optional YARA matching.
[ADR-0005](../../docs/adr/0005-binary-static-triage-and-analysis-reports.md)
records the design.

The importer stages:

- the exact original bytes under `originals/binary_static/`;
- an optional YARA ruleset under `method/binary_static/` — the method is frozen
  with the evidence it was applied to;
- one `binary_triage` observation per binary, plus one `signature_scan`
  observation per binary when a ruleset was supplied, under
  `observations/binary_static/`; and
- a canonical copy of the input package and an `analysis_unsupported` metadata
  record.

Call `freeze_staged_evidence()` to pass them through ZAYNOR's case freezer, or
`combine_staged_evidence()` first to freeze them together with
`freebsd_evidence` and `rootkit_scanner_reports` stages of the same case.

## Input contract

```python
from pathlib import Path

from tools.binary_static import import_binary_static

staged = import_binary_static(package, Path("acquisition"), Path("staging"))
```

```bash
python3 -m tools.binary_static \
  --package acquisition/binary-package.json \
  --source-root acquisition \
  --staging-root work/binary-stage \
  --cases-root cases
```

The package uses the same schema-version `1` `case_id`, FreeBSD `target` and
`acquisition` object as the other offline importers, and adds:

```json
{
  "binaries": [
    {
      "logical_path": "/boot/kernel/if_example.ko",
      "declared_kind": "kernel_module",
      "source_path": "files/boot/kernel/if_example.ko",
      "sha256": "<lowercase SHA-256>"
    }
  ],
  "signatures": {
    "engine": "yara",
    "ruleset_source_path": "rules/triage.yar",
    "ruleset_sha256": "<lowercase SHA-256>"
  }
}
```

`declared_kind` is the acquirer's declaration (`kernel_module`, `boot_file`,
`executable`, `shared_object`, `other`); it is recorded, never inferred.
`signatures` is optional; without it the bundle records
`signature_matching_not_performed`. The common bounds apply: 16 MiB per file,
64 MiB per package, 256 files, 10,000 observations; confined paths, no
symlinks, exact digests, no binary floats.

## What a `binary_triage` observation contains

| Field | Meaning |
|---|---|
| `content_sha256` | Digest of the original; the grouping key for any later adapter. |
| `format` | `elf`, `pe`, `mz` (MZ without a PE signature) or `null`. |
| `magic_hex` | First 16 bytes, hex. |
| `byte_histogram` | 256 exact counts. |
| `entropy_bits_per_byte` | Decimal string derived from the histogram (`entropy_method` names the computation). |
| `elf` / `pe` | Parsed structures, see below. |
| `parse_issues` | Every sub-structure that could not be read, as `{code, where}`. |
| `parse_error` | Why the header itself could not be parsed (`parse_failed` only). |

ELF: identification (class, byte order, OS/ABI), header, every section with
type/flags and a per-section SHA-256 and entropy, every program header with
SHA-256 and entropy for `PT_LOAD`, the `PT_INTERP` path, `DT_NEEDED`/`SONAME`/
`RPATH`/`RUNPATH` resolved through the load segments, symbol tables (counts of
every binding and type, and a listing of non-local symbols with an `undefined`
flag), notes (FreeBSD ABI tag decoded) and `.comment` strings. Extended section
and segment numbering is honored.

PE: DOS pointer, COFF header, PE32/PE32+ optional header, the data-directory
table, per-section SHA-256 and entropy, and the Authenticode certificate table
location. Import, export, resource and debug directories are located but not
walked; signatures are not verified. On FreeBSD this covers the UEFI boot
chain (`loader.efi`, `boot1.efi`).

## Statuses

- `observed` — the format was recognized and the header parsed. Parts that
  could not be read are listed in `parse_issues` and add a
  `binary_parse_issues:<logical_path>` limitation; they are never reported as
  empty tables.
- `parse_failed` — the header itself is unusable (for example a truncated ELF
  header). A parser fault on hostile input is reported the same way with
  `internal_parser_error:<type>` and never aborts the rest of the package.
- `unknown` — not a supported format (scripts, MZ without PE, others).

A `signature_scan` is `observed` when the engine ran to completion; its
`reported_matches` are what YARA reported for that ruleset, nothing more. It
is `unknown` when the engine is not installed, the ruleset was rejected, or the
scan timed out or failed. No status means "clean": a scan without matches
says only that this ruleset reported nothing on these bytes.

## Determinism

The parser is stdlib-only, so the transform is ZAYNOR code, not a third-party
library whose version would silently change the output. No binary floats are
produced: entropy is computed with `decimal` (correctly rounded `ln`) and
emitted as a string next to the exact histogram. Listings are in file order.
Two runs over the same package stage byte-identical records.

YARA rulesets are compiled with includes disabled, and a ruleset that loads
any module outside `pe`, `elf`, `math`, `hash`, `dotnet`, `dex`, `macho` and
`string` is rejected: `time` reads the wall clock and `magic` depends on the
host's libmagic database. The engine reports which modules the compiled rules
load; that report, not the source text, is authoritative. A scan timeout
depends on host speed, so it degrades to `unknown`, never to a result.

## Robustness bounds

Every offset and size comes from the file and is treated as hostile. Reads are
bounds-checked views of the size-bounded input; nothing is allocated from a
declared size. Sections and segments are capped (4,096 / 512), symbol scanning
is capped at 2,000,000 entries and listing at 4,096 symbols, notes at 64, and
hashing at four times the file size so that overlapping ranges cannot amplify
work. Each cap that is reached is a `parse_issue`, and `limits` records the
caps in every observation.

## Authority and lineage

All observations keep the acquisition's `lineage_id`. When this module and
`freebsd_evidence` stage the same file from one acquisition, both copies carry
the same digest and lineage: a second parser is not a second source.

The bundle stays `analysis_unsupported`. A future VIGIA adapter must follow
ADR-0005: one artifact per `content_sha256`, `unknown`/`parse_failed` mapped
to unanalyzed evidence, and no score computed by the adapter.
`tests/test_binary_static_vigia_assumptions.py` fails if the vendored engine
changes the assumptions that adapter would rely on.

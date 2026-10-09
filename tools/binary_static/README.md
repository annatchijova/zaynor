# Static binary triage importer

`tools.binary_static` measures and parses binaries already acquired from an
authorized FreeBSD, Linux or Windows system. It never executes, loads,
relocates, disassembles or emulates them, and it never decides whether a
binary is malicious, packed, benign or clean. It is the static slice that
[ADR-0003](../../docs/adr/0003-binary-and-bootkit-analysis-out-of-scope.md)
cleared for ZAYNOR — hashing, ELF/PE parsing, strings and optional YARA —
and [ADR-0005](../../docs/adr/0005-binary-static-triage-and-analysis-reports.md)
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
`combine_staged_evidence()` first to freeze them together with other stages of
the same case.

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

The package uses the shared schema-version `1` header. `target.os` is exactly
one of `FreeBSD`, `Linux` or `Windows`; the other three target fields keep
their meaning (`release`, `arch`, and `kernel_build` — the kernel release on
Linux, the OS build such as `22631.4317` on Windows). It adds:

```json
{
  "binaries": [
    {
      "logical_path": "C:\\Windows\\System32\\drivers\\example.sys",
      "declared_kind": "kernel_module",
      "source_path": "files/Windows/System32/drivers/example.sys",
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

`declared_kind` is the acquirer's declaration, recorded and never inferred:
`kernel_module` (FreeBSD or Linux `.ko`, Windows `.sys`), `boot_file` (kernel,
loader, UEFI images such as `loader.efi` or `bootmgfw.efi`), `executable`,
`shared_object` (`.so`, `.dll`) or `other`. `signatures` is optional; without
it the bundle records `signature_matching_not_performed`. The common bounds
apply: 16 MiB per file, 64 MiB per package, 256 files, 10,000 observations;
confined paths, no symlinks, exact digests, no binary floats.

## What a `binary_triage` observation contains

Every file, whatever its format:

| Field | Meaning |
|---|---|
| `content_sha256` | Digest of the original; the grouping key for any later adapter. |
| `format` | `elf`, `pe`, `mz` (MZ without a PE signature) or `null`. |
| `magic_hex` | First 16 bytes, hex. |
| `byte_histogram` | 256 exact counts. |
| `entropy_bits_per_byte` | Decimal string derived from the histogram (`entropy_method`). |
| `strings` | Printable ASCII and UTF-16LE runs of at least 6 characters: totals per encoding and the first 1,024 by file offset, each with its offset. |
| `parse_issues` | Every structure that could not be read or does not add up, as `{code, where}`. |
| `parse_error` | Why the header itself could not be parsed (`parse_failed` only). |

**ELF** (`elf`): identification (class, byte order, OS/ABI), header, every
section with type, flags, SHA-256 and entropy, every program header (SHA-256
and entropy for `PT_LOAD`), the entry point's segment and section, the
`PT_INTERP` path, `DT_NEEDED`/`SONAME`/`RPATH`/`RUNPATH` resolved through the
load segments, symbol tables (counts per binding and type, non-local symbols
listed with an `undefined` flag), GNU symbol-version requirements
(`version_needs`), notes (FreeBSD ABI tag, GNU ABI tag and build ID decoded),
`.comment` strings and, for Linux kernel modules, the `.modinfo` records
(`vermagic`, `license`, `depends`, `name`, ...). Extended numbering is honored.

The loader uses program headers; section headers can be shifted or rewritten
while a binary still runs. Each section that should be loaded therefore
carries `matches_load_segment`, and a disagreement with the load segments or a
misaligned table or section is a parse issue
(`section_not_mapped_as_declared`, `section_offset_misaligned`,
`section_table_misaligned`) — the section view is shown next to the loader's
view, not trusted instead of it.

**PE** (`pe`): DOS pointer and Rich header (entries, key, recomputed checksum
validity), COFF header, PE32/PE32+ optional header with the stored and the
recomputed checksum, data directories, sections with SHA-256 and entropy,
entry-point section, imports and delay imports (by name with hint, or by
ordinal exactly as imported — ordinals are not translated to names), exports
with forwarders, debug directory (CodeView PDB path, GUID and age; a `REPRO`
entry means the timestamp is a build hash), TLS callback table, resources
(type summary, per-leaf SHA-256 and entropy, version information: fixed file
info, `StringFileInfo` strings, translations), the overlay after the last
section, and each Authenticode `WIN_CERTIFICATE` entry's type and SHA-256.
Signatures are never verified (`authenticode_not_verified`). Load-config,
exception, relocation, bound-import and CLR metadata directories are located
but not walked (`pe_partial_directory_coverage`).

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

The parsers are stdlib-only, so the transform is ZAYNOR code, not a
third-party library whose version would silently change the output. No binary
floats are produced: entropy is computed with `decimal` (correctly rounded
`ln`) and emitted as a string next to the exact histogram; the PE checksum is
recomputed with integer arithmetic. String selection is positional. Listings
are in file order. Two runs over the same package stage byte-identical
records, in any process and under any hash seed.

YARA rulesets are compiled with includes disabled, and a ruleset that loads
any module outside `pe`, `elf`, `math`, `hash`, `dotnet`, `dex`, `macho` and
`string` is rejected: `time` reads the wall clock and `magic` depends on the
host's libmagic database. The engine reports which modules the compiled rules
load; that report, not the source text, is authoritative. A scan timeout
depends on host speed, so it degrades to `unknown`, never to a result.

## Robustness bounds

Every offset, size and RVA comes from the file and is treated as hostile.
Reads are bounds-checked views of the size-bounded input; nothing is
allocated from a declared size; RVAs are mapped literally through the section
table. Sections, segments, symbols, imports, exports, resources (cycle
protected), version strings, notes, TLS callbacks, certificates and strings
are capped, and hashing is capped at four times the file size so overlapping
ranges cannot amplify work. Each cap that is reached is a `parse_issue`, and
`limits` records the caps in every observation.

## Authority and lineage

All observations keep the acquisition's `lineage_id`. When another importer
stages the same file from one acquisition, both copies carry the same digest
and lineage: a second parser is not a second source.

Everything the binary says about itself — section names, version strings,
PDB paths, Rich entries, timestamps, declared imports — was written by
whoever built it. The importer records those claims with their location and
leaves their credibility to the authority.

The bundle stays `analysis_unsupported`. A future VIGIA adapter must follow
ADR-0005: one artifact per `content_sha256`, `unknown`/`parse_failed` mapped
to unanalyzed evidence, no score computed by the adapter, and calibration per
target system and build. `tests/test_binary_static_vigia_assumptions.py` fails
if the vendored engine changes the assumptions that adapter would rely on.

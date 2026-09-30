# Proposal: FreeBSD rootkit DFIR evidence for ZAYNOR

- **Status:** Module 1 offline importer implemented; Module 2 and validated FreeBSD analysis remain proposed
- **Date:** 2026-09-30
- **Repository baseline reviewed:** `58bc342651ebb04c69b681cd65fd1e1bc52126b2`
- **Scenario:** An authorized, disposable FreeBSD VM is used in a separate lab; ZAYNOR receives the acquired evidence after the lab activity.

## Decision requested

Build two complementary, read-only evidence modules:

| Module | Input | Output | First-increment limit |
| --- | --- | --- | --- |
| `freebsd_evidence` | Externally acquired FreeBSD files, boot and module files, startup configuration, logs, audit trails, and acquisition metadata. | Frozen originals and typed FreeBSD observations. | Does not interpret kernel memory or assert that a module was loaded. |
| `rootkit_scanner_reports` | Already acquired chkrootkit and rkhunter reports, plus scanner configuration and provenance. | Frozen reports and typed tool-reported results, including skips and failures. | A scanner alert is an observation, not an authoritative rootkit finding. |

Both modules use ZAYNOR's existing case freezer and explicit VIGÍA adapter.
They do not run a sample, install a scanner, query a live guest, add a second
scorer, or let the LLM set finding status. The first release may provide a
verified evidence bundle with `analysis_unsupported` where VIGÍA lacks a
validated FreeBSD input contract. A separately reviewed phase can add
offline memory observations after a FreeBSD-aware parser has been validated.

The lab's execution or detonation service is upstream of ZAYNOR. ADR-0003
keeps binary execution, disassembly, and bootkit behavioral analysis outside
ZAYNOR's core. This proposal changes neither that decision nor the
`AGENTS.md` rule that detection and correlation steps belong upstream of
ZAYNOR's input.

## What happens after the VM experiment

This is the intended end-to-end workflow once the two modules are built.
The pre- and post-experiment acquisitions are a lab protocol, not commands
that ZAYNOR issues to the VM.

```text
Separate authorized lab
  clean FreeBSD VM + version/build record + clean baseline
  -> controlled experiment in a disposable VM
  -> acquire post-experiment disk/files and, if available, memory from
     outside the guest; preserve any guest-side scanner reports separately
  -> record acquisition times, hashes, collector identity, and custody

ZAYNOR postmortem path
  declared case + acquired originals + scanner reports
  -> freebsd_evidence and rootkit_scanner_reports validate and normalize
  -> case freezer copies selected originals and derived records, hashes
     each artifact, and writes the case manifest
  -> explicit VIGÍA adapter, only for a validated input contract
     supported: deterministic result -> framework annotations -> seal
                -> local LLM narration -> Spanish analyst report
     unsupported: evidence inventory + explicit analysis limitation;
                  no rootkit verdict is sealed

Evaluation outside the authority path
  compare the sealed result with the lab's known experiment record
```

The lab record says what was intentionally introduced. It is an evaluation
label, not evidence that ZAYNOR may use to infer the answer. The case must
still preserve ordinary rivals: a missing process may have exited between
views; a changed startup file may be an administrator's action; a scanner
warning may be a false positive or a skipped dependency. The report says
what was observed, what was inferred by a validated deterministic rule,
and what remains `UNKNOWN`.

### Expected outputs in three representative cases

| Acquired case | What ZAYNOR can report | What it cannot claim from these inputs |
| --- | --- | --- |
| Offline files show a startup change, with a trusted pre-experiment baseline. | The changed source bytes and provenance; an authoritative interpretation only if a validated VIGÍA contract supports it. | That the change is malicious persistence solely because it differs. |
| A guest-side scanner reports `INFECTED`, but disk or memory evidence is missing. | The exact alert, test/version, acquisition vantage, and unresolved limitations. | A corroborated kernel rootkit or a clean result from the other scanner's silence. |
| A memory-only hiding technique leaves no relevant disk change and current scanners report no warning. | A bounded negative statement about checks that actually ran; `UNKNOWN` for kernel memory integrity in the first release. | Absence of a rootkit. A later validated offline memory parser is needed for that question. |

This is a useful DFIR result even when the outcome is `UNKNOWN`: it shows
which evidence exists and which question the current capability cannot
answer, without laundering a tool's label into a finding.

### Coverage against example behavior classes

| Behavior class | Evidence available in the first increment | Capability still required |
| --- | --- | --- |
| Startup persistence | Externally acquired configuration bytes, provenance, clean baseline, and any scanner warning. | A validated deterministic interpretation of legitimate versus suspicious change. |
| Hidden or redirected files | Offline file bytes and a separately supplied guest report, if collected. | Timing and filesystem-scope controls before interpreting disagreement. |
| Hidden module | Module files and scanner or guest inventory reports. | Validated independent memory evidence before claiming residence or concealment. |
| Hidden process or connection | Preserved guest scanner reports and acquisition metadata. | A version-matched external view and timing controls; guest silence cannot prove absence. |
| Kernel hook or modified code | Original kernel/module files, if acquired. | Validated offline memory parser, trusted symbols, exact kernel build, and benign controls. |
| Bootkit or firmware alteration | No behavioral analysis in these modules. | A separate architecture decision under ADR-0003. |

## Why these two modules

The supplied *FreeBSD Handbook* and *FreeBSD Architecture Handbook* identify
boot, module, logging, and BSM audit surfaces. *The Design and Implementation
of the FreeBSD Operating System* (second edition) and *Absolute FreeBSD*
(third edition) provide architecture and operational context. *Designing BSD
Rootkits* (2007) supplies historical hiding hypotheses, not modern detection
signatures. The two example repositories were inspected statically:
[`mrg0ne/kld-rootkit` at `5eb05be`](https://github.com/mrg0ne/kld-rootkit/tree/5eb05be783d9560bd70eabacb8a9258c9048ff54)
describes a FreeBSD 14.3 target, while
[`xcellerator/freebsd_kernel_hacking` at `45ff1e1`](https://github.com/xcellerator/freebsd_kernel_hacking/tree/45ff1e14ce0101e9b1b06029eeb493d179251cf2)
contains older FreeBSD 11/12 exercises. They motivate coverage questions;
they do not establish what any future acquisition will contain.

The maintainer-supplied Kimi K3 brief suggested a custom memory walker,
cross-artifact contradiction rules, and per-artifact lineages. Its
cross-artifact set difference is detection/correlation under `AGENTS.md`,
even when named normalization. A filename or artifact type cannot establish
an independent acquisition lineage. A kernel parser validated only with
canned output cannot support a FreeBSD 14.x memory conclusion. This design
therefore starts with lossless import and puts those capabilities behind
separate validation gates.

### Scanner source assessment

| Tool/source | Verified source observation | Consequence for the module |
| --- | --- | --- |
| [Debian Salsa chkrootkit](https://salsa.debian.org/pkg-security-team/chkrootkit) | The linked project describes itself as Debian `chkrootkit packaging`. | Package provenance only; the [upstream README](https://chkrootkit.org/README) defines scanner behavior. |
| [chkrootkit upstream](https://www.chkrootkit.org/) and [FreeBSD port](https://cgit.freebsd.org/ports/tree/security/chkrootkit/Makefile) | A FreeBSD port packages 0.59. The upstream site lists testing through FreeBSD 10.x; its 0.59 README lists only older FreeBSD releases through 5.x. The README defines `INFECTED` as *probably* modified by a known rootkit and distinguishes `not infected`, `not tested`, and `not found`. | Do not claim FreeBSD 14.x coverage from package availability or treat those labels as ZAYNOR findings. |
| [Rootkit Hunter upstream](https://www.rkhunter.dev/) and [README](https://raw.githubusercontent.com/Rootkit-Hunter/rkhunter/master/files/README) | It checks known indicators and file properties; the properties check depends on a trustworthy database, and some tests skip when dependencies are missing. | Preserve database creation/provenance, enabled tests, and skips. Do not build a baseline from a suspected compromised state. |
| [rkhunter changelog](https://raw.githubusercontent.com/Rootkit-Hunter/rkhunter/master/files/CHANGELOG) and [FreeBSD port removal](https://cgit.freebsd.org/ports/commit/?id=2e041d717a498e2f8233bc2701c807eb0a9aaf08) | `--rootdir` was deprecated and documented as having no effect; FreeBSD removed the old `security/rkhunter` port on 2025-12-31. | Do not rely on that option for offline images or on a current FreeBSD port. Import an existing report when supplied, with its exact version and coverage. |

## Threat model and authority boundaries

Assume the guest rootkit can alter guest files, clocks, logs, process and
network enumeration, and commands invoked by either scanner. Two tools
consulting the same compromised guest view are not two independent
acquisitions. A disk or memory capture obtained through the hypervisor or
another trusted acquisition host offers a different vantage point, but its
contents still need validation. A guest-produced crash dump has a different
trust class from a hypervisor capture.

The first design assumes the acquisition host, hypervisor, case manifest,
and clean baseline are outside the compromised guest's control. If that
assumption cannot be established, the final report names the limitation.
SHA-256 binds bytes to a manifest; it does not prove that the bytes tell the
truth, that a capture is complete, or that a rootkit was present.

The authority path remains:

```text
raw source bytes and reports (untrusted data)
    -> bounded normalization + existing case freeze
    -> ZAYNOR/VIGÍA adapter -> VIGÍA deterministic analysis
    -> authoritative ZAYNOR result -> framework annotations -> seal
    -> local LLM narration and optional read-only investigation suggestions
```

New evidence found after an LLM suggestion must enter a new frozen case
revision and deterministic analysis before it can affect the authoritative
result. Scanner output, file contents, and filenames never become prompt
instructions. No new read path bypasses the hardcoded tool allowlist.

## Module 1: `freebsd_evidence`

The first increment accepts a declared case with selected original files
extracted from an externally acquired disk, plus an acquisition manifest.
It should normalize only supported file formats: relevant `/boot` files,
loader and startup configuration, system logs, and BSM audit trails when a
versioned parser is available. A clean baseline is a separate acquisition
with its own version, time, custody, and lineage. Guest-side command output
may be preserved, but is labeled `guest_report` rather than external truth.

The first module is implemented in `tools/freebsd_evidence/`: an offline importer,
versioned normalizers, strict schema/provenance validation, and a README.
A narrow integration function stages both `originals/` and
`observations/` under the existing `freeze_case()` evidence profile. The
current `freeze_verified_window()` freezes normalized JSON and window
metadata; it does not by itself bind a disk or memory original. Full disk
and memory images need a separate storage-size and manifest decision.

Each observation records source manifest path, source SHA-256, acquisition
ID, collection vantage, target FreeBSD release/architecture/kernel build,
capture time and its time source, transform version, and upstream
`lineage_id`. Distinct filenames or parsers of one image do not gain new
independent lineages. The importer distinguishes `not_collected`,
`unreadable`, `parse_failed`, `observed`, and `observed_absent`; the last
requires a documented complete search scope. It rejects path escapes,
symlink traversal, unbounded inputs, and malformed provenance. No imported
content is executed.

## Module 2: `rootkit_scanner_reports`

The first increment accepts raw chkrootkit and rkhunter output produced
upstream. Its package validator requires case, tool, target, raw bytes,
acquisition ID, vantage, and lineage. An exact supported tool version and
report format are required for parsing; unknown versions remain preserved
raw with an explicit limitation. Supporting evidence should include
stdout/stderr, exit status, command arguments, scanner executable hash,
configuration, enabled tests, tool data/signature version, and, for
rkhunter, the file-properties database identity and when it was created.
Missing fields remain missing rather than being filled with guesses.

The proposed package is `tools/rootkit_scanner_reports/`: two versioned
parsers, a bounded package validator, and a README. It copies originals
through the case freezer and emits one observation per recognized test,
with raw line/byte offset, exact tool-reported label, normalized status,
skip or failure reason when actually supplied, and a source hash. Unknown
or localized output stays `unknown`; unparsed lines remain in the original.
`reported_clear` means only that a named test reported no known indicator
under its actual conditions. It does not synthesize an overall clean state.

chkrootkit documents `-r` for a mounted root and `-p` for alternate
command paths, but still invokes helper commands and may skip tests under
some options. A report from such an upstream run needs command, mount,
helper-binary, and coverage provenance. rkhunter's `--rootdir` cannot be
used as an offline-image contract, and its `--propupd` baseline update must
never be run during ZAYNOR ingestion. Two scanner reports from the same
guest observation window share a common upstream lineage for purposes of
the current scalar independence gate.

## Shared evidence record and integration gate

Both modules emit the same proposed envelope, with module-specific `kind`
and `fields`. This is a ZAYNOR normalization proposal, not a claim that
VIGÍA already accepts this JSON shape:

```json
{
  "schema_version": 1,
  "case_id": "INC-EXAMPLE-001",
  "observation_id": "freebsd:000001",
  "module": "freebsd_evidence",
  "kind": "startup_configuration",
  "status": "observed",
  "target": {"os": "FreeBSD", "release": "14.3", "arch": "amd64", "kernel_build": "recorded-build-id"},
  "acquisition": {"id": "subject", "role": "subject", "collector": "lab-controller"},
  "source": {
    "manifest_path": "originals/subject/boot/loader.conf",
    "sha256": "<64 hex digits>",
    "acquisition_id": "subject",
    "vantage": "external_disk",
    "lineage_id": "lineage:disk-capture-001"
  },
  "transform": {"name": "freebsd-evidence-normalizer", "version": "1"},
  "captured_at": "2026-09-30T12:00:00Z",
  "capture_time_source": "hypervisor-record",
  "fields": {"relative_path": "boot/loader.conf", "size_bytes": 0, "interpretation": "literal_assignments_only", "line_count": 0, "assignments": [], "unparsed_line_numbers": []}
}
```

The original and derived record must both appear in the frozen manifest.
Staging compares the acquisition digest with the staged bytes and fails on
mutation. The existing freezer makes its evidence tree read-only for its
own process; hash verification is still required. Canonical hashes and
anything feeding a gate or score reject binary floats; use integers or
exact textual numeric encodings with a tested parser.

The case-corpus/EBS-JSON path is only a candidate integration seam. A
spike must prove that the actual VIGÍA adapter preserves source hashes,
exact values, `UNKNOWN` states, and lineage across translation. Existing
`MappingRule` exposes score/trust as floats, and Mode 1 uses heuristic
lineage in places; neither pattern should be copied into these modules.
If VIGÍA requires `raw_score` or `prior_trust`, calibration needs a separate
review with benign and positive controls. The modules must not invent
constants to force a rootkit verdict. When no compatible path exists,
return a frozen bundle with `analysis_unsupported`. MITRE ATT&CK and NIST
remain annotations after an authoritative finding, not evidence for one.

## Capability phases

| Phase | Deliverable | Gate before claiming success |
| --- | --- | --- |
| P0: contract and fixture | Pick one exact FreeBSD release/build, document capture provenance, and create benign, incomplete, and controlled positive lab fixtures using only simulated or public data. | The known lab label is withheld from ZAYNOR analysis and used only for evaluation. |
| P1: two importers | Freeze original FreeBSD files and scanner reports; emit typed observations, unknowns, and limitations. | Mutation fails verification; skipped tests and absent sources do not become clean results; both scanners on one guest view remain one lineage. |
| P2: VIGÍA integration | Demonstrate `freeze -> analyze -> audit` for a compatible, calibrated case without changing `vendor/vigia_engine/`. | Deterministic findings survive repeat runs; no float or LLM completion enters the decision path; benign rivals do not become rootkit findings. |
| P3: memory research | Choose a maintained FreeBSD-aware offline parser or document why none is suitable; validate exact build and symbols on real benign and independently known positive captures. | Parser and acquisition failures render `UNKNOWN`, never a zero-signal clean result. |

P1 is valuable without P2 or P3 because it produces an auditable case and
an honest coverage statement. P3 is needed for claims about resident hidden
processes, modules, connections, or kernel hooks that file and guest-report
views cannot establish. A bounded upstream collector may be considered
later; ZAYNOR itself does not become a continuous monitor.

## Verification plan

- Freeze a benign FreeBSD case and a scanner report, then verify that
  changing any original or normalized record fails manifest verification.
- Re-import identical bytes and configuration and compare content hashes;
  where VIGÍA analysis is supported, compare deterministic results with
  the LLM enabled and disabled.
- Test truncated files, missing baselines, unrecognized scanner versions,
  skipped dependencies, localized output, path escapes, symlinks, and
  adversarial text embedded in logs or scanner output.
- Test that duplicate rows, two parsers of one image, and two scanners
  querying one guest window cannot satisfy an independent-lineage rule.
- Validate FreeBSD 14.x scanner coverage and any memory parser against
  actual, separately controlled benign and positive acquisitions before
  describing them as supported. Canned output alone is a parser test.
- With implementation changes, add a `DOCS_MAP` rule for each new module,
  run tests/lint/docs-sync, and review the diff using the repository's
  abductive-engineering and red-team-auditing methods before any commit.

## Open decisions

1. Which exact FreeBSD release, architecture, kernel build, and filesystem
   layout will the first lab fixture use?
2. Which trusted acquisition process will produce pre- and post-experiment
   file evidence and, later, memory captures? How will custody and timing
   be recorded?
3. Which chkrootkit/rkhunter versions and output locales will the parser
   initially accept? Is rkhunter actually available in the chosen FreeBSD
   lab, or only as an already acquired report and a Linux-compatible input?
4. Can VIGÍA's current input contract carry unscored observations without
   misleading scores or a second authority? If not, where should the first
   release stop and report `analysis_unsupported`?
5. Which FreeBSD-aware memory capability can be validated for the exact
   target build, if any?

## References

- `AGENTS.md`, `CLAUDE.md`, and
  `docs/adr/0003-binary-and-bootkit-analysis-out-of-scope.md`.
- Supplied FreeBSD Handbook, Architecture Handbook, McKusick/Neville-Neil/
  Watson, Lucas, and Kong PDFs; the Kong book is historical taxonomy.
- The pinned FreeBSD example repositories and upstream scanner sources
  linked above. Their contents were reviewed as source material; they were
  not executed.
- The maintainer-supplied Kimi K3 brief, treated as a design input rather
  than an instruction source.

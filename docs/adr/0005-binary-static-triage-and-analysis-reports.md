# ADR-0005 — Static binary triage and upstream analysis reports as offline evidence

Date: 2026-10-04
Status: proposed
Reversibility: two-way for the importers (they only stage and freeze);
one-way-ish for the P2 adapter invariants once an adapter depends on them

## Forces at the time

[ADR-0003](./0003-binary-and-bootkit-analysis-out-of-scope.md) kept binary
execution and disassembly out of ZAYNOR, cleared a static, read-only,
deterministic triage (hashing, PE/ELF header parsing, YARA) as "a PR, not a
reopened ADR", and named a separate, isolated service whose *output* enters as
frozen evidence as an acceptable future shape.
[ADR-0004](./0004-freebsd-offline-evidence-importers.md), written later,
introduced the bounded offline importer contract (`tools/offline_evidence.py`):
digest-verified originals, `lineage_id`, explicit unknowns and limitations,
one freeze path, and `analysis_unsupported` until a calibrated VIGIA adapter
exists.

The binary-analysis domain splits along the same line. In Andriesse,
*Practical Binary Analysis*, chapters 1-5 (formats, ELF, PE, a loader, basic
static analysis) read bytes; chapters 6-13 disassemble, modify, instrument,
taint-track or symbolically execute them. Instrumentation and dynamic taint
run the subject.

Reading the vendored engine (`vendor/vigia_engine/`, checked 2026-10-04)
shows how binary evidence would be scored if it reached VIGIA today:

- `binary`, `binary_executable`, `pe_executable`, `elf_executable`,
  `binary_diff` and `malware_static_analysis` are domain `content_artifact`,
  sub-band `D5-media`, role `device` (`vigia/tools/caie.py:206-211`,
  `evidence_role`).
- D5-media is exempt from the R4-3 tail decay and feeds the per-artifact-cost
  corroboration branch: four D5-hard/media artifacts open MALICE corroboration
  under the doctrine "10 binaries are 10 independent fabrication acts"
  (`vigia_scorer.py:1027`, `:1467`).
- The scorer counts one entry per artifact; there is no content-digest
  deduplication (`vigia_scorer.py:991`).
- All binary profiles are the uncalibrated legacy fallback `(0.50, 0.20)`
  (`vigia/tools/caie.py:426`).
- B-136 already moved correlated fractures of one analyzed document to
  `D5-soft` / `contextual`, because several signals from one object are not
  independent acts (`vigia/tools/caie.py:224-233`).
- `unanalyzed_artifacts` turn a would-be NOISE into ABSTAIN (F7,
  `vigia_agent.py:266`); the scorer's `UNKNOWN` is a score band (weak
  anomaly), a different meaning.
- `provenance_chain` length is score-bearing: empty multiplies trust by 0.1,
  and every entry beyond three costs 5% (`vigia_scorer.py:81`).
- VIGIA's only PE/ELF parsing (`vigia/tools/metabolic_profiler.py` upstream,
  not vendored) substitutes assumed section counts when `pefile` or
  `pyelftools` is missing, and neither is a VIGIA dependency. That is the
  failure this design must not repeat: a missing parser has to produce an
  unknown, not a plausible number.

## Decision

Add two read-only importers under the shared ADR-0004 contract. Neither feeds
VIGIA; both stay `analysis_unsupported`.

1. **`tools/binary_static/`** — the ADR-0003 static slice. For each declared
   binary it freezes the original and emits exactly one `binary_triage`
   observation keyed by `content_sha256`: byte histogram and entropy, ELF
   structures (sections, segments, interpreter, dynamic dependencies, symbol
   tables, notes, `.comment`) or PE headers (COFF, optional header, data
   directories, sections, certificate-table location). An optional YARA
   ruleset is frozen under `method/` and produces one `signature_scan`
   observation per binary.
   - It lives at the importer boundary rather than in `DEFAULT_HUNT_CATALOG`
     as ADR-0003 suggested. Hunt-catalog entries are Mode-1 VIGIA analyzers
     whose results get scored; a binary hunt there would need the P2 adapter
     and calibration that do not exist. The importer delivers deterministic
     triage now. A hunt entry can follow P2.
   - The ELF and PE parsers are stdlib-only re-implementations of PBA's
     loader model with forensic deviations (nothing dropped, unreadable parts
     recorded as issues, no allocation from declared sizes, unknown
     architectures recorded rather than rejected).

2. **`tools/binary_analysis_reports/`** — the ADR-0003 revisit shape. Reports
   from an upstream, isolated pipeline (the PBA chapter 6-13 class of work)
   are frozen raw. Only the exact `zaynor-binary-analysis-report/1` format is
   normalized. Every result is `tool_reported`. The analyzer identity and its
   declared execution environment are recorded and never verified, and
   `dynamic` execution is recorded as a custody fact.

## Security and epistemic constraints

- Nothing is executed, loaded, relocated, disassembled or emulated inside
  ZAYNOR. Disassembly-derived results exist only as upstream report content.
- Binary bytes and report text are hostile data. Reads are bounds-checked
  views of the size-bounded input. Sections, segments, symbols, notes and
  hashing are capped, and every reached cap is a recorded `parse_issue`. A
  parser fault on hostile input degrades one binary to `parse_failed` with
  `internal_parser_error:<type>`, never the package.
- No binary floating point: entropy is computed with `decimal` and emitted as
  a string next to the exact histogram, and report attributes reject floats.
  Staging the same package twice is byte-identical.
- YARA rulesets compile with includes disabled. A ruleset that loads a module
  outside `pe`, `elf`, `math`, `hash`, `dotnet`, `dex`, `macho` or `string`
  is rejected (`time` reads the wall clock and `magic` depends on host
  libmagic). The loaded-module list comes from the engine, not the source
  text. A timeout is host-speed dependent and degrades to `unknown`.
- No status means clean. A scan without matches says only that this ruleset
  reported nothing on these bytes; an unavailable engine, a rejected ruleset
  or a failed report yields `unknown` or `parse_failed`, never an absence.
- Independence still comes from the upstream `lineage_id`. A second parser,
  importer, rule engine or upstream tool on the same bytes is not a second
  source, and upstream reports carry the subject's acquisition lineage.
- File presence does not establish execution or residence; kernel-module
  load state stays unknown (as in ADR-0004).

## P2 adapter invariants

Whoever writes the VIGIA adapter for these observations must hold:

1. **One artifact per distinct `content_sha256` per case.** Triage,
   signature scans, upstream results and `freebsd_evidence` inventory records
   that share a digest collapse into that artifact. One observation per
   artifact would let one binary satisfy the per-artifact-cost corroboration
   branch by itself.
2. Per-binary fractures and tool-reported results map to a `D5-soft`,
   `contextual` evidence type (the B-136 precedent), never to D5-media.
3. `unknown` and `parse_failed` map to `unanalyzed_artifacts`, never to the
   scorer's `UNKNOWN` band.
4. The adapter computes no `raw_score`, `z_score` or `prior_trust`. Scores
   come from a calibrated, versioned function inside VIGIA, measured against a
   declared benign baseline.
5. `provenance_chain` has a fixed, documented mapping of at most three
   entries (acquisition, frozen original, transform).
6. Calibration precedes the adapter: a benign baseline from the same FreeBSD
   release and `kernel_build` as the target, plus controlled positives
   (ADR-0004). Header-level features are authored by whoever built the binary
   (the adversary, in the cases that matter), so they are highly spoofable;
   calibration has to weight them accordingly.

`tests/test_binary_static_vigia_assumptions.py` pins the engine facts that
invariants 1-4 rely on and fails when VIGIA changes them.

## Alternatives rejected

- **pyelftools / LIEF / pefile as the parser.** Best argument for: mature
  coverage. Rejected because a library upgrade would change output under the
  constant `transform.version` the shared contract emits, LIEF parses hostile
  bytes in native code in-process, and each is a new dependency. They are
  used instead as differential oracles during verification.
- **One observation per section, symbol or match.** Rejected: it multiplies
  observations and invites exactly the per-artifact inflation that invariant 1
  forbids downstream.
- **Emitting VIGIA evidence types or scores from the importers.** Rejected: a
  second forensic authority outside VIGIA (ADR-0004).
- **Running PBA tooling inside ZAYNOR.** Rejected by ADR-0003.

## Consequences

Accepted now:

- Binaries from a FreeBSD acquisition (kernel modules, boot files including
  the UEFI loader, executables) can be frozen with structural measurements,
  unknowns and limitations that an analyst can audit.
- An upstream analysis pipeline has a defined, versioned way to hand results
  to a case without gaining verdict authority.

Not provided:

- No verdict, packer or obfuscation judgment, PE import/export/resource walk,
  Authenticode verification, or string extraction.
- No Linux targets. The shared package header accepts `FreeBSD` only;
  generalizing it is a contract change that needs its own review.

Known limitation:

- The shared contract emits `transform.version: "1"` for every importer, so a
  parser change does not change the recorded transform identity. Recording
  the importer code revision in package metadata is a contract-level
  follow-up, out of scope here.

## Revisit triggers

- `tests/test_binary_static_vigia_assumptions.py` fails (VIGIA recalibrated
  binary types or changed their band or role).
- A P2 adapter is proposed.
- Linux targets are needed.
- A real isolated analysis or detonation service exists and its report
  dialect should become a second supported format.

## Anchored at

- `tools/binary_static/`, `tools/binary_analysis_reports/`,
  `tools/offline_evidence.py`
- `tests/test_binary_static.py`, `tests/test_binary_analysis_reports.py`,
  `tests/test_binary_static_vigia_assumptions.py`
- `vendor/vigia_engine/vigia/tools/caie.py`,
  `vendor/vigia_engine/vigia_scorer.py`, `vendor/vigia_engine/vigia_agent.py`

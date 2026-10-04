# Upstream binary-analysis report importer

`tools.binary_analysis_reports` imports reports produced by a binary-analysis
pipeline that runs **outside** ZAYNOR: disassembly, control-flow recovery,
binary instrumentation, taint tracking or symbolic execution. ZAYNOR never
runs that pipeline, never re-executes or re-analyzes the subject, and never
turns a reported result into a finding. This is the integration shape
[ADR-0003](../../docs/adr/0003-binary-and-bootkit-analysis-out-of-scope.md)
names as acceptable — a separate, isolated service whose *output* enters as
frozen evidence — and
[ADR-0005](../../docs/adr/0005-binary-static-triage-and-analysis-reports.md)
records it.

The pattern follows `rootkit_scanner_reports`: raw report bytes are frozen,
exactly one report format is normalized, every result is `tool_reported`,
and anything else stays raw with an `unknown` status.

## Input contract

```python
from pathlib import Path

from tools.binary_analysis_reports import import_analysis_reports

staged = import_analysis_reports(package, Path("reports-dir"), Path("staging"))
```

```bash
python3 -m tools.binary_analysis_reports \
  --package reports-dir/analysis-package.json \
  --source-root reports-dir \
  --staging-root work/analysis-stage \
  --cases-root cases
```

The package uses the shared schema-version `1` header. Its `acquisition` must
be the acquisition that produced the **subject** binary: analyzing a sample is
not a new acquisition, so it does not get a new `lineage_id`. It adds:

```json
{
  "analyzer": {
    "name": "pba-recursive-disasm",
    "version": "0.1.0",
    "executable_sha256": "<lowercase SHA-256>",
    "configuration_sha256": "<lowercase SHA-256 or null>",
    "command": ["pba-recursive-disasm", "--json", "if_example.ko"],
    "execution_mode": "static",
    "environment": {
      "isolation": "disposable_vm",
      "network": "disabled",
      "environment_id": "lab-vm-2026-10-01"
    }
  },
  "reports": [
    {
      "source_path": "reports/if_example.json",
      "sha256": "<lowercase SHA-256 of the report>",
      "subject_sha256": "<lowercase SHA-256 of the analyzed binary>",
      "subject_logical_path": "/boot/kernel/if_example.ko"
    }
  ]
}
```

`execution_mode` is `static` when the subject was only read and `dynamic` when
the pipeline ran it (instrumentation, dynamic taint, emulation, concolic
execution). `dynamic` adds `subject_executed_upstream`; `dynamic` with
`isolation: none` also adds `subject_executed_without_declared_isolation`. The
environment is recorded as declared and is never verified by ZAYNOR
(`upstream_environment_declared_not_verified`).

## Report format `zaynor-binary-analysis-report/1`

```json
{
  "format": "zaynor-binary-analysis-report/1",
  "analyzer": {"name": "pba-recursive-disasm", "version": "0.1.0"},
  "subject_sha256": "<must equal the package entry>",
  "results": [
    {
      "record_type": "function_entry",
      "label": null,
      "location": {"space": "vaddr", "value": 4198400},
      "attributes": {"size": 120}
    },
    {
      "record_type": "unreachable_bytes",
      "label": "not_reached_by_recursive_descent",
      "location": {"space": "file_offset", "value": 6144},
      "attributes": {"length": 512, "section": ".text"}
    }
  ]
}
```

`record_type` is a lowercase identifier chosen by the pipeline; `label` is the
tool's own label; `location.space` is `vaddr`, `rva` or `file_offset`;
`attributes` holds integers, booleans, strings (1,024 characters), lists and
objects (64 items, 4 levels). No floats: a probability or score belongs to the
authority, not to a report. Up to 4,096 results per report and 64 reports per
package.

## Statuses

- `analysis_report` / `observed` — the report matched the format, the declared
  analyzer and the declared subject; each result becomes one
  `analysis_result` observation with status `tool_reported`.
- `analysis_report` / `unknown` — another format, another analyzer identity,
  or another subject digest. The raw report is frozen; no result is
  normalized.
- `analysis_report` / `parse_failed` — invalid JSON, duplicate keys, floats,
  or a result outside the schema. The whole report is rejected rather than
  partially normalized, and the reason is recorded.

Report content problems never fail the package; package problems (identity,
environment, digests, paths) always do.

## Authority and lineage

Results describe one tool run on one subject. They are correlated with each
other and with any static triage of the same bytes, so a later VIGIA adapter
must not count them as independent artifacts (ADR-0005). The bundle stays
`analysis_unsupported`, and report text is evidence data that never enters an
LLM control channel.

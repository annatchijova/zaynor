# FreeBSD offline evidence importer

`freebsd_evidence` imports files acquired upstream from an authorized FreeBSD
case. It checks the acquisition manifest and every file against declared sizes
and SHA-256 digests, copies the original bytes, writes typed observations, and
calls ZAYNOR's existing `freeze_case()` boundary. It does not access a live VM,
execute a sample, run a scanner, parse kernel memory, or issue a rootkit verdict.

## Input layout

The JSON acquisition manifest is a separate input file. `--source-root` contains
one directory per acquisition ID; each `files[].path` is relative to that
directory. For example:

```text
acquired/
  baseline/boot/loader.conf
  subject/boot/loader.conf
  subject/boot/kernel/example.ko
acquisition.json
```

Manifest schema version 1 requires a case ID, declared target version/build
metadata, and one to eight acquisitions. Each acquisition needs an ID, `role`
(`baseline`, `subject`, or `auxiliary`), `vantage` (`external_disk` or
`guest_report`), upstream `lineage_id`, capture timestamp with timezone,
capture-time source, collector, and file list. A baseline is a separate
acquisition. Reusing a single disk capture or guest observation for multiple
derived files requires reusing its lineage ID.

```json
{
  "schema_version": 1,
  "case_id": "INC-FREEBSD-001",
  "target": {
    "os": "FreeBSD",
    "release": "14.3",
    "arch": "amd64",
    "kernel_build": "recorded-build-id"
  },
  "acquisitions": [
    {
      "acquisition_id": "subject",
      "role": "subject",
      "vantage": "external_disk",
      "lineage_id": "lineage:disk-capture-001",
      "captured_at": "2026-09-30T12:00:00Z",
      "capture_time_source": "hypervisor-record",
      "collector": "lab-controller",
      "files": [
        {
          "path": "boot/loader.conf",
          "kind": "startup_configuration",
          "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "size_bytes": 0
        }
      ]
    }
  ]
}
```

The sample digest and size describe an **empty** `subject/boot/loader.conf`;
replace them with the actual acquisition values. Supported kinds are
`boot_file`, `kernel_module_file`, `startup_configuration`, `system_log`,
`bsm_audit_trail`, and `guest_command_output`. The kind is a collector label,
not proof that file contents match a FreeBSD format. Files are preserved raw.
Only `startup_configuration` receives a conservative UTF-8 literal-assignment
parse; it does not evaluate shell syntax or infer effective boot settings.
Other kinds yield metadata observations only.

An acquisition may include `unavailable` entries with `path`, `kind`, `status`,
and `reason`. Supported statuses are `not_collected`, `unreadable`, and
`observed_absent`. The last also requires `search_scope` and
`"search_complete": true`; it records the collector's scoped absence report,
not proof that a rootkit or kernel module is absent. A parser failure is
recorded as `parse_failed` while keeping the original bytes.

## Import

From the repository root with its Python dependencies available:

```bash
PYTHONPATH=src:. python3 -m tools.freebsd_evidence \
  --manifest acquisition.json \
  --source-root acquired \
  --cases-root cases
```

The command writes `cases/<case_id>/evidence/originals/`,
`evidence/observations/freebsd.json`, and
`evidence/metadata/acquisition-manifest.json` and
`evidence/metadata/freebsd-import-status.json`, alongside the freezer's
`manifest.json` and `custody.json`. It refuses to overwrite an existing case.
The frozen status record and CLI JSON summary report
`analysis_status: analysis_unsupported`: this
module has no validated FreeBSD-to-VIGÍA rootkit analysis contract yet.
Observations are data and must not be treated as authoritative findings or
sent directly to an LLM as instructions.

The importer accepts at most 1 MiB of manifest JSON, 8 acquisitions,
256 total file/unavailable entries, 16 MiB per acquired file, and 128 MiB of
acquired file bytes per case. It rejects path escapes, symlink traversal,
duplicate paths/keys, changed or mismatched source bytes, nonregular files,
and binary floating-point values in the manifest. Full disk and memory images
are outside this size-bounded contract.

See [the FreeBSD rootkit DFIR proposal](../../docs/freebsd-rootkit-dfir-proposal.md)
for the broader two-module design and the later integration gates.

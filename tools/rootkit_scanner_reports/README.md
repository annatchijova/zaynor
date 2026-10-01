# Rootkit scanner report importer

`tools.rootkit_scanner_reports` imports raw reports produced upstream by
chkrootkit or Rootkit Hunter. ZAYNOR does not install or run either scanner,
invoke helper commands, update an rkhunter properties database, or query a
live FreeBSD guest.

The exact report bytes are frozen alongside typed tool observations. A scanner
label is never an authoritative rootkit finding:

- `reported_alert` means that one named scanner test emitted its alert label;
- `reported_clear` means that one named test emitted its clear label under the
  recorded run conditions;
- `skipped` preserves a scanner skip or missing-test label; and
- `unknown` covers unsupported versions, locales, encodings, or unparsed
  reports.

No overall clean result is synthesized.

## Input contract

The Python API is:

```python
from pathlib import Path

from tools.rootkit_scanner_reports import import_scanner_reports

staged = import_scanner_reports(package, Path("acquisition"), Path("staging"))
```

The checkout-local command-line entrypoint accepts a package JSON file:

```bash
python3 -m tools.rootkit_scanner_reports \
  --package acquisition/scanner-package.json \
  --source-root acquisition \
  --staging-root work/scanner-stage \
  --cases-root cases
```

`--cases-root` is optional. The command prints a JSON summary and exits nonzero
on invalid input. Package JSON is limited to 1 MiB and 32 nested levels;
duplicate keys, non-standard numeric constants, symlinks, and mutation while
reading fail closed. The canonical package record is frozen as
`metadata/rootkit_scanner_reports-input-package.json` and every observation
references it.

The package uses the same schema-version `1` `case_id`, FreeBSD `target`, and
`acquisition` object as the FreeBSD importer. It adds:

```json
{
  "scanner": {
    "name": "chkrootkit",
    "version": "0.59",
    "locale": "C",
    "command": ["chkrootkit", "-r", "/mnt/freebsd"],
    "executable_sha256": "<lowercase SHA-256>",
    "exit_status": 0,
    "configuration_sha256": "<lowercase SHA-256 or null>",
    "data_version": "fixture-1",
    "enabled_tests": ["amd", "bindshell"],
    "properties_database": null
  },
  "reports": [
    {
      "source_path": "reports/stdout.txt",
      "sha256": "<lowercase SHA-256>",
      "stream": "stdout"
    }
  ]
}
```

The required tool identity is the exact name, version, locale, command, and
executable hash. Exit status, configuration hash, data/signature version,
enabled tests, and rkhunter properties-database identity may be unavailable;
they stay `null` and produce explicit provenance limitations rather than
guesses. A supplied exit status must be an integer from `-255` through `255`.

Up to eight `stdout`, `stderr`, or `combined` report files are accepted. The
common importer bounds still apply: 16 MiB per file, 64 MiB in total, 10,000
observations, and 16,384 characters per normalized line. Oversized lines remain
in the frozen original and add a limitation. Paths must be confined, symlinks
are rejected, bytes must stay stable and match their exact digest, and binary
floats are not accepted.

## Versioned parsers

The first increment recognizes only these English/C report dialects:

- chkrootkit `0.59`; and
- rkhunter `1.4.6`.

The parsers accept only narrow, anchored result-line shapes. Each recognized
line records the exact line, line number, byte offset, test text, scanner
label, and normalized tool status. Every other line remains available in the
frozen original. A different tool version or locale is preserved raw and
reported as `unknown`; package availability is not treated as proof of parser
compatibility or FreeBSD coverage.

For rkhunter, the properties database should include its hash and creation
time. An upstream command containing `--propupd` adds a limitation because the
baseline may have changed; ingestion itself never runs that option. A
chkrootkit mounted-root report must preserve the command and helper context in
the supplied provenance; this module does not claim that a mounted-root run
covered every test.

## Authority and lineage

All results from one package retain the acquisition's `lineage_id`. Two
scanners that queried the same compromised guest window must be packaged with
the same upstream lineage if they are later evaluated for independence. Merely
using two tools does not create two trustworthy views.

The output remains `analysis_unsupported` until an explicit, calibrated VIGIA
adapter can carry raw observations, unknown states, source hashes, and lineage
without inventing scores. Scanner text is evidence data and never enters an
LLM control channel.

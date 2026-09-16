# ZAYNOR evidence sandbox contract

The API process never executes, opens, previews, converts, OCRs, decompresses,
or parses artifact bytes. It may store metadata and a byte identity supplied by
the worker, but it cannot inspect the artifact stream.

The evidence worker is a separate process/container per job. Its input is a
read-only evidence directory and its output is a write-only result directory.
It has no application credentials, no object-store write capability, no shell
access beyond an explicit command allowlist, and network access disabled by
default. The launcher must enforce CPU, memory, wall-clock, file-size, output,
file-count, nesting, and decompression-ratio limits before enabling a parser.

`zaynor.sandbox` implements the first small slice of that contract: confined
non-symlink file identity and bounded worker subprocess execution. It is not a
container launcher, parser, OCR engine, or proof of isolation. Deployment must
provide the remaining process/container controls before hostile artifact formats
are enabled.

The worker hashes a file before returning its bytes. SHA-256 records byte
identity only; it does not prove origin, truth, provenance, admissibility, or
malicious intent.

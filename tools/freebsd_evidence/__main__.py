"""Repository-local command for importing an acquired FreeBSD case."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.freebsd_evidence import FreeBSDImportError, import_freebsd_case


def main() -> int:
    parser = argparse.ArgumentParser(description="Freeze already acquired FreeBSD evidence")
    parser.add_argument("--manifest", required=True, type=Path, help="acquisition manifest JSON")
    parser.add_argument("--source-root", required=True, type=Path, help="root of acquired files")
    parser.add_argument("--cases-root", required=True, type=Path, help="destination case directory")
    args = parser.parse_args()
    try:
        result = import_freebsd_case(args.manifest, args.source_root, args.cases_root)
    except (FreeBSDImportError, OSError) as exc:
        parser.exit(2, f"FreeBSD evidence import failed: {exc}\n")
    print(
        json.dumps(
            {
                "case_id": result.manifest.case_id,
                "content_sha256": result.manifest.content_sha256,
                "evidence_dir": str(result.evidence_dir),
                "original_count": result.original_count,
                "observation_count": result.observation_count,
                "analysis_status": result.analysis_status,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

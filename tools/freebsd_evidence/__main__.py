"""Command-line entrypoint for the FreeBSD offline evidence importer."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if (REPO_ROOT / "src").is_dir():
    sys.path.insert(0, str(REPO_ROOT / "src"))

from tools.freebsd_evidence import import_freebsd_evidence  # noqa: E402
from tools.offline_evidence import run_import_cli  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(
        run_import_cli(
            import_freebsd_evidence,
            description="Stage and optionally freeze already-acquired FreeBSD evidence.",
            module_name="freebsd_evidence",
        )
    )

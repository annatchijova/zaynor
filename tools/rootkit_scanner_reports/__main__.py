"""Command-line entrypoint for the offline scanner-report importer."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if (REPO_ROOT / "src").is_dir():
    sys.path.insert(0, str(REPO_ROOT / "src"))

from tools.offline_evidence import run_import_cli  # noqa: E402
from tools.rootkit_scanner_reports import import_scanner_reports  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(
        run_import_cli(
            import_scanner_reports,
            description="Stage and optionally freeze already-acquired rootkit scanner reports.",
            module_name="rootkit_scanner_reports",
        )
    )

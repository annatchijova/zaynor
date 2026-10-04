"""Command-line entrypoint for the upstream binary-analysis report importer."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if (REPO_ROOT / "src").is_dir():
    sys.path.insert(0, str(REPO_ROOT / "src"))

from tools.binary_analysis_reports import import_analysis_reports  # noqa: E402
from tools.offline_evidence import run_import_cli  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(
        run_import_cli(
            import_analysis_reports,
            description=(
                "Stage and optionally freeze reports from an upstream binary-analysis pipeline."
            ),
            module_name="binary_analysis_reports",
        )
    )

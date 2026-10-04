"""Command-line entrypoint for the static binary triage importer."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if (REPO_ROOT / "src").is_dir():
    sys.path.insert(0, str(REPO_ROOT / "src"))

from tools.binary_static import import_binary_static  # noqa: E402
from tools.offline_evidence import run_import_cli  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(
        run_import_cli(
            import_binary_static,
            description="Stage and optionally freeze static triage of already-acquired binaries.",
            module_name="binary_static",
        )
    )

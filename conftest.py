import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent
sys.path.insert(0, str(REPO_ROOT / "src"))
# The demo-lab integration modules (tools/) and the vendored engine are
# plain packages imported from the repo root; pytest's rootdir conftest
# keeps them importable for tests/test_velociraptor_adapter.py and
# tests/test_aiops_aggregator.py without installing anything.
sys.path.insert(0, str(REPO_ROOT))

#!/usr/bin/env python3
"""Run the demo-lab integration tests with zero dependencies.

Runs tests/test_velociraptor_adapter.py and tests/test_aiops_aggregator.py:
via pytest when it is installed, otherwise through a built-in stdlib
shim that provides the tiny pytest surface those modules use (raises,
MonkeyPatch) plus tmp_path/monkeypatch fixture injection. This keeps the
demo-lab gate runnable on a bare clone (stdlib + the repo only), which is
the same sovereignty rule scripts/install-hooks.sh follows.

Exit code 0 = all tests passed, 1 = at least one failure.
"""

from __future__ import annotations

import importlib
import inspect
import sys
import tempfile
import traceback
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

LAB_TEST_MODULES = (
    "tests.test_velociraptor_adapter",
    "tests.test_aiops_aggregator",
)


def _pytest_available() -> bool:
    try:
        importlib.import_module("pytest")
    except ImportError:
        return False
    return True


class _ShimMonkeyPatch:
    """Minimal monkeypatch fixture: setattr with 2-arg (module-path form)
    or 3-arg (object, name, value) forms, plus undo on context exit."""

    def __init__(self) -> None:
        self._undo: list[tuple[object, str, object]] = []

    def setattr(self, *args: object) -> None:
        if len(args) == 3:
            obj, name, value = args
        else:
            target, value = args
            parts = str(target).rsplit(".", 1)
            module = importlib.import_module(parts[0])
            obj, name = module, parts[1]
        self._undo.append((obj, name, getattr(obj, name)))  # type: ignore[arg-type]
        setattr(obj, name, value)  # type: ignore[arg-type]

    def undo(self) -> None:
        for obj, name, value in reversed(self._undo):
            setattr(obj, name, value)


class _ShimPytest:
    """The subset of pytest the lab test modules use."""

    MonkeyPatch = _ShimMonkeyPatch

    @staticmethod
    def raises(exc_type: type) -> "_Raises":
        return _Raises(exc_type)


class _Raises:
    def __init__(self, exc_type: type) -> None:
        self.exc_type = exc_type

    def __enter__(self) -> "_Raises":
        return self

    def __exit__(self, exc_type: type, exc: object, tb: object) -> bool:
        return exc is not None and isinstance(exc, self.exc_type)


def _run_with_shim() -> tuple[int, int]:
    # Register the shim before importing the test modules: they do
    # `import pytest` at module level (for raises) and only use the
    # surface the shim provides.
    sys.modules.setdefault("pytest", _ShimPytest())  # type: ignore[assignment]
    failures = passed = 0
    for module_name in LAB_TEST_MODULES:
        module = importlib.import_module(module_name)
        for name, func in sorted(vars(module).items()):
            if not name.startswith("test_") or not callable(func):
                continue
            kwargs = {}
            sig = inspect.signature(func)
            if "tmp_path" in sig.parameters:
                kwargs["tmp_path"] = Path(tempfile.mkdtemp())
            if "monkeypatch" in sig.parameters:
                kwargs["monkeypatch"] = _ShimMonkeyPatch()
            try:
                func(**kwargs)
                passed += 1
            except Exception:
                failures += 1
                print(f"FAIL {module_name}.{name}", file=sys.stderr)
                traceback.print_exc(limit=4)
    return passed, failures


def main() -> int:
    if _pytest_available():
        import pytest

        args = [str(REPO_ROOT / "tests" / "test_velociraptor_adapter.py"),
                str(REPO_ROOT / "tests" / "test_aiops_aggregator.py"), "-q"]
        return 0 if pytest.main(args) == 0 else 1

    print("pytest not installed; using the built-in stdlib runner", file=sys.stderr)
    passed, failures = _run_with_shim()
    print(f"lab tests: passed={passed} failures={failures}", file=sys.stderr)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

import hashlib
import json

import pytest

from vendor.vigia_engine.vigia.core.canonicalize import _canonicalize

from zaynor.hybrid_integrations import (
    HybridIntegrationError,
    materialize_window,
    record_window_context,
    remember_window_summary,
    verify_annaconda_window,
)


def _window():
    body = {
        "schema_version": 1,
        "window_id": "CASE-w000001",
        "case_id": "CASE",
        "artifacts": [{"artifact_id": "pslist-a1", "evidence_type": "process"}],
    }
    body["window_hash"] = hashlib.sha256(
        json.dumps(_canonicalize(body), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    return body


def test_verified_window_materializes_freezeable_profile(tmp_path):
    root, profile = materialize_window(_window(), tmp_path / "stage")
    assert profile["annaconda-window"] == [
        "velociraptor/000000-pslist-a1.json",
        "velociraptor/window.json",
    ]
    assert json.loads((root / profile["annaconda-window"][0]).read_text())["artifact_id"] == "pslist-a1"


def test_tampered_window_fails_before_any_sink_or_write(tmp_path):
    window = _window()
    window["artifacts"][0]["evidence_type"] = "verdict"
    with pytest.raises(HybridIntegrationError, match="hash"):
        materialize_window(window, tmp_path / "stage")
    assert not (tmp_path / "stage").exists()


class Sink:
    def __init__(self):
        self.calls = []

    def record_tool(self, tool, result_summary):
        self.calls.append(("tool", tool, result_summary))

    def record_evidence(self, text, *, reference=""):
        self.calls.append(("evidence", text, reference))

    def close(self, decision_summary):
        self.calls.append(("close", decision_summary))

    def store(self, content, *, topic, claim, reason):
        self.calls.append(("store", content, topic, claim, reason))
        return "mem-test"


def test_cronos_and_mneme_receive_context_only():
    sink = Sink()
    window = _window()
    record_window_context(window, sink)
    memory_id = remember_window_summary(window, sink)
    assert memory_id == "mem-test"
    assert all(call[0] != "close" for call in sink.calls)
    assert all("verdict" not in json.dumps(call) for call in sink.calls)
    assert [call[0] for call in sink.calls] == ["tool", "evidence", "store"]


def test_invalid_window_is_rejected_before_sinks():
    sink = Sink()
    with pytest.raises(HybridIntegrationError):
        record_window_context({"case_id": "CASE", "window_hash": "bad", "artifacts": []}, sink)
    assert sink.calls == []

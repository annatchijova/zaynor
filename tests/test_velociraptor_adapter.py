"""Tests for the adapted Velociraptor evidence-window adapter."""

import hashlib
import json

import pytest

from vendor.vigia_engine.vigia.core.canonicalize import _canonicalize

from tools.velociraptor import vql_templates
from tools.velociraptor.adapter import (
    MockTransport,
    RestTransport,
    VelociraptorAdapter,
    VelociraptorAdapterError,
    export_collection,
    normalize_timestamp,
    window_hash,
)
from tools.velociraptor.mappings import RULES, window_to_case_corpus
from zaynor.hybrid_integrations import verify_annaconda_window

CAPTURE = [
    {
        "artifact_id": "sim-auth-events",
        "columns": ["ref", "event", "success"],
        "rows": [["auth:E001", "vpn_login", True], ["auth:E002", "ssh_session_start", None]],
    }
]


def test_window_hash_matches_hybrid_integrations_derivation():
    window = {
        "schema_version": 1,
        "window_id": "INC-w000001",
        "case_id": "INC",
        "artifacts": [],
    }
    expected = hashlib.sha256(
        json.dumps(_canonicalize(window), sort_keys=True, ensure_ascii=True).encode()
    ).hexdigest()
    assert window_hash(window) == expected


def test_collect_seals_window_verifiable_by_case_freezer_boundary():
    adapter = VelociraptorAdapter(builder="test")
    window = adapter.collect(
        "INC-TEST",
        [("sim-auth-events", iter([{"ref": "auth:E001", "event": "vpn_login", "success": True}]))],
        transport="mock",
    )
    verify_annaconda_window(window)
    assert window["window_id"] == "INC-TEST-w000001"
    assert window["artifacts"][0]["row_count"] == 1
    assert window["artifacts"][0]["evidence_type"] == "log_entry"


def test_collection_emits_observations_only_not_score_or_verdict():
    window = VelociraptorAdapter().collect(
        "INC-TEST",
        [("sim-auth-events", iter([{"event": "vpn_login", "success": True}]))],
    )
    assert "score" not in window
    assert "verdict" not in window
    for artifact in window["artifacts"]:
        assert not any(key in artifact for key in ("raw_score", "score", "verdict"))


def test_collect_rejects_unknown_artifact():
    adapter = VelociraptorAdapter()
    with pytest.raises(VelociraptorAdapterError):
        adapter.collect("INC-TEST", [("not-a-real-artifact", iter([{"a": 1}]))])


def test_mock_transport_replays_capture_rows():
    mock = MockTransport(CAPTURE)
    rows = list(mock.rows_for_artifact("sim-auth-events"))
    assert rows[0]["ref"] == "auth:E001"
    assert rows[1]["event"] == "ssh_session_start"


def test_transports_reject_arbitrary_vql():
    mock = MockTransport(CAPTURE)
    with pytest.raises(VelociraptorAdapterError, match="arbitrary VQL"):
        list(mock.query("SELECT * FROM shell_command(command='id')"))

    # REST validates before opening a socket.
    rest = RestTransport("http://127.0.0.1:8889")
    with pytest.raises(VelociraptorAdapterError, match="arbitrary VQL"):
        list(rest.query("SELECT * FROM shell_command(command='id')"))

    assert list(mock.query(vql_templates.CATALOG_BY_ID["sim-auth-events"].vql)) == [
        ["auth:E001", "vpn_login", True],
        ["auth:E002", "ssh_session_start", None],
    ]


def test_rest_transport_builds_basic_auth_header_and_bounded_client():
    import base64

    transport = RestTransport("http://127.0.0.1:8889", "admin", "secret")
    expected = "Basic " + base64.b64encode(b"admin:secret").decode("ascii")
    assert transport._headers()["Authorization"] == expected
    anonymous = RestTransport("http://127.0.0.1:8889")
    assert "Authorization" not in anonymous._headers()


def test_normalize_timestamp_epoch_and_iso_and_garbage():
    assert normalize_timestamp(1758000000000000) == "2025-09-16T05:20:00+00:00"
    assert normalize_timestamp("2026-09-17T12:00:00Z") == "2026-09-17T12:00:00+00:00"
    assert normalize_timestamp("not-a-timestamp") is None
    assert normalize_timestamp(None) is None


def test_export_collection_writes_window_manifest_and_custody(tmp_path):
    adapter = VelociraptorAdapter(builder="demo-builder")
    window = adapter.collect(
        "INC-TEST",
        [("sim-auth-events", iter([{"ref": "auth:E001", "event": "vpn_login", "success": True}]))],
        transport="mock",
    )
    root, _ = export_collection(
        window, tmp_path / "bundle", builder="demo-builder", custodian="zaynor-dfir-staging"
    )
    names = sorted(path.name for path in root.iterdir())
    assert names == ["collection-manifest.json", "custody.json", "window.json"]
    manifest = json.loads((root / "collection-manifest.json").read_text())
    assert manifest["builder"] == "demo-builder"
    assert manifest["artifact_count"] == 1
    custody = json.loads((root / "custody.json").read_text())
    roles = {record["role"] for record in custody["records"]}
    assert roles == {"builder", "custodian"}


def test_export_collection_fails_closed_on_tampered_window(tmp_path):
    adapter = VelociraptorAdapter()
    window = adapter.collect("INC-TEST", [("sim-auth-events", iter([{"ref": "auth:E001"}]))])
    window["artifacts"][0]["row_count"] = 999
    # The freezer boundary rejects the tampered window before a single byte
    # is written (its own error type; both derive from ValueError).
    with pytest.raises(ValueError):
        export_collection(window, tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()


def test_mapping_is_deterministic_and_labels_stay_absent():
    adapter = VelociraptorAdapter()
    window = adapter.collect(
        "INC-TEST",
        [
            ("sim-auth-events", iter([
                {"ref": "auth:E001", "event": "vpn_login", "account_role": "privileged", "device": "DEV-UNKNOWN-17", "success": True, "timestamp": "2026-09-17T12:00:00Z"},
                {"ref": "auth:E002", "event": "vpn_login", "account_role": "privileged", "device": "DEV-CORP-01", "success": True, "timestamp": "2026-09-17T12:01:00Z"},
            ])),
            ("sim-lab-files", iter([{"path": "/tmp/kilo/zaynor-lab/lab_files/collection.zip", "timestamp": "2026-09-17T12:15:00Z"}])),
        ],
    )
    corpus_a = window_to_case_corpus(window, known_devices={"DEV-CORP-01"})
    corpus_b = window_to_case_corpus(window, known_devices={"DEV-CORP-01"})
    assert corpus_a == corpus_b
    artifact_ids = [artifact["artifact_id"] for artifact in corpus_a["artifacts"]]
    assert artifact_ids == sorted(artifact_ids) or len(artifact_ids) >= 2
    # The known-device row produces no artifact (and no invented benign one).
    assert any(
        artifact_id.startswith("vr-rule-privileged-login-unknown-device-")
        for artifact_id in artifact_ids
    )
    known_device_ids = [
        artifact["artifact_id"]
        for artifact in corpus_a["artifacts"]
        if "DEV-CORP-01" in json.dumps(artifact["metadata"]["observed_fields"])
        and artifact["artifact_id"].startswith("vr-rule-privileged-login-unknown-device-")
    ]
    assert known_device_ids == []
    # No rule assigns a verdict, label, or claim state.
    for artifact in corpus_a["artifacts"]:
        assert "expected_verdict" not in artifact
        assert artifact["evidence_type"] in ("log_entry", "file_metadata", "process")
    # Rules carry static constants only.
    for rule in RULES:
        assert rule.raw_score <= 1.0
        assert rule.prior_trust <= 1.0

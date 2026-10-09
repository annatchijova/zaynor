import hashlib
import json
import subprocess
import sys

import pytest

from tools.binary_analysis_reports import (
    REPORT_FORMAT,
    OfflineEvidenceError,
    freeze_staged_evidence,
    import_analysis_reports,
)

SUBJECT = hashlib.sha256(b"subject binary bytes").hexdigest()


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _analyzer(**overrides):
    analyzer = {
        "name": "pba-recursive-disasm",
        "version": "0.1.0",
        "executable_sha256": "a" * 64,
        "configuration_sha256": "b" * 64,
        "command": ["pba-recursive-disasm", "--json", "subject.ko"],
        "execution_mode": "static",
        "environment": {
            "isolation": "disposable_vm",
            "network": "disabled",
            "environment_id": "lab-vm-2026-10-01",
        },
    }
    analyzer.update(overrides)
    return analyzer


def _report(results=None, **overrides):
    report = {
        "format": REPORT_FORMAT,
        "analyzer": {"name": "pba-recursive-disasm", "version": "0.1.0"},
        "subject_sha256": SUBJECT,
        "results": results if results is not None else [
            {"record_type": "function_entry", "label": None,
             "location": {"space": "vaddr", "value": 0x401000}, "attributes": {"size": 120}},
            {"record_type": "unreachable_bytes", "label": "not_reached_by_recursive_descent",
             "location": {"space": "file_offset", "value": 0x1800},
             "attributes": {"length": 512, "section": ".text"}},
        ],
    }
    report.update(overrides)
    return json.dumps(report).encode()


def _package(source, reports, analyzer=None):
    entries = []
    for index, data in enumerate(reports):
        relative = f"reports/report-{index}.json"
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        entries.append({
            "source_path": relative,
            "sha256": _sha256(data),
            "subject_sha256": SUBJECT,
            "subject_logical_path": "/boot/kernel/if_test.ko",
        })
    return {
        "schema_version": 1,
        "module": "binary_analysis_reports",
        "case_id": "INC-BINARY-001",
        "target": {
            "os": "FreeBSD",
            "release": "14.3-RELEASE",
            "arch": "amd64",
            "kernel_build": "GENERIC-14.3-p1",
        },
        "acquisition": {
            "acquisition_id": "acq-external-disk-001",
            "vantage": "external_disk",
            "lineage_id": "lineage:disk-capture-001",
            "captured_at": "2026-09-30T12:00:00Z",
            "capture_time_source": "hypervisor-record",
        },
        "analyzer": analyzer or _analyzer(),
        "reports": entries,
    }


def _observations(staging_root):
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(
            (staging_root / "observations" / "binary_analysis_reports").glob("*.json")
        )
    ]


def test_static_report_results_are_tool_reported_and_frozen(tmp_path):
    source = tmp_path / "source"
    staged = import_analysis_reports(_package(source, [_report()]), source, tmp_path / "staging")

    assert staged.analysis_status == "analysis_unsupported"
    assert {
        "vigia_input_contract_not_validated",
        "upstream_analysis_not_reproduced_by_zaynor",
        "upstream_environment_declared_not_verified",
        "analysis_does_not_establish_independent_acquisition",
    } <= set(staged.limitations)
    assert "subject_executed_upstream" not in staged.limitations
    observations = _observations(staged.staging_root)
    report, *results = observations
    assert report["kind"] == "analysis_report" and report["status"] == "observed"
    assert report["fields"]["subject_sha256"] == SUBJECT
    assert report["fields"]["result_count"] == 2
    assert [r["status"] for r in results] == ["tool_reported", "tool_reported"]
    assert results[1]["fields"]["tool_reported_label"] == "not_reached_by_recursive_descent"
    assert {r["fields"]["subject_sha256"] for r in results} == {SUBJECT}
    assert {o["source"]["lineage_id"] for o in observations} == {"lineage:disk-capture-001"}

    manifest, _ = freeze_staged_evidence(staged, tmp_path / "cases")
    assert "originals/binary_analysis_reports/reports/report-0.json" in {
        entry.relative_path for entry in manifest.entries
    }


def test_dynamic_execution_is_a_recorded_custody_fact(tmp_path):
    source = tmp_path / "source"
    analyzer = _analyzer(
        execution_mode="dynamic",
        configuration_sha256=None,
        environment={"isolation": "none", "network": "unknown", "environment_id": "laptop"},
    )

    staged = import_analysis_reports(
        _package(source, [_report()], analyzer), source, tmp_path / "staging"
    )

    assert {
        "subject_executed_upstream",
        "subject_executed_without_declared_isolation",
        "analyzer_provenance_missing:configuration_sha256",
    } <= set(staged.limitations)
    results = [o for o in _observations(staged.staging_root) if o["kind"] == "analysis_result"]
    assert {r["fields"]["execution_mode"] for r in results} == {"dynamic"}


@pytest.mark.parametrize(
    "report, status, reason",
    [
        (_report(subject_sha256="c" * 64), "unknown", "report_subject_mismatch"),
        (_report(analyzer={"name": "other", "version": "9"}), "unknown",
         "report_analyzer_mismatch"),
        (_report(format="vendor-x/3"), "unknown", "unsupported_report_format"),
        (b'{"format": "zaynor-binary-analysis-report/1", "results": [], "results": []}',
         "parse_failed", "invalid_json"),
        (_report([{"record_type": "f", "label": None, "location": None,
                   "attributes": {"score": 0.9}}]), "parse_failed",
         "floating_point_or_excessive_depth"),
        (_report([{"record_type": "Bad Type", "label": None, "location": None,
                   "attributes": {}}]), "parse_failed", "result_record_type_invalid"),
        (_report([{"record_type": "f", "label": None,
                   "location": {"space": "vaddr", "value": -1}, "attributes": {}}]),
         "parse_failed", "result_location_invalid"),
        (_report(extra=True), "parse_failed", "report_shape_invalid"),
        (b"\xff\xfe", "parse_failed", "invalid_json"),
    ],
)
def test_report_content_problems_are_observations_not_package_errors(
    tmp_path, report, status, reason
):
    source = tmp_path / "source"

    staged = import_analysis_reports(_package(source, [report]), source, tmp_path / "staging")

    (observation,) = _observations(staged.staging_root)
    assert observation["status"] == status
    assert observation["fields"]["rejection_reason"] == reason
    assert observation["fields"]["result_count"] == 0
    original = staged.staging_root / "originals/binary_analysis_reports/reports/report-0.json"
    assert original.read_bytes() == report


def test_result_count_is_bounded_per_report(tmp_path, monkeypatch):
    import tools.binary_analysis_reports.importer as importer

    monkeypatch.setattr(importer, "MAX_RESULTS_PER_REPORT", 1)
    source = tmp_path / "source"

    staged = import_analysis_reports(_package(source, [_report()]), source, tmp_path / "staging")

    (observation,) = _observations(staged.staging_root)
    assert observation["status"] == "parse_failed"
    assert observation["fields"]["rejection_reason"] == "results_exceed_limit"


@pytest.mark.parametrize(
    "analyzer, message",
    [
        (_analyzer(name="bad name"), "bounded identifier"),
        (_analyzer(execution_mode="emulated"), "static or dynamic"),
        (_analyzer(environment={"isolation": "cloud", "network": "disabled",
                                "environment_id": "x"}), "isolation is unsupported"),
        (_analyzer(executable_sha256="not-a-digest"), "SHA-256"),
        ({k: v for k, v in _analyzer().items() if k != "command"}, "requires name"),
    ],
)
def test_package_level_problems_fail_closed(tmp_path, analyzer, message):
    source = tmp_path / "source"
    with pytest.raises(OfflineEvidenceError, match=message):
        import_analysis_reports(
            _package(source, [_report()], analyzer), source, tmp_path / "s"
        )


def test_staging_is_byte_identical_across_runs(tmp_path):
    source = tmp_path / "source"
    package = _package(source, [_report(), _report(format="vendor-x/3")])

    first = import_analysis_reports(package, source, tmp_path / "first")
    second = import_analysis_reports(package, source, tmp_path / "second")

    for relative in first.relative_paths:
        assert (first.staging_root / relative).read_bytes() == (
            second.staging_root / relative
        ).read_bytes()


def test_module_cli_stages_a_package_file(tmp_path):
    source = tmp_path / "source"
    package = _package(source, [_report()])
    package_path = tmp_path / "reports-package.json"
    package_path.write_text(json.dumps(package), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable, "-m", "tools.binary_analysis_reports",
            "--package", str(package_path),
            "--source-root", str(source),
            "--staging-root", str(tmp_path / "cli-staging"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["analysis_status"] == "analysis_unsupported"
    assert output["observation_count"] == 3
    assert output["frozen"] is None


@pytest.mark.parametrize(
    "target",
    [
        {"os": "Linux", "release": "Ubuntu 24.04.1 LTS", "arch": "x86_64",
         "kernel_build": "6.8.0-45-generic"},
        {"os": "Windows", "release": "Windows 11 23H2", "arch": "AMD64",
         "kernel_build": "22631.4317"},
    ],
)
def test_reports_from_linux_and_windows_targets_are_accepted(tmp_path, target):
    source = tmp_path / "source"
    package = _package(source, [_report()])
    package["target"] = target

    staged = import_analysis_reports(package, source, tmp_path / "staging")

    assert {o["target"]["os"] for o in _observations(staged.staging_root)} == {target["os"]}

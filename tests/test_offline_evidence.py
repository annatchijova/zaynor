import hashlib

from tools.freebsd_evidence import import_freebsd_evidence
from tools.offline_evidence import combine_staged_evidence, freeze_staged_evidence
from tools.rootkit_scanner_reports import import_scanner_reports


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _header(module: str) -> dict:
    return {
        "schema_version": 1,
        "module": module,
        "case_id": "INC-COMBINED-001",
        "target": {
            "os": "FreeBSD",
            "release": "14.3-RELEASE",
            "arch": "amd64",
            "kernel_build": "GENERIC-14.3-p1",
        },
        "acquisition": {
            "acquisition_id": f"acq:{module}",
            "vantage": "external_disk" if module == "freebsd_evidence" else "guest_report",
            "lineage_id": f"lineage:{module}",
            "captured_at": "2026-09-30T12:00:00Z",
            "capture_time_source": "lab-record",
        },
    }


def test_combines_both_modules_before_one_case_freeze(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    config = b'example_load="YES"\n'
    report = b"Checking `amd'... not infected\n"
    (source / "loader.conf").write_bytes(config)
    (source / "chkrootkit.txt").write_bytes(report)

    freebsd_package = _header("freebsd_evidence")
    freebsd_package["artifacts"] = [
        {
            "logical_path": "/boot/loader.conf",
            "kind": "loader_configuration",
            "collection_status": "collected",
            "source_path": "loader.conf",
            "sha256": _sha256(config),
        }
    ]
    scanner_package = _header("rootkit_scanner_reports")
    scanner_package["scanner"] = {
        "name": "chkrootkit",
        "version": "0.59",
        "locale": "C",
        "command": ["chkrootkit"],
        "executable_sha256": "a" * 64,
        "exit_status": 0,
        "configuration_sha256": None,
        "data_version": None,
        "enabled_tests": None,
        "properties_database": None,
    }
    scanner_package["reports"] = [
        {"source_path": "chkrootkit.txt", "sha256": _sha256(report), "stream": "stdout"}
    ]

    freebsd = import_freebsd_evidence(freebsd_package, source, tmp_path / "stage-freebsd")
    scanner = import_scanner_reports(scanner_package, source, tmp_path / "stage-scanner")
    combined = combine_staged_evidence((freebsd, scanner), tmp_path / "stage-combined")
    manifest, _ = freeze_staged_evidence(combined, tmp_path / "cases")

    paths = {entry.relative_path for entry in manifest.entries}
    assert "originals/freebsd_evidence/loader.conf" in paths
    assert "originals/rootkit_scanner_reports/chkrootkit.txt" in paths
    assert "metadata/freebsd_evidence.json" in paths
    assert "metadata/rootkit_scanner_reports.json" in paths
    assert combined.observation_count == freebsd.observation_count + scanner.observation_count

    freebsd_again = import_freebsd_evidence(
        freebsd_package, source, tmp_path / "stage-freebsd-again"
    )
    scanner_again = import_scanner_reports(
        scanner_package, source, tmp_path / "stage-scanner-again"
    )
    combined_again = combine_staged_evidence(
        (freebsd_again, scanner_again), tmp_path / "stage-combined-again"
    )
    manifest_again, _ = freeze_staged_evidence(combined_again, tmp_path / "cases-again")
    assert manifest.content_sha256 == manifest_again.content_sha256

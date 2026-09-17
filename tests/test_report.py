from zaynor.authority_seal import seal_authoritative_result
from zaynor.report import ReportError, render_html, render_markdown, render_pdf
from zaynor.schemas import AuthoritativeFinding, EvidenceRef, ZaynorAuthoritativeResult


def _result() -> ZaynorAuthoritativeResult:
    return ZaynorAuthoritativeResult(
        case_id="CASE-REPORT-001",
        engine={"name": "vigia_agent", "version": "1.0.0-TEST"},
        verdict="SUSPICION",
        findings=(
            AuthoritativeFinding(
                finding_id="F-001",
                state="CORROBORATED",
                evidence_refs=(EvidenceRef(artifact="auth.jsonl", lineage_id="auth:E001"),),
                rationale="independent deterministic basis",
                mitre={"technique": "T1070.006"},
            ),
        ),
        unknowns=("credential origin",),
        integrity={"confidence": "3/4"},
    )


def test_markdown_report_contains_the_sealed_facts():
    result = _result()
    seal = seal_authoritative_result(result)
    text = render_markdown(result, seal)
    assert "CASE-REPORT-001" in text
    assert "SUSPICION" in text
    assert seal.sha256 in text
    assert "F-001" in text
    assert "T1070.006" in text
    assert "credential origin" in text
    assert "auth.jsonl" in text
    assert "auth:E001" in text
    assert "Agents in this pipeline" in text
    assert "MENTOR" in text
    assert "Detected by" in text
    assert "manifest_sha256" not in text  # this result has no real manifest/snapshot hashes
    assert "result_sha256" in text


def test_markdown_report_handles_a_result_with_no_findings():
    result = ZaynorAuthoritativeResult(case_id="CASE-EMPTY", engine={"name": "vigia_agent", "version": "1.0"})
    seal = seal_authoritative_result(result)
    text = render_markdown(result, seal)
    assert "No findings in this result." in text
    assert "None declared." in text
    assert "no ATT&CK technique corroborated" in text


def test_html_report_escapes_untrusted_finding_content():
    result = ZaynorAuthoritativeResult(
        case_id="CASE-XSS",
        engine={"name": "vigia_agent", "version": "1.0"},
        findings=(
            AuthoritativeFinding(
                finding_id="F-XSS",
                state="CORROBORATED",
                rationale="<script>alert(1)</script>",
            ),
        ),
    )
    seal = seal_authoritative_result(result)
    html = render_html(result, seal)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_report_contains_the_sealed_facts():
    result = _result()
    seal = seal_authoritative_result(result)
    html = render_html(result, seal)
    assert "CASE-REPORT-001" in html
    assert seal.sha256 in html
    assert "F-001" in html


def test_pdf_report_renders_real_bytes_or_reports_missing_dependency():
    """reportlab may or may not be installed in a given environment (it is
    an optional `[report]` extra) — either a real PDF comes back, or a clear
    ReportError names the extra to install. Never a silent empty result.
    """
    result = _result()
    seal = seal_authoritative_result(result)
    try:
        pdf_bytes = render_pdf(result, seal)
    except ReportError as exc:
        assert "pip install -e '.[report]'" in str(exc)
    else:
        assert pdf_bytes.startswith(b"%PDF-")

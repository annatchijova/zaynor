import sys
import warnings

import pytest

opentelemetry_sdk_trace = pytest.importorskip("opentelemetry.sdk.trace")
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from zaynor.audit_log import AuditLog
from zaynor.telemetry import annotate_with_audit_entry, case_root_span_id, case_trace_id, postmortem_span


def _tracer():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider.get_tracer("test"), exporter


def test_case_trace_id_is_deterministic_and_case_bound():
    assert case_trace_id("CASE-1") == case_trace_id("CASE-1")
    assert case_trace_id("CASE-1") != case_trace_id("CASE-2")
    assert 0 < case_trace_id("CASE-1") < 2**128


def test_case_root_span_id_is_deterministic_and_case_bound():
    assert case_root_span_id("CASE-1") == case_root_span_id("CASE-1")
    assert case_root_span_id("CASE-1") != case_root_span_id("CASE-2")
    assert 0 < case_root_span_id("CASE-1") < 2**64


def test_trace_id_and_root_span_id_do_not_collide_by_construction():
    assert case_trace_id("CASE-1") != case_root_span_id("CASE-1")


def test_postmortem_span_rejects_empty_case_id():
    with pytest.raises(ValueError, match="case_id"):
        with postmortem_span("", "zaynor.case_frozen"):
            pass


def test_postmortem_span_is_a_child_of_the_deterministic_root():
    tracer, exporter = _tracer()
    with postmortem_span("CASE-1", "zaynor.case_frozen", tracer=tracer):
        pass
    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "zaynor.case_frozen"
    assert span.context.trace_id == case_trace_id("CASE-1")
    assert span.parent.span_id == case_root_span_id("CASE-1")


def test_two_pipeline_steps_for_the_same_case_share_one_trace():
    tracer, exporter = _tracer()
    with postmortem_span("CASE-1", "zaynor.case_frozen", tracer=tracer):
        pass
    with postmortem_span("CASE-1", "zaynor.engine_invoked", tracer=tracer):
        pass
    spans = exporter.get_finished_spans()
    trace_ids = {span.context.trace_id for span in spans}
    assert trace_ids == {case_trace_id("CASE-1")}


def test_different_cases_never_share_a_trace():
    tracer, exporter = _tracer()
    with postmortem_span("CASE-1", "zaynor.case_frozen", tracer=tracer):
        pass
    with postmortem_span("CASE-2", "zaynor.case_frozen", tracer=tracer):
        pass
    spans = exporter.get_finished_spans()
    trace_ids = {span.context.trace_id for span in spans}
    assert trace_ids == {case_trace_id("CASE-1"), case_trace_id("CASE-2")}


def test_annotate_with_audit_entry_copies_the_entrys_own_fields(tmp_path):
    tracer, exporter = _tracer()
    audit = AuditLog(tmp_path / "audit.jsonl", case_id="CASE-1")
    entry = audit.append("CASE_FROZEN", {"manifest_sha256": "a" * 64}, reason="test freeze")
    with postmortem_span("CASE-1", "zaynor.case_frozen", tracer=tracer) as span:
        annotate_with_audit_entry(span, entry)
    spans = exporter.get_finished_spans()
    attrs = spans[0].attributes
    assert attrs["zaynor.case_id"] == "CASE-1"
    assert attrs["zaynor.audit.action"] == "CASE_FROZEN"
    assert attrs["zaynor.audit.reason"] == "test freeze"
    assert attrs["zaynor.audit.entry_hash"] == entry.entry_hash
    assert attrs["zaynor.audit.seq"] == 1


def test_annotate_with_audit_entry_on_a_none_span_is_a_silent_no_op():
    annotate_with_audit_entry(None, object())


def test_postmortem_span_degrades_honestly_without_the_sdk(monkeypatch):
    import zaynor.telemetry as telemetry

    monkeypatch.setitem(sys.modules, "opentelemetry", None)
    monkeypatch.setattr(telemetry, "_warned_missing_sdk", False)
    with pytest.warns(RuntimeWarning, match="opentelemetry-sdk not installed"):
        with postmortem_span("CASE-1", "zaynor.case_frozen") as span:
            assert span is None
    # Warns once per process, not once per call.
    with warnings.catch_warnings(record=True) as record:
        warnings.simplefilter("always")
        with postmortem_span("CASE-1", "zaynor.case_frozen") as span:
            assert span is None
    assert not any(issubclass(w.category, RuntimeWarning) for w in record)

#!/usr/bin/env python3
"""Synthetic demo service for the AIOps lab (stdlib only).

Emits the three telemetry planes ZAYNOR's AIOps path consumes:

- Metrics: Prometheus text format at ``/metrics`` (request counters,
  latency buckets, throughput).
- Logs: one structured JSON line per request on stdout and in the shared
  volume file (collected by the OTel Collector ``filelog`` receiver).
- Traces: Zipkin v2 JSON spans POSTed to the OTel Collector's zipkin
  receiver (which exports OTLP to Tempo).

Fault injection (synthetic, local): ``POST /admin/fault`` with
``{"mode": "none"|"latency"|"errors", "duration_seconds": N}``:

- ``latency``: every request sleeps an extra 400-900 ms (latency spike);
- ``errors``: most requests return HTTP 503 (error burst).

No external calls, no persistent state, and log content is evidence only.
"""

from __future__ import annotations

import json
import os
import random
import secrets
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

SERVICE_NAME = os.environ.get("ZAYNOR_DEMO_SERVICE", "demo-api")
ENVIRONMENT = os.environ.get("ZAYNOR_DEMO_ENV", "lab")
TRACE_URL = os.environ.get("ZAYNOR_OTLP_TRACE_URL", "http://otel-collector:9411/api/v2/spans")
LOG_FILE = os.environ.get("ZAYNOR_LOG_FILE", "/var/log/app/demo-api.jsonl")

_state_lock = threading.Lock()
_fault = {"mode": "none", "until": 0.0}
_request_count = 0
_error_count = 0
_latencies_ms: list[float] = []


def _log(level: str, event: str, **fields: Any) -> None:
    now = time.time()
    record = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
        + f".{int((now % 1) * 1000):03d}Z",
        "level": level,
        "service": SERVICE_NAME,
        "environment": os.environ.get("ZAYNOR_DEMO_ENV", "lab"),
        "event": event,
        **fields,
    }
    line = json.dumps(record, sort_keys=True)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        pass


def post_span(trace_id: str, span_id: str, name: str, start_us: int, duration_ms: int, status: str) -> None:
    span = {
        "traceId": trace_id,
        "id": span_id,
        "name": name,
        "localEndpoint": {"serviceName": SERVICE_NAME},
        "timestamp": int(start_us),
        "duration": int(duration_ms * 1000),
        "tags": {
            "environment": os.environ.get("ZAYNOR_DEMO_ENV", "lab"),
            "http.status_code": str(status),
        },
    }
    try:
        req = urllib.request.Request(
            TRACE_URL,
            data=json.dumps([span]).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5).read(4096)
    except OSError:
        pass  # traces are best-effort in the lab


MAX_BODY_BYTES = 64 * 1024


def _emit_work_span(start_us: float, duration_ms: float, status: int) -> None:
    """Emit one Zipkin span per /api/work request so the Tempo path of the
    demo actually carries data."""
    post_span(
        secrets.token_hex(16),
        secrets.token_hex(8),
        "api/work",
        int(start_us),
        duration_ms,
        str(status),
    )



class DemoHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:  # silence default stderr chatter
        pass

    def do_GET(self) -> None:  # noqa: N802
        global _request_count, _error_count
        if self.path == "/healthz":
            self._send(200, {"status": "ok"})
            return
        if self.path == "/metrics":
            body = render_metrics()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
            return
        if self.path.startswith("/api/work"):
            _record_request()
            mode, _ = fault_active()
            start = time.time()
            start_us = time.time() * 1_000_000
            if mode == "errors" and random.random() < 0.85:
                _record_error()
                _log("error", "work_failed", path=self.path, status=503)
                _emit_work_span(start_us, (time.time() - start) * 1000, status=503)
                self._send(503, {"error": "synthetic dependency failure"})
                return
            if mode == "latency":
                time.sleep(random.uniform(0.4, 0.9))
            _emit_work_span(start_us, (time.time() - start) * 1000, status=200)
            self._send(200, {"result": "synthetic-ok", "elapsed_ms": round((time.time() - start) * 1000, 1)})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/admin/fault":
            body, error = self._read_json()
            if error is not None:
                self._send(413, {"error": error})
                return
            mode = body.get("mode", "none")
            if mode not in ("none", "latency", "errors"):
                self._send(400, {"error": "mode must be none|latency|errors"})
                return
            duration = max(1, int(body.get("duration_seconds", 30)))
            with _state_lock:
                _fault["mode"] = mode
                _fault["until"] = time.time() + duration
            _log("warning", "fault_injected", fault_mode=mode, duration_seconds=duration)
            self._send(200, {"ok": True, "mode": mode, "duration_seconds": duration})
            return
        self._send(404, {"error": "not found"})

    def _send(self, code: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body, sort_keys=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self) -> tuple[dict[str, Any], str | None]:
        """Parse a bounded JSON body. Returns (body, error); error is a
        message when the declared body exceeds MAX_BODY_BYTES."""
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            return {}, None
        if length > MAX_BODY_BYTES:
            return {}, f"request body too large (limit {MAX_BODY_BYTES} bytes)"
        try:
            parsed = json.loads(self.rfile.read(length).decode("utf-8"))
            return (parsed if isinstance(parsed, dict) else {}), None
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}, None


def render_metrics() -> str:
    with _state_lock:
        count = _request_count
        errors = _error_count
        latencies = list(_latencies_ms)
    lines = [
        "# HELP demo_requests_total Total synthetic requests.",
        "# TYPE demo_requests_total counter",
        f"demo_requests_total {count}",
        "# TYPE demo_errors_total counter",
        f"demo_errors_total {errors}",
    ]
    bounds = [10, 25, 50, 100, 250, 500, 1000, 2500, 5000]
    cumulative = 0
    for bound in bounds:
        cumulative = sum(1 for value in latencies if value <= bound)
        lines.append(f'demo_request_latency_ms_bucket{{le="{bound:g}"}} {cumulative}')
    lines.append(f'demo_request_latency_ms_bucket{{le="+Inf"}} {len(latencies)}')
    if latencies:
        lines.append(f"demo_request_latency_ms_sum {sum(latencies):.3f}")
        lines.append(f"demo_request_latency_ms_count {len(latencies)}")
    lines.append("# TYPE demo_error_ratio gauge")
    if count:
        lines.append(f"demo_error_ratio {errors / count:.4f}")
    else:
        lines.append("demo_error_ratio 0")
    return "\n".join(lines) + "\n"


def fault_active() -> tuple[str, bool]:
    with _state_lock:
        if time.time() < _fault["until"]:
            return _fault["mode"], True
        return "none", False


def _record_request() -> None:
    global _request_count
    with _state_lock:
        _request_count += 1


def _record_error() -> None:
    global _error_count
    with _state_lock:
        _error_count += 1


def main() -> int:
    port = int(os.environ.get("ZAYNOR_DEMO_PORT", "8000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), DemoHandler)
    _log("info", "service_started", port=port)
    threading.Thread(target=_traffic_loop, daemon=True).start()
    server.serve_forever()
    return 0


def _traffic_loop() -> None:
    """Background synthetic traffic against this service's own /api/work."""
    while True:
        time.sleep(1.0)
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{os.environ.get('ZAYNOR_DEMO_PORT', '8000')}/api/work", timeout=10).read(4096)
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())

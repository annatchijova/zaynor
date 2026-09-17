"""Loopback transport tests for the local-only Ollama client."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from zaynor.agents.ollama_client import OllamaClient, OllamaError, list_available_models


class _OllamaFixtureHandler(BaseHTTPRequestHandler):
    requests: list[tuple[str, dict | None]] = []

    def do_GET(self):
        self.__class__.requests.append((self.path, None))
        body = b'{"models":[{"name":"tiny:1b"}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        payload = json.loads(self.rfile.read(length))
        self.__class__.requests.append((self.path, payload))
        body = b'{"response":"local fixture narration"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


@pytest.fixture
def ollama_fixture():
    _OllamaFixtureHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OllamaFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_loopback_transport_uses_configured_host_model_and_non_streaming(ollama_fixture):
    client = OllamaClient(host=ollama_fixture, model="tiny:1b", timeout_seconds=3)
    assert client.generate(system="system", prompt="prompt") == "local fixture narration"
    assert list_available_models(ollama_fixture, timeout_seconds=3) == ["tiny:1b"]
    assert _OllamaFixtureHandler.requests == [
        ("/api/generate", {
            "model": "tiny:1b",
            "system": "system",
            "prompt": "prompt",
            "stream": False,
        }),
        ("/api/tags", None),
    ]


def test_model_discovery_rejects_non_positive_timeout():
    with pytest.raises(OllamaError, match="timeout"):
        list_available_models(timeout_seconds=0)


class _OversizedResponseHandler(BaseHTTPRequestHandler):
    """Red team round 21 (R21-05, CODE FACT): neither `generate()` nor
    `list_available_models()` bounded `response.read()` before parsing --
    a misbehaving local Ollama could hand back an unbounded body. This
    fixture serves genuinely oversized bodies over a real loopback HTTP
    server (not a mock) to confirm the fix by induction, not code review.
    """

    def do_GET(self):
        oversized = b'{"models":[' + (b'{"name":"x"},' * 100_000) + b'{"name":"y"}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(oversized)))
        self.end_headers()
        self.wfile.write(oversized)

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        self.rfile.read(length)
        oversized = b'{"response":"' + (b"a" * (8 * 1024 * 1024 + 1024)) + b'"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(oversized)))
        self.end_headers()
        self.wfile.write(oversized)

    def log_message(self, *_args):
        return


@pytest.fixture
def oversized_ollama_fixture():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OversizedResponseHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_generate_rejects_a_genuinely_oversized_response(oversized_ollama_fixture):
    client = OllamaClient(host=oversized_ollama_fixture, model="tiny:1b", timeout_seconds=5)
    with pytest.raises(OllamaError, match="exceeded"):
        client.generate(system="system", prompt="prompt")


def test_list_available_models_rejects_a_genuinely_oversized_response(oversized_ollama_fixture):
    with pytest.raises(OllamaError, match="exceeded"):
        list_available_models(oversized_ollama_fixture, timeout_seconds=5)

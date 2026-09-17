"""Boundary tests for bounded OpenAI-compatible chat requests."""

import pytest
from pydantic import ValidationError

from zaynor.api import ChatRequest


def test_chat_request_rejects_too_many_messages():
    with pytest.raises(ValidationError):
        ChatRequest.model_validate({
            "messages": [{"role": "user", "content": "x"}] * 65,
        })


def test_chat_request_rejects_oversized_message_content():
    with pytest.raises(ValidationError):
        ChatRequest.model_validate({
            "messages": [{"role": "user", "content": "x" * 32_769}],
        })


def test_chat_request_rejects_oversized_total_utf8_content():
    with pytest.raises(ValidationError):
        ChatRequest.model_validate({
            "messages": [{"role": "user", "content": "é" * 70_000}],
        })

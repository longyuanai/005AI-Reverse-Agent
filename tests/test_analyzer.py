"""Tests for the LLM enricher."""

from __future__ import annotations

import json

import pytest

from ai_reverse_agent.analyzer import explain_function, explain_functions
from ai_reverse_agent.datatypes import EnrichedFunction, IdentifiedFunction
from ai_reverse_agent.fake_pe import make_fake_pe
from ai_reverse_agent.identifier import identify_functions
from ai_reverse_agent.parsers import parse_pe_bytes


def _stub_router(reply: dict | None = None) -> object:
    payload = reply if reply is not None else {
        "name": "X",
        "purpose": "opens a file handle",
    }

    class _R:
        def __init__(self) -> None:
            self.calls: list = []

        def chat(self, tier, req):
            from shared_llm_core import (
                ChatChoice,
                ChatMessage,
                ChatResponse,
                ChatUsage,
            )
            self.calls.append(req)
            return ChatResponse(
                id="x",
                model="m",
                created=0,
                choices=[
                    ChatChoice(
                        index=0,
                        message=ChatMessage(
                            role="assistant",
                            content=json.dumps(payload),
                        ),
                        finish_reason="stop",
                    )
                ],
                usage=ChatUsage(),
            )

    return _R()


def test_explain_function_returns_enriched():
    fn = IdentifiedFunction(
        name="CreateFileW",
        dll="kernel32.dll",
        address=0x1234,
        section=".idata",
        kind="import",
    )
    router = _stub_router({
        "name": "CreateFileW",
        "purpose": "opens a file for reading or writing",
    })
    out = explain_function(router, fn)
    assert isinstance(out, EnrichedFunction)
    assert "opens" in out.purpose.lower()


def test_explain_function_uses_json_object_format():
    fn = IdentifiedFunction(
        name="printf", dll="msvcrt.dll", address=0x123C, section=".idata", kind="import",
    )
    router = _stub_router()
    explain_function(router, fn)
    assert router.calls[0].response_format == {"type": "json_object"}


def test_explain_functions_handles_all_identified():
    router = _stub_router()
    ident = identify_functions(parse_pe_bytes(make_fake_pe()))
    out = explain_functions(router, ident)
    assert len(out) == len(ident)
    for ef in out:
        assert isinstance(ef, EnrichedFunction)


def test_explain_functions_calls_llm_per_function():
    router = _stub_router()
    ident = identify_functions(parse_pe_bytes(make_fake_pe()))
    explain_functions(router, ident)
    assert len(router.calls) == len(ident)


def test_explain_function_with_reversed_json_order():
    """LLM may return fields in any order — must still parse."""
    router = _stub_router({"purpose": "x", "name": "y"})
    fn = IdentifiedFunction(
        name="X", dll="Y", address=0, section=".text", kind="local",
    )
    out = explain_function(router, fn)
    assert out.purpose == "x"


def test_explain_function_strips_markdown_fences():
    """Some completions wrap JSON in ```json ... ``` — strip them."""
    class _R:
        def __init__(self):
            self.calls = []

        def chat(self, tier, req):
            from shared_llm_core import (
                ChatChoice,
                ChatMessage,
                ChatResponse,
                ChatUsage,
            )
            self.calls.append(req)
            return ChatResponse(
                id="x", model="m", created=0,
                choices=[ChatChoice(
                    index=0,
                    message=ChatMessage(
                        role="assistant",
                        content="```json\n{\"name\": \"Foo\", \"purpose\": \"bar\"}\n```",
                    ),
                    finish_reason="stop",
                )],
                usage=ChatUsage(),
            )

    fn = IdentifiedFunction(
        name="Foo", dll="bar.dll", address=0, section=".text", kind="import",
    )
    out = explain_function(_R(), fn)
    assert out.purpose == "bar"

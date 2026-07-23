"""Tests for the Markdown reporter."""

from __future__ import annotations

import json

from ai_reverse_agent.analyzer import explain_functions
from ai_reverse_agent.datatypes import EnrichedFunction, IdentifiedFunction
from ai_reverse_agent.fake_pe import make_fake_pe
from ai_reverse_agent.identifier import identify_functions
from ai_reverse_agent.parsers import parse_pe_bytes
from ai_reverse_agent.reporter import render_markdown


def _stub_router(purpose: str = "test purpose"):
    class _R:
        def chat(self, tier, req):
            from shared_llm_core import (
                ChatChoice,
                ChatMessage,
                ChatResponse,
                ChatUsage,
            )
            return ChatResponse(
                id="x", model="m", created=0,
                choices=[ChatChoice(
                    index=0,
                    message=ChatMessage(
                        role="assistant",
                        content=json.dumps({"name": "X", "purpose": purpose}),
                    ),
                    finish_reason="stop",
                )],
                usage=ChatUsage(),
            )
    return _R()


def _build():
    pe = parse_pe_bytes(make_fake_pe())
    ident = identify_functions(pe)
    enriched = explain_functions(_stub_router(), ident)
    return pe, enriched


def test_report_header_includes_machine_name():
    pe, enriched = _build()
    md = render_markdown(pe, enriched, source="demo")
    assert "AMD64" in md


def test_report_includes_section_table():
    pe, enriched = _build()
    md = render_markdown(pe, enriched, source="demo")
    assert "| `.text` |" in md
    assert "| `.rdata` |" in md
    assert "| `.idata` |" in md


def test_report_groups_imports_by_dll():
    pe, enriched = _build()
    md = render_markdown(pe, enriched, source="demo")
    # Each DLL should be a heading line.
    for dll in ("kernel32.dll", "user32.dll", "msvcrt.dll", "ws2_32.dll", "advapi32.dll"):
        assert f"### `{dll}`" in md


def test_report_lists_all_five_function_names():
    pe, enriched = _build()
    md = render_markdown(pe, enriched, source="demo")
    for name in ("CreateFileW", "MessageBoxW", "printf", "connect", "RegOpenKeyExW"):
        assert name in md


def test_report_includes_entry_point_summary():
    pe, enriched = _build()
    md = render_markdown(pe, enriched, source="demo")
    assert "**Entry point**" in md


def test_report_includes_source_label():
    pe, enriched = _build()
    md = render_markdown(pe, enriched, source="myfile.bin")
    assert "myfile.bin" in md


def test_report_handles_zero_functions():
    """If there are no functions, the report still renders cleanly."""
    from ai_reverse_agent.datatypes import OptionalHeader, CoffHeader
    from ai_reverse_agent.parsers import _parse  # noqa: PLC2701
    # Use the real parser on the real fake PE — then zero everything.
    pe = parse_pe_bytes(make_fake_pe())
    pe_no_fn = pe.__class__(
        coff=pe.coff,
        optional=pe.optional,
        sections=pe.sections,
        imports=[],
        functions=[],
    )
    md = render_markdown(pe_no_fn, [], source="empty")
    # Should render without crashing and contain PE header summary.
    assert "PE Header Summary" in md
    assert "_No identified functions._" in md

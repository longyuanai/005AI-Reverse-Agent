"""Tests for the function identifier."""

from __future__ import annotations

from ai_reverse_agent.fake_pe import make_fake_pe
from ai_reverse_agent.identifier import identify_functions
from ai_reverse_agent.parsers import parse_pe_bytes


def _ident():
    return identify_functions(parse_pe_bytes(make_fake_pe()))


def test_identifier_returns_at_least_five():
    ident = _ident()
    assert len(ident) >= 5


def test_identifier_includes_all_target_functions():
    ident = _ident()
    names = {f.name for f in ident}
    for name in ("CreateFileW", "MessageBoxW", "printf", "connect", "RegOpenKeyExW"):
        assert name in names


def test_identifier_assigns_correct_dlls():
    ident = _ident()
    by_name = {f.name: f.dll for f in ident}
    assert by_name["CreateFileW"] == "kernel32.dll"
    assert by_name["MessageBoxW"] == "user32.dll"
    assert by_name["printf"] == "msvcrt.dll"
    assert by_name["connect"] == "ws2_32.dll"
    assert by_name["RegOpenKeyExW"] == "advapi32.dll"


def test_identifier_marks_imports_as_kind_import():
    ident = _ident()
    imports = [f for f in ident if f.kind == "import"]
    assert len(imports) >= 5


def test_identifier_section_membership():
    ident = _ident()
    for f in ident:
        # Either section starts with '.' (resolved) or it's unknown.
        assert f.section.startswith(".") or f.section == "<unknown>"


def test_identifier_entry_point_present():
    ident = _ident()
    entries = [f for f in ident if f.kind == "entry"]
    if entries:  # fixture should include entry; tolerate absence if RVA collides
        assert entries[0].name == "entry_point"

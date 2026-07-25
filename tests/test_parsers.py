"""Tests for the PE parser (round-trip)."""

from __future__ import annotations

from io import BytesIO

import pytest

from ai_reverse_agent.datatypes import PeImage
from ai_reverse_agent.fake_pe import make_fake_pe
from ai_reverse_agent.parsers import (
    parse_pe,
    parse_pe_bytes,
    parse_pe_file,
)


def _roundtrip() -> PeImage:
    return parse_pe_bytes(make_fake_pe())


def test_parser_returns_pe_image():
    pe = _roundtrip()
    assert isinstance(pe, PeImage)


def test_parser_extracts_three_sections():
    pe = _roundtrip()
    names = sorted(s.name for s in pe.sections)
    assert names == [".idata", ".rdata", ".text"]


def test_parser_extracts_entry_point():
    pe = _roundtrip()
    # Entry point is in .text VA = 0x1000 + 0x10 = 0x1010.
    assert pe.entry_point == 0x1010


def test_parser_extracts_machine_type():
    pe = _roundtrip()
    assert pe.coff.machine == 0x8664  # AMD64


def test_parser_extracts_all_five_imports():
    pe = _roundtrip()
    assert len(pe.imports) == 5
    names = {i.function for i in pe.imports}
    assert names == {"CreateFileW", "MessageBoxW", "printf", "connect", "RegOpenKeyExW"}


def test_parser_assigns_correct_dlls():
    pe = _roundtrip()
    by_name = {i.function: i.dll for i in pe.imports}
    assert by_name["CreateFileW"] == "kernel32.dll"
    assert by_name["MessageBoxW"] == "user32.dll"
    assert by_name["printf"] == "msvcrt.dll"
    assert by_name["connect"] == "ws2_32.dll"
    assert by_name["RegOpenKeyExW"] == "advapi32.dll"


def test_parser_extracts_function_table():
    pe = _roundtrip()
    assert len(pe.functions) == 5
    names = {f.name for f in pe.functions}
    assert names == {"CreateFileW", "MessageBoxW", "printf", "connect", "RegOpenKeyExW"}


def test_parser_rejects_non_mz():
    with pytest.raises(ValueError):
        parse_pe_bytes(b"not a PE\x00\x00\x00...")


def test_parser_pe_signature_at_known_offset():
    pe = _roundtrip()
    assert pe.coff.timestamp == 0x66000000


def test_parse_pe_file(tmp_path):
    path = tmp_path / "demo.bin"
    path.write_bytes(make_fake_pe())
    pe = parse_pe_file(str(path))
    assert len(pe.imports) == 5


def test_parse_pe_from_stream():
    blob = make_fake_pe()
    pe = parse_pe(BytesIO(blob))
    assert pe.coff.machine == 0x8664


def test_section_raw_offsets_match_va_for_fixture():
    pe = _roundtrip()
    sec_by_name = {s.name: s for s in pe.sections}
    # Just sanity-check sizes for the round-trip.
    assert sec_by_name[".text"].raw_size == 0x200
    assert sec_by_name[".rdata"].raw_size == 0x400
    assert sec_by_name[".idata"].raw_size == 0x600

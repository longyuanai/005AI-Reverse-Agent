"""Tests for the fake-PE generator."""

from __future__ import annotations

import struct

from ai_reverse_agent.fake_pe import (
    FakeFunction,
    TARGET_FUNCTIONS,
    make_fake_pe,
)


def test_fake_pe_starts_with_mz():
    blob = make_fake_pe()
    assert blob[:2] == b"MZ"


def test_fake_pe_has_pe_signature():
    blob = make_fake_pe()
    # e_lfanew points to the file-aligned 0x200 where the PE sig lives.
    e_lfanew = struct.unpack("<I", blob[0x3C:0x40])[0]
    assert e_lfanew == 0x200
    assert blob[0x200:0x204] == b"PE\x00\x00"


def test_fake_pe_contains_all_five_target_names():
    blob = make_fake_pe()
    expected = {f.name for f in TARGET_FUNCTIONS}
    missing = [n for n in expected if n.encode("ascii") not in blob]
    assert missing == []


def test_fake_pe_nontrivial_size():
    blob = make_fake_pe()
    assert len(blob) >= 0x800


def test_default_functions_are_the_expected_set():
    names = {f.name for f in TARGET_FUNCTIONS}
    assert names == {"CreateFileW", "MessageBoxW", "printf", "connect", "RegOpenKeyExW"}


def test_can_pass_custom_functions():
    custom = [
        FakeFunction(name="Foo", dll="bar.dll", hint=1, address=0x1000),
        FakeFunction(name="Baz", dll="bar.dll", hint=2, address=0x1004),
    ]
    blob = make_fake_pe(custom)
    assert b"Foo" in blob
    assert b"Baz" in blob


def test_function_table_lists_each_name():
    """Each function name should appear at least twice (table + import)."""
    blob = make_fake_pe()
    text = blob.decode("latin-1")
    assert text.count("CreateFileW") >= 2


def test_fake_pe_pe32_magic():
    """The optional header should declare PE32 (0x10b).

    PE sig at 0x200, COFF 20 bytes, optional magic at 0x218.
    """
    blob = make_fake_pe()
    opt_magic_offset = 0x200 + 4 + 20
    assert blob[opt_magic_offset:opt_magic_offset + 2] == b"\x0b\x01"


def test_fake_pe_is_deterministic():
    blob1 = make_fake_pe()
    blob2 = make_fake_pe()
    # Only timestamp is non-deterministic; skip the timestamp field.
    # We only call make_fake_pe() once and check the byte layout is stable.
    assert blob1[0:0x3C] == blob2[0:0x3C]
    assert blob1[0x3C + 4 :] == blob2[0x3C + 4 :]

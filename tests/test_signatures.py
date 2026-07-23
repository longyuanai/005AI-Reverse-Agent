"""Tests for the built-in library signature matcher."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from ai_reverse_agent.cli import cli
from ai_reverse_agent.decompiler import decompile_bytes
from ai_reverse_agent.signatures import BUILTIN_SIGNATURES, match_code


MSVCRT_MEMCPY = bytes.fromhex(
    "8b 44 24 04 8b 4c 24 08 8b 54 24 0c 85 d2 74 06 "
    "8a 19 88 18 40 41 4a 75 f8 c3"
)
LIBC_STRLEN = bytes.fromhex(
    "31 c0 80 3c 07 00 74 05 48 ff c0 eb f5 c3"
)
LIBSTDCXX_TERMINATE = bytes.fromhex(
    "55 48 89 e5 e8 11 22 33 44 0f 0b"
)


def test_signature_table_covers_required_libraries():
    assert {signature.library for signature in BUILTIN_SIGNATURES} == {
        "msvcrt",
        "libc",
        "libstdc++",
    }


@pytest.mark.parametrize(
    ("code", "architecture", "library", "name"),
    [
        (MSVCRT_MEMCPY, "x86", "msvcrt", "memcpy"),
        (LIBC_STRLEN, "x64", "libc", "strlen"),
        (LIBSTDCXX_TERMINATE, "x64", "libstdc++", "_ZSt9terminatev"),
    ],
)
def test_matches_required_builtin_signatures(code, architecture, library, name):
    match = match_code(code, architecture)
    assert match is not None
    assert match.library == library
    assert match.name == name


def test_libstdcxx_signature_masks_call_relocation():
    variant = bytearray(LIBSTDCXX_TERMINATE)
    variant[5:9] = b"\xaa\xbb\xcc\xdd"
    match = match_code(bytes(variant), "x64")
    assert match is not None
    assert match.name == "_ZSt9terminatev"


def test_unknown_prefix_does_not_match():
    assert match_code(b"\x90\x90\xc3", "x64") is None


def test_decompiler_replaces_sub_name_on_signature_hit():
    function = decompile_bytes(LIBC_STRLEN, "x64", address=0x401000)[0]
    assert function.name == "strlen"
    assert function.library == "libc"
    assert function.pseudo_c.startswith("void strlen(void)")


def test_match_uses_only_first_sixteen_bytes():
    match = match_code(LIBC_STRLEN + b"\xcc" * 32, "x64")
    assert match is not None
    assert match.name == "strlen"


def test_cli_identify_libs(tmp_path):
    binary = tmp_path / "strlen.bin"
    binary.write_bytes(LIBC_STRLEN)
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "identify-libs",
            str(binary),
            "--arch",
            "x64",
            "--base-address",
            "0x401000",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "0x401000 libc!strlen" in result.output

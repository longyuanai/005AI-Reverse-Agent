"""Tests for Capstone-backed raw binary disassembly."""

from __future__ import annotations

import pytest

from ai_reverse_agent.architecture import Architecture, Endianness
from ai_reverse_agent.disassembler import (
    DisassemblyError,
    disassemble_bytes,
    disassemble_file,
    format_disassembly,
)


@pytest.mark.parametrize(
    ("architecture", "machine_code", "expected"),
    [
        ("x86", b"\xb8\x2a\x00\x00\x00\xc3", "mov"),
        ("x64", b"\x55\x48\x89\xe5\xc3", "push"),
        ("arm", b"\x00\x00\xa0\xe1\x1e\xff\x2f\xe1", "mov"),
        ("aarch64", b"\x1f\x20\x03\xd5\xc0\x03\x5f\xd6", "nop"),
        ("mips", b"\x08\x00\xe0\x03\x00\x00\x00\x00", "jr"),
        ("riscv", b"\x67\x80\x00\x00", "ret"),
    ],
)
def test_disassembles_each_stage_architecture(architecture, machine_code, expected):
    result = disassemble_bytes(machine_code, architecture)
    assert result.architecture.architecture is Architecture(architecture)
    assert result.instructions[0].mnemonic == expected
    assert result.trailing_bytes == b""


def test_disassembles_arm_thumb_mode():
    result = disassemble_bytes(b"\x70\x47", "arm", thumb=True)
    assert result.instructions[0].mnemonic == "bx"
    assert result.instructions[0].operands == "lr"


def test_disassembles_big_endian_mips():
    result = disassemble_bytes(
        b"\x03\xe0\x00\x08\x00\x00\x00\x00",
        "mips",
        endianness=Endianness.BIG,
    )
    assert result.instructions[0].mnemonic == "jr"


def test_honors_base_address_and_instruction_limit():
    result = disassemble_bytes(
        b"\x90\x90\xc3",
        "x64",
        base_address=0x401000,
        max_instructions=2,
    )
    assert [instruction.address for instruction in result.instructions] == [
        0x401000,
        0x401001,
    ]
    assert result.trailing_bytes == b"\xc3"
    assert result.truncated is True


def test_strict_mode_rejects_undecoded_tail():
    with pytest.raises(DisassemblyError, match="remain undecoded"):
        disassemble_bytes(b"\x0f", "x64", strict=True)


def test_rejects_thumb_for_non_arm():
    with pytest.raises(ValueError, match="only valid for the arm"):
        disassemble_bytes(b"\x90", "x86", thumb=True)


def test_disassemble_file_reads_real_bin(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x55\x48\x89\xe5\xc3")
    result = disassemble_file(binary, "amd64", base_address=0x1000)
    assert len(result.instructions) == 3
    assert result.instructions[-1].mnemonic == "ret"


def test_format_disassembly_includes_bytes_address_and_operands():
    result = disassemble_bytes(b"\xb8\x2a\x00\x00\x00", "x86", base_address=0x1000)
    listing = format_disassembly(result)
    assert "; architecture: x86 (32-bit, little-endian)" in listing
    assert "0x00001000:" in listing
    assert "b8 2a 00 00 00" in listing
    assert "mov eax, 0x2a" in listing


def test_empty_input_returns_empty_result():
    result = disassemble_bytes(b"", "aarch64")
    assert result.instructions == ()
    assert result.decoded_size == 0
    assert result.trailing_bytes == b""

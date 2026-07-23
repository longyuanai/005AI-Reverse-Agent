"""Tests for the stable normalized disassembly interface."""

from __future__ import annotations

import pytest
from capstone import CS_ARCH_X86, CS_MODE_64

from ai_reverse_agent.disasm import NormalizedInstruction, disassemble, disassemble_file
from ai_reverse_agent.fake_bin import make_fake_bin


def test_normalized_instruction_is_required_four_tuple():
    instruction = next(disassemble(make_fake_bin("x64"), "x64"))
    assert isinstance(instruction, NormalizedInstruction)
    assert tuple(instruction) == (
        instruction.address,
        instruction.mnemonic,
        instruction.op_str,
        instruction.bytes_hex,
    )


def test_normalized_bytes_are_lowercase_hex_without_separators():
    instruction = next(disassemble(b"\x48\x89\xe5", "x64"))
    assert instruction.bytes_hex == "4889e5"


def test_accepts_raw_capstone_arch_and_mode():
    instructions = list(disassemble(b"\x90\xc3", CS_ARCH_X86, CS_MODE_64))
    assert [instruction.mnemonic for instruction in instructions] == ["nop", "ret"]


def test_raw_capstone_arch_requires_mode():
    with pytest.raises(ValueError, match="mode is required"):
        list(disassemble(b"\x90", CS_ARCH_X86))


def test_disassemble_file_yields_normalized_stream(tmp_path):
    path = tmp_path / "demo.bin"
    path.write_bytes(make_fake_bin("riscv"))
    instructions = list(disassemble_file(path, "riscv", address=0x8000))
    assert len(instructions) == 3
    assert instructions[0].address == 0x8000

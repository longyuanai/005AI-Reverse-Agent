"""Tests for conservative pseudo-C decompilation."""

from __future__ import annotations

from click.testing import CliRunner

from ai_reverse_agent.cli import cli
from ai_reverse_agent.decompiler import (
    decompile_bytes,
    find_function_boundaries,
    identify_stack_variables,
)
from ai_reverse_agent.disasm import disassemble
from ai_reverse_agent.fake_bin import make_fake_bin


def test_finds_two_x64_functions_at_returns():
    code = make_fake_bin("x64") + make_fake_bin("x64")
    boundaries = find_function_boundaries(tuple(disassemble(code, "x64", address=0x1000)))
    assert len(boundaries) == 2
    assert boundaries[0].start_address == 0x1000
    assert boundaries[1].start_address == 0x1005


def test_identifies_x64_stack_variable_and_references():
    code = bytes.fromhex("55 48 89 e5 48 89 7d f8 48 8b 45 f8 c3")
    boundary = find_function_boundaries(tuple(disassemble(code, "x64")))[0]
    variables = identify_stack_variables(boundary)
    assert len(variables) == 1
    assert variables[0].offset == -8
    assert variables[0].name == "var_8"
    assert variables[0].references == (4, 8)


def test_decompile_emits_stack_declaration_and_evidence_addresses():
    code = bytes.fromhex("55 48 89 e5 48 89 7d f8 48 8b 45 f8 c3")
    function = decompile_bytes(code, "x64", address=0x401000)[0]
    assert "void sub_401000(void)" in function.pseudo_c
    assert "uintptr_t var_8" in function.pseudo_c
    assert "/* 0x401004 */ var_8 = rdi;" in function.pseudo_c
    assert "/* 0x40100c */ return;" in function.pseudo_c


def test_decompile_handles_all_six_architecture_fixtures():
    for architecture in ("x86", "x64", "arm", "aarch64", "mips", "riscv"):
        functions = decompile_bytes(make_fake_bin(architecture), architecture)
        assert len(functions) == 1
        assert "return;" in functions[0].pseudo_c


def test_cli_decompile_raw_binary(tmp_path):
    binary = tmp_path / "function.bin"
    binary.write_bytes(bytes.fromhex("55 48 89 e5 48 89 7d f8 c3"))
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "decompile",
            str(binary),
            "--arch",
            "x64",
            "--base-address",
            "0x401000",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "void sub_401000(void)" in result.output
    assert "uintptr_t var_8" in result.output

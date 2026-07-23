"""Tests for function- and instruction-level binary patch diffs."""

from __future__ import annotations

from click.testing import CliRunner

from ai_reverse_agent.cli import cli
from ai_reverse_agent.patch_diff import diff_binaries, format_patch_diff


BASELINE_X64 = bytes.fromhex("b8 01 00 00 00 c3")
PATCHED_X64 = bytes.fromhex("b8 02 00 00 00 c3")


def test_detects_modified_function_and_replaced_instruction():
    result = diff_binaries(BASELINE_X64, PATCHED_X64, "x64", address=0x401000)
    assert len(result.changed_functions) == 1
    function = result.changed_functions[0]
    assert function.status == "modified"
    assert function.baseline_address == 0x401000
    assert function.instruction_deltas[0].kind == "replaced"
    assert function.instruction_deltas[0].before.op_str == "eax, 1"
    assert function.instruction_deltas[0].after.op_str == "eax, 2"


def test_detects_added_function():
    result = diff_binaries(b"\xc3", b"\xc3\xc3", "x64", address=0x1000)
    assert len(result.functions) == 2
    assert result.functions[1].status == "added"
    assert result.functions[1].current_address == 0x1001


def test_detects_removed_function():
    result = diff_binaries(b"\xc3\xc3", b"\xc3", "x64", address=0x1000)
    assert len(result.functions) == 2
    assert result.functions[1].status == "removed"
    assert result.functions[1].baseline_address == 0x1001


def test_identical_binaries_have_no_changed_functions():
    result = diff_binaries(BASELINE_X64, BASELINE_X64, "x64")
    assert result.changed_functions == ()
    assert result.functions[0].status == "unchanged"


def test_formats_per_function_instruction_diff():
    report = format_patch_diff(
        diff_binaries(BASELINE_X64, PATCHED_X64, "x64", address=0x401000)
    )
    assert "Changed functions: 1" in report
    assert "MODIFIED function_0 0x401000 -> 0x401000" in report
    assert "- 0x401000 b801000000 mov eax, 1" in report
    assert "+ 0x401000 b802000000 mov eax, 2" in report


def test_supports_arm_instruction_diff():
    baseline = bytes.fromhex("01 00 a0 e3 1e ff 2f e1")
    current = bytes.fromhex("02 00 a0 e3 1e ff 2f e1")
    result = diff_binaries(baseline, current, "arm", address=0x8000)
    assert result.changed_functions[0].instruction_deltas[0].before.op_str == "r0, #1"
    assert result.changed_functions[0].instruction_deltas[0].after.op_str == "r0, #2"


def test_cli_patch_diff_outputs_changed_function(tmp_path):
    baseline = tmp_path / "baseline.bin"
    current = tmp_path / "current.bin"
    baseline.write_bytes(BASELINE_X64)
    current.write_bytes(PATCHED_X64)
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "patch-diff",
            str(baseline),
            str(current),
            "--arch",
            "x64",
            "--base-address",
            "0x401000",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Changed functions: 1" in result.output
    assert "mov eax, 1" in result.output
    assert "mov eax, 2" in result.output

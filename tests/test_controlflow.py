"""Tests for basic-block CFG construction and DOT/PNG output."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from ai_reverse_agent.cli import cli
from ai_reverse_agent.controlflow import (
    GraphvizUnavailable,
    build_cfg,
    render_png,
    to_dot,
)
from ai_reverse_agent.disasm import disassemble


BRANCHING_X64 = bytes.fromhex(
    "31 c0"        # xor eax, eax
    "74 03"        # je 0x1007
    "83 c0 01"     # add eax, 1
    "c3"           # ret
)


def test_build_cfg_splits_conditional_branch_into_three_blocks():
    instructions = tuple(disassemble(BRANCHING_X64, "x64", address=0x1000))
    graph = build_cfg(instructions)
    assert [block.start_address for block in graph.blocks] == [0x1000, 0x1004, 0x1007]


def test_build_cfg_adds_branch_and_fallthrough_edges():
    graph = build_cfg(tuple(disassemble(BRANCHING_X64, "x64", address=0x1000)))
    edges = {(edge.source, edge.target, edge.kind) for edge in graph.edges}
    assert (0x1000, 0x1007, "branch") in edges
    assert (0x1000, 0x1004, "fallthrough") in edges
    assert (0x1004, 0x1007, "fallthrough") in edges


def test_build_cfg_splits_call_and_links_target():
    code = bytes.fromhex("e8 01 00 00 00 c3 c3")
    graph = build_cfg(tuple(disassemble(code, "x64", address=0x2000)))
    assert [block.start_address for block in graph.blocks] == [0x2000, 0x2005, 0x2006]
    assert (0x2000, 0x2006, "call") in {
        (edge.source, edge.target, edge.kind) for edge in graph.edges
    }


def test_return_block_has_no_outgoing_edges():
    graph = build_cfg(tuple(disassemble(b"\xc3", "x64", address=0x3000)))
    assert len(graph.blocks) == 1
    assert graph.edges == ()


def test_dot_contains_blocks_instructions_and_edge_labels():
    graph = build_cfg(tuple(disassemble(BRANCHING_X64, "x64", address=0x1000)))
    dot = to_dot(graph, name="branch-demo")
    assert "digraph branch_demo" in dot
    assert '"block_1000"' in dot
    assert "je 0x1007" in dot
    assert 'label="branch"' in dot
    assert 'label="fallthrough"' in dot


def test_render_png_reports_missing_graphviz():
    with pytest.raises(GraphvizUnavailable, match="was not found"):
        render_png("digraph cfg {}", "unused.png", dot_executable="definitely-no-dot")


def test_render_png_invokes_graphviz(monkeypatch, tmp_path):
    output = tmp_path / "cfg.png"
    monkeypatch.setattr("shutil.which", lambda _name: "C:\\Graphviz\\bin\\dot.exe")

    def fake_run(command, **kwargs):
        Path(command[-1]).write_bytes(b"\x89PNG\r\n\x1a\n")
        assert kwargs["input"].startswith("digraph")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("subprocess.run", fake_run)
    rendered = render_png("digraph cfg {}", output)
    assert rendered == output
    assert output.read_bytes().startswith(b"\x89PNG")


def test_cli_cfg_writes_dot_without_graphviz(tmp_path):
    binary = tmp_path / "branch.bin"
    binary.write_bytes(BRANCHING_X64)
    dot_output = tmp_path / "branch.dot"
    png_output = tmp_path / "branch.png"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "cfg",
            str(binary),
            "--arch",
            "x64",
            "--base-address",
            "0x1000",
            "--dot-output",
            str(dot_output),
            "--png-output",
            str(png_output),
            "--dot-executable",
            "definitely-no-dot",
        ],
    )
    assert result.exit_code == 0, result.output
    assert dot_output.exists()
    assert "PNG skipped" in result.output or png_output.exists()

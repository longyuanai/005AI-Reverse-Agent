"""Tests for the CLI."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from ai_reverse_agent.cli import cli


def _stub_router_class():
    """Return a class whose instances respond to .chat() with canned JSON."""

    class _StubRouter:
        def __init__(self) -> None:
            self.calls = []

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def chat(self, tier, req):
            from shared_llm_core import (
                ChatChoice,
                ChatMessage,
                ChatResponse,
                ChatUsage,
            )
            self.calls.append(req)
            return ChatResponse(
                id="x", model="m", created=0,
                choices=[ChatChoice(
                    index=0,
                    message=ChatMessage(
                        role="assistant",
                        content=json.dumps({"name": "X", "purpose": "stub"}),
                    ),
                    finish_reason="stop",
                )],
                usage=ChatUsage(),
            )

    return _StubRouter


def test_cli_help():
    runner = CliRunner()
    res = runner.invoke(cli, ["--help"])
    assert res.exit_code == 0
    assert "reverse" in res.output.lower() or "AI" in res.output


def test_cli_demo_writes_report(tmp_path, monkeypatch):
    out = tmp_path / "report.md"
    stub_cls = _stub_router_class()
    monkeypatch.setattr("shared_llm_core.router.LLMRouter.from_env", stub_cls)
    runner = CliRunner()
    res = runner.invoke(cli, ["demo", "--output", str(out), "--provider", "stub"])
    assert res.exit_code == 0, res.output
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    # All 5 functions + at least one DLL.
    for fn in ("CreateFileW", "MessageBoxW", "printf", "connect", "RegOpenKeyExW"):
        assert fn in text
    assert "kernel32.dll" in text


def test_cli_demo_stdout(tmp_path, monkeypatch):
    """Without --output, the report goes to stdout."""
    stub_cls = _stub_router_class()
    monkeypatch.setattr("shared_llm_core.router.LLMRouter.from_env", stub_cls)
    runner = CliRunner()
    res = runner.invoke(cli, ["demo", "--provider", "stub"])
    assert res.exit_code == 0, res.output
    assert "x64 (64-bit, little-endian)" in res.output
    assert "Function Table" in res.output


def test_cli_analyze_missing_file(tmp_path):
    runner = CliRunner()
    res = runner.invoke(cli, ["analyze", str(tmp_path / "does-not-exist.bin")])
    assert res.exit_code != 0


def test_cli_analyze_runs_on_real_blob(tmp_path, monkeypatch):
    from ai_reverse_agent.fake_pe import make_fake_pe

    blob = make_fake_pe()
    src = tmp_path / "demo.bin"
    src.write_bytes(blob)
    out = tmp_path / "report.md"
    stub_cls = _stub_router_class()
    monkeypatch.setattr("shared_llm_core.router.LLMRouter.from_env", stub_cls)
    runner = CliRunner()
    res = runner.invoke(cli, ["analyze", str(src), "--output", str(out), "--provider", "stub"])
    assert res.exit_code == 0, res.output
    text = out.read_text(encoding="utf-8")
    assert "CreateFileW" in text


def test_cli_disassemble_raw_bin(tmp_path):
    binary = tmp_path / "x64.bin"
    binary.write_bytes(b"\x55\x48\x89\xe5\xc3")
    runner = CliRunner()
    res = runner.invoke(
        cli,
        ["disassemble", str(binary), "--arch", "x64", "--base-address", "0x401000"],
    )
    assert res.exit_code == 0, res.output
    assert "0x0000000000401000" in res.output
    assert "push rbp" in res.output
    assert "mov rbp, rsp" in res.output
    assert "ret" in res.output


def test_cli_disassemble_writes_listing(tmp_path):
    binary = tmp_path / "arm.bin"
    binary.write_bytes(b"\x70\x47")
    output = tmp_path / "arm.asm"
    runner = CliRunner()
    res = runner.invoke(
        cli,
        [
            "disassemble",
            str(binary),
            "--arch",
            "arm",
            "--thumb",
            "--output",
            str(output),
        ],
    )
    assert res.exit_code == 0, res.output
    assert output.exists()
    assert "bx lr" in output.read_text(encoding="utf-8")


def test_cli_disassemble_rejects_invalid_mode(tmp_path):
    binary = tmp_path / "x86.bin"
    binary.write_bytes(b"\x90")
    runner = CliRunner()
    res = runner.invoke(cli, ["disassemble", str(binary), "--arch", "x86", "--thumb"])
    assert res.exit_code != 0
    assert "thumb mode is only valid" in res.output

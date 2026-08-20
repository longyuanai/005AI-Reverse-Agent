"""Offline tests for the injectable Ghidra headless backend."""

from __future__ import annotations

import json
import socket
import subprocess

import pytest

from ai_reverse_agent.decompilers.ghidra import (
    GhidraDecompilerBackend,
    GhidraExecutionError,
    GhidraOutputError,
    GhidraTimeoutError,
)
from ai_reverse_agent.decompilers.native import NativeDecompilerBackend
from ai_reverse_agent.decompilers.selector import DecompilerSelector


@pytest.fixture(autouse=True)
def _forbid_real_processes_and_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*args, **kwargs):
        raise AssertionError("Ghidra backend tests must use offline injected doubles")

    monkeypatch.setattr(subprocess, "run", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


def _recorded_output() -> str:
    record = {
        "name": "synthetic_entry",
        "start_address": "0x401000",
        "end_address": "0x401006",
        "pseudo_c": "int synthetic_entry(void) {\n    return 7;\n}",
        "library": None,
        "stack_variables": [],
        "instructions": [
            {
                "address": "0x401000",
                "mnemonic": "MOV",
                "op_str": "EAX,0x7",
                "bytes_hex": "b807000000",
            },
            {
                "address": "0x401005",
                "mnemonic": "RET",
                "op_str": "",
                "bytes_hex": "c3",
            },
        ],
    }
    return "Ghidra startup log\nAI_REVERSE_DECOMPILER_JSON:" + json.dumps(record)


def test_unavailable_when_binary_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _name: None)

    assert GhidraDecompilerBackend().available() is False


def test_available_when_binary_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "shutil.which",
        lambda name: f"C:\\Synthetic\\{name}.bat",
    )

    assert GhidraDecompilerBackend().available() is True


def test_parses_recorded_output() -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, _recorded_output(), "")

    [function] = GhidraDecompilerBackend(runner=runner).decompile(b"MZ", "x64")

    assert function.name == "synthetic_entry"
    assert function.boundary.start_address == 0x401000
    assert function.boundary.end_address == 0x401006
    assert function.boundary.instructions[0].bytes_hex == "b807000000"
    assert function.pseudo_c.endswith("return 7;\n}")
    [(command, kwargs)] = calls
    assert command[0] == "analyzeHeadless"
    assert command[-2:] == ["ExportDecompilation.java", "-deleteProject"]
    assert kwargs == {
        "capture_output": True,
        "text": True,
        "timeout": 300.0,
        "check": False,
    }


def test_timeout_raises_typed_error() -> None:
    def runner(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    backend = GhidraDecompilerBackend(runner=runner, timeout_seconds=1.5)

    with pytest.raises(GhidraTimeoutError, match="1.5 seconds"):
        backend.decompile(b"MZ", "x64")


def test_nonzero_exit_raises_typed_error() -> None:
    leaked_path = r"C:\Users\operator\private\ghidra.log"

    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 7, "", leaked_path)

    with pytest.raises(GhidraExecutionError, match="status 7") as captured:
        GhidraDecompilerBackend(runner=runner).decompile(b"MZ", "x64")

    assert leaked_path not in str(captured.value)


def test_malformed_record_raises_typed_error() -> None:
    def runner(command, **kwargs):
        output = 'AI_REVERSE_DECOMPILER_JSON:{"name":"missing fields"}'
        return subprocess.CompletedProcess(command, 0, output, "")

    with pytest.raises(GhidraOutputError, match="invalid Ghidra"):
        GhidraDecompilerBackend(runner=runner).decompile(b"MZ", "x64")


def test_selector_falls_back_when_ghidra_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner_called = False

    def runner(command, **kwargs):
        nonlocal runner_called
        runner_called = True
        raise AssertionError("unavailable Ghidra runner must not execute")

    monkeypatch.setattr("shutil.which", lambda _name: None)
    selector = DecompilerSelector(
        (GhidraDecompilerBackend(runner=runner), NativeDecompilerBackend())
    )

    [function] = selector.decompile(b"\xc3", "x64")

    assert function.name == "sub_0"
    assert runner_called is False

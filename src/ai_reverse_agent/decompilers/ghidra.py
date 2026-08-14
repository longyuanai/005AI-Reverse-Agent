"""Ghidra headless decompiler with an injectable subprocess boundary."""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ai_reverse_agent.architecture import Architecture, Endianness
from ai_reverse_agent.decompiler import (
    DecompiledFunction,
    FunctionBoundary,
    StackVariable,
)
from ai_reverse_agent.disasm import NormalizedInstruction

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]

_OUTPUT_PREFIX = "AI_REVERSE_DECOMPILER_JSON:"
_DEFAULT_EXECUTABLE = "analyzeHeadless"
_DEFAULT_TIMEOUT_SECONDS = 300.0


class GhidraDecompilerError(RuntimeError):
    """Base class for typed Ghidra backend failures."""


class GhidraConfigurationError(GhidraDecompilerError):
    """Raised when backend environment configuration is invalid."""


class GhidraTimeoutError(GhidraDecompilerError):
    """Raised when headless analysis exceeds the configured timeout."""


class GhidraExecutionError(GhidraDecompilerError):
    """Raised when headless analysis exits unsuccessfully."""


class GhidraOutputError(GhidraDecompilerError):
    """Raised when recorded headless output violates the stable schema."""


class GhidraDecompilerBackend:
    """Run ``analyzeHeadless`` and parse evidence-preserving JSON records."""

    name = "ghidra"

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        executable: str | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        self._runner = runner or subprocess.run
        self.executable = executable or os.environ.get(
            "AI_REVERSE_GHIDRA_HEADLESS",
            _DEFAULT_EXECUTABLE,
        )
        self.timeout_seconds = (
            _timeout_from_environment()
            if timeout_seconds is None
            else _validated_timeout(timeout_seconds)
        )

    def available(self) -> bool:
        """Detect the configured headless launcher without executing it."""
        return shutil.which(self.executable) is not None

    def decompile(
        self,
        image: bytes,
        architecture: Architecture | str,
        *,
        address: int = 0,
        bits: int | None = None,
        endianness: Endianness | str = Endianness.LITTLE,
        thumb: bool = False,
        recognize_libraries: bool = True,
    ) -> tuple[DecompiledFunction, ...]:
        del architecture, address, bits, endianness, thumb, recognize_libraries
        stdout = self._run_headless(image)
        return parse_recorded_output(stdout)

    def _run_headless(self, image: bytes) -> str:
        script_dir = Path(__file__).with_name("scripts")
        with tempfile.TemporaryDirectory(prefix="ai-reverse-ghidra-") as temp:
            workspace = Path(temp)
            sample = workspace / "sample.bin"
            project_dir = workspace / "project"
            project_dir.mkdir()
            sample.write_bytes(image)
            command = [
                self.executable,
                str(project_dir),
                "ai-reverse-headless",
                "-import",
                str(sample),
                "-scriptPath",
                str(script_dir),
                "-postScript",
                "ExportDecompilation.java",
                "-deleteProject",
            ]
            try:
                completed = self._runner(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise GhidraTimeoutError(
                    f"Ghidra headless exceeded {self.timeout_seconds:g} seconds"
                ) from exc
            except OSError as exc:
                raise GhidraExecutionError(
                    "Ghidra headless could not be started"
                ) from exc

        if completed.returncode != 0:
            # stderr can contain local paths and is deliberately not retained.
            raise GhidraExecutionError(
                f"Ghidra headless exited with status {completed.returncode}"
            )
        return completed.stdout


def parse_recorded_output(output: str) -> tuple[DecompiledFunction, ...]:
    """Parse only exporter-prefixed JSON lines, ignoring Ghidra diagnostics."""
    records: list[DecompiledFunction] = []
    for line_number, line in enumerate(output.splitlines(), start=1):
        if not line.startswith(_OUTPUT_PREFIX):
            continue
        encoded = line.removeprefix(_OUTPUT_PREFIX)
        try:
            record = json.loads(encoded)
            records.append(_function_from_record(record))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise GhidraOutputError(
                f"invalid Ghidra decompilation record at output line {line_number}"
            ) from exc
    if not records:
        raise GhidraOutputError("Ghidra output contained no decompilation records")
    return tuple(records)


def _function_from_record(record: Any) -> DecompiledFunction:
    if not isinstance(record, dict):
        raise TypeError("record must be an object")
    name = record["name"]
    pseudo_c = record["pseudo_c"]
    if not isinstance(name, str) or not name:
        raise TypeError("name must be a non-empty string")
    if not isinstance(pseudo_c, str) or not pseudo_c:
        raise TypeError("pseudo_c must be a non-empty string")

    instructions = tuple(
        _instruction_from_record(item) for item in record["instructions"]
    )
    start_address = _parse_address(record["start_address"])
    end_address = _parse_address(record["end_address"])
    if end_address <= start_address:
        raise ValueError("end_address must be greater than start_address")

    library = record.get("library")
    if library is not None and not isinstance(library, str):
        raise TypeError("library must be a string or null")
    return DecompiledFunction(
        name=name,
        boundary=FunctionBoundary(
            start_address=start_address,
            end_address=end_address,
            instructions=instructions,
        ),
        stack_variables=tuple(
            _stack_variable_from_record(item)
            for item in record.get("stack_variables", ())
        ),
        pseudo_c=pseudo_c,
        library=library,
    )


def _instruction_from_record(record: Any) -> NormalizedInstruction:
    if not isinstance(record, dict):
        raise TypeError("instruction must be an object")
    mnemonic = record["mnemonic"]
    op_str = record["op_str"]
    bytes_hex = record["bytes_hex"]
    if not all(isinstance(value, str) for value in (mnemonic, op_str, bytes_hex)):
        raise TypeError("instruction text fields must be strings")
    bytes.fromhex(bytes_hex)
    return NormalizedInstruction(
        address=_parse_address(record["address"]),
        mnemonic=mnemonic,
        op_str=op_str,
        bytes_hex=bytes_hex.lower(),
    )


def _stack_variable_from_record(record: Any) -> StackVariable:
    if not isinstance(record, dict):
        raise TypeError("stack variable must be an object")
    name = record["name"]
    references = record.get("references", ())
    if not isinstance(name, str) or not name:
        raise TypeError("stack variable name must be a non-empty string")
    return StackVariable(
        offset=int(record["offset"]),
        name=name,
        references=tuple(_parse_address(value) for value in references),
    )


def _parse_address(value: object) -> int:
    if isinstance(value, bool):
        raise TypeError("address must not be boolean")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        parsed = int(value, 0)
    else:
        raise TypeError("address must be an integer or numeric string")
    if parsed < 0:
        raise ValueError("address must be non-negative")
    return parsed


def _timeout_from_environment() -> float:
    raw = os.environ.get("AI_REVERSE_GHIDRA_TIMEOUT_SECONDS")
    if raw is None:
        return _DEFAULT_TIMEOUT_SECONDS
    try:
        return _validated_timeout(float(raw))
    except ValueError as exc:
        raise GhidraConfigurationError(
            "AI_REVERSE_GHIDRA_TIMEOUT_SECONDS must be a positive number"
        ) from exc


def _validated_timeout(value: float) -> float:
    if not math.isfinite(value) or value <= 0:
        raise GhidraConfigurationError("Ghidra timeout must be positive")
    return value

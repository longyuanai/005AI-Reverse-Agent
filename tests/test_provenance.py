"""Decompiler provenance tests for Findings and CLI envelopes."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path

from click.testing import CliRunner

from ai_reverse_agent.adapter import ReverseProductAdapter
from ai_reverse_agent.cli import cli
from ai_reverse_agent.decompilers.native import NativeDecompilerBackend
from ai_reverse_agent.decompilers.selector import DecompilerSelector


ROOT = Path(__file__).resolve().parents[1]
MINI_X64_PE = ROOT / "samples" / "mini_binaries" / "mini_x64_pe.exe"


class _StubGhidraBackend:
    name = "ghidra"

    def available(self) -> bool:
        return True

    def decompile(self, image, architecture, **kwargs):
        native = NativeDecompilerBackend().decompile(image, architecture, **kwargs)
        return tuple(replace(function, backend="ghidra") for function in native)


def _collect(adapter: ReverseProductAdapter) -> list[object]:
    async def collect() -> list[object]:
        return [
            finding
            async for finding in adapter.scan(
                {"binary_path": str(MINI_X64_PE), "arch": "x64"}
            )
        ]

    return asyncio.run(collect())


def test_native_findings_are_tagged_native() -> None:
    findings = _collect(ReverseProductAdapter())

    assert findings
    assert all(
        finding.metadata["decompiler_backend"] == "native"
        for finding in findings
    )


def test_ghidra_findings_are_tagged_ghidra() -> None:
    selector = DecompilerSelector((_StubGhidraBackend(),))

    findings = _collect(ReverseProductAdapter(decompiler_selector=selector))

    assert findings
    assert all(
        finding.metadata["decompiler_backend"] == "ghidra"
        for finding in findings
    )


def test_envelope_top_level_shape_unchanged() -> None:
    payload = json.dumps({"binary_path": str(MINI_X64_PE), "arch": "x64"})

    result = CliRunner().invoke(cli, ["scan", "--input", payload, "--json"])

    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert set(envelope) == {"findings", "errors"}
    assert envelope["findings"]
    assert all(
        finding["metadata"]["decompiler_backend"] == "native"
        for finding in envelope["findings"]
    )

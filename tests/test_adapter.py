"""Tests for the in-process v0.5 ReverseProductAdapter."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

# Exercises the shared-suite integration layer; the static-analysis tests
# next to it run without the sibling 000shared-llm-core checkout.
pytest.importorskip("shared_llm_core", reason="suite extra not installed")

from click.testing import CliRunner
from shared_llm_core.finding import Finding, FindingSeverity, FindingSource

from ai_reverse_agent import ReverseProductAdapter
from ai_reverse_agent.cli import cli


ROOT = Path(__file__).resolve().parents[1]
MINI_X64_PE = ROOT / "samples" / "mini_binaries" / "mini_x64_pe.exe"


def _collect(payload: dict[str, object]) -> list[Finding]:
    adapter = ReverseProductAdapter()

    async def collect() -> list[Finding]:
        return [finding async for finding in adapter.scan(payload)]

    return asyncio.run(collect())


def test_adapter_source_is_reverse() -> None:
    assert ReverseProductAdapter.source is FindingSource.REVERSE


def test_adapter_health_returns_ok() -> None:
    health = ReverseProductAdapter().health()

    assert health == {
        "status": "ok",
        "product": "005-reverse",
        "version": "0.5.0",
    }


def test_scan_binary_path_yields_at_least_one_finding() -> None:
    findings = _collect({"binary_path": str(MINI_X64_PE), "arch": "x64"})

    assert findings
    assert all(isinstance(finding, Finding) for finding in findings)


def test_scan_findings_use_reverse_source() -> None:
    findings = _collect({"binary_path": str(MINI_X64_PE), "arch": "x64"})

    assert all(finding.source is FindingSource.REVERSE for finding in findings)


def test_scan_evidence_contains_architecture() -> None:
    findings = _collect({"binary_path": str(MINI_X64_PE), "arch": "x64"})

    assert all("arch=x64" in finding.evidence for finding in findings)


def test_missing_binary_path_yields_warning_finding() -> None:
    [finding] = _collect({"arch": "arm"})

    assert finding.severity is FindingSeverity.LOW
    assert "warning" in finding.tags
    assert finding.metadata["error_code"] == "invalid_binary_path"


def test_missing_architecture_defaults_to_x64() -> None:
    findings = _collect({"binary_path": str(MINI_X64_PE)})

    assert findings
    assert all("arch=x64" in finding.evidence for finding in findings)
    assert findings[-1].metadata["architecture"] == "x64"


def test_cli_scan_real_binary_returns_two_findings() -> None:
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            json.dumps({"binary_path": str(MINI_X64_PE), "arch": "x64"}),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert len(envelope["findings"]) == 2


def test_cli_scan_non_pe_returns_one_info_finding(tmp_path: Path) -> None:
    raw_binary = tmp_path / "raw-x64.bin"
    raw_binary.write_bytes(bytes.fromhex("90 c3"))
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            json.dumps({"binary_path": str(raw_binary), "arch": "x64"}),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    [finding] = json.loads(result.output)["findings"]
    assert finding["severity"] == "info"
    assert finding["metadata"]["container"] == "raw"


def test_repeated_scans_generate_distinct_finding_ids() -> None:
    payload = {"binary_path": str(MINI_X64_PE), "arch": "x64"}
    first = _collect(payload)
    second = _collect(payload)

    assert [finding.id for finding in first] != [finding.id for finding in second]
    assert not ({finding.id for finding in first} & {finding.id for finding in second})

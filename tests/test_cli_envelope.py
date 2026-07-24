"""IntegrationGateway JSON envelope contract tests."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from click.testing import CliRunner

from ai_reverse_agent.cli import cli
from ai_reverse_agent.fake_bin import make_fake_bin


ROOT = Path(__file__).resolve().parents[1]
INTEGRATION_SRC = ROOT.parent / "000shared-integration" / "src"


def test_scan_x64_binary(tmp_path: Path) -> None:
    binary = tmp_path / "x64.bin"
    binary.write_bytes(make_fake_bin("x64"))

    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            json.dumps({"binary_path": str(binary), "arch": "x64"}),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert envelope["errors"] == []
    assert envelope["findings"][0]["host"] == str(binary.resolve())
    assert envelope["findings"][-1]["metadata"]["architecture"] == "x64"
    assert envelope["findings"][-1]["metadata"]["instruction_count"] == 3


def test_scan_arm_binary(tmp_path: Path) -> None:
    binary = tmp_path / "arm.bin"
    binary.write_bytes(make_fake_bin("arm"))
    payload = json.dumps({"binary_path": str(binary), "arch": "arm"})

    result = CliRunner().invoke(cli, ["scan", "--json"], input=payload)

    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert envelope["errors"] == []
    assert envelope["findings"][-1]["title"] == "Disassembled arm binary"
    assert envelope["findings"][-1]["metadata"]["instruction_count"] == 3


def test_scan_handles_unsupported_arch_gracefully(tmp_path: Path) -> None:
    binary = tmp_path / "unknown.bin"
    binary.write_bytes(b"\x00\x01")

    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            json.dumps({"binary_path": str(binary), "arch": "sparc"}),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert envelope["findings"] == []
    assert envelope["errors"][0]["code"] == "unsupported_architecture"


def test_reverse_adapter_subprocess_end_to_end(tmp_path: Path) -> None:
    if str(INTEGRATION_SRC) not in sys.path:
        sys.path.insert(0, str(INTEGRATION_SRC))
    from shared_integration.adapters.reverse import ReverseAdapter

    binary = tmp_path / "adapter-x64.bin"
    binary.write_bytes(make_fake_bin("x64"))
    adapter = ReverseAdapter(ROOT)

    async def collect() -> list[object]:
        return [
            finding
            async for finding in adapter.scan(
                {"binary_path": str(binary), "arch": "x64"}
            )
        ]

    findings = asyncio.run(collect())

    assert findings
    assert findings[-1].source.value == "005"
    assert findings[-1].host == str(binary.resolve())
    assert findings[-1].metadata["architecture"] == "x64"

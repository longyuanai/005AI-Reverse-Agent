"""Known-imphash Finding and opt-in CLI enrichment tests."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from shared_llm_core.finding import FindingSeverity, FindingSource

from ai_reverse_agent.cli import cli
from ai_reverse_agent.findings import imphash_finding
from ai_reverse_agent.hashing import compute_pe_imphash
from ai_reverse_agent.iat import MalwareImphashDB, extract_pe_imports
from ai_reverse_agent.magic import MAX_STATIC_FILE_SIZE
from ai_reverse_agent.scan import scan_binary


ROOT = Path(__file__).resolve().parents[1]
PE_FIXTURE = ROOT / "samples" / "pe" / "mini_x64_pe.exe"


def _curated_database() -> MalwareImphashDB:
    digest = compute_pe_imphash(extract_pe_imports(PE_FIXTURE))
    return MalwareImphashDB(
        [
            {
                "imphash": digest,
                "family": "phase2-known-fixture",
                "sample_id": "mini-x64-pe",
                "provenance": "curated",
            }
        ],
        version="test-curated-v1",
    )


def test_curated_pe_imphash_emits_high_finding():
    finding = imphash_finding(
        extract_pe_imports(PE_FIXTURE),
        host=str(PE_FIXTURE),
        database=_curated_database(),
    )
    assert finding is not None
    assert finding.severity is FindingSeverity.HIGH


def test_known_imphash_finding_uses_reverse_source():
    finding = imphash_finding(
        extract_pe_imports(PE_FIXTURE),
        database=_curated_database(),
    )
    assert finding is not None
    assert finding.source is FindingSource.REVERSE
    assert finding.title == "imphash matched known malware phase2-known-fixture"


def test_known_imphash_finding_contains_digest_evidence():
    imported = extract_pe_imports(PE_FIXTURE)
    finding = imphash_finding(imported, database=_curated_database())
    assert finding is not None
    assert f"pe_imphash={compute_pe_imphash(imported)}" in finding.evidence


def test_unknown_imphash_does_not_emit_finding():
    db = MalwareImphashDB(
        [
            {
                "imphash": "0" * 32,
                "family": "unrelated",
                "sample_id": "none",
            }
        ]
    )
    assert imphash_finding(extract_pe_imports(PE_FIXTURE), database=db) is None


def test_cli_fixture_imphash_enrichment_does_not_emit_high_finding():
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            "--input",
            json.dumps(
                {
                    "binary_path": str(PE_FIXTURE),
                    "arch": "x64",
                    "enrich": ["imphash"],
                }
            ),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert envelope["errors"] == []
    assert all(item["severity"] != "high" for item in envelope["findings"])
    metadata = envelope["findings"][-1]["metadata"]
    assert metadata["pe_imphash"] == compute_pe_imphash(
        extract_pe_imports(PE_FIXTURE)
    )
    assert "import_set_hash" in metadata


def test_cli_iat_list_enrichment_is_in_summary_metadata():
    envelope = scan_binary(
        {
            "binary_path": str(PE_FIXTURE),
            "arch": "x64",
            "enrich": ["iat_list"],
        }
    )
    metadata = envelope["findings"][-1]["metadata"]
    assert metadata["import_count"] == 5
    assert metadata["iat_list"][0]["name"] == "CreateFileW"


def test_default_cli_envelope_is_not_enriched():
    envelope = scan_binary({"binary_path": str(PE_FIXTURE), "arch": "x64"})
    metadata = envelope["findings"][-1]["metadata"]
    assert "imphash" not in metadata
    assert "iat_list" not in metadata
    assert envelope["errors"] == []


def test_raw_iat_enrichment_fails_gracefully(tmp_path: Path):
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"\x90\xc3")
    envelope = scan_binary(
        {
            "binary_path": str(raw),
            "arch": "x64",
            "enrich": ["imphash", "iat_list"],
        }
    )
    assert envelope["errors"] == []
    assert envelope["findings"][-1]["metadata"]["iat_error"].startswith(
        "unsupported container"
    )


def test_scan_refuses_oversized_binary_with_magic_error(tmp_path: Path):
    oversized = tmp_path / "oversized.bin"
    with oversized.open("wb") as stream:
        stream.write(b"MZ")
        stream.seek(MAX_STATIC_FILE_SIZE)
        stream.write(b"\0")
    envelope = scan_binary({"binary_path": str(oversized), "arch": "x64"})
    assert envelope["findings"] == []
    assert envelope["errors"][0]["code"] == "magic_error"

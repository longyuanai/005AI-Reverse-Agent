"""ADR-002 four-scope FeatureIndex and RuleEngine integration."""

from __future__ import annotations

from pathlib import Path

import pytest
from shared_llm_core.rule_engine import RuleContext

from ai_reverse_agent.backends import BinaryLoader
from ai_reverse_agent.deobfuscation import build_reverse_rule_engine
from ai_reverse_agent.disasm import NormalizedInstruction
from ai_reverse_agent.features import (
    FeatureScope,
    cfg_metrics,
    extract_features,
    to_networkx,
)
from ai_reverse_agent.features.constants import shannon_entropy
from ai_reverse_agent.scan import scan_binary

ROOT = Path(__file__).resolve().parents[1]
PE = ROOT / "samples" / "pe" / "mini_x64_pe.exe"
NORMAL = ROOT / "samples" / "normal" / "normal_x64.exe"
XOR = ROOT / "samples" / "obfuscated" / "string_xor_x64.exe"


def _instructions() -> tuple[NormalizedInstruction, ...]:
    return (
        NormalizedInstruction(0x1000, "nop", "", "90"),
        NormalizedInstruction(0x1001, "jne", "0x1004", "7501"),
        NormalizedInstruction(0x1003, "ret", "", "c3"),
        NormalizedInstruction(0x1004, "ret", "", "c3"),
    )


def _index():
    return extract_features(BinaryLoader().load(PE), _instructions(), architecture="x64")


def test_feature_index_exposes_all_four_scopes():
    index = _index()
    assert index.find(FeatureScope.FILE, "backend")
    assert index.find(FeatureScope.FUNCTION, "instruction_count")
    assert index.find(FeatureScope.BASIC_BLOCK, "instruction_count")
    assert index.find(FeatureScope.INSTRUCTION, "mnemonic")


def test_feature_index_file_mapping_is_immutable():
    with pytest.raises(TypeError):
        _index().file["backend"] = "changed"


def test_feature_index_records_parser_backend():
    assert _index().file["backend"] == "pefile"


def test_feature_index_computes_both_import_hashes_for_pe():
    index = _index()
    assert index.file["pe_imphash"] == "c1f0cda7bd39190d4154ba8e2d3b3480"
    assert index.file["import_set_hash"] == "80b4fb3d5cced084a47675fec05e4d48"


def test_networkx_cfg_has_expected_nodes_and_edges():
    graph = _index().file["cfg"]
    digraph = to_networkx(graph)
    assert set(digraph.nodes) == {0x1000, 0x1003, 0x1004}
    assert digraph.number_of_edges() == 2


def test_cfg_metrics_report_scc_and_dispatcher():
    metrics = cfg_metrics(_index().file["cfg"])
    assert metrics["scc_count"] == 3
    assert metrics["dispatcher"] in {0x1000, 0x1003, 0x1004}


def test_rule_facts_share_same_feature_index():
    index = _index()
    facts = index.rule_facts()
    assert facts["feature_index"] is index
    assert facts["instructions"] is index.instructions
    assert facts["data"] is index.file["data"]


def test_feature_index_extracts_printable_strings():
    strings = _index().file["strings"]
    assert any("kernel32.dll" in value for _, value in strings)


def test_entropy_is_bounded_for_bytes():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\0" * 128) == 0.0
    assert 0.0 < shannon_entropy(bytes(range(256))) <= 8.0


def test_real_rule_engine_consumes_feature_index():
    index = extract_features(
        BinaryLoader().load(XOR),
        (),
        architecture="x64",
    )
    findings = build_reverse_rule_engine().evaluate(
        RuleContext(str(XOR), index.rule_facts())
    )
    assert any(item.metadata["rule_id"] == "reverse.string-xor" for item in findings)


def test_normal_feature_index_has_no_obfuscation_findings():
    index = extract_features(
        BinaryLoader().load(NORMAL),
        (),
        architecture="x64",
    )
    assert build_reverse_rule_engine().evaluate(
        RuleContext(str(NORMAL), index.rule_facts())
    ) == []


def test_scan_summary_exposes_backend_without_changing_envelope_shape():
    envelope = scan_binary({"binary_path": str(PE), "arch": "x64"})
    assert set(envelope) == {"findings", "errors"}
    assert envelope["findings"][-1]["metadata"]["backend"] == "pefile"

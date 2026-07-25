"""Phase-2 Hook A deobfuscation rule coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

# Exercises the shared-suite integration layer; the static-analysis tests
# next to it run without the sibling 000shared-llm-core checkout.
pytest.importorskip("shared_llm_core", reason="suite extra not installed")

from shared_llm_core.finding import FindingSource
from shared_llm_core.rule_engine import RuleContext

from ai_reverse_agent.controlflow import BasicBlock, ControlFlowEdge, ControlFlowGraph
from ai_reverse_agent.deobfuscation import (
    ControlFlowFlatteningRule,
    OpaquePredicateRule,
    Rc4StringRule,
    XorStringRule,
    build_reverse_rule_engine,
    calculate_block_stats,
    load_reverse_rules,
)
from ai_reverse_agent.deobfuscation.block_stats import has_switch_dispatcher
from ai_reverse_agent.deobfuscation.string_rc4 import find_rc4_strings, rc4_crypt
from ai_reverse_agent.deobfuscation.string_xor import find_xor_strings
from ai_reverse_agent.disasm import NormalizedInstruction


ROOT = Path(__file__).resolve().parents[1]
OBFUSCATED = ROOT / "samples" / "obfuscated"
NORMAL = ROOT / "samples" / "normal" / "normal_x64.exe"


def _instruction(address: int, mnemonic: str = "nop", op_str: str = ""):
    return NormalizedInstruction(address, mnemonic, op_str, "90")


def _dispatcher_graph() -> ControlFlowGraph:
    blocks = tuple(
        BasicBlock(0x1000 + index * 0x10, 0x1002 + index * 0x10, (_instruction(
            0x1000 + index * 0x10, "jmp", "0x1000"
        ),))
        for index in range(7)
    )
    edges = tuple(
        ControlFlowEdge(block.start_address, 0x1000, "branch") for block in blocks[1:]
    )
    return ControlFlowGraph(0x1000, blocks, edges)


def _normal_graph() -> ControlFlowGraph:
    first = BasicBlock(0x1000, 0x1002, (_instruction(0x1000), _instruction(0x1001)))
    second = BasicBlock(0x1010, 0x1011, (_instruction(0x1010, "ret"),))
    return ControlFlowGraph(
        0x1000,
        (first, second),
        (ControlFlowEdge(0x1000, 0x1010, "fallthrough"),),
    )


def test_block_stats_identify_dispatcher_topology():
    stats = calculate_block_stats(_dispatcher_graph())
    assert stats.block_count == 7
    assert stats.max_branch_indegree == 6
    assert has_switch_dispatcher(stats)


def test_block_stats_reject_normal_topology():
    stats = calculate_block_stats(_normal_graph())
    assert stats.block_count == 2
    assert not has_switch_dispatcher(stats)


def test_cff_rule_emits_reverse_finding():
    findings = ControlFlowFlatteningRule().evaluate(
        RuleContext("cff.exe", {"cfg": _dispatcher_graph()})
    )
    assert len(findings) == 1
    assert findings[0].source is FindingSource.REVERSE


def test_cff_rule_does_not_flag_normal_baseline():
    findings = ControlFlowFlatteningRule().evaluate(
        RuleContext(str(NORMAL), {"cfg": _normal_graph(), "data": NORMAL.read_bytes()})
    )
    assert findings == []


def test_opaque_predicate_rule_detects_forced_branch():
    instructions = (
        NormalizedInstruction(0x1000, "xor", "eax, eax", "31c0"),
        NormalizedInstruction(0x1002, "cmp", "eax, 0", "83f800"),
        NormalizedInstruction(0x1005, "jne", "0x1010", "7509"),
    )
    findings = OpaquePredicateRule().evaluate(
        RuleContext("opaque.exe", {"instructions": instructions})
    )
    assert len(findings) == 1
    assert "0x1005" in findings[0].evidence[0]


def test_opaque_predicate_rule_accepts_architecture_neutral_fact():
    findings = OpaquePredicateRule().evaluate(
        RuleContext("arm.bin", {"architecture": "arm", "opaque_predicates": 2})
    )
    assert findings[0].metadata["match_count"] == 1


def test_opaque_predicate_rule_rejects_normal_instructions():
    instructions = (
        NormalizedInstruction(0x1000, "mov", "eax, 1", "b801000000"),
        NormalizedInstruction(0x1005, "ret", "", "c3"),
    )
    assert OpaquePredicateRule().evaluate(
        RuleContext("normal.exe", {"instructions": instructions})
    ) == []


def test_xor_fixture_recovers_printable_string():
    decoded = find_xor_strings((OBFUSCATED / "string_xor_x64.exe").read_bytes())
    assert [item.value for item in decoded] == ["staged-command.example"]


def test_xor_rule_emits_evidence():
    path = OBFUSCATED / "string_xor_x64.exe"
    findings = XorStringRule().evaluate(RuleContext(str(path), {"data": path.read_bytes()}))
    assert len(findings) == 1
    assert "decoded='staged-command.example'" in findings[0].evidence[0]


def test_rc4_implementation_roundtrip():
    plaintext = b"phase-two-static-analysis"
    ciphertext = rc4_crypt(plaintext, b"fixture-key")
    assert ciphertext != plaintext
    assert rc4_crypt(ciphertext, b"fixture-key") == plaintext


def test_rc4_fixture_recovers_printable_string():
    decoded = find_rc4_strings((OBFUSCATED / "string_rc4_x64.exe").read_bytes())
    assert [item.value for item in decoded] == ["operator-token-fixture"]


def test_rc4_rule_emits_evidence():
    path = OBFUSCATED / "string_rc4_x64.exe"
    findings = Rc4StringRule().evaluate(RuleContext(str(path), {"data": path.read_bytes()}))
    assert len(findings) == 1
    assert findings[0].metadata["match_count"] == 1


def test_string_rules_do_not_flag_normal_baseline():
    context = RuleContext(str(NORMAL), {"data": NORMAL.read_bytes()})
    assert XorStringRule().evaluate(context) == []
    assert Rc4StringRule().evaluate(context) == []


def test_rule_loader_registers_all_builtin_rules():
    ids = {rule.id for rule in load_reverse_rules()}
    assert ids == {
        "reverse.control-flow-flattening",
        "reverse.opaque-predicate",
        "reverse.string-xor",
        "reverse.string-rc4",
    }
    assert len(build_reverse_rule_engine().registry) == 4


def test_five_obfuscated_samples_and_normal_baseline_exist():
    samples = sorted(OBFUSCATED.glob("*.exe"))
    assert len(samples) == 5
    assert all(path.read_bytes().startswith(b"MZ") for path in samples)
    assert NORMAL.read_bytes().startswith(b"MZ")

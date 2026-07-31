"""Markerless and multi-signal deobfuscation validation."""

from __future__ import annotations

from shared_llm_core.finding import FindingSeverity
from shared_llm_core.rule_engine import RuleContext

from ai_reverse_agent.controlflow import BasicBlock, ControlFlowEdge, ControlFlowGraph
from ai_reverse_agent.deobfuscation import (
    OpaquePredicateRule,
    Rc4StringRule,
    XorStringRule,
    calculate_block_stats,
)
from ai_reverse_agent.deobfuscation.scoring import score_cff
from ai_reverse_agent.deobfuscation.string_rc4 import detect_rc4_structure
from ai_reverse_agent.deobfuscation.string_xor import find_xor_strings
from ai_reverse_agent.disasm import NormalizedInstruction
from ai_reverse_agent.symbolic import symbolic_input


def _xor(plain: bytes, key: bytes) -> bytes:
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(plain))


def _insn(address: int, mnemonic: str, operands: str = ""):
    return NormalizedInstruction(address, mnemonic, operands, "90")


def test_markerless_single_byte_xor_recovers_plaintext():
    plain = b"hidden-config.example"
    data = b"\0" * 8 + _xor(plain, b"\xd3") + b"\0" * 8
    assert any(item.value == plain.decode() for item in find_xor_strings(data))


def test_markerless_repeating_xor_recovers_plaintext():
    plain = b"operator-command.example"
    data = b"\0" * 8 + _xor(plain, b"\x91\xb7") + b"\0" * 8
    recovered = find_xor_strings(data)
    assert any(item.value == plain.decode() for item in recovered)
    assert any(isinstance(item.key, bytes) for item in recovered)


def test_markerless_xor_rejects_plain_ascii():
    assert find_xor_strings(b"this-is-normal-plaintext") == ()


def test_markerless_xor_rule_records_algorithm():
    plain = b"password-config.example"
    context = RuleContext("sample.bin", {"data": _xor(plain, b"\xe1")})
    finding = XorStringRule().evaluate(context)[0]
    assert finding.metadata["algorithm"] == "xor"
    assert finding.metadata["backend"] == "native"


def test_rc4_structure_requires_all_three_signals():
    instructions = (
        _insn(0, "cmp", "eax, 0x100"),
        _insn(1, "xchg", "al, bl"),
        _insn(2, "xor", "cl, dl"),
    )
    assert detect_rc4_structure(instructions) == (
        "256-byte state loop",
        "state-byte swap",
        "keystream xor",
    )
    assert detect_rc4_structure(instructions[:2]) == ()


def test_rc4_structure_only_emits_low_finding():
    instructions = (
        _insn(0, "cmp", "eax, 256"),
        _insn(1, "xchg", "al, bl"),
        _insn(2, "xor", "cl, dl"),
    )
    finding = Rc4StringRule().evaluate(
        RuleContext("rc4.bin", {"instructions": instructions})
    )[0]
    assert finding.severity is FindingSeverity.LOW
    assert finding.metadata["decoded"] is False


def test_symbolic_opaque_predicate_proves_unreachable_branch():
    value = symbolic_input("x", 0, 3)
    finding = OpaquePredicateRule().evaluate(
        RuleContext("opaque.bin", {"symbolic_constraints": (value.equals(1),)})
    )
    assert finding == []

    forced = OpaquePredicateRule().evaluate(
        RuleContext(
            "opaque.bin",
            {
                "symbolic_constraints": (
                    value.equals(1),
                    value.not_equals(1),
                )
            },
        )
    )
    assert forced
    assert "unreachable" in forced[0].evidence[0]


def test_cff_score_requires_multiple_signals():
    instructions = (_insn(0x1000, "jmp", "0x1000"),)
    blocks = tuple(
        BasicBlock(0x1000 + index * 0x10, 0x1001 + index * 0x10, instructions)
        for index in range(7)
    )
    edges = tuple(
        ControlFlowEdge(block.start_address, 0x1000, "branch")
        for block in blocks[1:]
    )
    graph = ControlFlowGraph(0x1000, blocks, edges)
    scored = score_cff(
        calculate_block_stats(graph),
        {"loop_count": 1, "dominated_count": 4},
    )
    assert scored.detected
    assert scored.score >= 0.7


def test_cff_score_rejects_linear_function():
    block = BasicBlock(0x1000, 0x1001, (_insn(0x1000, "ret"),))
    graph = ControlFlowGraph(0x1000, (block,), ())
    assert not score_cff(calculate_block_stats(graph), {}).detected

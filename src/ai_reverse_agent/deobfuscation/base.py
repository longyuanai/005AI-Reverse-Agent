"""Shared helpers for architecture-neutral deobfuscation rules."""

from __future__ import annotations

from typing import Any, Iterable

from shared_llm_core.finding import Finding, FindingSeverity, FindingSource
from shared_llm_core.rule_engine import Rule, RuleContext


class ObfuscationRule(Rule):
    """Base class for static obfuscation detectors.

    Rules consume only normalized instructions, CFG facts, and byte strings.
    They never execute the analysed sample.
    """

    tactic = "reverse.obfuscation"
    severity = FindingSeverity.MEDIUM
    confidence = 0.7

    def make_finding(
        self,
        ctx: RuleContext,
        *,
        title: str,
        description: str,
        evidence: Iterable[str] = (),
        confidence: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        details = {"rule_id": self.id, "tactic": self.tactic}
        if metadata:
            details.update(metadata)
        return Finding(
            id="",
            source=FindingSource.REVERSE,
            severity=self.severity,
            confidence=self.confidence if confidence is None else confidence,
            title=title,
            description=description,
            host=ctx.subject,
            evidence=tuple(evidence),
            tags=frozenset({"obfuscation", self.id}),
            metadata=details,
        )


def fact_bytes(ctx: RuleContext) -> bytes:
    """Return the immutable byte fact, or an empty value when absent."""
    value = ctx.facts.get("data", b"")
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    return b""


def fact_instructions(ctx: RuleContext) -> tuple[Any, ...]:
    """Return normalized instruction-like objects without binding to Capstone."""
    value = ctx.facts.get("instructions", ())
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return ()


def instruction_parts(instruction: Any) -> tuple[int, str, str]:
    """Normalize dataclass, tuple, or mapping instructions for rule matching."""
    if isinstance(instruction, dict):
        return (
            int(instruction.get("address", 0)),
            str(instruction.get("mnemonic", "")).lower(),
            str(instruction.get("op_str", "")).lower(),
        )
    if hasattr(instruction, "mnemonic"):
        return (
            int(getattr(instruction, "address", 0)),
            str(getattr(instruction, "mnemonic", "")).lower(),
            str(getattr(instruction, "op_str", "")).lower(),
        )
    if isinstance(instruction, (tuple, list)) and len(instruction) >= 3:
        return int(instruction[0]), str(instruction[1]).lower(), str(instruction[2]).lower()
    return 0, "", ""

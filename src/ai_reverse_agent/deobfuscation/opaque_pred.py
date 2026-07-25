"""Opaque-predicate detection over normalized instructions."""

from __future__ import annotations

from shared_llm_core.rule_engine import RuleContext

from .base import ObfuscationRule, fact_instructions, instruction_parts


class OpaquePredicateRule(ObfuscationRule):
    """Detect branches whose condition is forced by a nearby identity."""

    id = "reverse.opaque-predicate"
    tactic = "reverse.obfuscation.opaque-predicate"
    confidence = 0.82

    def evaluate(self, ctx: RuleContext):
        explicit = ctx.facts.get("opaque_predicates", ())
        matches: list[str] = []
        if isinstance(explicit, int) and explicit > 0:
            matches.append(f"declared_predicates={explicit}")
        elif isinstance(explicit, (list, tuple)) and explicit:
            matches.extend(str(item) for item in explicit)

        normalized = [instruction_parts(item) for item in fact_instructions(ctx)]
        for index in range(max(0, len(normalized) - 2)):
            first, second, third = normalized[index : index + 3]
            _, first_mnemonic, first_ops = first
            _, second_mnemonic, second_ops = second
            address, third_mnemonic, _ = third
            operands = [part.strip() for part in first_ops.split(",")]
            self_zeroing = (
                first_mnemonic in {"xor", "sub"}
                and len(operands) == 2
                and operands[0] == operands[1]
            )
            compares_zero = (
                second_mnemonic in {"cmp", "test"}
                and operands
                and operands[0] in second_ops
                and ("0" in second_ops or second_mnemonic == "test")
            )
            if self_zeroing and compares_zero and third_mnemonic.startswith("j"):
                matches.append(f"forced branch at 0x{address:x}")

        if not matches:
            return []
        return [
            self.make_finding(
                ctx,
                title="Opaque predicate detected",
                description=(
                    "A branch condition is statically forced and likely hides "
                    "unreachable or misleading control flow."
                ),
                evidence=matches[:8],
                confidence=min(0.96, 0.78 + 0.03 * len(matches)),
                metadata={"match_count": len(matches)},
            )
        ]

"""Static, multi-architecture deobfuscation rules for reverse analysis."""

from __future__ import annotations

from importlib.metadata import entry_points

from shared_llm_core.rule_engine import Rule, RuleEngine, RuleRegistry

from .base import ObfuscationRule
from .block_stats import BlockStatistics, calculate_block_stats, has_switch_dispatcher
from .cff import ControlFlowFlatteningRule
from .opaque_pred import OpaquePredicateRule
from .string_rc4 import Rc4StringRule
from .string_xor import XorStringRule


BUILTIN_RULE_TYPES = (
    ControlFlowFlatteningRule,
    OpaquePredicateRule,
    XorStringRule,
    Rc4StringRule,
)


def load_reverse_rules() -> tuple[Rule, ...]:
    """Load installed product rules, with source-tree builtins as fallback."""
    discovered: list[Rule] = []
    selected = entry_points()
    if hasattr(selected, "select"):
        selected = selected.select(group="longyuanai.reverse_rules")
    else:  # pragma: no cover - legacy importlib.metadata
        selected = selected.get("longyuanai.reverse_rules", ())
    for point in selected:
        loaded = point.load()
        rule = loaded() if isinstance(loaded, type) else loaded
        if isinstance(rule, Rule):
            discovered.append(rule)
    if not discovered:
        discovered.extend(rule_type() for rule_type in BUILTIN_RULE_TYPES)
    unique = {rule.id: rule for rule in discovered}
    return tuple(unique.values())


def build_reverse_rule_engine() -> RuleEngine:
    """Create a RuleEngine containing only reverse-product rules."""
    registry = RuleRegistry()
    for rule in load_reverse_rules():
        registry.register(rule)
    return RuleEngine(registry)

__all__ = [
    "BlockStatistics",
    "ControlFlowFlatteningRule",
    "ObfuscationRule",
    "OpaquePredicateRule",
    "Rc4StringRule",
    "XorStringRule",
    "build_reverse_rule_engine",
    "calculate_block_stats",
    "has_switch_dispatcher",
    "load_reverse_rules",
]

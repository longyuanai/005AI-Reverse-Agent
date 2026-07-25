"""Static, multi-architecture deobfuscation rules for reverse analysis."""

from .base import ObfuscationRule
from .block_stats import BlockStatistics, calculate_block_stats, has_switch_dispatcher

__all__ = [
    "BlockStatistics",
    "ObfuscationRule",
    "calculate_block_stats",
    "has_switch_dispatcher",
]

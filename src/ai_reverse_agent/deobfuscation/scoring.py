"""Multi-signal deobfuscation scoring helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .block_stats import BlockStatistics


@dataclass(frozen=True)
class CffScore:
    score: float
    signals: tuple[str, ...]

    @property
    def detected(self) -> bool:
        return self.score >= 0.7 and len(self.signals) >= 3


def score_cff(
    stats: BlockStatistics,
    metrics: dict[str, Any] | None = None,
) -> CffScore:
    metrics = metrics or {}
    signals: list[str] = []
    score = 0.0
    if stats.block_count >= 6:
        score += 0.15
        signals.append("many-blocks")
    if stats.tiny_block_ratio >= 0.5:
        score += 0.2
        signals.append("tiny-blocks")
    if stats.max_branch_indegree >= 3:
        score += 0.25
        signals.append("dispatcher-indegree")
    if int(metrics.get("loop_count", 0)) >= 1:
        score += 0.2
        signals.append("dispatcher-loop")
    if int(metrics.get("dominated_count", 0)) >= 2:
        score += 0.15
        signals.append("dominance")
    if stats.indirect_branch_count:
        score += 0.1
        signals.append("indirect-state-branch")
    return CffScore(min(score, 1.0), tuple(signals))

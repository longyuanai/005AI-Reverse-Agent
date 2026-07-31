"""Control-flow flattening detection."""

from __future__ import annotations

from shared_llm_core.rule_engine import RuleContext

from .base import ObfuscationRule
from .block_stats import calculate_block_stats, has_switch_dispatcher
from .scoring import score_cff


class ControlFlowFlatteningRule(ObfuscationRule):
    """Detect dispatcher-heavy control-flow flattening."""

    id = "reverse.control-flow-flattening"
    tactic = "reverse.obfuscation.cff"
    confidence = 0.78

    def evaluate(self, ctx: RuleContext):
        index = ctx.facts.get("feature_index")
        graph = (
            getattr(index, "file", {}).get("cfg")
            if index is not None
            else ctx.facts.get("cfg")
        )
        explicit = bool(ctx.facts.get("cff_dispatcher"))
        if graph is None and not explicit:
            return []
        stats = calculate_block_stats(graph) if graph is not None else None
        metrics = (
            getattr(index, "file", {}).get("cfg_metrics", {})
            if index is not None
            else ctx.facts.get("cfg_metrics", {})
        )
        scored = score_cff(stats, dict(metrics)) if stats is not None else None
        detected = explicit or (
            stats is not None
            and (has_switch_dispatcher(stats) or scored is not None and scored.detected)
        )
        if not detected:
            return []
        evidence = ["dispatcher-style control flow"]
        metadata = {}
        if stats is not None:
            evidence.extend(
                [
                    f"blocks={stats.block_count}",
                    f"branches={stats.branch_count}",
                    f"max_branch_indegree={stats.max_branch_indegree}",
                ]
            )
            metadata["block_stats"] = {
                "block_count": stats.block_count,
                "edge_count": stats.edge_count,
                "branch_count": stats.branch_count,
                "tiny_block_ratio": round(stats.tiny_block_ratio, 4),
                "max_branch_indegree": stats.max_branch_indegree,
            }
            if scored is not None:
                metadata["cff_score"] = scored.score
                metadata["cff_signals"] = scored.signals
        return [
            self.make_finding(
                ctx,
                title="Control-flow flattening pattern detected",
                description=(
                    "A dispatcher and many small branch blocks obscure the "
                    "original control-flow structure."
                ),
                evidence=evidence,
                confidence=(
                    max(self.confidence, scored.score)
                    if scored is not None
                    else self.confidence
                ),
                metadata=metadata,
            )
        ]

"""Architecture-neutral basic-block statistics used by obfuscation rules."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from ai_reverse_agent.controlflow import ControlFlowGraph


@dataclass(frozen=True)
class BlockStatistics:
    """Small deterministic feature vector for one control-flow graph."""

    block_count: int
    edge_count: int
    branch_count: int
    average_instructions: float
    tiny_block_ratio: float
    branch_edge_ratio: float
    indirect_branch_count: int
    max_branch_indegree: int


def calculate_block_stats(graph: ControlFlowGraph | Any) -> BlockStatistics:
    """Calculate features without assuming a processor instruction encoding."""
    blocks = tuple(getattr(graph, "blocks", ()) or ())
    edges = tuple(getattr(graph, "edges", ()) or ())
    edge_kinds = [str(getattr(edge, "kind", "")).lower() for edge in edges]
    branch_count = sum(kind == "branch" for kind in edge_kinds)
    instruction_counts = [
        len(tuple(getattr(block, "instructions", ()) or ())) for block in blocks
    ]
    known_starts = {int(getattr(block, "start_address", -1)) for block in blocks}
    branch_indegrees = Counter(
        int(getattr(edge, "target", -1))
        for edge in edges
        if str(getattr(edge, "kind", "")).lower() == "branch"
        and int(getattr(edge, "target", -1)) in known_starts
    )
    indirect = 0
    for block in blocks:
        instructions = tuple(getattr(block, "instructions", ()) or ())
        if not instructions:
            continue
        terminal = instructions[-1]
        mnemonic = str(getattr(terminal, "mnemonic", "")).lower()
        operand = str(getattr(terminal, "op_str", "")).strip().lower()
        if mnemonic.startswith(("j", "b")) and operand:
            token = operand.split(",")[-1].strip().lstrip("#")
            try:
                int(token, 0)
            except ValueError:
                indirect += 1

    block_count = len(blocks)
    edge_count = len(edges)
    return BlockStatistics(
        block_count=block_count,
        edge_count=edge_count,
        branch_count=branch_count,
        average_instructions=(
            sum(instruction_counts) / block_count if block_count else 0.0
        ),
        tiny_block_ratio=(
            sum(count <= 2 for count in instruction_counts) / block_count
            if block_count
            else 0.0
        ),
        branch_edge_ratio=branch_count / edge_count if edge_count else 0.0,
        indirect_branch_count=indirect,
        max_branch_indegree=max(branch_indegrees.values(), default=0),
    )


def has_switch_dispatcher(stats: BlockStatistics) -> bool:
    """Return whether block topology resembles a flattened dispatcher loop."""
    return (
        stats.block_count >= 6
        and stats.branch_count >= 4
        and stats.max_branch_indegree >= 3
        and stats.tiny_block_ratio >= 0.5
    )

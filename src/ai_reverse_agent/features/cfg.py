"""NetworkX-backed CFG metrics used by deobfuscation rules."""

from __future__ import annotations

from typing import Any

import networkx as nx

from ai_reverse_agent.controlflow import ControlFlowGraph


def to_networkx(graph: ControlFlowGraph) -> nx.DiGraph:
    result = nx.DiGraph()
    for block in graph.blocks:
        result.add_node(block.start_address, block=block)
    for edge in graph.edges:
        if edge.target in result:
            result.add_edge(edge.source, edge.target, kind=edge.kind)
    return result


def cfg_metrics(graph: ControlFlowGraph) -> dict[str, Any]:
    """Return bounded topology features without mutating the source CFG."""
    digraph = to_networkx(graph)
    if not digraph:
        return {
            "scc_count": 0,
            "loop_count": 0,
            "max_indegree": 0,
            "dispatcher": None,
            "dominated_count": 0,
        }
    components = tuple(nx.strongly_connected_components(digraph))
    loops = tuple(component for component in components if len(component) > 1)
    dispatcher = max(digraph.nodes, key=lambda node: digraph.in_degree(node))
    dominated_count = 0
    if graph.entry_address in digraph:
        try:
            dominators = nx.immediate_dominators(digraph, graph.entry_address)
            dominated_count = sum(parent == dispatcher for parent in dominators.values())
        except nx.NetworkXError:
            dominated_count = 0
    return {
        "scc_count": len(components),
        "loop_count": len(loops),
        "largest_scc": max((len(item) for item in components), default=0),
        "max_indegree": digraph.in_degree(dispatcher),
        "dispatcher": dispatcher,
        "dominated_count": dominated_count,
    }

"""Build a FeatureIndex once from one parsed binary image."""

from __future__ import annotations

from ai_reverse_agent.backends import BinaryImage
from ai_reverse_agent.controlflow import build_cfg
from ai_reverse_agent.disasm import NormalizedInstruction

from .cfg import cfg_metrics
from .constants import shannon_entropy
from .imports import import_features
from .model import FeatureIndex, FeatureScope, ScopedFeature
from .strings import extract_ascii_strings


def extract_features(
    image: BinaryImage,
    instructions: tuple[NormalizedInstruction, ...],
    *,
    architecture: str,
) -> FeatureIndex:
    graph = build_cfg(instructions)
    metrics = cfg_metrics(graph)
    file_features = {
        "data": image.data,
        "size": len(image.data),
        "container": image.container,
        "backend": image.backend,
        "architecture": architecture,
        "imports": image.imports,
        "strings": extract_ascii_strings(image.data),
        "entropy": shannon_entropy(image.data),
        "cfg": graph,
        "cfg_metrics": metrics,
        **import_features(image.imports, container=image.container),
    }
    functions = (
        {
            "address": graph.entry_address,
            "block_count": len(graph.blocks),
            "instruction_count": len(instructions),
        },
    ) if instructions else ()
    blocks = tuple(
        {
            "address": block.start_address,
            "end_address": block.end_address,
            "instruction_count": len(block.instructions),
        }
        for block in graph.blocks
    )
    flat = [
        ScopedFeature(FeatureScope.FILE, key, value)
        for key, value in file_features.items()
    ]
    flat.extend(
        ScopedFeature(FeatureScope.FUNCTION, key, value, item["address"])
        for item in functions
        for key, value in item.items()
    )
    flat.extend(
        ScopedFeature(FeatureScope.BASIC_BLOCK, key, value, item["address"])
        for item in blocks
        for key, value in item.items()
    )
    flat.extend(
        ScopedFeature(
            FeatureScope.INSTRUCTION,
            "mnemonic",
            instruction.mnemonic,
            instruction.address,
        )
        for instruction in instructions
    )
    return FeatureIndex(
        file=file_features,
        functions=functions,
        basic_blocks=blocks,
        instructions=instructions,
        _flat=tuple(flat),
    )

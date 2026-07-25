"""Basic-block control-flow graphs from normalized instructions."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ai_reverse_agent.disasm import NormalizedInstruction


@dataclass(frozen=True)
class BasicBlock:
    """A maximal linear sequence of normalized instructions."""

    start_address: int
    end_address: int
    instructions: tuple[NormalizedInstruction, ...]


@dataclass(frozen=True)
class ControlFlowEdge:
    """A directed edge between blocks or an external call target."""

    source: int
    target: int
    kind: str


@dataclass(frozen=True)
class ControlFlowGraph:
    """A function-level graph with deterministic block and edge order."""

    entry_address: int | None
    blocks: tuple[BasicBlock, ...]
    edges: tuple[ControlFlowEdge, ...]


class GraphvizUnavailable(RuntimeError):
    """Raised when PNG rendering is requested without a Graphviz binary."""


_CALLS = {"call", "callq", "bl", "blx", "jal"}
_UNCONDITIONAL_JUMPS = {"jmp", "j", "b", "bra"}
_CONDITIONAL_JUMPS = {
    "ja",
    "jae",
    "jb",
    "jbe",
    "je",
    "jg",
    "jge",
    "jl",
    "jle",
    "jne",
    "jnz",
    "jz",
    "beq",
    "bne",
    "bgt",
    "bge",
    "blt",
    "ble",
    "cbz",
    "cbnz",
    "tbz",
    "tbnz",
}


def build_cfg(
    instructions: tuple[NormalizedInstruction, ...] | list[NormalizedInstruction],
) -> ControlFlowGraph:
    """Split instructions at jump/call/return boundaries and connect edges."""
    ordered = tuple(sorted(instructions, key=lambda instruction: instruction.address))
    if not ordered:
        return ControlFlowGraph(entry_address=None, blocks=(), edges=())

    instruction_addresses = {instruction.address for instruction in ordered}
    leaders = {ordered[0].address}
    for index, instruction in enumerate(ordered):
        target = _direct_target(instruction)
        if target in instruction_addresses:
            leaders.add(target)
        if _ends_block(instruction) and index + 1 < len(ordered):
            leaders.add(ordered[index + 1].address)

    blocks: list[BasicBlock] = []
    current: list[NormalizedInstruction] = []
    for instruction in ordered:
        if current and instruction.address in leaders:
            blocks.append(_make_block(current))
            current = []
        current.append(instruction)
    if current:
        blocks.append(_make_block(current))

    edges: list[ControlFlowEdge] = []
    for index, block in enumerate(blocks):
        terminator = block.instructions[-1]
        next_address = blocks[index + 1].start_address if index + 1 < len(blocks) else None
        target = _direct_target(terminator)

        if _is_return(terminator):
            continue
        if _is_call(terminator):
            if target is not None:
                edges.append(ControlFlowEdge(block.start_address, target, "call"))
            if next_address is not None:
                edges.append(ControlFlowEdge(block.start_address, next_address, "fallthrough"))
            continue
        if _is_unconditional_jump(terminator):
            if target is not None:
                edges.append(ControlFlowEdge(block.start_address, target, "branch"))
            continue
        if _is_conditional_jump(terminator):
            if target is not None:
                edges.append(ControlFlowEdge(block.start_address, target, "branch"))
            if next_address is not None:
                edges.append(ControlFlowEdge(block.start_address, next_address, "fallthrough"))
            continue
        if next_address is not None:
            edges.append(ControlFlowEdge(block.start_address, next_address, "fallthrough"))

    return ControlFlowGraph(
        entry_address=ordered[0].address,
        blocks=tuple(blocks),
        edges=tuple(edges),
    )


def to_dot(graph: ControlFlowGraph, *, name: str = "cfg") -> str:
    """Serialize a CFG as deterministic Graphviz DOT text."""
    safe_name = re.sub(r"\W+", "_", name).strip("_") or "cfg"
    lines = [
        f"digraph {safe_name} {{",
        '  graph [rankdir="TB"];',
        '  node [shape="box", fontname="Consolas"];',
        '  edge [fontname="Consolas"];',
    ]

    known_blocks = {block.start_address for block in graph.blocks}
    for block in graph.blocks:
        label_parts = [f"0x{block.start_address:x}:"]
        label_parts.extend(
            f"0x{instruction.address:x}  {instruction.mnemonic} {instruction.op_str}".rstrip()
            for instruction in block.instructions
        )
        label = r"\l".join(_dot_escape(part) for part in label_parts) + r"\l"
        lines.append(f'  "block_{block.start_address:x}" [label="{label}"];')

    external_targets = sorted(
        {edge.target for edge in graph.edges if edge.target not in known_blocks}
    )
    for target in external_targets:
        lines.append(
            f'  "external_{target:x}" '
            f'[label="external 0x{target:x}", shape="ellipse", style="dashed"];'
        )

    colors = {"branch": "blue", "fallthrough": "gray40", "call": "darkgreen"}
    for edge in graph.edges:
        target_node = (
            f"block_{edge.target:x}"
            if edge.target in known_blocks
            else f"external_{edge.target:x}"
        )
        lines.append(
            f'  "block_{edge.source:x}" -> "{target_node}" '
            f'[label="{edge.kind}", color="{colors.get(edge.kind, "black")}"];'
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_png(
    dot_text: str,
    output_path: str | Path,
    *,
    dot_executable: str = "dot",
) -> Path:
    """Render DOT through Graphviz's ``dot`` executable."""
    executable = shutil.which(dot_executable)
    if executable is None:
        raise GraphvizUnavailable(
            "Graphviz 'dot' executable was not found; DOT text is still available"
        )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [executable, "-Tpng", "-o", str(output)],
            input=dot_text,
            text=True,
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or str(exc)
        raise RuntimeError(f"Graphviz PNG rendering failed: {detail}") from exc
    return output


def _make_block(instructions: list[NormalizedInstruction]) -> BasicBlock:
    last = instructions[-1]
    return BasicBlock(
        start_address=instructions[0].address,
        end_address=last.address + len(bytes.fromhex(last.bytes_hex)),
        instructions=tuple(instructions),
    )


def _ends_block(instruction: NormalizedInstruction) -> bool:
    return (
        _is_call(instruction)
        or _is_unconditional_jump(instruction)
        or _is_conditional_jump(instruction)
        or _is_return(instruction)
    )


def _is_call(instruction: NormalizedInstruction) -> bool:
    return instruction.mnemonic.lower() in _CALLS


def _is_unconditional_jump(instruction: NormalizedInstruction) -> bool:
    return instruction.mnemonic.lower() in _UNCONDITIONAL_JUMPS


def _is_conditional_jump(instruction: NormalizedInstruction) -> bool:
    mnemonic = instruction.mnemonic.lower()
    return (
        mnemonic in _CONDITIONAL_JUMPS
        or mnemonic.startswith("b.")
        or (mnemonic.startswith("j") and mnemonic not in _UNCONDITIONAL_JUMPS)
    )


def _is_return(instruction: NormalizedInstruction) -> bool:
    mnemonic = instruction.mnemonic.lower()
    operands = instruction.op_str.lower().replace("$", "")
    return (
        mnemonic.startswith("ret")
        or (mnemonic == "bx" and operands == "lr")
        or (mnemonic == "jr" and operands in {"ra", "x1"})
        or (mnemonic == "jalr" and operands in {"zero, ra, 0", "x0, x1, 0"})
    )


def _direct_target(instruction: NormalizedInstruction) -> int | None:
    if not (
        _is_call(instruction)
        or _is_unconditional_jump(instruction)
        or _is_conditional_jump(instruction)
    ):
        return None
    token = instruction.op_str.split(",")[-1].strip().lstrip("#")
    try:
        return int(token, 0)
    except ValueError:
        return None


def _dot_escape(value: str) -> str:
    return value.replace("\\", r"\\").replace('"', r'\"')

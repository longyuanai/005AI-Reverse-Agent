"""Function- and instruction-level diffs for raw binaries."""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path

from ai_reverse_agent.architecture import Architecture, Endianness, resolve_architecture
from ai_reverse_agent.decompiler import FunctionBoundary, find_function_boundaries
from ai_reverse_agent.disasm import NormalizedInstruction, disassemble


@dataclass(frozen=True)
class InstructionDelta:
    """One added, removed, or replaced normalized instruction."""

    kind: str
    before: NormalizedInstruction | None = None
    after: NormalizedInstruction | None = None


@dataclass(frozen=True)
class FunctionDiff:
    """Changes for one ordinal function in a raw binary pair."""

    index: int
    status: str
    baseline_address: int | None
    current_address: int | None
    instruction_deltas: tuple[InstructionDelta, ...] = ()

    @property
    def name(self) -> str:
        return f"function_{self.index}"


@dataclass(frozen=True)
class PatchDiffResult:
    """Complete binary comparison result."""

    architecture: str
    baseline_size: int
    current_size: int
    functions: tuple[FunctionDiff, ...]

    @property
    def changed_functions(self) -> tuple[FunctionDiff, ...]:
        return tuple(function for function in self.functions if function.status != "unchanged")


def diff_binaries(
    baseline: bytes,
    current: bytes,
    architecture: Architecture | str,
    *,
    address: int = 0,
    bits: int | None = None,
    endianness: Endianness | str = Endianness.LITTLE,
    thumb: bool = False,
) -> PatchDiffResult:
    """Disassemble and compare two raw binaries."""
    spec = resolve_architecture(architecture, bits=bits, endianness=endianness)
    baseline_functions = _boundaries(
        baseline,
        architecture,
        address=address,
        bits=bits,
        endianness=endianness,
        thumb=thumb,
    )
    current_functions = _boundaries(
        current,
        architecture,
        address=address,
        bits=bits,
        endianness=endianness,
        thumb=thumb,
    )

    functions: list[FunctionDiff] = []
    total = max(len(baseline_functions), len(current_functions))
    for index in range(total):
        before = baseline_functions[index] if index < len(baseline_functions) else None
        after = current_functions[index] if index < len(current_functions) else None
        functions.append(_diff_function(index, before, after))

    return PatchDiffResult(
        architecture=spec.label,
        baseline_size=len(baseline),
        current_size=len(current),
        functions=tuple(functions),
    )


def diff_files(
    baseline_path: str | Path,
    current_path: str | Path,
    architecture: Architecture | str,
    **kwargs: object,
) -> PatchDiffResult:
    """Read and compare two raw binary files."""
    baseline = Path(baseline_path).read_bytes()
    current = Path(current_path).read_bytes()
    return diff_binaries(baseline, current, architecture, **kwargs)


def format_patch_diff(result: PatchDiffResult) -> str:
    """Render a stable human-readable patch report."""
    lines = [
        f"Architecture: {result.architecture}",
        f"Binary size: {result.baseline_size} -> {result.current_size} bytes",
        f"Changed functions: {len(result.changed_functions)}",
    ]
    for function in result.changed_functions:
        before = (
            "-"
            if function.baseline_address is None
            else f"0x{function.baseline_address:x}"
        )
        after = (
            "-"
            if function.current_address is None
            else f"0x{function.current_address:x}"
        )
        lines.append(
            f"\n{function.status.upper()} {function.name} {before} -> {after}"
        )
        for delta in function.instruction_deltas:
            if delta.before is not None:
                lines.append(f"- {_format_instruction(delta.before)}")
            if delta.after is not None:
                lines.append(f"+ {_format_instruction(delta.after)}")
    if not result.changed_functions:
        lines.append("\nNo instruction changes.")
    return "\n".join(lines) + "\n"


def _boundaries(
    data: bytes,
    architecture: Architecture | str,
    **kwargs: object,
) -> tuple[FunctionBoundary, ...]:
    instructions = tuple(disassemble(data, architecture, **kwargs))
    return find_function_boundaries(instructions)


def _diff_function(
    index: int,
    before: FunctionBoundary | None,
    after: FunctionBoundary | None,
) -> FunctionDiff:
    if before is None and after is not None:
        return FunctionDiff(
            index=index,
            status="added",
            baseline_address=None,
            current_address=after.start_address,
            instruction_deltas=tuple(
                InstructionDelta("added", after=instruction)
                for instruction in after.instructions
            ),
        )
    if before is not None and after is None:
        return FunctionDiff(
            index=index,
            status="removed",
            baseline_address=before.start_address,
            current_address=None,
            instruction_deltas=tuple(
                InstructionDelta("removed", before=instruction)
                for instruction in before.instructions
            ),
        )
    if before is None or after is None:
        raise AssertionError("unreachable function pairing")

    deltas = _instruction_diff(before.instructions, after.instructions)
    return FunctionDiff(
        index=index,
        status="modified" if deltas else "unchanged",
        baseline_address=before.start_address,
        current_address=after.start_address,
        instruction_deltas=deltas,
    )


def _instruction_diff(
    before: tuple[NormalizedInstruction, ...],
    after: tuple[NormalizedInstruction, ...],
) -> tuple[InstructionDelta, ...]:
    matcher = SequenceMatcher(
        a=[_instruction_key(instruction) for instruction in before],
        b=[_instruction_key(instruction) for instruction in after],
        autojunk=False,
    )
    deltas: list[InstructionDelta] = []
    for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes():
        if tag == "equal":
            continue
        old_items = before[old_start:old_end]
        new_items = after[new_start:new_end]
        if tag == "delete":
            deltas.extend(
                InstructionDelta("removed", before=instruction)
                for instruction in old_items
            )
        elif tag == "insert":
            deltas.extend(
                InstructionDelta("added", after=instruction)
                for instruction in new_items
            )
        elif tag == "replace":
            paired = min(len(old_items), len(new_items))
            deltas.extend(
                InstructionDelta(
                    "replaced",
                    before=old_items[offset],
                    after=new_items[offset],
                )
                for offset in range(paired)
            )
            deltas.extend(
                InstructionDelta("removed", before=instruction)
                for instruction in old_items[paired:]
            )
            deltas.extend(
                InstructionDelta("added", after=instruction)
                for instruction in new_items[paired:]
            )
    return tuple(deltas)


def _instruction_key(instruction: NormalizedInstruction) -> tuple[str, str, str]:
    return instruction.mnemonic, instruction.op_str, instruction.bytes_hex


def _format_instruction(instruction: NormalizedInstruction) -> str:
    text = f"{instruction.mnemonic} {instruction.op_str}".rstrip()
    return f"0x{instruction.address:x} {instruction.bytes_hex} {text}"

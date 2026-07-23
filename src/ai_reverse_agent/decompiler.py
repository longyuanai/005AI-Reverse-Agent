"""Small evidence-preserving pseudo-C decompiler for normalized instructions."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ai_reverse_agent.architecture import Architecture, Endianness
from ai_reverse_agent.disasm import NormalizedInstruction, disassemble


@dataclass(frozen=True)
class FunctionBoundary:
    """A sequential function body terminated by a return instruction."""

    start_address: int
    end_address: int
    instructions: tuple[NormalizedInstruction, ...]

    @property
    def default_name(self) -> str:
        return f"sub_{self.start_address:x}"


@dataclass(frozen=True)
class StackVariable:
    """A stack-frame slot referenced by one or more instructions."""

    offset: int
    name: str
    references: tuple[int, ...]


@dataclass(frozen=True)
class DecompiledFunction:
    """Pseudo-C output and the evidence used to produce it."""

    name: str
    boundary: FunctionBoundary
    stack_variables: tuple[StackVariable, ...]
    pseudo_c: str


_RETURN_MNEMONICS = {"ret", "retf", "iret", "iretd", "iretq"}
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
    "jo",
    "jp",
    "js",
    "jz",
    "jnz",
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
_CALL_MNEMONICS = {"call", "callq", "bl", "blx", "jal"}

_STACK_PATTERNS = (
    re.compile(r"\[(?:r|e)?bp\s*-\s*(0x[0-9a-f]+|\d+)\]", re.IGNORECASE),
    re.compile(r"\[sp\s*,\s*#?-(0x[0-9a-f]+|\d+)", re.IGNORECASE),
    re.compile(r"-(0x[0-9a-f]+|\d+)\(\$?sp\)", re.IGNORECASE),
)


def find_function_boundaries(
    instructions: tuple[NormalizedInstruction, ...] | list[NormalizedInstruction],
) -> tuple[FunctionBoundary, ...]:
    """Split a linear instruction stream at architecture return instructions."""
    if not instructions:
        return ()

    boundaries: list[FunctionBoundary] = []
    current: list[NormalizedInstruction] = []
    for instruction in instructions:
        current.append(instruction)
        if _is_return(instruction):
            boundaries.append(_make_boundary(current))
            current = []
    if current:
        boundaries.append(_make_boundary(current))
    return tuple(boundaries)


def identify_stack_variables(boundary: FunctionBoundary) -> tuple[StackVariable, ...]:
    """Collect negative frame-pointer/stack-pointer offsets."""
    references: dict[int, list[int]] = {}
    for instruction in boundary.instructions:
        offset = _stack_offset(instruction.op_str)
        if offset is not None:
            references.setdefault(offset, []).append(instruction.address)
    return tuple(
        StackVariable(
            offset=offset,
            name=f"var_{abs(offset):x}",
            references=tuple(addresses),
        )
        for offset, addresses in sorted(references.items())
    )


def decompile_function(
    boundary: FunctionBoundary,
    *,
    name: str | None = None,
) -> DecompiledFunction:
    """Lift one function boundary into conservative pseudo-C."""
    function_name = name or boundary.default_name
    stack_variables = identify_stack_variables(boundary)
    variable_by_offset = {variable.offset: variable.name for variable in stack_variables}

    lines = [f"void {function_name}(void) {{"]
    for variable in stack_variables:
        lines.append(
            f"    uintptr_t {variable.name}; "
            f"/* stack offset {variable.offset:+#x} */"
        )
    for instruction in boundary.instructions:
        statement = _instruction_to_c(instruction, variable_by_offset)
        lines.append(f"    /* 0x{instruction.address:x} */ {statement}")
    lines.append("}")

    return DecompiledFunction(
        name=function_name,
        boundary=boundary,
        stack_variables=stack_variables,
        pseudo_c="\n".join(lines),
    )


def decompile_bytes(
    data: bytes,
    architecture: Architecture | str,
    *,
    address: int = 0,
    bits: int | None = None,
    endianness: Endianness | str = Endianness.LITTLE,
    thumb: bool = False,
) -> tuple[DecompiledFunction, ...]:
    """Disassemble bytes through S1 and return pseudo-C functions."""
    instructions = tuple(
        disassemble(
            data,
            architecture,
            address=address,
            bits=bits,
            endianness=endianness,
            thumb=thumb,
        )
    )
    return tuple(
        decompile_function(boundary)
        for boundary in find_function_boundaries(instructions)
    )


def format_decompilation(functions: tuple[DecompiledFunction, ...]) -> str:
    """Render multiple pseudo-C functions with stable spacing."""
    return "\n\n".join(function.pseudo_c for function in functions) + ("\n" if functions else "")


def _make_boundary(instructions: list[NormalizedInstruction]) -> FunctionBoundary:
    last = instructions[-1]
    return FunctionBoundary(
        start_address=instructions[0].address,
        end_address=last.address + len(bytes.fromhex(last.bytes_hex)),
        instructions=tuple(instructions),
    )


def _is_return(instruction: NormalizedInstruction) -> bool:
    mnemonic = instruction.mnemonic.lower()
    operands = instruction.op_str.lower().replace("$", "")
    return (
        mnemonic in _RETURN_MNEMONICS
        or (mnemonic == "bx" and operands == "lr")
        or (mnemonic == "jr" and operands in {"ra", "x1"})
        or (mnemonic == "jalr" and operands in {"zero, ra, 0", "x0, x1, 0"})
    )


def _stack_offset(operands: str) -> int | None:
    for pattern in _STACK_PATTERNS:
        match = pattern.search(operands)
        if match:
            return -int(match.group(1), 0)
    return None


def _instruction_to_c(
    instruction: NormalizedInstruction,
    variables: dict[int, str],
) -> str:
    mnemonic = instruction.mnemonic.lower()
    operands = instruction.op_str

    if _is_return(instruction):
        return "return;"
    if mnemonic in _CALL_MNEMONICS:
        return f"{_target_name(operands)}();"
    if mnemonic in {"jmp", "b", "bra"}:
        return f"goto {_target_name(operands)};"
    if mnemonic in _CONDITIONAL_JUMPS or mnemonic.startswith("j") and mnemonic != "jmp":
        return f"if (/* {mnemonic} */) goto {_target_name(operands)};"

    left, separator, right = operands.partition(",")
    if separator:
        destination = _operand_to_c(left.strip(), variables)
        source = _operand_to_c(right.strip(), variables)
        if mnemonic in {"mov", "movabs", "ldr", "ld", "lw", "li"}:
            return f"{destination} = {source};"
        if mnemonic in {"str", "sd", "sw"}:
            return f"{source} = {destination};"
        assignment = {
            "add": "+=",
            "addi": "+=",
            "addiu": "+=",
            "sub": "-=",
            "subi": "-=",
            "xor": "^=",
            "and": "&=",
            "or": "|=",
        }.get(mnemonic)
        if assignment:
            return f"{destination} {assignment} {source};"
    return f"/* {instruction.mnemonic} {instruction.op_str} */".rstrip()


def _operand_to_c(operand: str, variables: dict[int, str]) -> str:
    offset = _stack_offset(operand)
    if offset is not None and offset in variables:
        return variables[offset]
    cleaned = re.sub(
        r"^(?:byte|word|dword|qword|ptr)\s+",
        "",
        operand,
        flags=re.IGNORECASE,
    )
    return cleaned.replace("#", "")


def _target_name(operand: str) -> str:
    token = operand.strip().split(",")[-1].strip()
    try:
        address = int(token.lstrip("#"), 0)
    except ValueError:
        safe = re.sub(r"\W+", "_", token).strip("_")
        return safe or "unknown_target"
    return f"sub_{address:x}"

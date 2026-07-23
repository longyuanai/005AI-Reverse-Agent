"""Capstone-backed disassembly for raw binary data."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ai_reverse_agent.architecture import (
    Architecture,
    ArchitectureSpec,
    Endianness,
    resolve_architecture,
)


@dataclass(frozen=True)
class DisassembledInstruction:
    """One instruction decoded from a raw byte stream."""

    address: int
    size: int
    bytes: bytes
    mnemonic: str
    operands: str

    @property
    def text(self) -> str:
        """Return the mnemonic and operands in conventional assembly form."""
        return f"{self.mnemonic} {self.operands}".rstrip()


@dataclass(frozen=True)
class DisassemblyResult:
    """Decoded instructions plus information about any unconsumed input."""

    architecture: ArchitectureSpec
    base_address: int
    input_size: int
    instructions: tuple[DisassembledInstruction, ...]
    decoded_size: int
    trailing_bytes: bytes
    truncated: bool


class DisassemblyError(ValueError):
    """Raised when Capstone cannot fully decode a strict request."""


def disassemble_bytes(
    data: bytes,
    architecture: Architecture | str,
    *,
    bits: int | None = None,
    endianness: Endianness | str = Endianness.LITTLE,
    base_address: int = 0,
    thumb: bool = False,
    max_instructions: int | None = None,
    strict: bool = False,
) -> DisassemblyResult:
    """Disassemble raw bytes using a validated Capstone configuration.

    Raw binaries do not carry architecture metadata, so ``architecture`` is
    required. ARM Thumb mode is explicit; RISC-V compressed instructions are
    accepted automatically.
    """
    if base_address < 0:
        raise ValueError("base_address must be non-negative")
    if max_instructions is not None and max_instructions < 1:
        raise ValueError("max_instructions must be at least 1")

    spec = resolve_architecture(architecture, bits=bits, endianness=endianness)
    if thumb and spec.architecture is not Architecture.ARM:
        raise ValueError("thumb mode is only valid for the arm architecture")

    capstone_arch, capstone_mode = _capstone_configuration(spec, thumb=thumb)

    try:
        from capstone import Cs, CsError

        engine = Cs(capstone_arch, capstone_mode)
        decoded = engine.disasm(
            data,
            base_address,
            count=0 if max_instructions is None else max_instructions,
        )
        instructions = tuple(
            DisassembledInstruction(
                address=instruction.address,
                size=instruction.size,
                bytes=bytes(instruction.bytes),
                mnemonic=instruction.mnemonic,
                operands=instruction.op_str,
            )
            for instruction in decoded
        )
    except CsError as exc:
        raise DisassemblyError(f"Capstone failed to initialize or decode: {exc}") from exc

    decoded_size = (
        instructions[-1].address + instructions[-1].size - base_address
        if instructions
        else 0
    )
    trailing_bytes = data[decoded_size:]
    truncated = (
        max_instructions is not None
        and len(instructions) == max_instructions
        and bool(trailing_bytes)
    )
    if strict and trailing_bytes and not truncated:
        failure_address = base_address + decoded_size
        raise DisassemblyError(
            f"Capstone stopped at 0x{failure_address:x}; "
            f"{len(trailing_bytes)} byte(s) remain undecoded"
        )

    return DisassemblyResult(
        architecture=spec,
        base_address=base_address,
        input_size=len(data),
        instructions=instructions,
        decoded_size=decoded_size,
        trailing_bytes=trailing_bytes,
        truncated=truncated,
    )


def disassemble_file(
    path: str | Path,
    architecture: Architecture | str,
    **kwargs: object,
) -> DisassemblyResult:
    """Read and disassemble a raw binary file."""
    return disassemble_bytes(Path(path).read_bytes(), architecture, **kwargs)


def format_disassembly(result: DisassemblyResult) -> str:
    """Render a stable, plain-text disassembly listing."""
    address_width = max(8, result.architecture.bits // 4)
    byte_width = 24
    lines = [
        f"; architecture: {result.architecture.label}",
        f"; base address: 0x{result.base_address:0{address_width}x}",
    ]
    for instruction in result.instructions:
        raw = instruction.bytes.hex(" ")
        lines.append(
            f"0x{instruction.address:0{address_width}x}: "
            f"{raw:<{byte_width}} {instruction.text}"
        )

    if result.trailing_bytes:
        reason = "instruction limit reached" if result.truncated else "undecoded bytes"
        lines.append(f"; {reason}: {len(result.trailing_bytes)} byte(s)")
    return "\n".join(lines) + "\n"


def _capstone_configuration(spec: ArchitectureSpec, *, thumb: bool) -> tuple[int, int]:
    """Translate an architecture spec into Capstone constants."""
    from capstone import (
        CS_ARCH_ARM,
        CS_ARCH_ARM64,
        CS_ARCH_MIPS,
        CS_ARCH_RISCV,
        CS_ARCH_X86,
        CS_MODE_32,
        CS_MODE_64,
        CS_MODE_ARM,
        CS_MODE_BIG_ENDIAN,
        CS_MODE_LITTLE_ENDIAN,
        CS_MODE_MIPS32,
        CS_MODE_MIPS64,
        CS_MODE_RISCVC,
        CS_MODE_RISCV32,
        CS_MODE_RISCV64,
        CS_MODE_THUMB,
    )

    endian_mode = (
        CS_MODE_BIG_ENDIAN
        if spec.endianness is Endianness.BIG
        else CS_MODE_LITTLE_ENDIAN
    )
    if spec.architecture is Architecture.X86:
        return CS_ARCH_X86, CS_MODE_32
    if spec.architecture is Architecture.X64:
        return CS_ARCH_X86, CS_MODE_64
    if spec.architecture is Architecture.ARM:
        instruction_mode = CS_MODE_THUMB if thumb else CS_MODE_ARM
        return CS_ARCH_ARM, instruction_mode | endian_mode
    if spec.architecture is Architecture.AARCH64:
        return CS_ARCH_ARM64, CS_MODE_ARM | endian_mode
    if spec.architecture is Architecture.MIPS:
        instruction_mode = CS_MODE_MIPS64 if spec.bits == 64 else CS_MODE_MIPS32
        return CS_ARCH_MIPS, instruction_mode | endian_mode
    if spec.architecture is Architecture.RISCV:
        instruction_mode = CS_MODE_RISCV64 if spec.bits == 64 else CS_MODE_RISCV32
        return CS_ARCH_RISCV, instruction_mode | CS_MODE_RISCVC
    raise AssertionError(f"Unhandled architecture: {spec.architecture}")

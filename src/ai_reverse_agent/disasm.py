"""Stable normalized instruction stream built on Capstone.

The public iterator yields ``NormalizedInstruction`` values, which are named
tuples compatible with the required
``(address, mnemonic, op_str, bytes_hex)`` contract.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

from ai_reverse_agent.architecture import Architecture, Endianness
from ai_reverse_agent.disassembler import disassemble_bytes


class NormalizedInstruction(NamedTuple):
    """Architecture-neutral instruction fields used by later stages."""

    address: int
    mnemonic: str
    op_str: str
    bytes_hex: str


def disassemble(
    code: bytes,
    arch: Architecture | str | int,
    mode: int | None = None,
    *,
    address: int = 0,
    bits: int | None = None,
    endianness: Endianness | str = Endianness.LITTLE,
    thumb: bool = False,
    count: int | None = None,
) -> Iterator[NormalizedInstruction]:
    """Yield normalized instructions from a Capstone architecture/mode pair.

    ``arch`` may be a canonical architecture name (preferred) or a raw
    Capstone ``CS_ARCH_*`` integer. Integer architectures require ``mode``.
    """
    if isinstance(arch, int):
        if mode is None:
            raise ValueError("mode is required when arch is a Capstone integer")
        yield from _disassemble_capstone(code, arch, mode, address=address, count=count)
        return

    result = disassemble_bytes(
        code,
        arch,
        bits=bits,
        endianness=endianness,
        base_address=address,
        thumb=thumb,
        max_instructions=count,
    )
    for instruction in result.instructions:
        yield NormalizedInstruction(
            address=instruction.address,
            mnemonic=instruction.mnemonic,
            op_str=instruction.operands,
            bytes_hex=instruction.bytes.hex(),
        )


def disassemble_file(
    path: str | Path,
    arch: Architecture | str | int,
    mode: int | None = None,
    **kwargs: object,
) -> Iterator[NormalizedInstruction]:
    """Read a raw binary and yield normalized instructions."""
    yield from disassemble(Path(path).read_bytes(), arch, mode, **kwargs)


def _disassemble_capstone(
    code: bytes,
    arch: int,
    mode: int,
    *,
    address: int,
    count: int | None,
) -> Iterator[NormalizedInstruction]:
    from capstone import Cs

    if address < 0:
        raise ValueError("address must be non-negative")
    if count is not None and count < 1:
        raise ValueError("count must be at least 1")

    engine = Cs(arch, mode)
    for instruction in engine.disasm(code, address, count=0 if count is None else count):
        yield NormalizedInstruction(
            address=instruction.address,
            mnemonic=instruction.mnemonic,
            op_str=instruction.op_str,
            bytes_hex=bytes(instruction.bytes).hex(),
        )

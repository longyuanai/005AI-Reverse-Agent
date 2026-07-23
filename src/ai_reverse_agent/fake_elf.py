"""Minimal ELF fixtures used to test architecture detection."""

from __future__ import annotations

import struct

from ai_reverse_agent.architecture import Architecture, ArchitectureSpec, resolve_architecture
from ai_reverse_agent.fake_bin import make_fake_bin


_ELF_MACHINES = {
    Architecture.X86: 3,
    Architecture.MIPS: 8,
    Architecture.ARM: 40,
    Architecture.X64: 62,
    Architecture.AARCH64: 183,
    Architecture.RISCV: 243,
}


def make_fake_elf(architecture: Architecture | str) -> bytes:
    """Build a minimal executable ELF header followed by fixture code."""
    spec = resolve_architecture(architecture)
    header = _elf_header(spec)
    return header + make_fake_bin(spec.architecture)


def _elf_header(spec: ArchitectureSpec) -> bytes:
    elf_class = 1 if spec.bits == 32 else 2
    data_encoding = 1 if spec.endianness.value == "little" else 2
    ident = b"\x7fELF" + bytes([elf_class, data_encoding, 1, 0, 0]) + bytes(7)
    endian_prefix = "<" if data_encoding == 1 else ">"
    machine = _ELF_MACHINES[spec.architecture]

    if spec.bits == 32:
        return struct.pack(
            f"{endian_prefix}16sHHIIIIIHHHHHH",
            ident,
            2,
            machine,
            1,
            0x1000,
            0,
            0,
            0,
            52,
            0,
            0,
            0,
            0,
            0,
        )
    return struct.pack(
        f"{endian_prefix}16sHHIQQQIHHHHHH",
        ident,
        2,
        machine,
        1,
        0x1000,
        0,
        0,
        0,
        64,
        0,
        0,
        0,
        0,
        0,
    )

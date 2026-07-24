"""Build tiny, structurally valid PE/ELF samples for integration tests."""

from __future__ import annotations

import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "samples" / "mini_binaries"


def build_x64_pe() -> bytes:
    """Return a one-section PE32+ executable with x64 machine code."""

    dos = bytearray(0x80)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<4sHHIIIHH",
        b"PE\0\0",
        0x8664,
        1,
        0,
        0,
        0,
        240,
        0x0022,
    )
    optional = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,
        14,
        0,
        0x200,
        0,
        0,
        0x1000,
        0x1000,
        0x140000000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x2000,
        0x200,
        0,
        3,
        0x8160,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    optional += bytes(16 * 8)
    assert len(optional) == 240

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        0x200,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    headers = bytes(dos) + coff + optional + section
    headers += bytes(0x200 - len(headers))

    code = bytes.fromhex("55 48 89 e5 31 c0 5d c3")
    text = code + b"admin:password123\0"
    text += bytes(0x200 - len(text))
    return headers + text


def build_elf32(machine: int, code: bytes, *, flags: int = 0) -> bytes:
    """Return a little-endian ELF32 executable with one executable segment."""

    ident = b"\x7fELF" + bytes([1, 1, 1, 0, 0]) + bytes(7)
    file_offset = 0x100
    virtual_address = 0x10000
    elf_header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident,
        2,
        machine,
        1,
        virtual_address,
        52,
        0,
        flags,
        52,
        32,
        1,
        0,
        0,
        0,
    )
    program_header = struct.pack(
        "<IIIIIIII",
        1,
        file_offset,
        virtual_address,
        virtual_address,
        len(code),
        len(code),
        5,
        0x1000,
    )
    headers = elf_header + program_header
    return headers + bytes(file_offset - len(headers)) + code


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    samples = {
        "mini_x64_pe.exe": build_x64_pe(),
        "mini_arm_elf.bin": build_elf32(
            40,
            bytes.fromhex(
                "00 00 a0 e1"
                "01 10 a0 e3"
                "1e ff 2f e1"
            ),
            flags=0x05000200,
        ),
        "mini_mips_elf.bin": build_elf32(
            8,
            bytes.fromhex(
                "00 00 00 00"
                "01 00 02 24"
                "08 00 e0 03"
            ),
        ),
    }
    for name, data in samples.items():
        (OUTPUT / name).write_bytes(data)


if __name__ == "__main__":
    main()

"""PE parser.

Reads a fake-PE byte stream produced by `fake_pe.make_fake_pe()` and
returns a `PeImage`. We do not handle real PE edge cases (size of
optional header, alignment oddities) — we only need to round-trip the
PoC fixture.
"""

from __future__ import annotations

import struct
from io import BytesIO
from pathlib import Path
from typing import IO, BinaryIO

from ai_reverse_agent.datatypes import (
    CoffHeader,
    FunctionEntry,
    ImportEntry,
    OptionalHeader,
    PeImage,
    Section,
)


def parse_pe(stream: IO[bytes]) -> PeImage:
    """Parse a fake-PE byte stream and return a `PeImage`."""
    data = stream.read()
    return parse_pe_bytes(data)


def parse_pe_bytes(data: bytes) -> PeImage:
    """Parse a fake-PE from a bytes object (convenience)."""
    return _parse(BytesIO(data))


def parse_pe_file(path: str | Path) -> PeImage:
    """Parse a fake-PE from disk."""
    with open(path, "rb") as f:
        return parse_pe(f)


# ---------- Low-level helpers ----------
def _read_u8(buf: BinaryIO) -> int:
    data = buf.read(1)
    if not data:
        raise ValueError("Unexpected EOF while reading byte")
    return data[0]


def _read_u16(buf: BinaryIO) -> int:
    data = buf.read(2)
    if len(data) < 2:
        raise ValueError("Unexpected EOF while reading u16")
    return struct.unpack("<H", data)[0]


def _read_u32(buf: BinaryIO) -> int:
    data = buf.read(4)
    if len(data) < 4:
        raise ValueError("Unexpected EOF while reading u32")
    return struct.unpack("<I", data)[0]


def _read_cstring(buf: BinaryIO) -> str:
    """Read a NUL-terminated ASCII string."""
    out = bytearray()
    while True:
        c = buf.read(1)
        if not c or c == b"\x00":
            break
        out += c
    return out.decode("ascii", errors="replace")


def _rva_to_file(rva: int, sections: list[Section], raw_by_name: dict[str, int]) -> int | None:
    """Translate an RVA into a file offset using the section table."""
    for s in sections:
        if s.virtual_address <= rva < s.virtual_address + s.virtual_size:
            raw = raw_by_name.get(s.name)
            if raw is None:
                return None
            return raw + (rva - s.virtual_address)
    return None


def _parse(data_stream: BinaryIO) -> PeImage:
    # ----- DOS header -----
    if data_stream.read(2) != b"MZ":
        raise ValueError("Not a PE file: missing MZ signature")
    data_stream.read(0x3A)                        # skip to e_lfanew
    e_lfanew = _read_u32(data_stream)

    # ----- PE signature -----
    data_stream.seek(e_lfanew)
    if data_stream.read(4) != b"PE\x00\x00":
        raise ValueError("Not a PE file: missing PE signature")

    # ----- COFF header (20 bytes) -----
    machine = _read_u16(data_stream)
    num_sections = _read_u16(data_stream)
    timestamp = _read_u32(data_stream)
    data_stream.read(8)                           # PointerToSymbolTable + NumberOfSymbols
    data_stream.read(2)                           # SizeOfOptionalHeader
    characteristics = _read_u16(data_stream)
    coff = CoffHeader(
        machine=machine,
        number_of_sections=num_sections,
        timestamp=timestamp,
        characteristics=characteristics,
    )

    # ----- Optional header -----
    opt_magic = _read_u16(data_stream)
    data_stream.read(1)                           # LinkerVer minor
    data_stream.read(1)                           # LinkerVer major
    data_stream.read(4)                           # SizeOfCode
    data_stream.read(4)                           # SizeOfInitializedData
    data_stream.read(4)                           # SizeOfUninitializedData
    entry_point = _read_u32(data_stream)
    data_stream.read(4)                           # BaseOfCode
    data_stream.read(4)                           # BaseOfData
    image_base = _read_u32(data_stream)
    section_align = _read_u32(data_stream)
    file_align = _read_u32(data_stream)
    data_stream.read(4 + 4 + 4)                   # OS/Image/Subsystem versions
    data_stream.read(4)                           # Win32VersionValue
    size_image = _read_u32(data_stream)
    data_stream.read(4)                           # SizeOfHeaders
    data_stream.read(4)                           # CheckSum
    data_stream.read(2)                           # Subsystem
    data_stream.read(2)                           # DllCharacteristics
    data_stream.read(16)                          # Stack + Heap sizes
    data_stream.read(4)                           # LoaderFlags
    num_rva_sizes = _read_u32(data_stream)
    # 16 data directories.
    data_directories: list[tuple[int, int]] = []
    for _ in range(16):
        rva = _read_u32(data_stream)
        sz = _read_u32(data_stream)
        data_directories.append((rva, sz))

    opt = OptionalHeader(
        magic=opt_magic,
        entry_point=entry_point,
        image_base=image_base,
        section_alignment=section_align,
        file_alignment=file_align,
        size_of_image=size_image,
        number_of_rva_and_sizes=num_rva_sizes,
    )

    # ----- Section table (40 bytes per entry) -----
    sections: list[Section] = []
    raw_by_name: dict[str, int] = {}
    for _ in range(num_sections):
        sname = data_stream.read(8).rstrip(b"\x00").decode("ascii", errors="replace")
        vsize = _read_u32(data_stream)
        vaddr = _read_u32(data_stream)
        rsize = _read_u32(data_stream)
        raddr = _read_u32(data_stream)
        data_stream.read(12)                      # Pointer + NumberOfRelocs/Linenumbers
        chars = _read_u32(data_stream)
        sections.append(
            Section(
                name=sname,
                virtual_address=vaddr,
                virtual_size=vsize,
                raw_size=rsize,
                characteristics=chars,
            )
        )
        raw_by_name[sname] = raddr

    sections_by_va = sorted(sections, key=lambda s: s.virtual_address)

    # ----- Imports -----
    imports: list[ImportEntry] = []
    import_rva = data_directories[1][0]
    if import_rva != 0:
        imports = _read_imports(data_stream, sections_by_va, raw_by_name, import_rva)

    # ----- Function table -----
    functions: list[FunctionEntry] = []
    if ".rdata" in raw_by_name:
        functions = _read_function_table(data_stream, raw_by_name[".rdata"])

    return PeImage(
        coff=coff,
        optional=opt,
        sections=sections,
        imports=imports,
        functions=functions,
    )


def _read_imports(
    data_stream: BinaryIO,
    sections: list[Section],
    raw_by_name: dict[str, int],
    import_rva: int,
) -> list[ImportEntry]:
    """Read the IMAGE_IMPORT_DESCRIPTOR array and walk each DLL's ILT chain.

    The descriptor array is a sequence of 20-byte IMAGE_IMPORT_DESCRIPTOR
    entries, each pointing (via OriginalFirstThunk) to a chain of u32
    thunks ending with a zero terminator. The array ends with a zero-filled
    terminator entry.
    """
    sec = next(
        (
            s
            for s in sections
            if s.virtual_address <= import_rva < s.virtual_address + s.virtual_size
        ),
        None,
    )
    if sec is None or sec.name not in raw_by_name:
        return []
    sec_raw = raw_by_name[sec.name]
    sec_va = sec.virtual_address

    def to_abs(rva: int) -> int | None:
        """Translate an RVA inside `sec` to a file offset."""
        if sec.virtual_address <= rva < sec.virtual_address + sec.virtual_size:
            return sec_raw + (rva - sec_va)
        return None

    imports: list[ImportEntry] = []
    desc_rva = import_rva
    for _ in range(2048):                           # safety
        desc_off = to_abs(desc_rva)
        if desc_off is None:
            break
        data_stream.seek(desc_off)
        oft = _read_u32(data_stream)
        _read_u32(data_stream)                       # TimeDate
        _read_u32(data_stream)                       # Forwarder
        name_rva = _read_u32(data_stream)
        first_thunk = _read_u32(data_stream)
        if oft == 0 and name_rva == 0 and first_thunk == 0:
            break

        # DLL name.
        dll_off = to_abs(name_rva)
        if dll_off is None:
            desc_rva += 20
            continue
        data_stream.seek(dll_off)
        dll = _read_cstring(data_stream)

        # Walk ILT thunks.
        ilt_source = oft if oft else first_thunk
        thunk_rva = ilt_source
        for _ in range(2048):
            thunk_off = to_abs(thunk_rva)
            if thunk_off is None:
                break
            data_stream.seek(thunk_off)
            thunk = _read_u32(data_stream)
            if thunk == 0:
                break
            address = thunk_rva
            thunk_rva += 4
            if thunk & 0x80000000:
                name_rva_hint = thunk & 0x7FFFFFFF
            else:
                name_rva_hint = thunk
            hint_off = to_abs(name_rva_hint)
            if hint_off is None:
                continue
            data_stream.seek(hint_off)
            hint_data = data_stream.read(2)
            if len(hint_data) < 2:
                break
            hint = struct.unpack("<H", hint_data)[0]
            name = _read_cstring(data_stream)
            imports.append(
                ImportEntry(
                    dll=dll,
                    function=name,
                    hint=hint,
                    address=address,
                )
            )
        desc_rva += 20
    return imports


def _read_function_table(
    data_stream: BinaryIO,
    rdata_raw_offset: int,
) -> list[FunctionEntry]:
    """Read the fixed-layout function table from .rdata."""
    data_stream.seek(rdata_raw_offset)
    functions: list[FunctionEntry] = []
    for _ in range(4096):
        addr_data = data_stream.read(4)
        if len(addr_data) < 4:
            break
        addr = struct.unpack("<I", addr_data)[0]
        if addr == 0:
            break
        nlen_data = data_stream.read(1)
        if not nlen_data:
            break
        nlen = nlen_data[0]
        if nlen == 0:
            break
        name_data = data_stream.read(nlen)
        if len(name_data) < nlen:
            break
        name = name_data.decode("ascii", errors="replace")
        functions.append(FunctionEntry(address=addr, name=name))
    return functions

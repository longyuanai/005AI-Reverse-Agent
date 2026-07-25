"""Bounded PE32/PE32+ import-directory parser."""

from __future__ import annotations

from pathlib import Path

from ai_reverse_agent.magic import MagicError, read_static_file, validate_bytes

from .imphash import ImportedSymbol


def extract_pe_imports(source: str | Path | bytes) -> tuple[ImportedSymbol, ...]:
    """Extract imports from the PE import directory without executing the file."""
    data = (
        source
        if isinstance(source, bytes)
        else read_static_file(source, expected_magic=(b"MZ",))
    )
    return parse_pe_imports(data)


def parse_pe_imports(data: bytes) -> tuple[ImportedSymbol, ...]:
    """Parse a PE byte string with strict bounds and bounded table walks."""
    validate_bytes(data, expected_magic=(b"MZ",))
    if len(data) < 0x40:
        raise MagicError("truncated DOS header")
    pe_offset = _integer(data, 0x3C, 4)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise MagicError("invalid PE signature")

    section_count = _integer(data, pe_offset + 6, 2)
    optional_size = _integer(data, pe_offset + 20, 2)
    optional_offset = pe_offset + 24
    if optional_offset + optional_size > len(data):
        raise MagicError("truncated PE optional header")
    optional_magic = _integer(data, optional_offset, 2)
    if optional_magic == 0x10B:
        directory_offset = optional_offset + 96
        thunk_size = 4
        ordinal_mask = 1 << 31
    elif optional_magic == 0x20B:
        directory_offset = optional_offset + 112
        thunk_size = 8
        ordinal_mask = 1 << 63
    else:
        raise MagicError(f"unsupported PE optional-header magic 0x{optional_magic:x}")
    if directory_offset + 16 > optional_offset + optional_size:
        raise MagicError("PE optional header has no import data directory")

    import_rva = _integer(data, directory_offset + 8, 4)
    import_size = _integer(data, directory_offset + 12, 4)
    if import_rva == 0 or import_size == 0:
        return ()

    section_table = optional_offset + optional_size
    sections: list[tuple[int, int, int, int]] = []
    for index in range(section_count):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            raise MagicError("truncated PE section table")
        virtual_size = _integer(data, offset + 8, 4)
        virtual_address = _integer(data, offset + 12, 4)
        raw_size = _integer(data, offset + 16, 4)
        raw_offset = _integer(data, offset + 20, 4)
        sections.append(
            (virtual_address, max(virtual_size, raw_size), raw_offset, raw_size)
        )

    def rva_to_offset(rva: int) -> int:
        for virtual_address, span, raw_offset, raw_size in sections:
            if virtual_address <= rva < virtual_address + span:
                relative = rva - virtual_address
                if relative >= raw_size or raw_offset + relative >= len(data):
                    break
                return raw_offset + relative
        if rva < section_table and rva < len(data):
            return rva
        raise MagicError(f"PE RVA 0x{rva:x} is outside file-backed sections")

    descriptor_offset = rva_to_offset(import_rva)
    imports: list[ImportedSymbol] = []
    max_descriptors = min(4096, max(1, import_size // 20 + 1))
    for descriptor_index in range(max_descriptors):
        offset = descriptor_offset + descriptor_index * 20
        if offset + 20 > len(data):
            raise MagicError("truncated PE import descriptor")
        fields = tuple(_integer(data, offset + step * 4, 4) for step in range(5))
        if fields == (0, 0, 0, 0, 0):
            break
        original_thunk, _, _, name_rva, first_thunk = fields
        library = _cstring(data, rva_to_offset(name_rva))
        thunk_rva = original_thunk or first_thunk
        thunk_offset = rva_to_offset(thunk_rva)
        for thunk_index in range(65536):
            item_offset = thunk_offset + thunk_index * thunk_size
            value = _integer(data, item_offset, thunk_size)
            if value == 0:
                break
            address = first_thunk + thunk_index * thunk_size
            if value & ordinal_mask:
                name = f"ordinal_{value & 0xFFFF}"
                imports.append(
                    ImportedSymbol(library=library, name=name, address=address)
                )
                continue
            name_offset = rva_to_offset(value)
            hint = _integer(data, name_offset, 2)
            name = _cstring(data, name_offset + 2)
            imports.append(
                ImportedSymbol(
                    library=library,
                    name=name,
                    hint=hint,
                    address=address,
                )
            )
        else:
            raise MagicError("PE import thunk table exceeds safety bound")
    else:
        raise MagicError("PE import descriptor table exceeds safety bound")
    return tuple(imports)


def _integer(data: bytes, offset: int, size: int) -> int:
    if offset < 0 or offset + size > len(data):
        raise MagicError(f"truncated integer at file offset 0x{offset:x}")
    return int.from_bytes(data[offset : offset + size], "little")


def _cstring(data: bytes, offset: int, *, limit: int = 512) -> str:
    if offset < 0 or offset >= len(data):
        raise MagicError(f"string offset 0x{offset:x} is outside the file")
    end = data.find(b"\0", offset, min(len(data), offset + limit))
    if end < 0:
        raise MagicError(f"unterminated string at file offset 0x{offset:x}")
    try:
        return data[offset:end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise MagicError(f"non-ASCII import string at file offset 0x{offset:x}") from exc

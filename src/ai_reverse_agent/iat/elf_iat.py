"""Bounded ELF32/ELF64 dynamic-symbol import parser."""

from __future__ import annotations

import struct
from pathlib import Path

from ai_reverse_agent.magic import MagicError, read_static_file, validate_bytes

from .imphash import ImportedSymbol

_SHT_NOBITS = 8
_SHT_DYNSYM = 11


def extract_elf_imports(source: str | Path | bytes) -> tuple[ImportedSymbol, ...]:
    """Extract undefined dynamic symbols from a local ELF image."""
    data = (
        source
        if isinstance(source, bytes)
        else read_static_file(source, expected_magic=(b"\x7fELF",))
    )
    return parse_elf_imports(data)


def parse_elf_imports(data: bytes) -> tuple[ImportedSymbol, ...]:
    """Parse `.dynsym` using the ELF section table with strict bounds."""
    validate_bytes(data, expected_magic=(b"\x7fELF",))
    if len(data) < 52:
        raise MagicError("truncated ELF header")
    elf_class = data[4]
    data_encoding = data[5]
    if elf_class not in {1, 2} or data_encoding not in {1, 2}:
        raise MagicError("unsupported ELF class or byte order")
    prefix = "<" if data_encoding == 1 else ">"
    if elf_class == 1:
        if len(data) < 52:
            raise MagicError("truncated ELF32 header")
        section_offset = struct.unpack_from(prefix + "I", data, 32)[0]
        section_entry_size, section_count, names_index = struct.unpack_from(
            prefix + "HHH", data, 46
        )
        section_format = prefix + "IIIIIIIIII"
        symbol_format = prefix + "IIIBBH"
    else:
        if len(data) < 64:
            raise MagicError("truncated ELF64 header")
        section_offset = struct.unpack_from(prefix + "Q", data, 40)[0]
        section_entry_size, section_count, names_index = struct.unpack_from(
            prefix + "HHH", data, 58
        )
        section_format = prefix + "IIQQQQIIQQ"
        symbol_format = prefix + "IBBHQQ"

    expected_section_size = struct.calcsize(section_format)
    if section_entry_size < expected_section_size or section_count > 65535:
        raise MagicError("invalid ELF section-table dimensions")
    if section_offset + section_entry_size * section_count > len(data):
        raise MagicError("truncated ELF section table")

    sections = []
    for index in range(section_count):
        offset = section_offset + index * section_entry_size
        # Elf32_Shdr and Elf64_Shdr order their fields identically; only the
        # widths differ, which `section_format` already encodes.
        name, section_type, _, _, file_offset, size, link, _, _, entry_size = (
            struct.unpack_from(section_format, data, offset)
        )
        # SHT_NOBITS (.bss) occupies no file space, so sh_offset + sh_size
        # legitimately runs past EOF. Bounds-checking it rejects most real
        # executables, so only file-backed sections are checked here.
        if section_type != _SHT_NOBITS and file_offset + size > len(data):
            raise MagicError(f"ELF section {index} exceeds file bounds")
        sections.append(
            {
                "name_offset": name,
                "type": section_type,
                "offset": file_offset,
                "size": size,
                "link": link,
                "entry_size": entry_size,
            }
        )
    if names_index >= len(sections):
        raise MagicError("ELF section-name table index is invalid")
    names_section = sections[names_index]
    names = data[
        names_section["offset"] : names_section["offset"] + names_section["size"]
    ]

    imports: list[ImportedSymbol] = []
    expected_symbol_size = struct.calcsize(symbol_format)
    for section in sections:
        if section["type"] == _SHT_NOBITS:
            continue
        section_name = _table_string(names, section["name_offset"])
        if section["type"] != _SHT_DYNSYM and section_name != ".dynsym":
            continue
        if section["link"] >= len(sections):
            raise MagicError("ELF dynamic-symbol string-table link is invalid")
        strings_section = sections[section["link"]]
        strings = data[
            strings_section["offset"] : strings_section["offset"] + strings_section["size"]
        ]
        entry_size = section["entry_size"] or expected_symbol_size
        if entry_size < expected_symbol_size:
            raise MagicError("ELF dynamic-symbol entry is too small")
        count = section["size"] // entry_size
        for index in range(count):
            offset = section["offset"] + index * entry_size
            if offset + expected_symbol_size > len(data):
                raise MagicError("ELF dynamic-symbol table exceeds file bounds")
            fields = struct.unpack_from(symbol_format, data, offset)
            if elf_class == 1:
                name_offset, value, _, _, _, section_index = fields
            else:
                name_offset, _, _, section_index, value, _ = fields
            if index == 0 or section_index != 0 or name_offset == 0:
                continue
            name = _table_string(strings, name_offset)
            if name:
                imports.append(
                    ImportedSymbol(
                        library="elf",
                        name=name,
                        address=value or None,
                    )
                )
    return tuple(imports)


def _table_string(table: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(table):
        raise MagicError(f"ELF string offset 0x{offset:x} is invalid")
    end = table.find(b"\0", offset)
    if end < 0:
        raise MagicError(f"unterminated ELF string at offset 0x{offset:x}")
    try:
        return table[offset:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MagicError(f"invalid ELF UTF-8 string at offset 0x{offset:x}") from exc

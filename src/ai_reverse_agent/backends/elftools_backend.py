"""ELF backend powered by pyelftools."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from ai_reverse_agent.iat.imphash import ImportedSymbol
from ai_reverse_agent.magic import MagicError

from .base import BinaryImage


class ElfToolsBackend:
    """Extract undefined dynamic symbols plus GOT/PLT relocation addresses."""

    name = "pyelftools"
    _MAX_SYMBOLS = 65_536
    _MAX_RELOCATIONS = 65_536

    def supports(self, data: bytes) -> bool:
        return data.startswith(b"\x7fELF")

    def load(self, path: Path, data: bytes) -> BinaryImage:
        try:
            elf = ELFFile(BytesIO(data))
            relocation_addresses = self._relocations(elf)
            imports: list[ImportedSymbol] = []
            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                if section.name != ".dynsym":
                    continue
                for symbol in section.iter_symbols():
                    if symbol["st_shndx"] != "SHN_UNDEF" or not symbol.name:
                        continue
                    if len(imports) >= self._MAX_SYMBOLS:
                        raise MagicError("ELF dynamic symbol count exceeds safety bound")
                    imports.append(
                        ImportedSymbol(
                            library="elf",
                            name=symbol.name,
                            address=relocation_addresses.get(symbol.name),
                        )
                    )
        except (ELFError, OSError, TypeError, ValueError) as exc:
            if isinstance(exc, MagicError):
                raise
            raise MagicError(f"pyelftools rejected ELF image: {exc}") from exc
        return BinaryImage(
            path=path,
            data=data,
            container="elf",
            backend=self.name,
            imports=tuple(imports),
            metadata={
                "elf_class": elf.elfclass,
                "little_endian": elf.little_endian,
                "machine": elf.get_machine_arch(),
                "relocation_count": len(relocation_addresses),
            },
        )

    def _relocations(self, elf: ELFFile) -> dict[str, int]:
        addresses: dict[str, int] = {}
        count = 0
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            symbol_table = elf.get_section(section["sh_link"])
            if not isinstance(symbol_table, SymbolTableSection):
                continue
            for relocation in section.iter_relocations():
                count += 1
                if count > self._MAX_RELOCATIONS:
                    raise MagicError("ELF relocation count exceeds safety bound")
                index = relocation["r_info_sym"]
                if index == 0:
                    continue
                symbol = symbol_table.get_symbol(index)
                if symbol.name:
                    addresses.setdefault(symbol.name, int(relocation["r_offset"]))
        return addresses

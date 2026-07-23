"""Core datatypes for parsed PE images and identified functions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Section:
    """A PE section entry."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    characteristics: int


@dataclass(frozen=True)
class ImportEntry:
    """A single imported function."""

    dll: str
    function: str
    hint: int
    address: int  # RVA where the import thunk lives


@dataclass(frozen=True)
class FunctionEntry:
    """A single entry from the function table (e.g. .rdata/.text export)."""

    address: int
    name: str


@dataclass(frozen=True)
class CoffHeader:
    machine: int
    number_of_sections: int
    timestamp: int
    characteristics: int


@dataclass(frozen=True)
class OptionalHeader:
    magic: int
    entry_point: int
    image_base: int
    section_alignment: int
    file_alignment: int
    size_of_image: int
    number_of_rva_and_sizes: int


@dataclass(frozen=True)
class PeImage:
    coff: CoffHeader
    optional: OptionalHeader
    sections: list[Section]
    imports: list[ImportEntry]
    functions: list[FunctionEntry]

    @property
    def entry_point(self) -> int:
        return self.optional.entry_point

    def to_prompt_dict(self) -> dict[str, Any]:
        return {
            "machine": self.coff.machine,
            "timestamp": self.coff.timestamp,
            "characteristics": self.coff.characteristics,
            "entry_point": f"0x{self.optional.entry_point:08x}",
            "image_base": f"0x{self.optional.image_base:08x}",
            "sections": [
                {
                    "name": s.name,
                    "virtual_address": f"0x{s.virtual_address:08x}",
                    "size": s.virtual_size,
                }
                for s in self.sections
            ],
            "import_count": len(self.imports),
            "function_count": len(self.functions),
        }


@dataclass(frozen=True)
class IdentifiedFunction:
    """A function discovered from imports + function table + section membership."""

    name: str
    dll: str
    address: int
    section: str  # ".text" / ".rdata" / ".idata"
    kind: str     # "import" / "local" / "entry"

    def to_prompt_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "dll": self.dll,
            "address": f"0x{self.address:08x}",
            "section": self.section,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class EnrichedFunction:
    """An identified function plus an LLM-generated one-line purpose."""

    func: IdentifiedFunction
    purpose: str

    def to_markdown(self) -> str:
        return (
            f"- **`{self.func.name}`** (`{self.func.dll}`, "
            f"{self.func.section}, {self.func.kind})\n"
            f"  - _Purpose_: {self.purpose}"
        )

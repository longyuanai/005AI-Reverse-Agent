"""Existing bounded parsers exposed as an explicit fallback backend."""

from __future__ import annotations

from pathlib import Path

from ai_reverse_agent.iat.elf_iat import parse_elf_imports
from ai_reverse_agent.iat.pe_iat import parse_pe_imports
from ai_reverse_agent.magic import MagicError

from .base import BinaryImage


class MinimalFixtureBackend:
    name = "minimal"

    def supports(self, data: bytes) -> bool:
        return data.startswith((b"MZ", b"\x7fELF"))

    def load(self, path: Path, data: bytes) -> BinaryImage:
        if data.startswith(b"MZ"):
            container = "pe"
            imports = parse_pe_imports(data)
        elif data.startswith(b"\x7fELF"):
            container = "elf"
            imports = parse_elf_imports(data)
        else:
            raise MagicError("minimal backend supports only PE and ELF")
        return BinaryImage(
            path=path,
            data=data,
            container=container,
            backend=self.name,
            imports=imports,
        )

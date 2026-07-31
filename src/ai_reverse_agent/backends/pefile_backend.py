"""PE backend powered by pefile."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pefile

from ai_reverse_agent.iat.imphash import ImportedSymbol
from ai_reverse_agent.magic import MagicError

from .base import BinaryImage


class PeFileBackend:
    """Extract normal and delay imports with pefile's mature parser."""

    name = "pefile"
    _MAX_IMPORTS = 65_536

    def supports(self, data: bytes) -> bool:
        return data.startswith(b"MZ")

    def load(self, path: Path, data: bytes) -> BinaryImage:
        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
                ]
            )
        except pefile.PEFormatError as exc:
            raise MagicError(f"pefile rejected PE image: {exc}") from exc

        imports: list[ImportedSymbol] = []
        delay_count = 0
        for directory_name, delayed in (
            ("DIRECTORY_ENTRY_IMPORT", False),
            ("DIRECTORY_ENTRY_DELAY_IMPORT", True),
        ):
            for descriptor in tuple(getattr(pe, directory_name, ()) or ()):
                library = _decode(getattr(descriptor, "dll", b""))
                for entry in tuple(getattr(descriptor, "imports", ()) or ()):
                    if len(imports) >= self._MAX_IMPORTS:
                        raise MagicError("PE import count exceeds safety bound")
                    name = _import_name(entry)
                    imports.append(
                        ImportedSymbol(
                            library=library,
                            name=name,
                            hint=getattr(entry, "hint", None),
                            address=getattr(entry, "address", None),
                            ordinal=getattr(entry, "ordinal", None),
                            delayed=delayed,
                        )
                    )
                    delay_count += int(delayed)
        try:
            standard_imphash = pe.get_imphash()
        except (AttributeError, TypeError, ValueError):
            standard_imphash = ""
        metadata: dict[str, Any] = {
            "machine": int(pe.FILE_HEADER.Machine),
            "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
            "delay_import_count": delay_count,
            "pefile_imphash": standard_imphash,
        }
        return BinaryImage(
            path=path,
            data=data,
            container="pe",
            backend=self.name,
            imports=tuple(imports),
            metadata=metadata,
        )


def _decode(value: bytes | str | None) -> str:
    if isinstance(value, bytes):
        return value.decode("ascii", errors="replace")
    return str(value or "")


def _import_name(entry: Any) -> str:
    name = getattr(entry, "name", None)
    if name:
        return _decode(name)
    ordinal = getattr(entry, "ordinal", None)
    return f"ordinal_{ordinal}" if ordinal is not None else "ordinal_unknown"

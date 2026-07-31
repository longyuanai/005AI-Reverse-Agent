"""Industry-compatible PE import hash."""

from __future__ import annotations

import re
from collections.abc import Iterable

from ai_reverse_agent.iat.imphash import ImportLike, ImportedSymbol

from .import_set_hash import _md5

_PE_EXTENSION = re.compile(r"\.(dll|sys|ocx)$", re.IGNORECASE)


def normalize_pe_import(value: ImportLike) -> str:
    """Normalize one PE import while preserving the surrounding import order."""
    if isinstance(value, ImportedSymbol):
        library, name = value.library, value.name
    elif isinstance(value, tuple) and len(value) == 2:
        library, name = value
    elif isinstance(value, str):
        if "." not in value:
            return value.strip().lower()
        library, name = value.rsplit(".", 1)
    else:
        raise TypeError(f"unsupported import value: {value!r}")
    normalized_library = _PE_EXTENSION.sub("", str(library).strip().lower())
    normalized_name = str(name).strip().lower()
    if not normalized_name:
        raise ValueError("import name must not be empty")
    return (
        f"{normalized_library}.{normalized_name}"
        if normalized_library
        else normalized_name
    )


def compute_pe_imphash(imports: Iterable[ImportLike]) -> str:
    """Return the order-sensitive PE imphash compatible with pefile."""
    normalized = [normalize_pe_import(item) for item in imports]
    return _md5(",".join(normalized).encode("utf-8"))

"""Deterministic sorted-import MD5 imphash."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from collections.abc import Iterable


@dataclass(frozen=True)
class ImportedSymbol:
    """One imported function from a PE IAT or ELF dynamic symbol table."""

    library: str
    name: str
    hint: int | None = None
    address: int | None = None

    @property
    def canonical_name(self) -> str:
        library = self.library.strip().lower()
        name = self.name.strip().lower()
        return f"{library}.{name}" if library else name


ImportLike = ImportedSymbol | str | tuple[str, str]


def normalize_import(value: ImportLike) -> str:
    """Normalize supported import representations to lowercase text."""
    if isinstance(value, ImportedSymbol):
        normalized = value.canonical_name
    elif isinstance(value, str):
        normalized = value.strip().lower()
    elif isinstance(value, tuple) and len(value) == 2:
        normalized = f"{value[0].strip().lower()}.{value[1].strip().lower()}"
    else:
        raise TypeError(f"unsupported import value: {value!r}")
    if not normalized:
        raise ValueError("import name must not be empty")
    return normalized


def compute_imphash(imports: Iterable[ImportLike]) -> str:
    """Return MD5(sorted normalized imports joined by commas)."""
    canonical = sorted(normalize_import(item) for item in imports)
    payload = ",".join(canonical).encode("utf-8")
    try:
        digest = hashlib.md5(payload, usedforsecurity=False)
    except TypeError:  # pragma: no cover - older Python/OpenSSL
        digest = hashlib.md5(payload)
    return digest.hexdigest()

"""Deterministic sorted-import MD5 imphash."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ImportedSymbol:
    """One imported function from a PE IAT or ELF dynamic symbol table."""

    library: str
    name: str
    hint: int | None = None
    address: int | None = None
    ordinal: int | None = None
    delayed: bool = False

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
    """Deprecated alias for :func:`compute_import_set_hash`."""
    from ai_reverse_agent.hashing.import_set_hash import compute_import_set_hash

    return compute_import_set_hash(imports)

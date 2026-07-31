"""Hash result models with explicit algorithm names."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ImportHashes:
    pe_imphash: str | None
    import_set_hash: str
    pe_algorithm: str = "pe-imphash-v1"
    set_algorithm: str = "import-set-md5-v1"

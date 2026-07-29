"""Order-independent import-set hashing."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from ai_reverse_agent.iat.imphash import ImportLike, normalize_import


def _md5(payload: bytes) -> str:
    try:
        return hashlib.md5(payload, usedforsecurity=False).hexdigest()
    except TypeError:  # pragma: no cover
        return hashlib.md5(payload).hexdigest()


def compute_import_set_hash(imports: Iterable[ImportLike]) -> str:
    """Return MD5(sorted lowercase ``library.function`` values)."""
    normalized = sorted(normalize_import(item) for item in imports)
    return _md5(",".join(normalized).encode("utf-8"))

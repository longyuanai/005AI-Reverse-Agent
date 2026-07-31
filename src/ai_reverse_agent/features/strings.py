"""Bounded printable-string extraction."""

from __future__ import annotations

import re

_ASCII = re.compile(rb"[\x20-\x7e]{4,}")


def extract_ascii_strings(data: bytes, *, limit: int = 4096) -> tuple[tuple[int, str], ...]:
    found: list[tuple[int, str]] = []
    for match in _ASCII.finditer(data):
        found.append((match.start(), match.group().decode("ascii")))
        if len(found) >= limit:
            break
    return tuple(found)

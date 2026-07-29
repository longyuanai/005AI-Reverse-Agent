"""Small file-level constant features."""

from __future__ import annotations

from collections import Counter
from math import log2


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    size = len(data)
    return -sum((count / size) * log2(count / size) for count in counts.values())

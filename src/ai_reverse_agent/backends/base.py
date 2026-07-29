"""Static binary backend contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ai_reverse_agent.iat.imphash import ImportedSymbol


@dataclass(frozen=True)
class BinaryImage:
    """One bounded, immutable parse result shared by analysis services."""

    path: Path
    data: bytes
    container: str
    backend: str
    imports: tuple[ImportedSymbol, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


class BinaryBackend(Protocol):
    """Protocol implemented by concrete file-format loaders."""

    name: str

    def supports(self, data: bytes) -> bool:
        """Return whether this backend recognizes the supplied bytes."""

    def load(self, path: Path, data: bytes) -> BinaryImage:
        """Return a bounded parse result without executing the sample."""

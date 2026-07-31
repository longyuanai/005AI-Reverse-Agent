"""Raw-byte fallback backend."""

from __future__ import annotations

from pathlib import Path

from .base import BinaryImage


class RawBackend:
    name = "raw"

    def supports(self, data: bytes) -> bool:
        return True

    def load(self, path: Path, data: bytes) -> BinaryImage:
        return BinaryImage(path=path, data=data, container="raw", backend=self.name)

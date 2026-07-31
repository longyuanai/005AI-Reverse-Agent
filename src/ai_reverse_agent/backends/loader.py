"""Single-pass bounded binary loader."""

from __future__ import annotations

from pathlib import Path

from ai_reverse_agent.magic import MagicError, read_static_file

from .base import BinaryBackend, BinaryImage
from .elftools_backend import ElfToolsBackend
from .minimal_backend import MinimalFixtureBackend
from .pefile_backend import PeFileBackend
from .raw_backend import RawBackend


class BinaryLoader:
    """Select a mature backend and optionally fall back to bounded parsers."""

    def __init__(
        self,
        backends: tuple[BinaryBackend, ...] | None = None,
        *,
        allow_minimal_fallback: bool = True,
    ) -> None:
        self.backends = backends or (PeFileBackend(), ElfToolsBackend(), RawBackend())
        self.allow_minimal_fallback = allow_minimal_fallback

    def load(self, source: str | Path) -> BinaryImage:
        path = Path(source).expanduser().resolve()
        data = read_static_file(path)
        for backend in self.backends:
            if not backend.supports(data):
                continue
            try:
                return backend.load(path, data)
            except MagicError:
                if (
                    self.allow_minimal_fallback
                    and data.startswith((b"MZ", b"\x7fELF"))
                    and not isinstance(backend, MinimalFixtureBackend)
                ):
                    return MinimalFixtureBackend().load(path, data)
                raise
        raise MagicError("no binary backend accepted the sample")

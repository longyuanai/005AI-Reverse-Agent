"""Availability-aware decompiler backend selection."""

from __future__ import annotations

from ai_reverse_agent.architecture import Architecture, Endianness
from ai_reverse_agent.decompiler import DecompiledFunction

from .base import DecompilerBackend
from .native import NativeDecompilerBackend


class DecompilerUnavailable(RuntimeError):
    """Raised when no configured decompiler backend is available."""


class DecompilerSelector:
    """Select the first available backend in configured priority order."""

    def __init__(self, backends: tuple[DecompilerBackend, ...]) -> None:
        self.backends = backends

    def selected_backend(self) -> DecompilerBackend:
        for backend in self.backends:
            if backend.available():
                return backend
        raise DecompilerUnavailable("no decompiler backend is available")

    def decompile(
        self,
        image: bytes,
        architecture: Architecture | str,
        *,
        address: int = 0,
        bits: int | None = None,
        endianness: Endianness | str = Endianness.LITTLE,
        thumb: bool = False,
        recognize_libraries: bool = True,
    ) -> tuple[DecompiledFunction, ...]:
        backend = self.selected_backend()
        return backend.decompile(
            image,
            architecture,
            address=address,
            bits=bits,
            endianness=endianness,
            thumb=thumb,
            recognize_libraries=recognize_libraries,
        )


def default_decompiler_selector() -> DecompilerSelector:
    """Return the default lightweight-only selector for this release seam."""
    return DecompilerSelector((NativeDecompilerBackend(),))

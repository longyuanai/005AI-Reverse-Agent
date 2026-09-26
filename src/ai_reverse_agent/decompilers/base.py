"""Decompiler backend contract, separate from binary loading backends."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from ai_reverse_agent.architecture import Architecture, Endianness

if TYPE_CHECKING:
    from ai_reverse_agent.decompiler import DecompiledFunction


class DecompilerBackend(Protocol):
    """Protocol implemented by native and external decompilers."""

    name: str

    def available(self) -> bool:
        """Return whether this backend can run in the current environment."""

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
        """Decompile one in-memory image without changing the public API."""

"""Native Capstone-backed pseudo-C decompiler."""

from __future__ import annotations

from ai_reverse_agent.architecture import Architecture, Endianness
from ai_reverse_agent.decompiler import DecompiledFunction


class NativeDecompilerBackend:
    """Preserve the original lightweight decompilation path."""

    name = "native"

    def available(self) -> bool:
        return True

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
        from ai_reverse_agent.decompiler import _decompile_bytes_native

        return _decompile_bytes_native(
            image,
            architecture,
            address=address,
            bits=bits,
            endianness=endianness,
            thumb=thumb,
            recognize_libraries=recognize_libraries,
        )

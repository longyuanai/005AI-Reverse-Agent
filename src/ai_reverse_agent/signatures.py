"""Small built-in function-signature matcher over Capstone instructions."""

from __future__ import annotations

from dataclasses import dataclass

from ai_reverse_agent.architecture import Architecture, resolve_architecture
from ai_reverse_agent.disasm import NormalizedInstruction, disassemble


@dataclass(frozen=True)
class LibrarySignature:
    """One architecture-specific byte pattern with optional wildcards."""

    library: str
    name: str
    architecture: Architecture
    pattern: bytes
    mask: bytes

    def __post_init__(self) -> None:
        if not self.pattern or len(self.pattern) > 16:
            raise ValueError("signature patterns must contain 1 to 16 bytes")
        if len(self.pattern) != len(self.mask):
            raise ValueError("signature pattern and mask must have equal length")


@dataclass(frozen=True)
class SignatureMatch:
    """A successful match against the built-in signature table."""

    library: str
    name: str
    architecture: Architecture
    matched_bytes: int

    @property
    def qualified_name(self) -> str:
        return f"{self.library}!{self.name}"


def _exact(
    library: str,
    name: str,
    architecture: Architecture,
    hex_pattern: str,
) -> LibrarySignature:
    pattern = bytes.fromhex(hex_pattern)
    return LibrarySignature(
        library=library,
        name=name,
        architecture=architecture,
        pattern=pattern,
        mask=b"\xff" * len(pattern),
    )


BUILTIN_SIGNATURES: tuple[LibrarySignature, ...] = (
    _exact(
        "msvcrt",
        "memcpy",
        Architecture.X86,
        "8b 44 24 04 8b 4c 24 08 8b 54 24 0c 85 d2 74 06",
    ),
    _exact(
        "libc",
        "strlen",
        Architecture.X64,
        "31 c0 80 3c 07 00 74 05 48 ff c0 eb f5 c3",
    ),
    LibrarySignature(
        library="libstdc++",
        name="_ZSt9terminatev",
        architecture=Architecture.X64,
        pattern=bytes.fromhex("55 48 89 e5 e8 00 00 00 00 0f 0b"),
        mask=bytes.fromhex("ff ff ff ff ff 00 00 00 00 ff ff"),
    ),
)


def signature_bytes(
    instructions: tuple[NormalizedInstruction, ...] | list[NormalizedInstruction],
) -> bytes:
    """Rebuild at most the first 16 decoded bytes of a function."""
    raw = bytearray()
    for instruction in instructions:
        raw.extend(bytes.fromhex(instruction.bytes_hex))
        if len(raw) >= 16:
            break
    return bytes(raw[:16])


def match_instructions(
    instructions: tuple[NormalizedInstruction, ...] | list[NormalizedInstruction],
    architecture: Architecture | str,
) -> SignatureMatch | None:
    """Match a normalized instruction stream against built-in signatures."""
    resolved = resolve_architecture(architecture).architecture
    prefix = signature_bytes(instructions)
    for signature in BUILTIN_SIGNATURES:
        if signature.architecture is not resolved:
            continue
        if _matches(prefix, signature):
            return SignatureMatch(
                library=signature.library,
                name=signature.name,
                architecture=resolved,
                matched_bytes=len(signature.pattern),
            )
    return None


def match_code(
    code: bytes,
    architecture: Architecture | str,
    **disasm_options: object,
) -> SignatureMatch | None:
    """Capstone-decode the first 16 bytes and match the normalized stream."""
    instructions = tuple(disassemble(code[:16], architecture, **disasm_options))
    return match_instructions(instructions, architecture)


def _matches(prefix: bytes, signature: LibrarySignature) -> bool:
    if len(prefix) < len(signature.pattern):
        return False
    return all(
        mask == 0 or actual == expected
        # `prefix` is the full 16-byte window and is normally longer than the
        # signature, so the shortest-input zip semantics are intentional here.
        for actual, expected, mask in zip(
            prefix, signature.pattern, signature.mask, strict=False
        )
    )

"""Identify high-confidence cryptographic constants in binary data."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct


AES_SBOX = bytes.fromhex(
    """
    63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
    ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
    b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
    04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
    09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
    53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
    d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
    51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
    cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
    60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
    e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
    e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
    ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
    70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
    e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df
    8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16
    """
)

SHA256_K_PREFIX = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
)

SHA1_INITIAL_STATE = (
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
)


@dataclass(frozen=True)
class CryptoDetection:
    """A recognized cryptographic constant sequence."""

    algorithm: str
    constant: str
    offset: int
    length: int
    endianness: str | None
    evidence_hex: str


@dataclass(frozen=True)
class _KnownPattern:
    algorithm: str
    constant: str
    data: bytes
    endianness: str | None


def identify_crypto(data: bytes) -> tuple[CryptoDetection, ...]:
    """Return all known cryptographic constants found in *data*."""

    detections: list[CryptoDetection] = []
    for pattern in _known_patterns():
        start = 0
        while True:
            offset = data.find(pattern.data, start)
            if offset < 0:
                break
            detections.append(
                CryptoDetection(
                    algorithm=pattern.algorithm,
                    constant=pattern.constant,
                    offset=offset,
                    length=len(pattern.data),
                    endianness=pattern.endianness,
                    evidence_hex=pattern.data[:32].hex(),
                )
            )
            start = offset + 1

    detections.sort(
        key=lambda detection: (
            detection.offset,
            detection.algorithm,
            detection.endianness or "",
        )
    )
    return tuple(detections)


def identify_crypto_file(path: str | Path) -> tuple[CryptoDetection, ...]:
    """Read *path* and identify its known cryptographic constants."""

    return identify_crypto(Path(path).read_bytes())


def format_crypto_detections(detections: tuple[CryptoDetection, ...]) -> str:
    """Format detections as deterministic, human-readable text."""

    if not detections:
        return "No known cryptographic constants found.\n"

    algorithms = {detection.algorithm for detection in detections}
    lines = [f"Detected algorithms: {len(algorithms)}"]
    for detection in detections:
        endianness = detection.endianness or "byte-table"
        lines.append(
            f"0x{detection.offset:x} {detection.algorithm} "
            f"{detection.constant} length={detection.length} "
            f"endian={endianness}"
        )
        lines.append(f"  evidence={detection.evidence_hex}")
    return "\n".join(lines) + "\n"


def _known_patterns() -> tuple[_KnownPattern, ...]:
    return (
        _KnownPattern("AES", "S-box", AES_SBOX, None),
        _KnownPattern(
            "SHA-256",
            "K constants prefix",
            _pack_words(SHA256_K_PREFIX, "little"),
            "little",
        ),
        _KnownPattern(
            "SHA-256",
            "K constants prefix",
            _pack_words(SHA256_K_PREFIX, "big"),
            "big",
        ),
        _KnownPattern(
            "SHA-1",
            "initial state",
            _pack_words(SHA1_INITIAL_STATE, "little"),
            "little",
        ),
        _KnownPattern(
            "SHA-1",
            "initial state",
            _pack_words(SHA1_INITIAL_STATE, "big"),
            "big",
        ),
    )


def _pack_words(words: tuple[int, ...], endianness: str) -> bytes:
    prefix = "<" if endianness == "little" else ">"
    return struct.pack(f"{prefix}{len(words)}I", *words)

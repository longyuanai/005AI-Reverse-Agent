"""Small raw machine-code fixtures for every supported architecture."""

from __future__ import annotations

from pathlib import Path

from ai_reverse_agent.architecture import Architecture, resolve_architecture


FAKE_BINARIES: dict[Architecture, bytes] = {
    Architecture.X86: bytes.fromhex("55 89 e5 c3"),
    Architecture.X64: bytes.fromhex("55 48 89 e5 c3"),
    Architecture.ARM: bytes.fromhex(
        "00 00 a0 e1"  # mov r0, r0
        "01 10 a0 e3"  # mov r1, #1
        "1e ff 2f e1"  # bx lr
    ),
    Architecture.AARCH64: bytes.fromhex(
        "1f 20 03 d5"  # nop
        "20 00 80 d2"  # mov x0, #1
        "c0 03 5f d6"  # ret
    ),
    Architecture.MIPS: bytes.fromhex(
        "00 00 00 00"  # nop
        "01 00 02 24"  # addiu v0, zero, 1
        "08 00 e0 03"  # jr ra
    ),
    Architecture.RISCV: bytes.fromhex(
        "13 00 00 00"  # nop
        "13 05 10 00"  # li a0, 1
        "67 80 00 00"  # ret
    ),
}


def make_fake_bin(architecture: Architecture | str) -> bytes:
    """Return a deterministic three-instruction raw fixture."""
    resolved = resolve_architecture(architecture).architecture
    return FAKE_BINARIES[resolved]


def write_fake_bins(directory: str | Path) -> tuple[Path, ...]:
    """Write all raw fixtures as ``<architecture>-demo.bin`` files."""
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for architecture, data in FAKE_BINARIES.items():
        path = root / f"{architecture.value}-demo.bin"
        path.write_bytes(data)
        paths.append(path)
    return tuple(paths)

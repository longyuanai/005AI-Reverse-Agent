"""Architecture names, aliases, and PE machine mappings."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Architecture(str, Enum):
    """Canonical architectures supported by the analysis pipeline."""

    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    AARCH64 = "aarch64"
    MIPS = "mips"
    RISCV = "riscv"


class Endianness(str, Enum):
    """Byte order used when decoding instructions."""

    LITTLE = "little"
    BIG = "big"


@dataclass(frozen=True)
class ArchitectureSpec:
    """A fully resolved architecture configuration."""

    architecture: Architecture
    bits: int
    endianness: Endianness = Endianness.LITTLE

    def __post_init__(self) -> None:
        valid_bits = {
            Architecture.X86: {32},
            Architecture.X64: {64},
            Architecture.ARM: {32},
            Architecture.AARCH64: {64},
            Architecture.MIPS: {32, 64},
            Architecture.RISCV: {32, 64},
        }
        if self.bits not in valid_bits[self.architecture]:
            supported = ", ".join(str(value) for value in sorted(valid_bits[self.architecture]))
            raise ValueError(
                f"{self.architecture.value} supports bit width(s): {supported}; "
                f"got {self.bits}"
            )
        if (
            self.endianness is Endianness.BIG
            and self.architecture in {Architecture.X86, Architecture.X64, Architecture.RISCV}
        ):
            raise ValueError(f"{self.architecture.value} only supports little-endian mode")

    @property
    def label(self) -> str:
        """Human-readable architecture summary."""
        return f"{self.architecture.value} ({self.bits}-bit, {self.endianness.value}-endian)"


_ALIASES: dict[str, tuple[Architecture, int]] = {
    "x86": (Architecture.X86, 32),
    "i386": (Architecture.X86, 32),
    "i486": (Architecture.X86, 32),
    "i586": (Architecture.X86, 32),
    "i686": (Architecture.X86, 32),
    "ia32": (Architecture.X86, 32),
    "x64": (Architecture.X64, 64),
    "x8664": (Architecture.X64, 64),
    "amd64": (Architecture.X64, 64),
    "arm": (Architecture.ARM, 32),
    "arm32": (Architecture.ARM, 32),
    "aarch64": (Architecture.AARCH64, 64),
    "arm64": (Architecture.AARCH64, 64),
    "mips": (Architecture.MIPS, 32),
    "mips32": (Architecture.MIPS, 32),
    "mips64": (Architecture.MIPS, 64),
    "riscv": (Architecture.RISCV, 64),
    "riscv32": (Architecture.RISCV, 32),
    "riscv64": (Architecture.RISCV, 64),
}


_PE_MACHINE_SPECS: dict[int, tuple[Architecture, int]] = {
    0x014C: (Architecture.X86, 32),       # IMAGE_FILE_MACHINE_I386
    0x8664: (Architecture.X64, 64),       # IMAGE_FILE_MACHINE_AMD64
    0x01C0: (Architecture.ARM, 32),       # IMAGE_FILE_MACHINE_ARM
    0x01C2: (Architecture.ARM, 32),       # IMAGE_FILE_MACHINE_THUMB
    0x01C4: (Architecture.ARM, 32),       # IMAGE_FILE_MACHINE_ARMNT
    0xAA64: (Architecture.AARCH64, 64),   # IMAGE_FILE_MACHINE_ARM64
    0x0162: (Architecture.MIPS, 32),      # IMAGE_FILE_MACHINE_R3000
    0x0166: (Architecture.MIPS, 32),      # IMAGE_FILE_MACHINE_R4000
    0x0168: (Architecture.MIPS, 32),      # IMAGE_FILE_MACHINE_R10000
    0x0169: (Architecture.MIPS, 32),      # IMAGE_FILE_MACHINE_WCEMIPSV2
    0x0266: (Architecture.MIPS, 32),      # IMAGE_FILE_MACHINE_MIPS16
    0x0366: (Architecture.MIPS, 32),      # IMAGE_FILE_MACHINE_MIPSFPU
    0x0466: (Architecture.MIPS, 32),      # IMAGE_FILE_MACHINE_MIPSFPU16
    0x5032: (Architecture.RISCV, 32),     # IMAGE_FILE_MACHINE_RISCV32
    0x5064: (Architecture.RISCV, 64),     # IMAGE_FILE_MACHINE_RISCV64
}

_ELF_MACHINE_ARCHITECTURES: dict[int, Architecture] = {
    3: Architecture.X86,       # EM_386
    8: Architecture.MIPS,      # EM_MIPS
    40: Architecture.ARM,      # EM_ARM
    62: Architecture.X64,      # EM_X86_64
    183: Architecture.AARCH64, # EM_AARCH64
    243: Architecture.RISCV,   # EM_RISCV
}


def resolve_architecture(
    value: Architecture | str,
    *,
    bits: int | None = None,
    endianness: Endianness | str = Endianness.LITTLE,
) -> ArchitectureSpec:
    """Resolve a user-facing architecture name into a validated spec."""
    if isinstance(value, Architecture):
        architecture = value
        default_bits = {
            Architecture.X86: 32,
            Architecture.X64: 64,
            Architecture.ARM: 32,
            Architecture.AARCH64: 64,
            Architecture.MIPS: 32,
            Architecture.RISCV: 64,
        }[value]
    else:
        normalized = value.strip().lower().replace("-", "").replace("_", "").replace(" ", "")
        try:
            architecture, default_bits = _ALIASES[normalized]
        except KeyError as exc:
            supported = ", ".join(member.value for member in Architecture)
            raise ValueError(
                f"Unsupported architecture {value!r}; choose one of: {supported}"
            ) from exc

    byte_order = (
        endianness
        if isinstance(endianness, Endianness)
        else Endianness(endianness.strip().lower())
    )
    return ArchitectureSpec(
        architecture=architecture,
        bits=default_bits if bits is None else bits,
        endianness=byte_order,
    )


def architecture_from_pe_machine(machine: int) -> ArchitectureSpec:
    """Map a PE/COFF machine field to a supported architecture."""
    try:
        architecture, bits = _PE_MACHINE_SPECS[machine]
    except KeyError as exc:
        raise ValueError(f"Unsupported PE machine type: 0x{machine:04x}") from exc
    return ArchitectureSpec(architecture=architecture, bits=bits)


def architecture_from_elf_machine(
    machine: int,
    *,
    bits: int,
    endianness: Endianness | str = Endianness.LITTLE,
) -> ArchitectureSpec:
    """Map an ELF e_machine value and ELF class to an architecture."""
    try:
        architecture = _ELF_MACHINE_ARCHITECTURES[machine]
    except KeyError as exc:
        raise ValueError(f"Unsupported ELF machine type: {machine}") from exc
    return resolve_architecture(architecture, bits=bits, endianness=endianness)


def detect_elf_architecture(data: bytes) -> ArchitectureSpec:
    """Read ELF identification fields and return a validated architecture."""
    if len(data) < 20 or data[:4] != b"\x7fELF":
        raise ValueError("Not an ELF file: missing or truncated ELF header")

    elf_class = data[4]
    if elf_class not in {1, 2}:
        raise ValueError(f"Unsupported ELF class: {elf_class}")
    bits = 32 if elf_class == 1 else 64

    data_encoding = data[5]
    if data_encoding == 1:
        endianness = Endianness.LITTLE
        byte_order = "little"
    elif data_encoding == 2:
        endianness = Endianness.BIG
        byte_order = "big"
    else:
        raise ValueError(f"Unsupported ELF data encoding: {data_encoding}")

    machine = int.from_bytes(data[18:20], byteorder=byte_order)
    return architecture_from_elf_machine(
        machine,
        bits=bits,
        endianness=endianness,
    )

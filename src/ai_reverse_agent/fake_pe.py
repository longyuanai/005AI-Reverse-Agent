"""Pure-Python fake PE generator for the PoC.

Builds a minimal but structurally valid PE32 image in memory. This is
NOT meant to defeat a real disassembler — it's a known-format fixture
that `parsers.py` can read back deterministically so the full pipeline
(generate → parse → identify → enrich → report) can be exercised
end-to-end in tests without real binaries.

File layout (file alignment = 0x200):
  0x000  IMAGE_DOS_HEADER (64 bytes) + DOS stub message
  0x080  DOS stub message tail + padding to 0x200
  0x200  PE signature (4) + COFF header (20)
  0x218  Optional header (224 bytes for PE32)
  0x2F8  Section table (3 × 40 = 120 bytes)
  0x400  .text body (code)
  0x600  .rdata body (function table, fixed record layout)
  0x800  .idata body (imports, fixed layout)

So ``e_lfanew = 0x200`` — the PE signature lives at the file-aligned
offset, not the conventional 0x80.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from io import BytesIO


@dataclass(frozen=True)
class FakeFunction:
    """One function referenced by the fake PE."""

    name: str
    dll: str
    hint: int
    address: int  # RVA in the image (added to ImageBase by the loader)


# Default target functions for the demo.
TARGET_FUNCTIONS: list[FakeFunction] = [
    FakeFunction(name="CreateFileW", dll="kernel32.dll", hint=123, address=0x00001234),
    FakeFunction(name="MessageBoxW", dll="user32.dll", hint=130, address=0x00001238),
    FakeFunction(name="printf", dll="msvcrt.dll", hint=42, address=0x0000123C),
    FakeFunction(name="connect", dll="ws2_32.dll", hint=44, address=0x00001240),
    FakeFunction(name="RegOpenKeyExW", dll="advapi32.dll", hint=159, address=0x00001244),
]


# DOS stub message — classic "This program cannot be run in DOS mode".
_DOS_STUB_MSG = (
    b"This program cannot be run in DOS mode.\r\n\x00"
)


def _pad_to(buf: BytesIO, target: int) -> None:
    """Pad the buffer up to `target` with NULs."""
    cur = buf.tell()
    if cur < target:
        buf.write(b"\x00" * (target - cur))


def _encode_section_name(name: str) -> bytes:
    """Encode an 8-byte section name (NUL-padded)."""
    raw = name.encode("ascii", errors="replace")[:8]
    return raw + b"\x00" * (8 - len(raw))


# ---------- Top-level layout constants ----------
_IMAGE_BASE = 0x00400000
_FILE_ALIGN = 0x200
_SECTION_ALIGN = 0x1000

_TEXT_RAW = 0x400
_RDATA_RAW = 0x600
_IDATA_RAW = 0x800

_TEXT_VA = 0x1000
_RDATA_VA = 0x2000
_IDATA_VA = 0x3000

_TEXT_SIZE = 0x200
_RDATA_SIZE = 0x400
_IDATA_SIZE = 0x600

_ENTRY_RVA = _TEXT_VA + 0x10


def _write_dos_header(buf: BytesIO) -> None:
    """Write IMAGE_DOS_HEADER and DOS stub.

    e_lfanew points to 0x200 (file-aligned) so the layout matches our
    intended flow: full headers region ≤ 0x400, then section bodies.
    """
    e_lfanew = 0x200
    buf.write(b"MZ")                                    # bytes 0x00..0x01
    buf.write(b"\x00" * 58)                             # bytes 0x02..0x3B
    buf.write(struct.pack("<I", e_lfanew))              # bytes 0x3C..0x3F
    buf.write(_DOS_STUB_MSG)                            # bytes 0x40..end
    _pad_to(buf, _FILE_ALIGN)                           # up to 0x200


def _write_pe_signature(buf: BytesIO) -> None:
    buf.write(b"PE\x00\x00")


def _write_coff_header(buf: BytesIO, num_sections: int) -> None:
    """Write IMAGE_FILE_HEADER (20 bytes)."""
    buf.write(struct.pack("<H", 0x8664))                # Machine: AMD64
    buf.write(struct.pack("<H", num_sections))
    buf.write(struct.pack("<I", 0x66000000))            # TimeDateStamp
    buf.write(struct.pack("<I", 0))                     # PointerToSymbolTable
    buf.write(struct.pack("<I", 0))                     # NumberOfSymbols
    buf.write(struct.pack("<H", 224))                   # SizeOfOptionalHeader (PE32 = 224)
    buf.write(struct.pack("<H", 0x2102))                # Characteristics


def _write_optional_header(buf: BytesIO, imports_rva: int, imports_size: int) -> None:
    """Write IMAGE_OPTIONAL_HEADER (PE32 = 224 bytes)."""
    buf.write(struct.pack("<H", 0x10b))                 # Magic: PE32
    buf.write(struct.pack("<BB", 14, 0))                # LinkerVersion 14.0
    buf.write(struct.pack("<I", _TEXT_SIZE))            # SizeOfCode
    buf.write(struct.pack("<I", _RDATA_SIZE + _IDATA_SIZE))  # SizeOfInitializedData
    buf.write(struct.pack("<I", 0))                     # SizeOfUninitializedData
    buf.write(struct.pack("<I", _ENTRY_RVA))            # AddressOfEntryPoint
    buf.write(struct.pack("<I", _TEXT_VA))              # BaseOfCode
    buf.write(struct.pack("<I", 0))                     # BaseOfData (PE32 only)
    buf.write(struct.pack("<I", _IMAGE_BASE))           # ImageBase
    buf.write(struct.pack("<I", _SECTION_ALIGN))        # SectionAlignment
    buf.write(struct.pack("<I", _FILE_ALIGN))           # FileAlignment
    buf.write(struct.pack("<HH", 6, 0))                 # OSVersionMajor.Minor
    buf.write(struct.pack("<HH", 0, 0))                 # ImageVersion
    buf.write(struct.pack("<HH", 6, 0))                 # SubsystemVersion
    buf.write(struct.pack("<I", 0))                     # Win32VersionValue
    buf.write(struct.pack("<I", 0x5000))                # SizeOfImage
    buf.write(struct.pack("<I", _IDATA_RAW + _IDATA_SIZE))  # SizeOfHeaders
    buf.write(struct.pack("<I", 0))                     # CheckSum
    buf.write(struct.pack("<H", 3))                     # Subsystem: Windows CUI
    buf.write(struct.pack("<H", 0))                     # DllCharacteristics
    buf.write(struct.pack("<I", 0x100000))              # SizeOfStackReserve
    buf.write(struct.pack("<I", 0x1000))                # SizeOfStackCommit
    buf.write(struct.pack("<I", 0x100000))              # SizeOfHeapReserve
    buf.write(struct.pack("<I", 0x1000))                # SizeOfHeapCommit
    buf.write(struct.pack("<I", 0))                     # LoaderFlags
    buf.write(struct.pack("<I", 16))                    # NumberOfRvaAndSizes
    # 16 data directories (8 bytes each = 128 bytes).
    for i in range(16):
        if i == 1:  # IMAGE_DIRECTORY_ENTRY_IMPORT
            buf.write(struct.pack("<II", imports_rva, imports_size))
        else:
            buf.write(struct.pack("<II", 0, 0))


def _write_section_headers(buf: BytesIO) -> None:
    """Write the 3 section headers."""
    # .text
    buf.write(_encode_section_name(".text"))
    buf.write(struct.pack("<I", _TEXT_SIZE))             # VirtualSize
    buf.write(struct.pack("<I", _TEXT_VA))               # VirtualAddress
    buf.write(struct.pack("<I", _TEXT_SIZE))             # SizeOfRawData
    buf.write(struct.pack("<I", _TEXT_RAW))              # PointerToRawData
    buf.write(struct.pack("<I", 0))                      # PointerToRelocations
    buf.write(struct.pack("<I", 0))                      # PointerToLinenumbers
    buf.write(struct.pack("<H", 0))                      # NumberOfRelocations
    buf.write(struct.pack("<H", 0))                      # NumberOfLinenumbers
    buf.write(struct.pack("<I", 0x60000020))             # Characteristics

    # .rdata
    buf.write(_encode_section_name(".rdata"))
    buf.write(struct.pack("<I", _RDATA_SIZE))
    buf.write(struct.pack("<I", _RDATA_VA))
    buf.write(struct.pack("<I", _RDATA_SIZE))
    buf.write(struct.pack("<I", _RDATA_RAW))
    buf.write(struct.pack("<I", 0))
    buf.write(struct.pack("<I", 0))
    buf.write(struct.pack("<H", 0))
    buf.write(struct.pack("<H", 0))
    buf.write(struct.pack("<I", 0x40000040))             # INITIALIZED_DATA | READ

    # .idata
    buf.write(_encode_section_name(".idata"))
    buf.write(struct.pack("<I", _IDATA_SIZE))
    buf.write(struct.pack("<I", _IDATA_VA))
    buf.write(struct.pack("<I", _IDATA_SIZE))
    buf.write(struct.pack("<I", _IDATA_RAW))
    buf.write(struct.pack("<I", 0))
    buf.write(struct.pack("<I", 0))
    buf.write(struct.pack("<H", 0))
    buf.write(struct.pack("<H", 0))
    buf.write(struct.pack("<I", 0x40000040))


def _write_text(buf: BytesIO) -> None:
    """Write .text body — a short INT3 + NOP sled."""
    _pad_to(buf, _TEXT_RAW)
    buf.write(b"\xCC\x90")                              # INT3, NOP at entry
    buf.write(b"\x90" * (_TEXT_SIZE - 2))
    _pad_to(buf, _TEXT_RAW + _TEXT_SIZE)


def _write_rdata(buf: BytesIO, functions: list[FakeFunction]) -> None:
    """Write .rdata body — function table with fixed record layout.

    Each record: (4-byte RVA, 1-byte name length, N-byte ASCII name).
    Parser reads records sequentially until length=0 or EOF.
    """
    _pad_to(buf, _RDATA_RAW)
    for fn in functions:
        name_bytes = fn.name.encode("ascii")
        buf.write(struct.pack("<I", fn.address))
        buf.write(struct.pack("<B", len(name_bytes)))
        buf.write(name_bytes)
    # End-of-table marker (length 0).
    buf.write(struct.pack("<I", 0))
    buf.write(struct.pack("<B", 0))
    _pad_to(buf, _RDATA_RAW + _RDATA_SIZE)


# Layout inside .idata (offsets from IDATA_RAW):
#   0x000  IMAGE_IMPORT_DESCRIPTOR array (20 bytes per DLL + 20-byte terminator)
#   0x080  unused padding to 0x100
#   0x100  IMAGE_IMPORT_BY_NAME blobs (Hint(2) + NUL-terminated name)
#   0x200  IAT thunks (4 bytes per import; hi-bit set for "import by name")
#   0x300  DLL name string pool (concatenated, NUL-terminated)
_IDATA_DESC_OFF = 0x000
_IDATA_NAME_OFF = 0x100
_IDATA_IAT_OFF = 0x200
_IDATA_DLLNAMES_OFF = 0x300


def _write_idata(buf: BytesIO, functions: list[FakeFunction]) -> tuple[int, int]:
    """Write .idata body — returns (imports_rva, imports_size).

    The .idata layout is:
      +0x000  IMAGE_IMPORT_DESCRIPTOR array (20 bytes per DLL + 20-byte terminator)
      +0x100  IMAGE_IMPORT_BY_NAME blobs (Hint(2) + NUL-terminated name)
      +0x200  IAT thunks, grouped per DLL (each group terminated by a 0 thunk)
      +0x300  DLL name string pool

    We write each region at its absolute file offset and track RVAs from there.
    """
    # Group by DLL.
    by_dll: dict[str, list[FakeFunction]] = {}
    for fn in functions:
        by_dll.setdefault(fn.dll, []).append(fn)
    dlls = list(by_dll.keys())

    # ----- Pass 1: name blobs at +0x100 -----
    name_vas: dict[str, int] = {}  # function name → RVA in .idata
    buf.seek(_IDATA_RAW + _IDATA_NAME_OFF)
    for fn in functions:
        if fn.name in name_vas:
            continue
        offset = buf.tell()
        buf.write(struct.pack("<H", fn.hint))
        buf.write(fn.name.encode("ascii") + b"\x00")
        name_vas[fn.name] = _IDATA_VA + (offset - _IDATA_RAW)

    # ----- Pass 2: per-DLL IAT groups at +0x200 -----
    iat_per_dll: dict[str, tuple[int, int]] = {}  # dll → (first_thunk_rva, count)
    buf.seek(_IDATA_RAW + _IDATA_IAT_OFF)
    for dll in dlls:
        first_offset = buf.tell()
        first_va = _IDATA_VA + (first_offset - _IDATA_RAW)
        for fn in by_dll[dll]:
            buf.write(struct.pack("<I", name_vas[fn.name] | 0x80000000))
        # Terminator: 0 thunk.
        buf.write(struct.pack("<I", 0))
        iat_per_dll[dll] = (first_va, len(by_dll[dll]))

    # ----- Pass 3: DLL name string pool at +0x300 -----
    dll_name_vas: dict[str, int] = {}
    buf.seek(_IDATA_RAW + _IDATA_DLLNAMES_OFF)
    for dll in dlls:
        offset = buf.tell()
        buf.write(dll.encode("ascii") + b"\x00")
        dll_name_vas[dll] = _IDATA_VA + (offset - _IDATA_RAW)

    # ----- Pass 4: IMAGE_IMPORT_DESCRIPTOR array at +0x000 -----
    buf.seek(_IDATA_RAW + _IDATA_DESC_OFF)
    for dll in dlls:
        first_va, _count = iat_per_dll[dll]
        buf.write(struct.pack("<I", first_va))           # OriginalFirstThunk
        buf.write(struct.pack("<I", 0))                  # TimeDate
        buf.write(struct.pack("<I", 0))                  # Forwarder
        buf.write(struct.pack("<I", dll_name_vas[dll]))  # Name RVA
        buf.write(struct.pack("<I", first_va))            # FirstThunk

    # Null-terminated descriptor.
    buf.write(b"\x00" * 20)

    buf.seek(_IDATA_RAW + _IDATA_SIZE)
    imports_rva = _IDATA_VA + _IDATA_DESC_OFF
    imports_size = 0x100
    return imports_rva, imports_size


def make_fake_pe(functions: list[FakeFunction] | None = None) -> bytes:
    """Build a minimal fake PE32 binary. See module docstring for layout."""
    if functions is None:
        functions = TARGET_FUNCTIONS

    buf = BytesIO()

    # Headers.
    _write_dos_header(buf)
    _write_pe_signature(buf)
    _write_coff_header(buf, num_sections=3)
    # Patch imports_rva/size after we know them.
    placeholder_rva = _IDATA_VA
    placeholder_size = 0x100
    _write_optional_header(buf, placeholder_rva, placeholder_size)
    _write_section_headers(buf)
    # Pad headers to start of .text (which is the first section body).
    _pad_to(buf, _TEXT_RAW)

    # Section bodies.
    _write_text(buf)
    _write_rdata(buf, functions)
    imports_rva, imports_size = _write_idata(buf, functions)

    # Patch the import data directory in the optional header.
    raw = bytearray(buf.getvalue())
    # PE sig (4 bytes at 0x200) + COFF header (20 bytes) = optional at 0x218.
    opt_off = 0x200 + 4 + 20
    # 96 bytes of fixed Standard Fields, then 16 data directories
    # (8 bytes each). Index 1 (IMPORT) is the second one.
    dd_offset = opt_off + 96 + 1 * 8
    struct.pack_into("<II", raw, dd_offset, imports_rva, imports_size)
    return bytes(raw)

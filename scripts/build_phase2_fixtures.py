"""Build deterministic local-only Phase-2 fixtures."""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

from build_mini_binaries import ROOT, build_x64_pe

sys.path.insert(0, str(ROOT / "src"))
from ai_reverse_agent.fake_pe import make_fake_pe


def _rc4(data: bytes, key: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for index in range(256):
        j = (j + state[index] + key[index % len(key)]) & 0xFF
        state[index], state[j] = state[j], state[index]
    result = bytearray()
    i = j = 0
    for value in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        result.append(value ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(result)


def _pe_with_payload(payload: bytes) -> bytes:
    image = bytearray(build_x64_pe())
    if len(payload) > 0x180:
        raise ValueError("fixture payload is too large")
    image[0x200 : 0x200 + len(payload)] = payload
    return bytes(image)


def build_obfuscation_fixtures() -> None:
    obfuscated = ROOT / "samples" / "obfuscated"
    normal = ROOT / "samples" / "normal"
    obfuscated.mkdir(parents=True, exist_ok=True)
    normal.mkdir(parents=True, exist_ok=True)

    xor_plaintext = b"staged-command.example"
    xor_key = 0x5A
    xor_record = (
        b"XORSTR\x01"
        + bytes([xor_key, len(xor_plaintext)])
        + bytes(value ^ xor_key for value in xor_plaintext)
    )

    rc4_plaintext = b"operator-token-fixture"
    rc4_key = b"phase2"
    rc4_record = (
        b"RC4STR\x01"
        + bytes([len(rc4_key)])
        + len(rc4_plaintext).to_bytes(2, "little")
        + rc4_key
        + _rc4(rc4_plaintext, rc4_key)
    )

    samples = {
        "cff_dispatcher_x64.exe": b"CFFMETA\x01" + bytes.fromhex(
            "83f800740a83f8017405ebf431c0ebf0c3"
        ),
        "opaque_predicate_x64.exe": b"OPAQUEMETA\x01"
        + bytes.fromhex("31c083f8007505b801000000c3"),
        "string_xor_x64.exe": bytes.fromhex("554889e5") + xor_record + b"\xc3",
        "string_rc4_x64.exe": bytes.fromhex("554889e5") + rc4_record + b"\xc3",
        "block_stats_x64.exe": b"BLOCKMETA\x01" + b"\xeb\x00" * 12 + b"\xc3",
    }
    for name, payload in samples.items():
        (obfuscated / name).write_bytes(_pe_with_payload(payload))

    (normal / "normal_x64.exe").write_bytes(
        _pe_with_payload(bytes.fromhex("554889e531c05dc3"))
    )


def build_pe_iat_fixture() -> bytes:
    """Return the existing fake PE with standards-compliant name thunks."""
    image = bytearray(make_fake_pe())
    for index in range(5):
        offset = 0xA00 + index * 8
        thunk = int.from_bytes(image[offset : offset + 4], "little")
        image[offset : offset + 4] = (thunk & 0x7FFFFFFF).to_bytes(4, "little")
    return bytes(image)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def build_elf_iat_fixture() -> bytes:
    """Return a minimal ELF64 image with two undefined dynamic symbols."""
    section_names = b"\0.shstrtab\0.dynstr\0.dynsym\0.rela.plt\0"
    dynamic_strings = b"\0puts\0printf\0"
    dynamic_symbols = b"\0" * 24
    dynamic_symbols += struct.pack("<IBBHQQ", 1, 0x12, 0, 0, 0, 0)
    dynamic_symbols += struct.pack("<IBBHQQ", 6, 0x12, 0, 0, 0, 0)
    relocations = struct.pack("<QQq", 0x601018, (1 << 32) | 7, 0)
    relocations += struct.pack("<QQq", 0x601020, (2 << 32) | 7, 0)

    names_offset = 64
    strings_offset = _align(names_offset + len(section_names), 8)
    symbols_offset = _align(strings_offset + len(dynamic_strings), 8)
    relocations_offset = _align(symbols_offset + len(dynamic_symbols), 8)
    sections_offset = _align(relocations_offset + len(relocations), 8)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + bytes(7)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        3,
        62,
        1,
        0,
        0,
        sections_offset,
        0,
        64,
        0,
        0,
        64,
        5,
        1,
    )
    image = bytearray(header)
    image.extend(b"\0" * (names_offset - len(image)))
    image.extend(section_names)
    image.extend(b"\0" * (strings_offset - len(image)))
    image.extend(dynamic_strings)
    image.extend(b"\0" * (symbols_offset - len(image)))
    image.extend(dynamic_symbols)
    image.extend(b"\0" * (relocations_offset - len(image)))
    image.extend(relocations)
    image.extend(b"\0" * (sections_offset - len(image)))

    section_header = "<IIQQQQIIQQ"
    image.extend(struct.pack(section_header, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    image.extend(
        struct.pack(
            section_header,
            section_names.index(b".shstrtab"),
            3,
            0,
            0,
            names_offset,
            len(section_names),
            0,
            0,
            1,
            0,
        )
    )
    image.extend(
        struct.pack(
            section_header,
            section_names.index(b".dynstr"),
            3,
            0,
            0,
            strings_offset,
            len(dynamic_strings),
            0,
            0,
            1,
            0,
        )
    )
    image.extend(
        struct.pack(
            section_header,
            section_names.index(b".dynsym"),
            11,
            2,
            0,
            symbols_offset,
            len(dynamic_symbols),
            2,
            1,
            8,
            24,
        )
    )
    image.extend(
        struct.pack(
            section_header,
            section_names.index(b".rela.plt"),
            4,
            2,
            0,
            relocations_offset,
            len(relocations),
            3,
            0,
            8,
            24,
        )
    )
    return bytes(image)


def build_iat_fixtures() -> None:
    pe_output = ROOT / "samples" / "pe"
    elf_output = ROOT / "samples" / "elf"
    pe_output.mkdir(parents=True, exist_ok=True)
    elf_output.mkdir(parents=True, exist_ok=True)
    pe_output.joinpath("mini_x64_pe.exe").write_bytes(build_pe_iat_fixture())
    elf_output.joinpath("mini_x64_elf.bin").write_bytes(build_elf_iat_fixture())


def build_imphash_database() -> None:
    known_imports = [
        "kernel32.createfilew",
        "user32.messageboxw",
        "msvcrt.printf",
        "ws2_32.connect",
        "advapi32.regopenkeyexw",
    ]
    known_hash = hashlib.md5(
        ",".join(known_imports).encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()
    samples = [
        {
            "imphash": known_hash,
            "family": "phase2-known-fixture",
            "sample_id": "mini-x64-pe",
            "source": "local-test-fixture",
        }
    ]
    for index in range(1, 1000):
        digest = hashlib.md5(
            f"local-malware-fixture-{index:04d}".encode("ascii"),
            usedforsecurity=False,
        ).hexdigest()
        samples.append(
            {
                "imphash": digest,
                "family": f"fixture-family-{index % 37:02d}",
                "sample_id": f"fixture-{index:04d}",
                "source": "local-generated-fixture",
            }
        )
    output = ROOT / "data" / "malware_imphashes.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "version": "phase2-fixture-2026.07",
                "algorithm": "pe-imphash-v1",
                "provenance": "fixture",
                "samples": samples,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    build_obfuscation_fixtures()
    build_iat_fixtures()
    build_imphash_database()


if __name__ == "__main__":
    main()

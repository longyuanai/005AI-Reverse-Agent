"""Phase-2 Hook B PE/ELF IAT and local imphash database coverage."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from ai_reverse_agent.iat import (
    DATABASE_PATH_ENV,
    DEFAULT_DATABASE,
    ImportedSymbol,
    MalwareImphashDB,
    MalwareImphashDBUnavailable,
    compute_imphash,
    default_database_path,
    extract_elf_imports,
    extract_pe_imports,
    parse_elf_imports,
    parse_pe_imports,
)
from ai_reverse_agent.iat.db import PACKAGE_DATABASE
from ai_reverse_agent.magic import MAX_STATIC_FILE_SIZE, MagicError


ROOT = Path(__file__).resolve().parents[1]
PE_FIXTURE = ROOT / "samples" / "pe" / "mini_x64_pe.exe"
ELF_FIXTURE = ROOT / "samples" / "elf" / "mini_x64_elf.bin"
KNOWN_HASH = "80b4fb3d5cced084a47675fec05e4d48"


def test_pe_iat_extracts_five_named_imports():
    imports = extract_pe_imports(PE_FIXTURE)
    assert [item.name for item in imports] == [
        "CreateFileW",
        "MessageBoxW",
        "printf",
        "connect",
        "RegOpenKeyExW",
    ]


def test_pe_iat_preserves_libraries_hints_and_addresses():
    imports = extract_pe_imports(PE_FIXTURE)
    assert imports[0] == ImportedSymbol(
        library="kernel32.dll",
        name="CreateFileW",
        hint=123,
        address=0x3200,
    )


def test_pe_iat_rejects_bad_magic_gracefully():
    with pytest.raises(MagicError, match="magic"):
        parse_pe_imports(b"not-a-pe")


def test_elf_iat_extracts_undefined_dynamic_symbols():
    imports = extract_elf_imports(ELF_FIXTURE)
    assert [item.canonical_name for item in imports] == ["elf.puts", "elf.printf"]


def test_elf_iat_rejects_truncated_header_gracefully():
    with pytest.raises(MagicError, match="truncated"):
        parse_elf_imports(b"\x7fELF\x02\x01")


def _with_bss_section(data: bytes) -> bytes:
    """Append a `.bss`-style SHT_NOBITS section whose span runs past EOF.

    This is what `.bss` looks like in a real executable: it occupies address
    space but no file space, so `sh_offset + sh_size` legitimately exceeds the
    file size. `/bin/ls` and `/usr/bin/python3` both look like this.
    """
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    entry_size, count, _ = struct.unpack_from("<HHH", data, 58)
    # The section table must stay contiguous for the appended header to count.
    assert section_offset + entry_size * count == len(data)

    bss = bytearray(entry_size)
    struct.pack_into("<I", bss, 0, 0)  # sh_name -> empty string
    struct.pack_into("<I", bss, 4, 8)  # sh_type = SHT_NOBITS
    struct.pack_into("<Q", bss, 24, len(data))  # sh_offset at EOF
    struct.pack_into("<Q", bss, 32, 0x4000)  # sh_size runs well past it

    patched = bytearray(data) + bss
    struct.pack_into("<H", patched, 60, count + 1)  # e_shnum
    return bytes(patched)


def test_elf_iat_accepts_nobits_section_past_end_of_file():
    """Regression: a `.bss`-style section must not fail the whole parse."""
    fixture = _with_bss_section(ELF_FIXTURE.read_bytes())

    imports = parse_elf_imports(fixture)

    assert [item.canonical_name for item in imports] == ["elf.puts", "elf.printf"]


def test_elf_iat_still_rejects_file_backed_section_past_end_of_file():
    data = bytearray(ELF_FIXTURE.read_bytes())
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    entry_size, _, _ = struct.unpack_from("<HHH", data, 58)
    struct.pack_into("<Q", data, section_offset + entry_size + 32, 0x4000)

    with pytest.raises(MagicError, match="exceeds file bounds"):
        parse_elf_imports(bytes(data))


def test_imphash_is_case_and_order_stable():
    left = compute_imphash(
        [("KERNEL32.DLL", "CreateFileW"), ("MSVCRT.DLL", "printf")]
    )
    right = compute_imphash(["msvcrt.dll.printf", "kernel32.dll.createfilew"])
    assert left == right


def test_imphash_matches_known_sorted_imports_md5():
    assert compute_imphash(extract_pe_imports(PE_FIXTURE)) == KNOWN_HASH


def test_imphash_empty_input_is_md5_of_empty_string():
    assert compute_imphash([]) == "d41d8cd98f00b204e9800998ecf8427e"


def test_local_database_contains_at_least_one_thousand_samples():
    payload = json.loads(DEFAULT_DATABASE.read_text(encoding="utf-8"))
    assert payload["algorithm"] == "sorted-imports-md5"
    assert len(payload["samples"]) >= 1000
    assert len(MalwareImphashDB.from_file()) >= 1000


def test_local_database_matches_known_pe_fixture():
    match = MalwareImphashDB.from_file().lookup(KNOWN_HASH)
    assert match is not None
    assert match.family == "phase2-known-fixture"
    assert match.sample_id == "mini-x64-pe"


def test_local_database_returns_none_for_unknown_hash():
    assert MalwareImphashDB.from_file().lookup("0" * 32) is None


def test_default_database_ships_inside_the_installed_package():
    """Regression: the fixture DB must live in the wheel, not the repo root."""
    assert PACKAGE_DATABASE.is_file()
    assert DEFAULT_DATABASE == PACKAGE_DATABASE
    assert PACKAGE_DATABASE.parent.parent.name == "ai_reverse_agent"


def test_database_path_honours_the_environment_override(monkeypatch, tmp_path: Path):
    override = tmp_path / "custom.json"
    monkeypatch.setenv(DATABASE_PATH_ENV, str(override))

    assert default_database_path() == override


def test_missing_database_raises_a_typed_error(tmp_path: Path):
    missing = tmp_path / "absent.json"

    with pytest.raises(MalwareImphashDBUnavailable, match="unavailable"):
        MalwareImphashDB.from_file(missing)


def test_iat_parser_refuses_file_over_one_hundred_mib(tmp_path: Path):
    oversized = tmp_path / "oversized.exe"
    with oversized.open("wb") as stream:
        stream.write(b"MZ")
        stream.seek(MAX_STATIC_FILE_SIZE)
        stream.write(b"\0")
    with pytest.raises(MagicError, match="exceeds 100 MiB"):
        extract_pe_imports(oversized)

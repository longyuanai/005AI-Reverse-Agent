"""Phase-2 Hook B PE/ELF IAT and local imphash database coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_reverse_agent.iat import (
    DEFAULT_DATABASE,
    ImportedSymbol,
    MalwareImphashDB,
    compute_imphash,
    extract_elf_imports,
    extract_pe_imports,
    parse_elf_imports,
    parse_pe_imports,
)
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


def test_iat_parser_refuses_file_over_one_hundred_mib(tmp_path: Path):
    oversized = tmp_path / "oversized.exe"
    with oversized.open("wb") as stream:
        stream.write(b"MZ")
        stream.seek(MAX_STATIC_FILE_SIZE)
        stream.write(b"\0")
    with pytest.raises(MagicError, match="exceeds 100 MiB"):
        extract_pe_imports(oversized)

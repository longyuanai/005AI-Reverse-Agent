"""ADR-002 dual-hash semantics and database provenance."""

from __future__ import annotations

from pathlib import Path

import pefile

from ai_reverse_agent.backends import BinaryLoader
from ai_reverse_agent.hashing import (
    compute_import_set_hash,
    compute_pe_imphash,
    normalize_pe_import,
)
from ai_reverse_agent.iat import ImportedSymbol, MalwareImphashDB, compute_imphash

ROOT = Path(__file__).resolve().parents[1]
PE = ROOT / "samples" / "pe" / "mini_x64_pe.exe"


def test_pe_imphash_is_order_sensitive():
    imports = [("a.dll", "One"), ("b.dll", "Two")]
    assert compute_pe_imphash(imports) != compute_pe_imphash(reversed(imports))


def test_import_set_hash_is_order_independent():
    imports = [("a.dll", "One"), ("b.dll", "Two")]
    assert compute_import_set_hash(imports) == compute_import_set_hash(
        reversed(imports)
    )


def test_pe_normalization_strips_industry_extensions():
    assert normalize_pe_import(("KERNEL32.DLL", "CreateFileW")) == (
        "kernel32.createfilew"
    )
    assert normalize_pe_import(("driver.SYS", "Entry")) == "driver.entry"
    assert normalize_pe_import(("control.OCX", "Load")) == "control.load"


def test_pe_imphash_is_case_insensitive():
    assert compute_pe_imphash([("A.DLL", "Func")]) == compute_pe_imphash(
        [("a.dll", "func")]
    )


def test_pe_imphash_matches_pefile_golden():
    image = BinaryLoader().load(PE)
    assert compute_pe_imphash(image.imports) == pefile.PE(str(PE)).get_imphash()


def test_legacy_compute_imphash_aliases_import_set_hash():
    imports = [("z.dll", "Last"), ("a.dll", "First")]
    assert compute_imphash(imports) == compute_import_set_hash(imports)


def test_empty_dual_hashes_are_md5_empty():
    empty = "d41d8cd98f00b204e9800998ecf8427e"
    assert compute_pe_imphash(()) == empty
    assert compute_import_set_hash(()) == empty


def test_fixture_database_record_is_not_trusted():
    match = MalwareImphashDB.from_file().lookup(
        "c1f0cda7bd39190d4154ba8e2d3b3480"
    )
    assert match is not None
    assert match.provenance == "local-test-fixture"
    assert match.trusted is False


def test_curated_standard_record_is_trusted():
    db = MalwareImphashDB(
        [
            {
                "imphash": "1" * 32,
                "family": "verified",
                "sample_id": "sample",
                "provenance": "curated",
            }
        ],
        version="2026.07",
    )
    match = db.lookup("1" * 32)
    assert match is not None
    assert match.trusted
    assert match.database_version == "2026.07"


def test_database_separates_hash_algorithms():
    db = MalwareImphashDB(
        [
            {
                "imphash": "2" * 32,
                "algorithm": "import-set-md5-v1",
                "provenance": "curated",
            }
        ]
    )
    assert db.lookup("2" * 32) is None
    assert db.lookup("2" * 32, algorithm="import-set-md5-v1") is not None


def test_imported_symbol_preserves_delay_and_ordinal_metadata():
    symbol = ImportedSymbol(
        "kernel32.dll",
        "ordinal_5",
        ordinal=5,
        delayed=True,
    )
    assert symbol.ordinal == 5
    assert symbol.delayed is True

"""ADR-002 mature backend and fallback coverage."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from ai_reverse_agent.backends import (
    BinaryImage,
    BinaryLoader,
    ElfToolsBackend,
    MinimalFixtureBackend,
    PeFileBackend,
    RawBackend,
)
from ai_reverse_agent.iat import parse_elf_imports, parse_pe_imports
from ai_reverse_agent.magic import MAX_STATIC_FILE_SIZE, MagicError

ROOT = Path(__file__).resolve().parents[1]
PE = ROOT / "samples" / "pe" / "mini_x64_pe.exe"
ELF = ROOT / "samples" / "elf" / "mini_x64_elf.bin"


def test_binary_loader_selects_pefile_backend():
    image = BinaryLoader().load(PE)
    assert image.container == "pe"
    assert image.backend == "pefile"


def test_pefile_and_minimal_backends_agree_on_named_imports():
    image = BinaryLoader().load(PE)
    minimal = parse_pe_imports(PE.read_bytes())
    assert [(item.library, item.name) for item in image.imports] == [
        (item.library, item.name) for item in minimal
    ]


def test_binary_loader_selects_pyelftools_backend():
    image = BinaryLoader().load(ELF)
    assert image.container == "elf"
    assert image.backend == "pyelftools"


def test_pyelftools_and_minimal_backends_agree_on_symbols():
    image = BinaryLoader().load(ELF)
    minimal = parse_elf_imports(ELF.read_bytes())
    assert [item.name for item in image.imports] == [item.name for item in minimal]


def test_elf_backend_maps_plt_relocation_addresses():
    image = BinaryLoader().load(ELF)
    assert [item.address for item in image.imports] == [0x601018, 0x601020]
    assert image.metadata["relocation_count"] == 2


def test_raw_backend_accepts_unrecognized_bytes(tmp_path: Path):
    sample = tmp_path / "raw.bin"
    sample.write_bytes(b"\x90\xc3")
    image = BinaryLoader().load(sample)
    assert image == BinaryImage(sample.resolve(), b"\x90\xc3", "raw", "raw")


def test_minimal_backend_rejects_raw_bytes():
    with pytest.raises(MagicError, match="only PE and ELF"):
        MinimalFixtureBackend().load(Path("raw.bin"), b"raw")


def test_loader_rejects_corrupt_pe_even_with_fallback(tmp_path: Path):
    sample = tmp_path / "broken.exe"
    sample.write_bytes(b"MZ" + b"\0" * 62)
    with pytest.raises(MagicError):
        BinaryLoader().load(sample)


def test_loader_checks_size_before_backend_parse(tmp_path: Path):
    sample = tmp_path / "oversized.bin"
    with sample.open("wb") as stream:
        stream.seek(MAX_STATIC_FILE_SIZE)
        stream.write(b"\0")
    with pytest.raises(MagicError, match="exceeds 100 MiB"):
        BinaryLoader().load(sample)


def test_pe_backend_records_pefile_golden_hash():
    image = BinaryLoader().load(PE)
    assert image.metadata["pefile_imphash"] == "c1f0cda7bd39190d4154ba8e2d3b3480"


def test_custom_backend_can_be_injected(tmp_path: Path):
    sample = tmp_path / "custom.bin"
    sample.write_bytes(b"CUSTOM")

    class CustomBackend:
        name = "custom"

        def supports(self, data: bytes) -> bool:
            return data.startswith(b"CUSTOM")

        def load(self, path: Path, data: bytes) -> BinaryImage:
            return BinaryImage(path, data, "custom", self.name)

    assert BinaryLoader((CustomBackend(),)).load(sample).backend == "custom"


def test_pe_backend_handles_delay_ordinal_import(monkeypatch: pytest.MonkeyPatch):
    entry = SimpleNamespace(
        name=None,
        ordinal=7,
        hint=None,
        address=0x401000,
    )
    descriptor = SimpleNamespace(dll=b"USER32.dll", imports=[entry])

    class FakePE:
        FILE_HEADER = SimpleNamespace(Machine=0x8664)
        OPTIONAL_HEADER = SimpleNamespace(ImageBase=0x400000)
        DIRECTORY_ENTRY_IMPORT = ()
        DIRECTORY_ENTRY_DELAY_IMPORT = (descriptor,)

        def parse_data_directories(self, directories: list[int]) -> None:
            assert len(directories) == 2

        def get_imphash(self) -> str:
            return "0" * 32

    monkeypatch.setattr(
        "ai_reverse_agent.backends.pefile_backend.pefile.PE",
        lambda **_: FakePE(),
    )
    image = PeFileBackend().load(Path("delay.exe"), b"MZ")
    assert image.imports[0].name == "ordinal_7"
    assert image.imports[0].ordinal == 7
    assert image.imports[0].delayed is True
    assert image.metadata["delay_import_count"] == 1


def test_backend_support_predicates_are_format_specific():
    assert PeFileBackend().supports(b"MZ...")
    assert ElfToolsBackend().supports(b"\x7fELF...")
    assert RawBackend().supports(b"anything")

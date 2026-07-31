"""PE/ELF static import extraction and local imphash matching."""

from .db import DEFAULT_DATABASE, MalwareImphashDB, MalwareImphashMatch
from .elf_iat import extract_elf_imports, parse_elf_imports
from .imphash import ImportedSymbol, compute_imphash, normalize_import
from .pe_iat import extract_pe_imports, parse_pe_imports
from ai_reverse_agent.hashing import compute_import_set_hash, compute_pe_imphash

__all__ = [
    "DEFAULT_DATABASE",
    "ImportedSymbol",
    "MalwareImphashDB",
    "MalwareImphashMatch",
    "compute_imphash",
    "compute_import_set_hash",
    "compute_pe_imphash",
    "extract_elf_imports",
    "extract_pe_imports",
    "normalize_import",
    "parse_elf_imports",
    "parse_pe_imports",
]

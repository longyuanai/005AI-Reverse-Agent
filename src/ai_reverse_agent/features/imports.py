"""Import features detached from concrete parser implementations."""

from __future__ import annotations

from ai_reverse_agent.hashing import compute_import_set_hash, compute_pe_imphash
from ai_reverse_agent.iat import ImportedSymbol


def import_features(
    imports: tuple[ImportedSymbol, ...],
    *,
    container: str,
) -> dict[str, object]:
    result: dict[str, object] = {
        "imports": imports,
        "import_count": len(imports),
        "import_set_hash": compute_import_set_hash(imports),
    }
    if container == "pe":
        result["pe_imphash"] = compute_pe_imphash(imports)
    return result

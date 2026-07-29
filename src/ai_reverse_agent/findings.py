"""Reverse-product Finding builders for Phase-2 enrichment."""

from __future__ import annotations

from collections.abc import Iterable

from shared_llm_core.finding import Finding, FindingSeverity, FindingSource

from ai_reverse_agent.iat import (
    ImportedSymbol,
    MalwareImphashDB,
)
from ai_reverse_agent.hashing import compute_pe_imphash


def imphash_finding(
    imports: Iterable[ImportedSymbol],
    *,
    host: str | None = None,
    database: MalwareImphashDB | None = None,
) -> Finding | None:
    """Return HIGH only for an exact, curated standard PE imphash match."""
    imported = tuple(imports)
    digest = compute_pe_imphash(imported)
    db = database or MalwareImphashDB.from_file()
    match = db.lookup(digest, algorithm="pe-imphash-v1")
    if match is None or not match.trusted:
        return None
    return Finding(
        id="",
        source=FindingSource.REVERSE,
        severity=FindingSeverity.HIGH,
        confidence=0.98,
        title=f"imphash matched known malware {match.family}",
        description=(
            "The binary's standard PE imphash exactly matches a curated "
            "local malware record."
        ),
        host=host,
        evidence=(
            f"pe_imphash={digest}",
            f"import_count={len(imported)}",
            f"sample_id={match.sample_id}",
        ),
        tags=frozenset({"imphash", "known-malware", "static-analysis"}),
        metadata={
            "pe_imphash": digest,
            "algorithm": match.algorithm,
            "family": match.family,
            "sample_id": match.sample_id,
            "database_version": match.database_version,
            "provenance": match.provenance,
        },
    )

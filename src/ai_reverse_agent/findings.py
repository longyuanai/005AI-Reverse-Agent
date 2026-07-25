"""Reverse-product Finding builders for Phase-2 enrichment."""

from __future__ import annotations

from collections.abc import Iterable

from shared_llm_core.finding import Finding, FindingSeverity, FindingSource

from ai_reverse_agent.iat import (
    ImportedSymbol,
    MalwareImphashDB,
    compute_imphash,
)


def imphash_finding(
    imports: Iterable[ImportedSymbol],
    *,
    host: str | None = None,
    database: MalwareImphashDB | None = None,
) -> Finding | None:
    """Return a HIGH Finding when sorted-import MD5 matches the local DB."""
    imported = tuple(imports)
    digest = compute_imphash(imported)
    db = database or MalwareImphashDB.from_file()
    match = db.lookup(digest)
    if match is None:
        return None
    return Finding(
        id="",
        source=FindingSource.REVERSE,
        severity=FindingSeverity.HIGH,
        confidence=0.98,
        title=f"imphash matched known malware {match.family}",
        description=(
            "The binary's normalized import set matches a checked-in local "
            "malware imphash fixture."
        ),
        host=host,
        evidence=(
            f"imphash={digest}",
            f"import_count={len(imported)}",
            f"sample_id={match.sample_id}",
        ),
        tags=frozenset({"imphash", "known-malware", "static-analysis"}),
        metadata={
            "imphash": digest,
            "family": match.family,
            "sample_id": match.sample_id,
            "database": "local-fixture",
        },
    )

"""Local-only malware imphash fixture database."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_MD5_RE = re.compile(r"^[0-9a-f]{32}$")

#: Environment variable pointing at an alternative fixture database.
DATABASE_PATH_ENV = "AI_REVERSE_IMPHASH_DB"

#: Shipped inside the wheel, so an installed package can always find it.
PACKAGE_DATABASE = (
    Path(__file__).resolve().parent.parent / "data" / "malware_imphashes.json"
)

#: Pre-0.2 location, kept working for source checkouts that still hold it.
LEGACY_DATABASE = (
    Path(__file__).resolve().parents[3] / "data" / "malware_imphashes.json"
)


class MalwareImphashDBUnavailable(FileNotFoundError):
    """Raised when no local imphash fixture database can be located."""


def default_database_path() -> Path:
    """Resolve the database location at call time, not at import time.

    Checked in order: ``$AI_REVERSE_IMPHASH_DB``, the copy shipped in the
    package, then the pre-0.2 repository-root path.
    """
    override = os.environ.get(DATABASE_PATH_ENV)
    if override:
        return Path(override).expanduser()
    if PACKAGE_DATABASE.is_file():
        return PACKAGE_DATABASE
    return LEGACY_DATABASE


DEFAULT_DATABASE = default_database_path()


@dataclass(frozen=True)
class MalwareImphashMatch:
    imphash: str
    family: str
    sample_id: str
    metadata: dict[str, Any]


class MalwareImphashDB:
    """Immutable lookup over the checked-in fixture JSON."""

    def __init__(self, samples: list[dict[str, Any]]) -> None:
        records: dict[str, MalwareImphashMatch] = {}
        for sample in samples:
            digest = str(sample.get("imphash", "")).strip().lower()
            if not _MD5_RE.fullmatch(digest):
                raise ValueError(f"invalid imphash in local database: {digest!r}")
            metadata = {
                key: value
                for key, value in sample.items()
                if key not in {"imphash", "family", "sample_id"}
            }
            records[digest] = MalwareImphashMatch(
                imphash=digest,
                family=str(sample.get("family", "unknown")),
                sample_id=str(sample.get("sample_id", digest)),
                metadata=metadata,
            )
        self._records = records

    @classmethod
    def from_file(cls, path: str | Path | None = None) -> "MalwareImphashDB":
        """Load the fixture database, resolving the default path lazily."""
        resolved = Path(path) if path is not None else default_database_path()
        try:
            raw = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            raise MalwareImphashDBUnavailable(
                f"malware imphash database is unavailable at {resolved}: {exc}"
            ) from exc
        payload = json.loads(raw)
        samples = payload.get("samples", ())
        if not isinstance(samples, list):
            raise ValueError("malware imphash database must contain a samples list")
        return cls(samples)

    def lookup(self, imphash: str) -> MalwareImphashMatch | None:
        return self._records.get(imphash.strip().lower())

    def __len__(self) -> int:
        return len(self._records)

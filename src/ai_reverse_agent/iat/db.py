"""Local-only malware imphash fixture database."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_MD5_RE = re.compile(r"^[0-9a-f]{32}$")
DEFAULT_DATABASE = Path(__file__).resolve().parents[3] / "data" / "malware_imphashes.json"


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
    def from_file(cls, path: str | Path = DEFAULT_DATABASE) -> "MalwareImphashDB":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        samples = payload.get("samples", ())
        if not isinstance(samples, list):
            raise ValueError("malware imphash database must contain a samples list")
        return cls(samples)

    def lookup(self, imphash: str) -> MalwareImphashMatch | None:
        return self._records.get(imphash.strip().lower())

    def __len__(self) -> int:
        return len(self._records)

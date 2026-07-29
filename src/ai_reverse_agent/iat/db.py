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
    digest: str
    algorithm: str
    family: str
    sample_id: str
    database_version: str
    provenance: str
    metadata: dict[str, Any]

    @property
    def imphash(self) -> str:
        """Backward-compatible digest alias."""
        return self.digest

    @property
    def trusted(self) -> bool:
        """Only curated, standard PE hashes may drive a HIGH Finding."""
        return (
            self.algorithm == "pe-imphash-v1"
            and self.provenance in {"curated", "vendor-curated", "analyst-verified"}
        )


class MalwareImphashDB:
    """Immutable lookup over the checked-in fixture JSON."""

    def __init__(
        self,
        samples: list[dict[str, Any]],
        *,
        algorithm: str = "pe-imphash-v1",
        version: str = "adhoc",
        provenance: str = "unknown",
    ) -> None:
        records: dict[tuple[str, str], MalwareImphashMatch] = {}
        for sample in samples:
            sample_algorithm = str(sample.get("algorithm", algorithm)).strip().lower()
            digest = str(
                sample.get("digest", sample.get("imphash", ""))
            ).strip().lower()
            if not _MD5_RE.fullmatch(digest):
                raise ValueError(f"invalid imphash in local database: {digest!r}")
            sample_provenance = str(
                sample.get("provenance", sample.get("source", provenance))
            ).strip().lower()
            metadata = {
                key: value
                for key, value in sample.items()
                if key
                not in {
                    "algorithm",
                    "digest",
                    "imphash",
                    "family",
                    "sample_id",
                    "provenance",
                }
            }
            records[(sample_algorithm, digest)] = MalwareImphashMatch(
                digest=digest,
                algorithm=sample_algorithm,
                family=str(sample.get("family", "unknown")),
                sample_id=str(sample.get("sample_id", digest)),
                database_version=version,
                provenance=sample_provenance,
                metadata=metadata,
            )
        self._records = records
        self.version = version
        self.provenance = provenance

    @classmethod
    def from_file(cls, path: str | Path = DEFAULT_DATABASE) -> "MalwareImphashDB":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        samples = payload.get("samples", ())
        if not isinstance(samples, list):
            raise ValueError("malware imphash database must contain a samples list")
        return cls(
            samples,
            algorithm=str(payload.get("algorithm", "pe-imphash-v1")),
            version=str(payload.get("version", payload.get("schema_version", "unknown"))),
            provenance=str(payload.get("provenance", "unknown")),
        )

    def lookup(
        self,
        imphash: str,
        *,
        algorithm: str = "pe-imphash-v1",
    ) -> MalwareImphashMatch | None:
        return self._records.get((algorithm.strip().lower(), imphash.strip().lower()))

    def __len__(self) -> int:
        return len(self._records)

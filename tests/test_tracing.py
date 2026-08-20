from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from ai_reverse_agent import scan


def test_scan_entrypoint_creates_span(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str, dict[str, object]]] = []

    @contextmanager
    def recording_span(
        name: str,
        *,
        attributes: dict[str, object],
    ) -> Iterator[None]:
        captured.append((name, attributes))
        yield

    expected = {"findings": [], "errors": []}
    monkeypatch.setattr(scan, "span", recording_span)
    monkeypatch.setattr(scan, "_scan_binary", lambda _payload, **_kwargs: expected)

    assert scan.scan_binary({"binary_path": "C:/private/sample.bin"}) is expected
    assert captured == [
        (
            "product.scan",
            {"product.id": "005", "scan.target_type": "binary_file"},
        )
    ]

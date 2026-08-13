from __future__ import annotations

import re
from pathlib import Path

import pytest
from shared_llm_core.evaluation import EvalCase, run_eval

FIXTURES = Path(__file__).resolve().parents[1] / "evals" / "fixtures"

_CASE_ROWS = (
    ("reverse-known-open", {"symbol": "SyntheticOpen", "sample": "known"}),
    ("reverse-known-read", {"symbol": "SyntheticRead", "sample": "known"}),
    ("reverse-unknown-function", {"symbol": "sub_synthetic_unknown", "sample": "unknown"}),
    ("reverse-packed-entry", {"symbol": "SyntheticPackedEntry", "sample": "packed"}),
    ("reverse-empty-imports", {"imports": [], "sample": "empty"}),
    ("reverse-known-cleanup", {"symbol": "SyntheticClose", "sample": "known"}),
)


def _cases() -> list[EvalCase]:
    return [
        EvalCase(
            id=case_id,
            inputs=inputs,
            expected={
                "required_fields": ["name", "purpose"],
            },
        )
        for case_id, inputs in _CASE_ROWS
    ]


def test_golden_set_passes_in_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHARED_LLM_EVAL_MODE", "replay")
    monkeypatch.setenv("SHARED_LLM_EVAL_FIXTURES", str(FIXTURES))
    results = run_eval(_cases())
    assert all(result.passed for result in results), results


def test_golden_set_has_expected_case_count() -> None:
    cases = _cases()
    assert len(cases) >= 6
    assert len({case.id for case in cases}) == len(cases)
    assert {path.stem for path in FIXTURES.glob("*.json")} == {case.id for case in cases}


def test_fixtures_contain_no_real_identifiers() -> None:
    combined = "\n".join(path.read_text(encoding="utf-8") for path in FIXTURES.glob("*.json"))
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", combined)
    assert not re.search(r"(?i)(?:api[_-]?key|password|secret|token)\s*[:=]", combined)
    assert not re.search(r"(?i)(?:[a-z]:\\|/(?:home|users|workspace|repo)/)", combined)
    assert "customer" not in combined.lower()

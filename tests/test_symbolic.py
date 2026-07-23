"""Tests for the lightweight symbolic branch solver."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from ai_reverse_agent.cli import cli
from ai_reverse_agent.symbolic import (
    SymbolicBackendUnavailable,
    SymbolicError,
    loop_value,
    solve_branch,
    symbolic_input,
)


def test_solves_simple_arithmetic_branch():
    user_input = symbolic_input("input", 0, 20)
    solution = solve_branch((user_input * 3 + 1).equals(22), backend="mini")
    assert solution.satisfiable is True
    assert solution.inputs == {"input": 7}


def test_solves_multiple_if_constraints():
    user_input = symbolic_input("input", 0, 20)
    solution = solve_branch(
        [user_input > 10, user_input < 13],
        backend="mini",
    )
    assert solution.inputs == {"input": 11}


def test_reports_unsatisfiable_branch():
    user_input = symbolic_input("input", 0, 10)
    solution = solve_branch(
        [user_input < 2, user_input > 8],
        backend="mini",
    )
    assert solution.satisfiable is False
    assert solution.inputs == {}


def test_models_fixed_count_loop_constraint():
    user_input = symbolic_input("input", 0, 20)
    after_loop = loop_value(user_input, step=2, iterations=4)
    solution = solve_branch(after_loop.equals(15), backend="mini")
    assert solution.inputs == {"input": 7}


def test_can_solve_opposite_branch_with_negation():
    user_input = symbolic_input("input", 0, 3)
    solution = solve_branch(user_input.equals(0).negate(), backend="mini")
    assert solution.inputs == {"input": 1}


def test_rejects_candidate_space_over_limit():
    left = symbolic_input("left", 0, 100)
    right = symbolic_input("right", 0, 100)
    with pytest.raises(SymbolicError, match="exceeds limit"):
        solve_branch((left + right).equals(50), max_candidates=100)


def test_explicit_z3_backend_reports_missing_optional_dependency(monkeypatch):
    monkeypatch.setattr("ai_reverse_agent.symbolic.importlib.util.find_spec", lambda _name: None)
    with pytest.raises(SymbolicBackendUnavailable, match="not installed"):
        solve_branch(symbolic_input("input").equals(7), backend="z3")


def test_cli_outputs_branch_triggering_input():
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "solve-branch",
            "--variable",
            "input",
            "--max-value",
            "20",
            "--multiplier",
            "3",
            "--offset",
            "1",
            "--target",
            "22",
            "--backend",
            "mini",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "input=7 backend=mini" in result.output

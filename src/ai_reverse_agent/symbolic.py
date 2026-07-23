"""Lightweight symbolic integer constraints with an optional Z3 backend."""

from __future__ import annotations

import importlib.util
import itertools
from dataclasses import dataclass
from typing import Mapping


class SymbolicError(ValueError):
    """Base error for invalid symbolic expressions or solve requests."""


class SymbolicBackendUnavailable(SymbolicError):
    """Raised when an explicitly requested solver backend is unavailable."""


class Expression:
    """Base class for integer expressions."""

    def evaluate(self, values: Mapping[str, int]) -> int:
        raise NotImplementedError

    def symbols(self) -> tuple["Symbol", ...]:
        raise NotImplementedError

    def __add__(self, other: int | "Expression") -> "BinaryExpression":
        return BinaryExpression("add", self, _coerce_expression(other))

    def __radd__(self, other: int | "Expression") -> "BinaryExpression":
        return _coerce_expression(other) + self

    def __sub__(self, other: int | "Expression") -> "BinaryExpression":
        return BinaryExpression("sub", self, _coerce_expression(other))

    def __rsub__(self, other: int | "Expression") -> "BinaryExpression":
        return _coerce_expression(other) - self

    def __mul__(self, other: int | "Expression") -> "BinaryExpression":
        return BinaryExpression("mul", self, _coerce_expression(other))

    def __rmul__(self, other: int | "Expression") -> "BinaryExpression":
        return _coerce_expression(other) * self

    def __floordiv__(self, other: int | "Expression") -> "BinaryExpression":
        return BinaryExpression("floordiv", self, _coerce_expression(other))

    def __mod__(self, other: int | "Expression") -> "BinaryExpression":
        return BinaryExpression("mod", self, _coerce_expression(other))

    def equals(self, other: int | "Expression") -> "Constraint":
        return Constraint("eq", self, _coerce_expression(other))

    def not_equals(self, other: int | "Expression") -> "Constraint":
        return Constraint("ne", self, _coerce_expression(other))

    def __lt__(self, other: int | "Expression") -> "Constraint":
        return Constraint("lt", self, _coerce_expression(other))

    def __le__(self, other: int | "Expression") -> "Constraint":
        return Constraint("le", self, _coerce_expression(other))

    def __gt__(self, other: int | "Expression") -> "Constraint":
        return Constraint("gt", self, _coerce_expression(other))

    def __ge__(self, other: int | "Expression") -> "Constraint":
        return Constraint("ge", self, _coerce_expression(other))


@dataclass(frozen=True)
class Constant(Expression):
    value: int

    def evaluate(self, values: Mapping[str, int]) -> int:
        return self.value

    def symbols(self) -> tuple["Symbol", ...]:
        return ()


@dataclass(frozen=True)
class Symbol(Expression):
    """A bounded symbolic integer input."""

    name: str
    minimum: int = 0
    maximum: int = 255

    def __post_init__(self) -> None:
        if not self.name or not self.name.isidentifier():
            raise SymbolicError(f"invalid symbolic input name: {self.name!r}")
        if self.minimum > self.maximum:
            raise SymbolicError("symbol minimum must not exceed maximum")

    def evaluate(self, values: Mapping[str, int]) -> int:
        try:
            value = values[self.name]
        except KeyError as exc:
            raise SymbolicError(f"missing value for symbolic input {self.name!r}") from exc
        if not self.minimum <= value <= self.maximum:
            raise SymbolicError(
                f"value {value} for {self.name!r} is outside "
                f"[{self.minimum}, {self.maximum}]"
            )
        return value

    def symbols(self) -> tuple["Symbol", ...]:
        return (self,)


@dataclass(frozen=True)
class BinaryExpression(Expression):
    operator: str
    left: Expression
    right: Expression

    def evaluate(self, values: Mapping[str, int]) -> int:
        left = self.left.evaluate(values)
        right = self.right.evaluate(values)
        if self.operator == "add":
            return left + right
        if self.operator == "sub":
            return left - right
        if self.operator == "mul":
            return left * right
        if self.operator == "floordiv":
            if right == 0:
                raise ZeroDivisionError
            return left // right
        if self.operator == "mod":
            if right == 0:
                raise ZeroDivisionError
            return left % right
        raise SymbolicError(f"unsupported arithmetic operator: {self.operator}")

    def symbols(self) -> tuple[Symbol, ...]:
        return _merge_symbols(self.left.symbols(), self.right.symbols())


@dataclass(frozen=True)
class Constraint:
    """A boolean comparison between two integer expressions."""

    operator: str
    left: Expression
    right: Expression

    def evaluate(self, values: Mapping[str, int]) -> bool:
        left = self.left.evaluate(values)
        right = self.right.evaluate(values)
        if self.operator == "eq":
            return left == right
        if self.operator == "ne":
            return left != right
        if self.operator == "lt":
            return left < right
        if self.operator == "le":
            return left <= right
        if self.operator == "gt":
            return left > right
        if self.operator == "ge":
            return left >= right
        raise SymbolicError(f"unsupported comparison operator: {self.operator}")

    def symbols(self) -> tuple[Symbol, ...]:
        return _merge_symbols(self.left.symbols(), self.right.symbols())

    def negate(self) -> "Constraint":
        inverse = {
            "eq": "ne",
            "ne": "eq",
            "lt": "ge",
            "le": "gt",
            "gt": "le",
            "ge": "lt",
        }
        try:
            operator = inverse[self.operator]
        except KeyError as exc:
            raise SymbolicError(
                f"unsupported comparison operator: {self.operator}"
            ) from exc
        return Constraint(operator, self.left, self.right)


@dataclass(frozen=True)
class SymbolicSolution:
    """A concrete input assignment that satisfies a branch."""

    satisfiable: bool
    inputs: Mapping[str, int]
    backend: str
    candidates_evaluated: int


def symbolic_input(name: str, minimum: int = 0, maximum: int = 255) -> Symbol:
    """Create a bounded symbolic integer."""
    return Symbol(name=name, minimum=minimum, maximum=maximum)


def loop_value(
    initial: int | Expression,
    *,
    step: int | Expression,
    iterations: int,
) -> Expression:
    """Model a simple fixed-count loop as ``initial + step * iterations``."""
    if iterations < 0:
        raise SymbolicError("loop iterations must be non-negative")
    return _coerce_expression(initial) + _coerce_expression(step) * iterations


def solve_branch(
    constraints: Constraint | tuple[Constraint, ...] | list[Constraint],
    *,
    backend: str = "auto",
    max_candidates: int = 100_000,
) -> SymbolicSolution:
    """Return an input assignment that makes every constraint true."""
    normalized = (
        (constraints,)
        if isinstance(constraints, Constraint)
        else tuple(constraints)
    )
    if not normalized:
        raise SymbolicError("at least one branch constraint is required")
    if max_candidates < 1:
        raise SymbolicError("max_candidates must be at least 1")
    if backend not in {"auto", "mini", "z3"}:
        raise SymbolicError("backend must be one of: auto, mini, z3")

    z3_available = importlib.util.find_spec("z3") is not None
    selected = "z3" if backend == "z3" or backend == "auto" and z3_available else "mini"
    if selected == "z3" and not z3_available:
        raise SymbolicBackendUnavailable(
            "z3 backend requested but z3-solver is not installed"
        )
    if selected == "z3":
        return _solve_with_z3(normalized)
    return _solve_with_mini(normalized, max_candidates=max_candidates)


def _solve_with_mini(
    constraints: tuple[Constraint, ...],
    *,
    max_candidates: int,
) -> SymbolicSolution:
    symbols = _constraint_symbols(constraints)
    candidate_count = 1
    for symbol in symbols:
        candidate_count *= symbol.maximum - symbol.minimum + 1
        if candidate_count > max_candidates:
            raise SymbolicError(
                f"candidate space {candidate_count} exceeds limit {max_candidates}"
            )

    domains = [
        range(symbol.minimum, symbol.maximum + 1)
        for symbol in symbols
    ]
    evaluated = 0
    for candidate in itertools.product(*domains):
        values = dict(zip((symbol.name for symbol in symbols), candidate))
        evaluated += 1
        try:
            satisfied = all(constraint.evaluate(values) for constraint in constraints)
        except ZeroDivisionError:
            satisfied = False
        if satisfied:
            return SymbolicSolution(True, values, "mini", evaluated)
    return SymbolicSolution(False, {}, "mini", evaluated)


def _solve_with_z3(constraints: tuple[Constraint, ...]) -> SymbolicSolution:
    import z3

    symbols = _constraint_symbols(constraints)
    z3_symbols = {symbol.name: z3.Int(symbol.name) for symbol in symbols}
    solver = z3.Solver()
    for symbol in symbols:
        z3_symbol = z3_symbols[symbol.name]
        solver.add(z3_symbol >= symbol.minimum, z3_symbol <= symbol.maximum)
    for constraint in constraints:
        solver.add(_constraint_to_z3(constraint, z3_symbols))

    if solver.check() != z3.sat:
        return SymbolicSolution(False, {}, "z3", 0)
    model = solver.model()
    values = {
        symbol.name: model.eval(z3_symbols[symbol.name], model_completion=True).as_long()
        for symbol in symbols
    }
    return SymbolicSolution(True, values, "z3", 0)


def _expression_to_z3(expression: Expression, symbols: Mapping[str, object]):
    if isinstance(expression, Constant):
        return expression.value
    if isinstance(expression, Symbol):
        return symbols[expression.name]
    if isinstance(expression, BinaryExpression):
        left = _expression_to_z3(expression.left, symbols)
        right = _expression_to_z3(expression.right, symbols)
        if expression.operator == "add":
            return left + right
        if expression.operator == "sub":
            return left - right
        if expression.operator == "mul":
            return left * right
        if expression.operator == "floordiv":
            return left / right
        if expression.operator == "mod":
            return left % right
    raise SymbolicError(f"unsupported expression for z3: {expression!r}")


def _constraint_to_z3(constraint: Constraint, symbols: Mapping[str, object]):
    left = _expression_to_z3(constraint.left, symbols)
    right = _expression_to_z3(constraint.right, symbols)
    if constraint.operator == "eq":
        return left == right
    if constraint.operator == "ne":
        return left != right
    if constraint.operator == "lt":
        return left < right
    if constraint.operator == "le":
        return left <= right
    if constraint.operator == "gt":
        return left > right
    if constraint.operator == "ge":
        return left >= right
    raise SymbolicError(f"unsupported comparison for z3: {constraint.operator}")


def _constraint_symbols(constraints: tuple[Constraint, ...]) -> tuple[Symbol, ...]:
    symbols: tuple[Symbol, ...] = ()
    for constraint in constraints:
        symbols = _merge_symbols(symbols, constraint.symbols())
    return symbols


def _merge_symbols(
    left: tuple[Symbol, ...],
    right: tuple[Symbol, ...],
) -> tuple[Symbol, ...]:
    by_name = {symbol.name: symbol for symbol in left}
    for symbol in right:
        existing = by_name.get(symbol.name)
        if existing is not None and existing != symbol:
            raise SymbolicError(f"conflicting domains for symbol {symbol.name!r}")
        by_name[symbol.name] = symbol
    return tuple(by_name[name] for name in sorted(by_name))


def _coerce_expression(value: int | Expression) -> Expression:
    if isinstance(value, Expression):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"expected int or Expression, got {type(value).__name__}")
    return Constant(value)

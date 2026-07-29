"""Optional heavy-analysis adapter contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ai_reverse_agent.features import FeatureIndex


class IntegrationUnavailable(RuntimeError):
    """Raised when an explicitly selected optional backend is unavailable."""


@dataclass(frozen=True)
class IntegrationCapability:
    name: str
    available: bool
    mode: str
    detail: str


class OptionalAnalysisBackend(Protocol):
    name: str

    def capability(self) -> IntegrationCapability:
        """Report availability without importing or launching the backend."""

    def analyze(self, features: FeatureIndex) -> tuple[dict[str, object], ...]:
        """Analyze one already-built FeatureIndex."""

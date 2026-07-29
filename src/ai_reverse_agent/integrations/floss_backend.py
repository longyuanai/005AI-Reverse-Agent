"""Capability boundary for an optional FLOSS string adapter."""

from __future__ import annotations

import importlib.util

from ai_reverse_agent.features import FeatureIndex

from .base import IntegrationCapability, IntegrationUnavailable


class FlossBackend:
    name = "floss"

    def capability(self) -> IntegrationCapability:
        available = importlib.util.find_spec("floss") is not None
        return IntegrationCapability(
            self.name,
            available,
            "optional-process",
            "FLOSS package detected" if available else "FLOSS is not installed",
        )

    def analyze(self, features: FeatureIndex) -> tuple[dict[str, object], ...]:
        raise IntegrationUnavailable(
            "FLOSS result mapping is reserved for OPTIONAL-ADAPTERS follow-up"
        )

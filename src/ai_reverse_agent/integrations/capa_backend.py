"""Capability boundary for an optional Mandiant capa adapter."""

from __future__ import annotations

import importlib.util

from ai_reverse_agent.features import FeatureIndex

from .base import IntegrationCapability, IntegrationUnavailable


class CapaBackend:
    name = "capa"

    def capability(self) -> IntegrationCapability:
        available = importlib.util.find_spec("capa") is not None
        return IntegrationCapability(
            self.name,
            available,
            "optional-process",
            "capa package detected" if available else "capa is not installed",
        )

    def analyze(self, features: FeatureIndex) -> tuple[dict[str, object], ...]:
        raise IntegrationUnavailable(
            "capa result mapping is reserved for OPTIONAL-ADAPTERS follow-up"
        )

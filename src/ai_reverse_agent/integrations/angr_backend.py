"""Deferred angr capability boundary."""

from __future__ import annotations

import importlib.util

from ai_reverse_agent.features import FeatureIndex

from .base import IntegrationCapability, IntegrationUnavailable


class AngrBackend:
    name = "angr"

    def capability(self) -> IntegrationCapability:
        detected = importlib.util.find_spec("angr") is not None
        return IntegrationCapability(
            self.name,
            False,
            "deferred-v1.0",
            (
                "angr detected but execution is disabled until v1.0"
                if detected
                else "angr not installed; integration deferred until v1.0"
            ),
        )

    def analyze(self, features: FeatureIndex) -> tuple[dict[str, object], ...]:
        raise IntegrationUnavailable("angr integration is deferred until v1.0")

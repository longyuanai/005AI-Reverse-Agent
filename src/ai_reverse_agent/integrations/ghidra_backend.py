"""Deferred Ghidra headless capability boundary."""

from __future__ import annotations

import shutil

from ai_reverse_agent.features import FeatureIndex

from .base import IntegrationCapability, IntegrationUnavailable


class GhidraBackend:
    name = "ghidra"

    def capability(self) -> IntegrationCapability:
        detected = shutil.which("analyzeHeadless") is not None
        return IntegrationCapability(
            self.name,
            False,
            "deferred-v1.0",
            (
                "analyzeHeadless detected but launch is disabled until v1.0"
                if detected
                else "Ghidra headless not detected; integration deferred until v1.0"
            ),
        )

    def analyze(self, features: FeatureIndex) -> tuple[dict[str, object], ...]:
        raise IntegrationUnavailable("Ghidra integration is deferred until v1.0")

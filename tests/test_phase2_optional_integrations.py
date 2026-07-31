"""Heavy integrations stay capability-gated and out of the default scan."""

from __future__ import annotations

import pytest

from ai_reverse_agent.integrations import (
    AngrBackend,
    CapaBackend,
    FlossBackend,
    GhidraBackend,
    IntegrationCapability,
    IntegrationUnavailable,
)


@pytest.mark.parametrize("backend", [CapaBackend(), FlossBackend()])
def test_optional_backend_capability_is_non_launching(backend):
    capability = backend.capability()
    assert isinstance(capability, IntegrationCapability)
    assert capability.mode == "optional-process"


@pytest.mark.parametrize("backend", [AngrBackend(), GhidraBackend()])
def test_deferred_backend_is_never_available_in_phase2(backend):
    capability = backend.capability()
    assert capability.available is False
    assert capability.mode == "deferred-v1.0"


@pytest.mark.parametrize(
    "backend",
    [CapaBackend(), FlossBackend(), AngrBackend(), GhidraBackend()],
)
def test_unimplemented_optional_analysis_fails_explicitly(backend):
    with pytest.raises(IntegrationUnavailable):
        backend.analyze(None)

"""Live ReverseAdapter tests against an IntegrationGateway on port 18080."""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import uvicorn


ROOT = Path(__file__).resolve().parents[2]
SUITE_ROOT = ROOT.parent
INTEGRATION_SRC = SUITE_ROOT / "000shared-integration" / "src"
if str(INTEGRATION_SRC) not in sys.path:
    sys.path.insert(0, str(INTEGRATION_SRC))

from shared_integration.gateway import build_gateway


@pytest.fixture(scope="module")
def gateway_url() -> Iterator[str]:
    gateway = build_gateway(SUITE_ROOT)
    server = uvicorn.Server(
        uvicorn.Config(
            gateway.app,
            host="127.0.0.1",
            port=18080,
            log_level="error",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.monotonic() + 10
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.02)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=2)
        raise RuntimeError("IntegrationGateway did not start on port 18080")

    try:
        yield "http://127.0.0.1:18080"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_post_scan_returns_findings(gateway_url: str) -> None:
    binary = ROOT / "samples" / "mini_binaries" / "mini_x64_pe.exe"

    with httpx.Client(timeout=15, trust_env=False) as client:
        response = client.post(
            f"{gateway_url}/v0.5/005/scan",
            json={"binary_path": str(binary), "arch": "x64"},
        )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["source"] == "005"
    assert payload["count"] >= 1
    assert payload["findings"][0]["host"] == str(binary.resolve())


def test_health_endpoint_reports_reverse_ok(gateway_url: str) -> None:
    with httpx.Client(timeout=10, trust_env=False) as client:
        response = client.get(f"{gateway_url}/v0.5/health")

    assert response.status_code == 200, response.text
    reverse = response.json()["products"]["005"]
    assert reverse["status"] == "ok"
    assert reverse["source"] == "005-reverse"
    assert reverse["available"] is True

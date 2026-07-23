"""Shared fixtures for tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Make sure src/ is on the import path.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture()
def stub_router() -> object:
    """LLMRouter stub that returns a canned JSON reply.

    Tests use this to avoid hitting any network. Each call records the
    `ChatRequest` so tests can inspect prompts.
    """

    class _StubRouter:
        def __init__(self) -> None:
            self.calls: list = []
            self.reply = {
                "name": "X",
                "purpose": "stub-purpose description",
            }

        def chat(self, tier, req):  # noqa: ARG002
            from shared_llm_core import (
                ChatChoice,
                ChatMessage,
                ChatResponse,
                ChatUsage,
            )
            self.calls.append(req)
            return ChatResponse(
                id="x",
                model="stub",
                created=0,
                choices=[
                    ChatChoice(
                        index=0,
                        message=ChatMessage(
                            role="assistant",
                            content=json.dumps(self.reply),
                        ),
                        finish_reason="stop",
                    )
                ],
                usage=ChatUsage(),
            )

    return _StubRouter()

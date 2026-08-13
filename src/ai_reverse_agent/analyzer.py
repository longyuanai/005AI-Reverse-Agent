"""LLM enricher.

For each `IdentifiedFunction`, ask the LLM (via `shared-llm_core`) for a
concise one-line purpose description. Uses `response_format={"type":
"json_object"}` so the response is deterministic to parse.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from shared_llm_core import (
    ChatMessage,
    ChatRequest,
    ChatResponse,
)
from shared_llm_core.router import TaskTier
from shared_llm_core.untrusted import (
    INJECTION_GUARD_SYSTEM_PROMPT,
    wrap_untrusted,
)

from ai_reverse_agent.datatypes import EnrichedFunction, IdentifiedFunction


@dataclass(frozen=True)
class FunctionExplanation:
    """LLM response for one function."""

    name: str
    purpose: str


_SYSTEM = """You are a reverse-engineering assistant.
Given a function name and the DLL that exports it, return strict JSON:

{
  "name": "<echo of the input name>",
  "purpose": "ONE sentence (<= 20 words) describing what this API does"
}

Never invent facts. Only describe what the function name + DLL imply."""


_USER_TEMPLATE = """Function: {name}
DLL: {dll}

Return JSON only."""


def _strip(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        # Strip ``` and optional 'json' marker.
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
        return text.strip()
    return text


def explain_function(router: object, fn: IdentifiedFunction) -> EnrichedFunction:
    """Ask the LLM for the purpose of one function."""
    req = ChatRequest(
        messages=[
            ChatMessage(
                role="system",
                content=f"{_SYSTEM}\n\n{INJECTION_GUARD_SYSTEM_PROMPT}",
            ),
            ChatMessage(
                role="user",
                content=_USER_TEMPLATE.format(
                    name=wrap_untrusted(fn.name, kind="binary_symbol"),
                    dll=wrap_untrusted(fn.dll, kind="binary_symbol"),
                ),
            ),
        ],
        temperature=0.2,
        max_tokens=120,
        response_format={"type": "json_object"},
    )
    resp: ChatResponse = router.chat(TaskTier.STANDARD, req)
    data = json.loads(_strip(resp.choices[0].message.content))
    return EnrichedFunction(
        func=fn,
        purpose=str(data.get("purpose", "<no explanation>")),
    )


def explain_functions(
    router: object,
    fns: list[IdentifiedFunction],
) -> list[EnrichedFunction]:
    """Enrich all identified functions with LLM-generated purposes."""
    return [explain_function(router, fn) for fn in fns]

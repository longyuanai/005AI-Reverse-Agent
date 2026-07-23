"""AI-Reverse-Agent: PE parsing + LLM-enriched function identification.

PoC scope: parses a synthetic fake PE32 binary, identifies imported and
local functions, asks the LLM (via shared-llm-core) for a one-line
purpose of each, and emits a Markdown report.

Real binaries (Capstone, IDA, Ghidra's P-Code, etc.) are out of scope
for PoC. The `parsers.parse_pe()` and `identifier.identify_functions()`
interfaces are designed so a real disassembler-backed parser can replace
the fake-PE fixture without touching anything else.
"""

from ai_reverse_agent.analyzer import explain_functions
from ai_reverse_agent.datatypes import (
    EnrichedFunction,
    IdentifiedFunction,
    PeImage,
)
from ai_reverse_agent.fake_pe import make_fake_pe
from ai_reverse_agent.identifier import identify_functions
from ai_reverse_agent.parsers import parse_pe, parse_pe_bytes
from ai_reverse_agent.reporter import render_markdown

__version__ = "0.1.0"

__all__ = [
    "EnrichedFunction",
    "IdentifiedFunction",
    "PeImage",
    "__version__",
    "explain_functions",
    "identify_functions",
    "make_fake_pe",
    "parse_pe",
    "parse_pe_bytes",
    "render_markdown",
]

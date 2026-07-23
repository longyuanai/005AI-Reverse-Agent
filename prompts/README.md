# AI-Reverse-Agent prompts

This directory holds versioned prompt templates (YAML or JSON) for the LLM
enricher. The v0.1 PoC keeps prompts inline in `analyzer.py` — no external
template is required.

When the PoC graduates to multi-step renaming or RAG, drop the new prompt
files in here and load via `shared_llm_core.templates.PromptTemplate`.

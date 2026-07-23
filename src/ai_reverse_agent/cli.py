"""CLI: `ai-reverse-agent analyze PATH` and `ai-reverse-agent demo`.

Supports:
  - analyze PATH  — parse a binary from disk
  - demo          — run the entire pipeline against an in-memory fake PE
"""

from __future__ import annotations

import json
import os
import sys
from io import BytesIO

import click
from rich.console import Console

from ai_reverse_agent import __version__
from ai_reverse_agent.analyzer import explain_functions
from ai_reverse_agent.fake_pe import make_fake_pe
from ai_reverse_agent.identifier import identify_functions
from ai_reverse_agent.parsers import parse_pe_bytes
from ai_reverse_agent.reporter import render_markdown


console = Console()


def _stub_router() -> object:
    """A drop-in router stub that returns canned JSON without network.

    Used by `--no-llm` to keep the demo fully reproducible and offline.
    """

    class _Router:
        def __init__(self) -> None:
            self.calls: list = []

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def close(self) -> None:
            pass

        def chat(self, _tier, req):
            from shared_llm_core import (
                ChatChoice,
                ChatMessage,
                ChatResponse,
                ChatUsage,
            )
            self.calls.append(req)
            # Pull the function name from the prompt user-message.
            user = req.messages[-1].content
            name = "<unknown>"
            for line in user.splitlines():
                if line.startswith("Function:"):
                    name = line.split(":", 1)[1].strip()
                    break
            payload = {
                "name": name,
                "purpose": f"<offline stub — describes `{name}`>",
            }
            return ChatResponse(
                id="stub",
                model="stub",
                created=0,
                choices=[
                    ChatChoice(
                        index=0,
                        message=ChatMessage(
                            role="assistant",
                            content=json.dumps(payload),
                        ),
                        finish_reason="stop",
                    )
                ],
                usage=ChatUsage(),
            )

    return _Router()


@click.group()
@click.version_option(__version__)
def cli() -> None:
    """AI-Reverse-Agent: PE parsing + function enrichment (PoC v0.1)."""


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", "output_path", default="-", type=click.Path())
@click.option("--provider", "-p", default="local", show_default=True)
@click.option("--no-llm", is_flag=True, help="Use a stub router (no network).")
def analyze(path: str, output_path: str, provider: str, no_llm: bool) -> None:
    """Parse a binary file and produce a Markdown analysis report."""
    os.environ.setdefault("LLM_PROVIDERS", provider)

    console.print(f"[bold]Reading[/bold] {path} ...")
    with open(path, "rb") as f:
        data = f.read()
    pe = parse_pe_bytes(data)
    console.print(f"  [green]{len(pe.imports)}[/green] imports, "
                  f"[green]{len(pe.functions)}[/green] function-table entries")

    identified = identify_functions(pe)
    console.print(f"[bold]Identifying[/bold] {len(identified)} functions ...")

    console.print("[bold]Enriching[/bold] functions via shared-llm-core ...")
    if no_llm:
        router = _stub_router()
    else:
        from shared_llm_core.router import LLMRouter
        router = LLMRouter.from_env()
    try:
        enriched = explain_functions(router, identified)
    finally:
        if hasattr(router, "close"):
            router.close()

    report = render_markdown(pe, enriched, source=path)
    if output_path == "-":
        sys.stdout.write(report)
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
        console.print(f"[green]Wrote[/green] {output_path}")


@cli.command()
@click.option("--output", "-o", "output_path", default="-", type=click.Path())
@click.option("--provider", "-p", default="local", show_default=True)
@click.option("--no-llm", is_flag=True, help="Use a stub router (no network).")
def demo(output_path: str, provider: str, no_llm: bool) -> None:
    """Run the full pipeline against an in-memory fake PE.

    No file required; uses the 5 canonical target functions
    (CreateFileW, MessageBoxW, printf, connect, RegOpenKeyExW).
    """
    os.environ.setdefault("LLM_PROVIDERS", provider)

    console.print("[bold]Building[/bold] fake PE in memory ...")
    blob = make_fake_pe()
    pe = parse_pe_bytes(blob)
    console.print(f"  [green]{len(pe.imports)}[/green] imports, "
                  f"[green]{len(pe.functions)}[/green] function-table entries")

    identified = identify_functions(pe)
    console.print(f"[bold]Identifying[/bold] {len(identified)} functions ...")

    console.print("[bold]Enriching[/bold] functions via shared-llm-core ...")
    if no_llm:
        router = _stub_router()
    else:
        from shared_llm_core.router import LLMRouter
        router = LLMRouter.from_env()
    try:
        enriched = explain_functions(router, identified)
    finally:
        if hasattr(router, "close"):
            router.close()

    report = render_markdown(pe, enriched, source="<demo-fake-pe>")
    if output_path == "-":
        sys.stdout.write(report)
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
        console.print(f"[green]Wrote[/green] {output_path}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()

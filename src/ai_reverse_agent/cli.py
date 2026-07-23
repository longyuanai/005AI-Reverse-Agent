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
from pathlib import Path

import click
from rich.console import Console

from ai_reverse_agent import __version__
from ai_reverse_agent.analyzer import explain_functions
from ai_reverse_agent.disassembler import (
    DisassemblyError,
    disassemble_file,
    format_disassembly,
)
from ai_reverse_agent.decompiler import decompile_bytes, format_decompilation
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


def _print_pe_summary(pe) -> None:
    console.print(f"  Architecture: [green]{pe.architecture.label}[/green]")
    console.print(f"  [green]{len(pe.imports)}[/green] imports, "
                  f"[green]{len(pe.functions)}[/green] function-table entries")


class _AutoInt(click.ParamType):
    name = "integer"

    def convert(self, value, param, ctx):
        try:
            parsed = int(str(value), 0)
        except (TypeError, ValueError):
            self.fail(f"{value!r} is not a decimal or 0x-prefixed integer", param, ctx)
        if parsed < 0:
            self.fail(f"{value!r} must be non-negative", param, ctx)
        return parsed


AUTO_INT = _AutoInt()


@cli.command("disassemble")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--arch",
    "architecture",
    required=True,
    help="Architecture or alias: x86, x64, ARM, AArch64, MIPS, or RISC-V.",
)
@click.option("--bits", type=click.Choice(["32", "64"]), default=None)
@click.option(
    "--endian",
    type=click.Choice(["little", "big"], case_sensitive=False),
    default="little",
    show_default=True,
)
@click.option("--base-address", type=AUTO_INT, default="0", show_default=True)
@click.option("--thumb", is_flag=True, help="Decode ARM Thumb instructions.")
@click.option("--max-instructions", type=click.IntRange(min=1), default=None)
@click.option("--strict", is_flag=True, help="Fail if Capstone leaves undecoded bytes.")
@click.option("--output", "-o", "output_path", default="-", type=click.Path(dir_okay=False))
def disassemble_command(
    path: str,
    architecture: str,
    bits: str | None,
    endian: str,
    base_address: int,
    thumb: bool,
    max_instructions: int | None,
    strict: bool,
    output_path: str,
) -> None:
    """Disassemble a raw binary file with Capstone."""
    try:
        result = disassemble_file(
            path,
            architecture,
            bits=None if bits is None else int(bits),
            endianness=endian,
            base_address=base_address,
            thumb=thumb,
            max_instructions=max_instructions,
            strict=strict,
        )
    except (DisassemblyError, OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    listing = format_disassembly(result)
    if output_path == "-":
        click.echo(listing, nl=False)
    else:
        Path(output_path).write_text(listing, encoding="utf-8")
        console.print(f"[green]Wrote[/green] {output_path}")


@cli.command("decompile")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--arch", "architecture", required=True)
@click.option("--bits", type=click.Choice(["32", "64"]), default=None)
@click.option(
    "--endian",
    type=click.Choice(["little", "big"], case_sensitive=False),
    default="little",
    show_default=True,
)
@click.option("--base-address", type=AUTO_INT, default="0", show_default=True)
@click.option("--thumb", is_flag=True, help="Decode ARM Thumb instructions.")
@click.option("--output", "-o", "output_path", default="-", type=click.Path(dir_okay=False))
def decompile_command(
    path: str,
    architecture: str,
    bits: str | None,
    endian: str,
    base_address: int,
    thumb: bool,
    output_path: str,
) -> None:
    """Produce conservative pseudo-C from a raw binary."""
    try:
        functions = decompile_bytes(
            Path(path).read_bytes(),
            architecture,
            address=base_address,
            bits=None if bits is None else int(bits),
            endianness=endian,
            thumb=thumb,
        )
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    pseudo_c = format_decompilation(functions)
    if output_path == "-":
        click.echo(pseudo_c, nl=False)
    else:
        Path(output_path).write_text(pseudo_c, encoding="utf-8")
        console.print(f"[green]Wrote[/green] {output_path}")


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
    _print_pe_summary(pe)

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
    _print_pe_summary(pe)

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

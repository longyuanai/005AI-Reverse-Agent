"""CLI entrypoint for local analysis and IntegrationGateway scans.

Supports:
  - scan          — emit a JSON Finding envelope for shared-integration
  - analyze PATH  — parse a binary from disk
  - demo          — run the entire pipeline against an in-memory fake PE
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click
from rich.console import Console

from ai_reverse_agent import __version__
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
from ai_reverse_agent.scan import scan_binary
from ai_reverse_agent.signatures import match_instructions
from ai_reverse_agent.disasm import disassemble
from ai_reverse_agent.decompiler import find_function_boundaries
from ai_reverse_agent.symbolic import loop_value, solve_branch, symbolic_input
from ai_reverse_agent.patch_diff import diff_files, format_patch_diff
from ai_reverse_agent.crypto_id import (
    format_crypto_detections,
    identify_crypto_file,
)
from ai_reverse_agent.controlflow import (
    GraphvizUnavailable,
    build_cfg,
    render_png,
    to_dot,
)


console = Console()


def _load_enricher():
    """Import the LLM enricher on demand.

    Only `analyze` and `demo` need shared-llm-core; every other subcommand is
    pure static analysis and must keep working without the suite package.
    """
    try:
        from ai_reverse_agent.analyzer import explain_functions
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise click.ClickException(
            f"LLM enrichment requires the 'shared-llm-core' package: {exc}"
        ) from exc
    return explain_functions


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


@click.group(invoke_without_command=True)
@click.version_option(__version__)
@click.option("--input", "adapter_input", hidden=True)
@click.option("--json", "adapter_json", is_flag=True, hidden=True)
@click.pass_context
def cli(
    ctx: click.Context,
    adapter_input: str | None,
    adapter_json: bool,
) -> None:
    """AI-Reverse-Agent: PE parsing + function enrichment (PoC v0.1)."""

    if ctx.invoked_subcommand is not None:
        return
    if adapter_input is not None or adapter_json:
        _run_scan_cli(adapter_input, adapter_json)
        return
    click.echo(ctx.get_help())


@cli.command("scan")
@click.option(
    "--input",
    "input_payload",
    help="Inline JSON payload; when omitted, read JSON from stdin.",
)
@click.option("--json", "json_output", is_flag=True, help="Emit a JSON envelope.")
def scan_command(input_payload: str | None, json_output: bool) -> None:
    """Scan a binary for the shared IntegrationGateway adapter."""

    _run_scan_cli(input_payload, json_output)


def _run_scan_cli(input_payload: str | None, json_output: bool) -> None:
    raw_payload = input_payload
    if raw_payload is None:
        raw_payload = click.get_text_stream("stdin").read()

    try:
        payload = json.loads(raw_payload)
        if not isinstance(payload, dict):
            raise ValueError("scan payload must be a JSON object")
    except (json.JSONDecodeError, ValueError) as exc:
        envelope = {
            "findings": [],
            "errors": [{"code": "invalid_payload", "message": str(exc)}],
        }
    else:
        try:
            envelope = scan_binary(payload)
        except Exception as exc:
            # IntegrationGateway parses stdout as JSON, so an unexpected
            # failure has to be reported inside the envelope, not as a
            # traceback on stderr.
            envelope = {
                "findings": [],
                "errors": [
                    {
                        "code": "internal_error",
                        "message": f"{type(exc).__name__}: {exc}",
                    }
                ],
            }

    if json_output:
        # Keep subprocess output ASCII-only. On Windows, redirected stdout can
        # otherwise use the active code page while the adapter decodes UTF-8.
        click.echo(json.dumps(envelope, ensure_ascii=True))
        return

    if envelope["errors"]:
        for error in envelope["errors"]:
            click.echo(f"ERROR {error['code']}: {error['message']}")
        return
    click.echo(f"Findings: {len(envelope['findings'])}")
    for finding in envelope["findings"]:
        click.echo(f"- [{finding['severity']}] {finding['title']}")


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


@cli.command("identify-libs")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--arch", "architecture", required=True)
@click.option("--bits", type=click.Choice(["32", "64"]), default=None)
@click.option("--base-address", type=AUTO_INT, default="0", show_default=True)
def identify_libs_command(
    path: str,
    architecture: str,
    bits: str | None,
    base_address: int,
) -> None:
    """Identify built-in library signatures in a raw binary."""
    try:
        instructions = tuple(
            disassemble(
                Path(path).read_bytes(),
                architecture,
                address=base_address,
                bits=None if bits is None else int(bits),
            )
        )
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    found = 0
    for boundary in find_function_boundaries(instructions):
        match = match_instructions(boundary.instructions, architecture)
        if match is not None:
            click.echo(f"0x{boundary.start_address:x} {match.qualified_name}")
            found += 1
    if not found:
        click.echo("No built-in library signatures matched.")


@cli.command("cfg")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--arch", "architecture", required=True)
@click.option("--bits", type=click.Choice(["32", "64"]), default=None)
@click.option("--base-address", type=AUTO_INT, default="0", show_default=True)
@click.option("--dot-output", required=True, type=click.Path(dir_okay=False))
@click.option("--png-output", default=None, type=click.Path(dir_okay=False))
@click.option(
    "--dot-executable",
    default="dot",
    show_default=True,
    help="Graphviz dot command name or full path.",
)
def cfg_command(
    path: str,
    architecture: str,
    bits: str | None,
    base_address: int,
    dot_output: str,
    png_output: str | None,
    dot_executable: str,
) -> None:
    """Build a basic-block CFG and write DOT, optionally PNG."""
    try:
        instructions = tuple(
            disassemble(
                Path(path).read_bytes(),
                architecture,
                address=base_address,
                bits=None if bits is None else int(bits),
            )
        )
        dot_text = to_dot(build_cfg(instructions), name=Path(path).stem)
        Path(dot_output).write_text(dot_text, encoding="utf-8")
        console.print(f"[green]Wrote DOT[/green] {dot_output}")
        if png_output is not None:
            try:
                render_png(dot_text, png_output, dot_executable=dot_executable)
            except GraphvizUnavailable as exc:
                console.print(f"[yellow]PNG skipped:[/yellow] {exc}")
            else:
                console.print(f"[green]Wrote PNG[/green] {png_output}")
    except (OSError, RuntimeError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc


@cli.command("solve-branch")
@click.option("--variable", default="input", show_default=True)
@click.option("--min-value", type=int, default=0, show_default=True)
@click.option("--max-value", type=int, default=255, show_default=True)
@click.option("--multiplier", type=int, default=1, show_default=True)
@click.option("--offset", type=int, default=0, show_default=True)
@click.option("--loop-step", type=int, default=0, show_default=True)
@click.option("--loop-iterations", type=click.IntRange(min=0), default=0, show_default=True)
@click.option(
    "--operator",
    "operator_name",
    type=click.Choice(["eq", "ne", "lt", "le", "gt", "ge"]),
    default="eq",
    show_default=True,
)
@click.option("--target", type=int, required=True)
@click.option(
    "--backend",
    type=click.Choice(["auto", "mini", "z3"]),
    default="auto",
    show_default=True,
)
def solve_branch_command(
    variable: str,
    min_value: int,
    max_value: int,
    multiplier: int,
    offset: int,
    loop_step: int,
    loop_iterations: int,
    operator_name: str,
    target: int,
    backend: str,
) -> None:
    """Solve a bounded arithmetic condition for a branch-triggering input."""
    try:
        symbol = symbolic_input(variable, min_value, max_value)
        expression = symbol * multiplier + offset
        expression = loop_value(
            expression,
            step=loop_step,
            iterations=loop_iterations,
        )
        comparison = {
            "eq": expression.equals,
            "ne": expression.not_equals,
            "lt": expression.__lt__,
            "le": expression.__le__,
            "gt": expression.__gt__,
            "ge": expression.__ge__,
        }[operator_name](target)
        solution = solve_branch(comparison, backend=backend)
    except (TypeError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    if not solution.satisfiable:
        raise click.ClickException("branch is unsatisfiable in the requested domain")
    assignment = " ".join(
        f"{name}={value}" for name, value in solution.inputs.items()
    )
    click.echo(f"{assignment} backend={solution.backend}")


@cli.command("patch-diff")
@click.argument("baseline", type=click.Path(exists=True, dir_okay=False))
@click.argument("current", type=click.Path(exists=True, dir_okay=False))
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
def patch_diff_command(
    baseline: str,
    current: str,
    architecture: str,
    bits: str | None,
    endian: str,
    base_address: int,
    thumb: bool,
    output_path: str,
) -> None:
    """Compare two raw binaries at function and instruction level."""
    try:
        result = diff_files(
            baseline,
            current,
            architecture,
            address=base_address,
            bits=None if bits is None else int(bits),
            endianness=endian,
            thumb=thumb,
        )
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    report = format_patch_diff(result)
    if output_path == "-":
        click.echo(report, nl=False)
    else:
        Path(output_path).write_text(report, encoding="utf-8")
        console.print(f"[green]Wrote[/green] {output_path}")


@cli.command("crypto-id")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", "output_path", default="-", type=click.Path(dir_okay=False))
def crypto_id_command(path: str, output_path: str) -> None:
    """Identify known cryptographic constants in a binary."""

    try:
        report = format_crypto_detections(identify_crypto_file(path))
    except OSError as exc:
        raise click.ClickException(str(exc)) from exc

    if output_path == "-":
        click.echo(report, nl=False)
    else:
        Path(output_path).write_text(report, encoding="utf-8")
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
    explain_functions = _load_enricher()
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
    explain_functions = _load_enricher()
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

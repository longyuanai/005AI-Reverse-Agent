"""Markdown report renderer for binary analysis."""

from __future__ import annotations

from datetime import datetime
from io import StringIO

from ai_reverse_agent.datatypes import EnrichedFunction, PeImage


_MACHINE_NAMES = {
    0x14C: "i386",
    0x200: "IA64",
    0x8664: "AMD64",
    0x1C0: "ARM",
    0xAA64: "AArch64",
}


def _machine_name(machine: int) -> str:
    return _MACHINE_NAMES.get(machine, f"0x{machine:04x}")


def render_markdown(pe: PeImage, functions: list[EnrichedFunction], source: str = "") -> str:
    """Render a Markdown reverse-engineering report."""
    out = StringIO()
    out.write("# AI Reverse-Engineering Report\n\n")
    out.write(f"_Generated at {datetime.now().isoformat(timespec='seconds')}_\n\n")
    if source:
        out.write(f"_Source: `{source}`_\n\n")

    # --- Header summary ---
    out.write("## PE Header Summary\n\n")
    out.write(f"- **Machine**: `{_machine_name(pe.coff.machine)}` (0x{pe.coff.machine:04x})\n")
    out.write(f"- **Timestamp**: 0x{pe.coff.timestamp:08x}\n")
    out.write(f"- **Characteristics**: 0x{pe.coff.characteristics:04x}\n")
    out.write(f"- **Entry point**: `0x{pe.optional.entry_point:08x}`\n")
    out.write(f"- **ImageBase**: `0x{pe.optional.image_base:08x}`\n")
    out.write(f"- **Section alignment**: 0x{pe.optional.section_alignment:x}\n")
    out.write(f"- **File alignment**: 0x{pe.optional.file_alignment:x}\n")
    out.write(f"- **Number of sections**: {len(pe.sections)}\n")
    out.write(f"- **Imports**: {len(pe.imports)}\n")
    out.write(f"- **Function table size**: {len(pe.functions)}\n\n")

    # --- Section table ---
    out.write("## Sections\n\n")
    out.write("| Name | Virtual Address | Virtual Size | Raw Size | Characteristics |\n")
    out.write("|------|-----------------|--------------|----------|------------------|\n")
    for s in pe.sections:
        out.write(
            f"| `{s.name}` | 0x{s.virtual_address:08x} | {s.virtual_size} | "
            f"{s.raw_size} | 0x{s.characteristics:08x} |\n"
        )
    out.write("\n")

    # --- Imports grouped by DLL ---
    out.write("## Imports\n\n")
    if not pe.imports:
        out.write("_No imports._\n\n")
    else:
        by_dll: dict[str, list] = {}
        for imp in pe.imports:
            by_dll.setdefault(imp.dll, []).append(imp)
        for dll, entries in by_dll.items():
            out.write(f"### `{dll}`\n\n")
            for e in entries:
                out.write(f"- `{e.function}` (hint={e.hint}, addr=0x{e.address:08x})\n")
            out.write("\n")

    # --- Function table with LLM-enriched purposes ---
    out.write("## Function Table (LLM-enriched)\n\n")
    if not functions:
        out.write("_No identified functions._\n\n")
    else:
        for ef in functions:
            out.write(ef.to_markdown() + "\n\n")
    out.write("---\n")
    out.write(f"_Total identified: {len(functions)}_\n")
    return out.getvalue()

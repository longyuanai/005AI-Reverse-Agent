"""Function identifier.

Joins the three PE sources of function names — imports, the per-binary
function table, and section membership — into a single list of
`IdentifiedFunction`s with a `kind` field:
  * `import` — function came from the import directory
  * `local`  — function came from the binary's function table only
  * `entry`  — the PE entry point, treated as a local "unknown" function
"""

from __future__ import annotations

from ai_reverse_agent.datatypes import IdentifiedFunction, PeImage


def identify_functions(pe: PeImage) -> list[IdentifiedFunction]:
    """Combine PE imports + function table + entry point."""
    identified: list[IdentifiedFunction] = []
    seen: set[tuple[str, str]] = set()

    for imp in pe.imports:
        key = (imp.function, imp.dll)
        if key in seen:
            continue
        seen.add(key)
        identified.append(
            IdentifiedFunction(
                name=imp.function,
                dll=imp.dll,
                address=imp.address,
                section=_section_for_va(pe, imp.address),
                kind="import",
            )
        )

    # 2) Function table — local symbols.
    for fn in pe.functions:
        # If we already have this as an import, skip (imports take priority).
        already_imported = any(i.function == fn.name for i in pe.imports)
        if already_imported:
            continue
        identified.append(
            IdentifiedFunction(
                name=fn.name,
                dll="(local)",
                address=fn.address,
                section=_section_for_va(pe, fn.address),
                kind="local",
            )
        )

    # 3) Entry point — label as "entry" so the reporter always has a lead.
    if pe.entry_point not in (i.address for i in identified):
        identified.append(
            IdentifiedFunction(
                name="entry_point",
                dll="(self)",
                address=pe.entry_point,
                section=_section_for_va(pe, pe.entry_point),
                kind="entry",
            )
        )

    return identified


def _section_for_va(pe: PeImage, rva: int) -> str:
    """Return the section name containing the given RVA, or `<unknown>`."""
    for s in pe.sections:
        if s.virtual_address <= rva < s.virtual_address + s.virtual_size:
            return s.name
    # Closest preceding section as a best-effort fallback.
    match = "<unknown>"
    for s in pe.sections:
        if s.virtual_address <= rva:
            match = s.name
    return match

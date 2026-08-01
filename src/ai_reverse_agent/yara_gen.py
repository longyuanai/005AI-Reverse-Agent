"""Deterministic YARA rule generation from static reverse features."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ai_reverse_agent.backends import BinaryLoader
from ai_reverse_agent.deobfuscation.string_xor import find_xor_strings
from ai_reverse_agent.features import FeatureIndex, extract_features
from ai_reverse_agent.magic import MagicError


MAX_YARA_STRINGS = 64
DEFAULT_MAX_STRINGS = 16
MIN_YARA_STRING_LENGTH = 6
MAX_YARA_STRING_LENGTH = 120
_IDENTIFIER_RE = re.compile(r"[^A-Za-z0-9_]+")
_NOISY_STRINGS = {
    "this program cannot be run in dos mode.",
    "rich",
    ".text",
    ".data",
    ".rdata",
    ".reloc",
}
_SECTION_NAMES = (
    ".text",
    ".data",
    ".rdata",
    ".idata",
    ".reloc",
    ".bss",
    ".rsrc",
)


class YaraGenerationError(ValueError):
    """Raised when a safe deterministic YARA rule cannot be generated."""


@dataclass(frozen=True)
class YaraString:
    """One selected literal and its provenance within the binary."""

    identifier: str
    value: str
    offset: int
    provenance: str


@dataclass(frozen=True)
class GeneratedYaraRule:
    """Rendered rule plus structured values useful to callers and tests."""

    name: str
    text: str
    imports: tuple[str, ...]
    metadata: dict[str, str | int]
    strings: tuple[YaraString, ...]
    condition: str


def sanitize_rule_name(value: str) -> str:
    """Return a valid, bounded YARA identifier."""
    normalized = _IDENTIFIER_RE.sub("_", value.strip()).strip("_")
    if not normalized:
        normalized = "binary"
    if normalized[0].isdigit():
        normalized = f"sample_{normalized}"
    return normalized[:128]


def escape_yara_string(value: str) -> str:
    """Escape an ASCII literal for a YARA quoted string."""
    escaped: list[str] = []
    for character in value:
        code = ord(character)
        if character == "\\":
            escaped.append("\\\\")
        elif character == '"':
            escaped.append('\\"')
        elif character == "\n":
            escaped.append("\\n")
        elif character == "\r":
            escaped.append("\\r")
        elif character == "\t":
            escaped.append("\\t")
        elif 0x20 <= code <= 0x7E:
            escaped.append(character)
        else:
            escaped.extend(f"\\x{byte:02x}" for byte in character.encode("utf-8"))
    return "".join(escaped)


def generate_yara_rule(
    features: FeatureIndex,
    *,
    source_name: str,
    rule_name: str | None = None,
    max_strings: int = DEFAULT_MAX_STRINGS,
    exact_fallback: bool = True,
) -> GeneratedYaraRule:
    """Generate a bounded YARA rule from a precomputed FeatureIndex."""
    if not 1 <= max_strings <= MAX_YARA_STRINGS:
        raise YaraGenerationError(
            f"max_strings must be between 1 and {MAX_YARA_STRINGS}"
        )
    data = features.file.get("data", b"")
    if not isinstance(data, bytes):
        raise YaraGenerationError("FeatureIndex file data must be immutable bytes")
    if not data:
        raise YaraGenerationError("cannot generate a YARA rule for an empty binary")

    digest = hashlib.sha256(data).hexdigest()
    name = sanitize_rule_name(
        rule_name or f"longyuanai_{Path(source_name).stem}_{digest[:12]}"
    )
    strings = _select_strings(features, max_strings=max_strings)
    container = str(features.file.get("container", "raw"))
    metadata: dict[str, str | int] = {
        "author": "longyuanai",
        "generated_by": "005-ai-reverse-agent",
        "source_name": Path(source_name).name,
        "source_sha256": digest,
        "source_size": len(data),
        "container": container,
        "backend": str(features.file.get("backend", "unknown")),
        "architecture": str(features.file.get("architecture", "unknown")),
    }
    imported = features.file.get("imports", ())
    import_set_hash = features.file.get("import_set_hash")
    if imported and isinstance(import_set_hash, str) and import_set_hash:
        metadata["import_set_hash"] = import_set_hash
    pe_imphash = features.file.get("pe_imphash")
    if isinstance(pe_imphash, str) and pe_imphash:
        metadata["pe_imphash"] = pe_imphash
    decoded_count = sum(item.provenance == "decoded-xor" for item in strings)
    metadata["decoded_xor_strings"] = decoded_count

    imports: list[str] = []
    clauses: list[str] = []
    if container == "pe" and isinstance(pe_imphash, str) and pe_imphash:
        imports.append("pe")
        clauses.extend(["pe.is_pe", f'pe.imphash() == "{pe_imphash}"'])
        if strings:
            clauses.append("1 of ($s*)")
    elif len(strings) >= 2:
        lower_size = max(1, len(data) * 3 // 4)
        upper_size = min(100 * 1024 * 1024, max(lower_size, len(data) * 5 // 4))
        clauses.extend(
            [
                f"filesize >= {lower_size}",
                f"filesize <= {upper_size}",
                "2 of ($s*)",
            ]
        )
    elif exact_fallback:
        imports.append("hash")
        clauses.append(f'hash.sha256(0, filesize) == "{digest}"')
    else:
        raise YaraGenerationError(
            "not enough stable features; enable exact_fallback for an exact-file rule"
        )

    condition = " and ".join(clauses)
    text = _render_rule(
        name=name,
        imports=tuple(imports),
        metadata=metadata,
        strings=strings,
        condition=condition,
    )
    return GeneratedYaraRule(
        name=name,
        text=text,
        imports=tuple(imports),
        metadata=metadata,
        strings=strings,
        condition=condition,
    )


def generate_yara_for_file(
    path: str | Path,
    *,
    architecture: str,
    rule_name: str | None = None,
    max_strings: int = DEFAULT_MAX_STRINGS,
    exact_fallback: bool = True,
) -> GeneratedYaraRule:
    """Load a bounded local binary once and generate its YARA rule."""
    image = BinaryLoader().load(path)
    features = extract_features(image, (), architecture=architecture)
    return generate_yara_rule(
        features,
        source_name=image.path.name,
        rule_name=rule_name,
        max_strings=max_strings,
        exact_fallback=exact_fallback,
    )


def _select_strings(
    features: FeatureIndex,
    *,
    max_strings: int,
) -> tuple[YaraString, ...]:
    candidates: list[tuple[int, int, str, str]] = []
    data = features.file.get("data", b"")
    if isinstance(data, bytes):
        for decoded in find_xor_strings(data):
            candidates.append(
                (
                    1000 + _string_score(decoded.value),
                    decoded.offset,
                    decoded.value,
                    "decoded-xor",
                )
            )

    import_names: set[str] = set()
    imported = features.file.get("imports", ())
    if isinstance(imported, tuple):
        for item in imported:
            name = getattr(item, "name", None)
            if not isinstance(name, str) or _string_score(name) == 0:
                continue
            import_names.add(name.casefold())
            encoded = name.encode("ascii", errors="ignore")
            offset = data.find(encoded) if isinstance(data, bytes) and encoded else -1
            candidates.append((800 + _string_score(name), max(0, offset), name, "import"))

    raw_strings = features.file.get("strings", ())
    if isinstance(raw_strings, tuple):
        for item in raw_strings:
            if not isinstance(item, tuple) or len(item) != 2:
                continue
            offset, value = item
            if not isinstance(offset, int) or not isinstance(value, str):
                continue
            lowered = value.casefold().strip()
            if any(
                lowered != imported_name and lowered.startswith(imported_name)
                for imported_name in import_names
            ):
                continue
            if lowered.lstrip("`@_ ").startswith(_SECTION_NAMES):
                continue
            score = _string_score(value)
            if score > 0:
                candidates.append((score, offset, value, "ascii"))

    candidates.sort(key=lambda item: (-item[0], item[1], item[2].lower()))
    selected: list[YaraString] = []
    seen: set[str] = set()
    for _, offset, value, provenance in candidates:
        normalized = value.casefold()
        if normalized in seen:
            continue
        seen.add(normalized)
        selected.append(
            YaraString(
                identifier=f"s{len(selected) + 1}",
                value=value,
                offset=offset,
                provenance=provenance,
            )
        )
        if len(selected) >= max_strings:
            break
    return tuple(selected)


def _string_score(value: str) -> int:
    if not MIN_YARA_STRING_LENGTH <= len(value) <= MAX_YARA_STRING_LENGTH:
        return 0
    lowered = value.casefold().strip()
    if lowered in _NOISY_STRINGS or lowered.endswith((".dll", ".sys", ".ocx")):
        return 0
    if len(set(lowered)) < 4:
        return 0
    alpha_count = sum(character.isalpha() for character in value)
    if alpha_count < 3:
        return 0
    score = min(len(value), 48) + min(len(set(value)), 16)
    score += 12 * any(character in value for character in "._-:/@=")
    score += 8 * any(character.isdigit() for character in value)
    score += 6 * (value.lower() != value and value.upper() != value)
    return score


def _render_rule(
    *,
    name: str,
    imports: tuple[str, ...],
    metadata: dict[str, str | int],
    strings: tuple[YaraString, ...],
    condition: str,
) -> str:
    lines = [f'import "{module}"' for module in imports]
    if lines:
        lines.append("")
    lines.extend([f"rule {name} : generated reverse", "{", "    meta:"])
    for key in sorted(metadata):
        value: Any = metadata[key]
        if isinstance(value, int):
            lines.append(f"        {key} = {value}")
        else:
            lines.append(f'        {key} = "{escape_yara_string(str(value))}"')
    if strings:
        lines.append("    strings:")
        for item in strings:
            escaped = escape_yara_string(item.value)
            lines.append(
                f'        ${item.identifier} = "{escaped}" ascii wide'
                f" // 0x{item.offset:x} {item.provenance}"
            )
    lines.extend(["    condition:", f"        {condition}", "}"])
    return "\n".join(lines) + "\n"


__all__ = [
    "DEFAULT_MAX_STRINGS",
    "GeneratedYaraRule",
    "MAX_YARA_STRINGS",
    "YaraGenerationError",
    "YaraString",
    "escape_yara_string",
    "generate_yara_for_file",
    "generate_yara_rule",
    "sanitize_rule_name",
]

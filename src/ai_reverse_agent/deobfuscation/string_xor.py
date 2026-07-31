"""XOR-obfuscated string recovery."""

from __future__ import annotations

from dataclasses import dataclass
import re

from shared_llm_core.rule_engine import RuleContext

from .base import ObfuscationRule, fact_bytes

XOR_MARKER = b"XORSTR\x01"


@dataclass(frozen=True)
class DecodedXorString:
    offset: int
    key: int | bytes
    value: str


def find_xor_strings(data: bytes) -> tuple[DecodedXorString, ...]:
    """Recover tagged fixtures and bounded markerless single-byte XOR strings."""
    found: list[DecodedXorString] = []
    cursor = 0
    while True:
        offset = data.find(XOR_MARKER, cursor)
        if offset < 0:
            break
        header = offset + len(XOR_MARKER)
        if header + 2 > len(data):
            break
        key = data[header]
        length = data[header + 1]
        encoded = data[header + 2 : header + 2 + length]
        if len(encoded) != length:
            break
        decoded = bytes(value ^ key for value in encoded)
        if len(decoded) >= 4 and all(0x20 <= value <= 0x7E for value in decoded):
            found.append(DecodedXorString(offset=offset, key=key, value=decoded.decode()))
        cursor = header + 2 + length
    found.extend(_markerless_single_byte(data, occupied=found))
    found.extend(_markerless_repeating_key(data, occupied=found))
    unique = {(item.offset, item.key, item.value): item for item in found}
    return tuple(sorted(unique.values(), key=lambda item: (item.offset, item.key)))


def _markerless_single_byte(
    data: bytes,
    *,
    occupied: list[DecodedXorString],
) -> list[DecodedXorString]:
    """Brute force a bounded prefix and retain only high-quality text."""
    sample = data[: 256 * 1024]
    occupied_ranges = tuple(
        (
            item.offset,
            item.offset + len(XOR_MARKER) + 2 + len(item.value),
        )
        for item in occupied
    )
    candidates: list[tuple[float, DecodedXorString]] = []
    for key in range(1, 256):
        transformed = bytes(value ^ key for value in sample)
        for match in re.finditer(rb"[\x20-\x7e]{12,96}", transformed):
            offset = match.start()
            if any(
                not (
                    match.end() <= occupied_start
                    or offset >= occupied_end
                )
                for occupied_start, occupied_end in occupied_ranges
            ):
                continue
            original = sample[match.start() : match.end()]
            if all(0x20 <= value <= 0x7E for value in original):
                continue
            decoded = match.group()
            score = _text_score(decoded)
            if score < 0.82:
                continue
            candidates.append(
                (
                    score,
                    DecodedXorString(
                        offset=offset,
                        key=key,
                        value=decoded.decode("ascii"),
                    ),
                )
            )
            if len(candidates) >= 256:
                break
        if len(candidates) >= 256:
            break
    candidates.sort(key=lambda item: (-item[0], item[1].offset))
    accepted: list[DecodedXorString] = []
    for _, candidate in candidates:
        start = candidate.offset
        end = start + len(candidate.value)
        if any(
            not (end <= item.offset or start >= item.offset + len(item.value))
            for item in accepted
        ):
            continue
        accepted.append(candidate)
        if len(accepted) >= 32:
            break
    return accepted


def _markerless_repeating_key(
    data: bytes,
    *,
    occupied: list[DecodedXorString],
) -> list[DecodedXorString]:
    """Infer short repeating keys from bounded non-zero byte regions."""
    sample = data[: 256 * 1024]
    candidates: list[tuple[float, DecodedXorString]] = []
    for region_index, match in enumerate(re.finditer(rb"[^\x00]{12,128}", sample)):
        if region_index >= 256:
            break
        encoded = match.group()
        if all(0x20 <= value <= 0x7E for value in encoded):
            continue
        for key_length in range(2, min(8, len(encoded) // 3) + 1):
            key = bytes(
                max(
                    range(1, 256),
                    key=lambda candidate: sum(
                        _character_weight(value ^ candidate)
                        for value in encoded[position::key_length]
                    ),
                )
                for position in range(key_length)
            )
            if len(set(key)) == 1:
                continue
            decoded = bytes(
                value ^ key[index % key_length]
                for index, value in enumerate(encoded)
            )
            if not all(0x20 <= value <= 0x7E for value in decoded):
                continue
            score = _text_score(decoded)
            if score >= 0.86:
                candidates.append(
                    (
                        score,
                        DecodedXorString(match.start(), key, decoded.decode("ascii")),
                    )
                )
    candidates.sort(key=lambda item: (-item[0], len(item[1].value)))
    accepted: list[DecodedXorString] = []
    occupied_ranges = [
        (item.offset, item.offset + len(item.value))
        for item in occupied
    ]
    for _, candidate in candidates:
        end = candidate.offset + len(candidate.value)
        if any(
            not (end <= start or candidate.offset >= stop)
            for start, stop in occupied_ranges
        ):
            continue
        accepted.append(candidate)
        occupied_ranges.append((candidate.offset, end))
        if len(accepted) >= 16:
            break
    return accepted


def _character_weight(value: int) -> float:
    raw = chr(value)
    character = raw.lower()
    case_bonus = 0.25 if raw.islower() else 0.0
    if character in " etaoinshrdlu":
        return 3.0 + case_bonus
    if character.isalpha():
        return 2.0 + case_bonus
    if raw.isdigit() or raw in "._:/\\-@=":
        return 1.5
    if 0x20 <= value <= 0x7E:
        return 0.2
    return -8.0


def _text_score(value: bytes) -> float:
    text = value.decode("ascii", errors="ignore").lower()
    if len(set(text)) < 5:
        return 0.0
    alpha = sum(character.isalpha() for character in text) / len(text)
    vowels = sum(character in "aeiou" for character in text)
    vowel_ratio = vowels / max(1, sum(character.isalpha() for character in text))
    separators = sum(character in " ._:/\\-@=" for character in text) / len(text)
    common = sum(
        token in text
        for token in (
            "config",
            "http",
            "token",
            "command",
            "password",
            "admin",
            "user",
            "path",
            "error",
            "example",
        )
    )
    natural_vowels = 0.2 <= vowel_ratio <= 0.6
    return min(
        1.0,
        alpha * 0.65
        + separators * 0.6
        + (0.12 if natural_vowels else 0.0)
        + min(common, 2) * 0.12,
    )


class XorStringRule(ObfuscationRule):
    """Detect and recover statically tagged XOR string records."""

    id = "reverse.string-xor"
    tactic = "reverse.obfuscation.string-xor"
    confidence = 0.93

    def evaluate(self, ctx: RuleContext):
        decoded = find_xor_strings(fact_bytes(ctx))
        if not decoded:
            return []
        evidence = [
            f"0x{item.offset:x}: key={_format_key(item.key)}, decoded={item.value!r}"
            for item in decoded[:8]
        ]
        return [
            self.make_finding(
                ctx,
                title="XOR-obfuscated strings recovered",
                description="Static XOR decoding recovered printable embedded strings.",
                evidence=evidence,
                metadata={
                    "algorithm": "xor",
                    "decoded_strings": [item.value for item in decoded],
                    "match_count": len(decoded),
                },
            )
        ]


def _format_key(key: int | bytes) -> str:
    return f"0x{key:02x}" if isinstance(key, int) else key.hex()

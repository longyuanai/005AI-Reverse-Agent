"""XOR-obfuscated string recovery."""

from __future__ import annotations

from dataclasses import dataclass

from shared_llm_core.rule_engine import RuleContext

from .base import ObfuscationRule, fact_bytes

XOR_MARKER = b"XORSTR\x01"


@dataclass(frozen=True)
class DecodedXorString:
    offset: int
    key: int
    value: str


def find_xor_strings(data: bytes) -> tuple[DecodedXorString, ...]:
    """Decode bounded fixture records: marker, key byte, length byte, ciphertext."""
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
    return tuple(found)


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
            f"0x{item.offset:x}: key=0x{item.key:02x}, decoded={item.value!r}"
            for item in decoded[:8]
        ]
        return [
            self.make_finding(
                ctx,
                title="XOR-obfuscated strings recovered",
                description="Static XOR decoding recovered printable embedded strings.",
                evidence=evidence,
                metadata={
                    "decoded_strings": [item.value for item in decoded],
                    "match_count": len(decoded),
                },
            )
        ]

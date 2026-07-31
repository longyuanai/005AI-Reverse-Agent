"""RC4-obfuscated string recovery."""

from __future__ import annotations

from dataclasses import dataclass

from shared_llm_core.rule_engine import RuleContext

from .base import ObfuscationRule, fact_bytes
from .base import fact_instructions, instruction_parts
from shared_llm_core.finding import FindingSeverity

RC4_MARKER = b"RC4STR\x01"


@dataclass(frozen=True)
class DecodedRc4String:
    offset: int
    key: bytes
    value: str


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """Apply the RC4 KSA/PRGA; encryption and decryption are identical."""
    if not key:
        raise ValueError("RC4 key must not be empty")
    state = list(range(256))
    j = 0
    for index in range(256):
        j = (j + state[index] + key[index % len(key)]) & 0xFF
        state[index], state[j] = state[j], state[index]
    result = bytearray()
    i = j = 0
    for value in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        result.append(value ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(result)


def find_rc4_strings(data: bytes) -> tuple[DecodedRc4String, ...]:
    """Decode bounded fixture records: marker, key length, data length, payload."""
    found: list[DecodedRc4String] = []
    cursor = 0
    while True:
        offset = data.find(RC4_MARKER, cursor)
        if offset < 0:
            break
        header = offset + len(RC4_MARKER)
        if header + 3 > len(data):
            break
        key_length = data[header]
        data_length = int.from_bytes(data[header + 1 : header + 3], "little")
        payload = header + 3
        key = data[payload : payload + key_length]
        encoded = data[payload + key_length : payload + key_length + data_length]
        if not key or len(encoded) != data_length:
            break
        decoded = rc4_crypt(encoded, key)
        if len(decoded) >= 4 and all(0x20 <= value <= 0x7E for value in decoded):
            found.append(DecodedRc4String(offset=offset, key=key, value=decoded.decode()))
        cursor = payload + key_length + data_length
    return tuple(found)


class Rc4StringRule(ObfuscationRule):
    """Detect and recover statically tagged RC4 string records."""

    id = "reverse.string-rc4"
    tactic = "reverse.obfuscation.string-rc4"
    confidence = 0.94

    def evaluate(self, ctx: RuleContext):
        decoded = find_rc4_strings(fact_bytes(ctx))
        structure = detect_rc4_structure(fact_instructions(ctx))
        if not decoded and not structure:
            return []
        if not decoded:
            return [
                self.make_finding(
                    ctx,
                    title="RC4-like key scheduling structure detected",
                    description=(
                        "Static instruction features resemble RC4 KSA/PRGA, "
                        "but no key or plaintext was proven."
                    ),
                    evidence=structure,
                    severity=FindingSeverity.LOW,
                    confidence=0.62,
                    metadata={"algorithm": "rc4", "decoded": False},
                )
            ]
        evidence = [
            f"0x{item.offset:x}: key={item.key.hex()}, decoded={item.value!r}"
            for item in decoded[:8]
        ]
        return [
            self.make_finding(
                ctx,
                title="RC4-obfuscated strings recovered",
                description="Static RC4 decoding recovered printable embedded strings.",
                evidence=evidence,
                metadata={
                    "algorithm": "rc4",
                    "decoded": True,
                    "decoded_strings": [item.value for item in decoded],
                    "match_count": len(decoded),
                },
            )
        ]


def detect_rc4_structure(instructions: tuple[object, ...]) -> tuple[str, ...]:
    """Recognize architecture-neutral RC4 loop/swap/XOR instruction signals."""
    normalized = [instruction_parts(item) for item in instructions[:4096]]
    has_256_bound = any(
        mnemonic in {"cmp", "slti", "sub"}
        and any(token in operands for token in ("0x100", "256"))
        for _, mnemonic, operands in normalized
    )
    has_swap = any(
        mnemonic in {"xchg", "swap", "strb", "sb"}
        for _, mnemonic, _ in normalized
    )
    has_xor = any(
        mnemonic in {"xor", "eor", "xori"}
        for _, mnemonic, _ in normalized
    )
    signals = []
    if has_256_bound:
        signals.append("256-byte state loop")
    if has_swap:
        signals.append("state-byte swap")
    if has_xor:
        signals.append("keystream xor")
    return tuple(signals) if len(signals) == 3 else ()

"""Build deterministic local-only Phase-2 fixtures."""

from __future__ import annotations

from pathlib import Path

from build_mini_binaries import ROOT, build_x64_pe


def _rc4(data: bytes, key: bytes) -> bytes:
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


def _pe_with_payload(payload: bytes) -> bytes:
    image = bytearray(build_x64_pe())
    if len(payload) > 0x180:
        raise ValueError("fixture payload is too large")
    image[0x200 : 0x200 + len(payload)] = payload
    return bytes(image)


def build_obfuscation_fixtures() -> None:
    obfuscated = ROOT / "samples" / "obfuscated"
    normal = ROOT / "samples" / "normal"
    obfuscated.mkdir(parents=True, exist_ok=True)
    normal.mkdir(parents=True, exist_ok=True)

    xor_plaintext = b"staged-command.example"
    xor_key = 0x5A
    xor_record = (
        b"XORSTR\x01"
        + bytes([xor_key, len(xor_plaintext)])
        + bytes(value ^ xor_key for value in xor_plaintext)
    )

    rc4_plaintext = b"operator-token-fixture"
    rc4_key = b"phase2"
    rc4_record = (
        b"RC4STR\x01"
        + bytes([len(rc4_key)])
        + len(rc4_plaintext).to_bytes(2, "little")
        + rc4_key
        + _rc4(rc4_plaintext, rc4_key)
    )

    samples = {
        "cff_dispatcher_x64.exe": b"CFFMETA\x01" + bytes.fromhex(
            "83f800740a83f8017405ebf431c0ebf0c3"
        ),
        "opaque_predicate_x64.exe": b"OPAQUEMETA\x01"
        + bytes.fromhex("31c083f8007505b801000000c3"),
        "string_xor_x64.exe": bytes.fromhex("554889e5") + xor_record + b"\xc3",
        "string_rc4_x64.exe": bytes.fromhex("554889e5") + rc4_record + b"\xc3",
        "block_stats_x64.exe": b"BLOCKMETA\x01" + b"\xeb\x00" * 12 + b"\xc3",
    }
    for name, payload in samples.items():
        (obfuscated / name).write_bytes(_pe_with_payload(payload))

    (normal / "normal_x64.exe").write_bytes(
        _pe_with_payload(bytes.fromhex("554889e531c05dc3"))
    )


def main() -> None:
    build_obfuscation_fixtures()


if __name__ == "__main__":
    main()

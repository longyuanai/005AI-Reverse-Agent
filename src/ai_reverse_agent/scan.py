"""Integration-facing binary scan that emits a Finding JSON envelope."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from ai_reverse_agent.architecture import resolve_architecture
from ai_reverse_agent.crypto_id import identify_crypto
from ai_reverse_agent.disasm import disassemble


def scan_binary(payload: dict[str, Any]) -> dict[str, Any]:
    """Scan one binary described by the IntegrationGateway payload."""

    binary_path = payload.get("binary_path")
    architecture = payload.get("arch")
    if not isinstance(binary_path, str) or not binary_path.strip():
        return _error_envelope(
            "invalid_binary_path",
            "payload field 'binary_path' must be a non-empty string",
        )
    if not isinstance(architecture, str) or not architecture.strip():
        return _error_envelope(
            "invalid_architecture",
            "payload field 'arch' must be a non-empty string",
        )

    path = Path(binary_path).expanduser().resolve()
    if not path.is_file():
        return _error_envelope(
            "binary_not_found",
            f"binary does not exist or is not a file: {path}",
        )

    try:
        spec = resolve_architecture(architecture)
    except ValueError as exc:
        return _error_envelope("unsupported_architecture", str(exc))

    try:
        data = path.read_bytes()
        code, base_address, container = _extract_code(data)
        instructions = tuple(
            disassemble(
                code,
                spec.architecture,
                address=base_address,
                bits=spec.bits,
                endianness=spec.endianness,
                count=256,
            )
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return _error_envelope("analysis_failed", str(exc))

    findings = _security_findings(data, path)
    findings.append(
        {
            "id": _finding_id(data, "summary"),
            "severity": "info",
            "confidence": 0.95,
            "title": f"Disassembled {spec.architecture.value} binary",
            "host": str(path),
            "description": (
                f"Capstone decoded {len(instructions)} instructions from "
                f"{len(code)} executable bytes."
            ),
            "narrative": (
                f"container={container}; architecture={spec.label}; "
                f"instructions={len(instructions)}"
            ),
            "metadata": {
                "architecture": spec.architecture.value,
                "bits": spec.bits,
                "endianness": spec.endianness.value,
                "container": container,
                "instruction_count": len(instructions),
                "binary_size": len(data),
            },
        }
    )
    return {"findings": findings, "errors": []}


def _security_findings(data: bytes, path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    credential_markers = (
        b"admin:password123",
        b"password=",
        b"passwd=",
    )
    for marker in credential_markers:
        offset = data.lower().find(marker)
        if offset < 0:
            continue
        findings.append(
            {
                "id": _finding_id(data, f"credential:{offset}"),
                "severity": "high",
                "confidence": 0.85,
                "title": f"Hardcoded credential marker at 0x{offset:x}",
                "host": str(path),
                "description": "A plaintext credential marker is embedded in the binary.",
                "narrative": f"Embedded marker: {marker.decode('ascii')!r}",
                "evidence": [marker.decode("ascii")],
            }
        )

    for detection in identify_crypto(data):
        findings.append(
            {
                "id": _finding_id(
                    data,
                    f"crypto:{detection.algorithm}:{detection.offset}",
                ),
                "severity": "medium",
                "confidence": 0.95,
                "title": (
                    f"{detection.algorithm} {detection.constant} "
                    f"at 0x{detection.offset:x}"
                ),
                "host": str(path),
                "description": "A known cryptographic constant table was detected.",
                "narrative": (
                    f"endianness={detection.endianness or 'byte-table'}; "
                    f"length={detection.length}"
                ),
                "evidence": [detection.evidence_hex],
            }
        )
    return findings


def _extract_code(data: bytes) -> tuple[bytes, int, str]:
    if data.startswith(b"MZ"):
        extracted = _extract_pe_text(data)
        if extracted is not None:
            return (*extracted, "pe")
    if data.startswith(b"\x7fELF"):
        extracted = _extract_elf_body(data)
        if extracted is not None:
            return (*extracted, "elf")
    return data, 0, "raw"


def _extract_pe_text(data: bytes) -> tuple[bytes, int] | None:
    if len(data) < 0x40:
        return None
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None

    section_count = int.from_bytes(data[pe_offset + 6 : pe_offset + 8], "little")
    optional_size = int.from_bytes(data[pe_offset + 20 : pe_offset + 22], "little")
    section_table = pe_offset + 24 + optional_size
    for index in range(section_count):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            return None
        name = data[offset : offset + 8].rstrip(b"\0")
        characteristics = int.from_bytes(data[offset + 36 : offset + 40], "little")
        if name != b".text" and not characteristics & 0x20000000:
            continue
        raw_size = int.from_bytes(data[offset + 16 : offset + 20], "little")
        raw_offset = int.from_bytes(data[offset + 20 : offset + 24], "little")
        virtual_address = int.from_bytes(data[offset + 12 : offset + 16], "little")
        if raw_offset >= len(data):
            return None
        return data[raw_offset : raw_offset + raw_size], virtual_address
    return None


def _extract_elf_body(data: bytes) -> tuple[bytes, int] | None:
    if len(data) < 52 or data[4] not in {1, 2} or data[5] not in {1, 2}:
        return None
    byte_order = "little" if data[5] == 1 else "big"
    if data[4] == 1:
        header_size_offset = 40
        entry = int.from_bytes(data[24:28], byte_order)
    else:
        header_size_offset = 52
        entry = int.from_bytes(data[24:32], byte_order)
    header_size = int.from_bytes(
        data[header_size_offset : header_size_offset + 2],
        byte_order,
    )
    if header_size < 1 or header_size > len(data):
        return None
    return data[header_size:], entry


def _finding_id(data: bytes, kind: str) -> str:
    digest = hashlib.sha256(data + kind.encode("utf-8")).hexdigest()[:16]
    return f"rev-bin-{digest}"


def _error_envelope(code: str, message: str) -> dict[str, Any]:
    return {
        "findings": [],
        "errors": [{"code": code, "message": message}],
    }

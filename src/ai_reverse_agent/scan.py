"""Integration-facing binary scan that emits a Finding JSON envelope."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from shared_llm_core.rule_engine import RuleContext

from ai_reverse_agent.architecture import resolve_architecture
from ai_reverse_agent.backends import BinaryImage, BinaryLoader
from ai_reverse_agent.crypto_id import identify_crypto
from ai_reverse_agent.deobfuscation import build_reverse_rule_engine
from ai_reverse_agent.decompilers.selector import (
    DecompilerSelector,
    default_decompiler_selector,
)
from ai_reverse_agent.disasm import disassemble
from ai_reverse_agent.features import extract_features
from ai_reverse_agent.findings import imphash_finding
from ai_reverse_agent.hashing import compute_import_set_hash, compute_pe_imphash
from ai_reverse_agent.magic import MagicError


def scan_binary(
    payload: dict[str, Any],
    *,
    decompiler_selector: DecompilerSelector | None = None,
) -> dict[str, Any]:
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
        image = BinaryLoader().load(path)
        data = image.data
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
        decompiled = (decompiler_selector or default_decompiler_selector()).decompile(
            code,
            spec.architecture,
            address=base_address,
            bits=spec.bits,
            endianness=spec.endianness,
        )
    except MagicError as exc:
        return _error_envelope("magic_error", str(exc))
    except (OSError, RuntimeError, ValueError) as exc:
        return _error_envelope("analysis_failed", str(exc))

    feature_index = extract_features(
        image,
        instructions,
        architecture=spec.architecture.value,
    )
    findings = _security_findings(data, path)
    for finding in build_reverse_rule_engine().evaluate(
        RuleContext(str(path), feature_index.rule_facts())
    ):
        item = finding.to_dict()
        item["narrative"] = finding.description
        findings.append(item)
    summary_metadata = {
        "architecture": spec.architecture.value,
        "bits": spec.bits,
        "endianness": spec.endianness.value,
        "container": container,
        "instruction_count": len(instructions),
        "binary_size": len(data),
        "backend": image.backend,
        "decompiler_backend": (
            decompiled[0].backend if decompiled else "native"
        ),
        "decompiled_function_count": len(decompiled),
    }
    requested_enrichment = payload.get("enrich", ())
    if isinstance(requested_enrichment, (list, tuple, set)):
        requested = {str(value).lower() for value in requested_enrichment}
    else:
        requested = set()
    if requested & {
        "imphash",
        "pe_imphash",
        "import_set_hash",
        "iat_list",
    }:
        _apply_import_enrichment(
            image=image,
            path=path,
            requested=requested,
            findings=findings,
            summary_metadata=summary_metadata,
        )
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
            "metadata": summary_metadata,
        }
    )
    for finding in findings:
        metadata = finding.get("metadata")
        normalized_metadata = dict(metadata) if isinstance(metadata, dict) else {}
        normalized_metadata.setdefault(
            "decompiler_backend",
            summary_metadata["decompiler_backend"],
        )
        finding["metadata"] = normalized_metadata
    return {"findings": findings, "errors": []}


def _apply_import_enrichment(
    *,
    image: BinaryImage,
    path: Path,
    requested: set[str],
    findings: list[dict[str, Any]],
    summary_metadata: dict[str, Any],
) -> None:
    imported = image.imports
    if image.container not in {"pe", "elf"}:
        summary_metadata["iat_error"] = "unsupported container for IAT extraction"
        return

    summary_metadata["import_count"] = len(imported)
    summary_metadata["import_backend"] = image.backend
    if "iat_list" in requested:
        summary_metadata["iat_list"] = [
            {
                "library": item.library,
                "name": item.name,
                "hint": item.hint,
                "address": item.address,
                "ordinal": item.ordinal,
                "delayed": item.delayed,
            }
            for item in imported
        ]
    if requested & {"imphash", "import_set_hash"}:
        summary_metadata["import_set_hash"] = compute_import_set_hash(imported)
        summary_metadata["import_set_hash_algorithm"] = "import-set-md5-v1"
    if image.container == "pe" and requested & {"imphash", "pe_imphash"}:
        digest = compute_pe_imphash(imported)
        summary_metadata["pe_imphash"] = digest
        summary_metadata["pe_imphash_algorithm"] = "pe-imphash-v1"
        finding = imphash_finding(imported, host=str(path))
        if finding is not None:
            item = finding.to_dict()
            item["narrative"] = finding.description
            findings.append(item)


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
        program_offset = int.from_bytes(data[28:32], byte_order)
        program_entry_size = int.from_bytes(data[42:44], byte_order)
        program_count = int.from_bytes(data[44:46], byte_order)
    else:
        header_size_offset = 52
        entry = int.from_bytes(data[24:32], byte_order)
        program_offset = int.from_bytes(data[32:40], byte_order)
        program_entry_size = int.from_bytes(data[54:56], byte_order)
        program_count = int.from_bytes(data[56:58], byte_order)

    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        if program_entry_size < 32 or offset + program_entry_size > len(data):
            break
        program_type = int.from_bytes(data[offset : offset + 4], byte_order)
        if data[4] == 1:
            file_offset = int.from_bytes(data[offset + 4 : offset + 8], byte_order)
            virtual_address = int.from_bytes(
                data[offset + 8 : offset + 12],
                byte_order,
            )
            file_size = int.from_bytes(data[offset + 16 : offset + 20], byte_order)
            flags = int.from_bytes(data[offset + 24 : offset + 28], byte_order)
        else:
            flags = int.from_bytes(data[offset + 4 : offset + 8], byte_order)
            file_offset = int.from_bytes(data[offset + 8 : offset + 16], byte_order)
            virtual_address = int.from_bytes(
                data[offset + 16 : offset + 24],
                byte_order,
            )
            file_size = int.from_bytes(data[offset + 32 : offset + 40], byte_order)
        if program_type == 1 and flags & 1 and file_offset < len(data):
            return (
                data[file_offset : file_offset + file_size],
                virtual_address,
            )

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

from __future__ import annotations

import struct

from click.testing import CliRunner

from ai_reverse_agent.cli import cli
from ai_reverse_agent.crypto_id import (
    AES_SBOX,
    SHA1_INITIAL_STATE,
    SHA256_K_PREFIX,
    format_crypto_detections,
    identify_crypto,
    identify_crypto_file,
)


def test_detects_complete_aes_sbox_at_offset() -> None:
    detections = identify_crypto(b"\x90" * 7 + AES_SBOX + b"\x00")

    assert len(detections) == 1
    assert detections[0].algorithm == "AES"
    assert detections[0].constant == "S-box"
    assert detections[0].offset == 7
    assert detections[0].endianness is None


def test_detects_little_endian_sha256_constants() -> None:
    encoded = struct.pack("<8I", *SHA256_K_PREFIX)

    detections = identify_crypto(encoded)

    assert [(item.algorithm, item.endianness) for item in detections] == [
        ("SHA-256", "little")
    ]


def test_detects_big_endian_sha256_constants() -> None:
    encoded = struct.pack(">8I", *SHA256_K_PREFIX)

    detections = identify_crypto(b"prefix" + encoded)

    assert detections[0].algorithm == "SHA-256"
    assert detections[0].offset == 6
    assert detections[0].endianness == "big"


def test_detects_sha1_initial_state() -> None:
    encoded = struct.pack("<5I", *SHA1_INITIAL_STATE)

    detections = identify_crypto(encoded)

    assert len(detections) == 1
    assert detections[0].algorithm == "SHA-1"
    assert detections[0].constant == "initial state"


def test_unknown_data_returns_no_detections() -> None:
    assert identify_crypto(bytes(range(64))) == ()


def test_detects_multiple_algorithms_in_position_order() -> None:
    sha1 = struct.pack(">5I", *SHA1_INITIAL_STATE)
    data = sha1 + b"\x00" * 3 + AES_SBOX

    detections = identify_crypto(data)

    assert [item.algorithm for item in detections] == ["SHA-1", "AES"]
    assert [item.offset for item in detections] == [0, len(sha1) + 3]


def test_file_api_and_formatter_include_evidence(tmp_path) -> None:
    sample = tmp_path / "sha256.bin"
    sample.write_bytes(b"\xff" * 4 + struct.pack("<8I", *SHA256_K_PREFIX))

    report = format_crypto_detections(identify_crypto_file(sample))

    assert "Detected algorithms: 1" in report
    assert "0x4 SHA-256 K constants prefix" in report
    assert "endian=little" in report
    assert "evidence=982f8a42" in report


def test_cli_crypto_id_reports_algorithm_and_location(tmp_path) -> None:
    sample = tmp_path / "aes.bin"
    sample.write_bytes(b"\x00" * 11 + AES_SBOX)

    result = CliRunner().invoke(cli, ["crypto-id", str(sample)])

    assert result.exit_code == 0
    assert "0xb AES S-box" in result.output
    assert "endian=byte-table" in result.output

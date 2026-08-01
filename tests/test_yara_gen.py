"""Deterministic YARA rule generation coverage."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from ai_reverse_agent.backends import BinaryImage, BinaryLoader
from ai_reverse_agent.cli import cli
from ai_reverse_agent.features import extract_features
from ai_reverse_agent.magic import MAX_STATIC_FILE_SIZE, MagicError
from ai_reverse_agent.yara_gen import (
    YaraGenerationError,
    escape_yara_string,
    generate_yara_for_file,
    generate_yara_rule,
    sanitize_rule_name,
)


ROOT = Path(__file__).resolve().parents[1]
PE_FIXTURE = ROOT / "samples" / "pe" / "mini_x64_pe.exe"


def _raw_features(data: bytes, tmp_path: Path):
    path = tmp_path / "sample.bin"
    image = BinaryImage(path, data, "raw", "raw")
    return extract_features(image, (), architecture="x64")


def test_rule_name_is_sanitized_and_bounded():
    assert sanitize_rule_name(" 123 bad/name! ") == "sample_123_bad_name"
    assert len(sanitize_rule_name("x" * 200)) == 128


def test_empty_rule_name_has_stable_fallback():
    assert sanitize_rule_name("///") == "binary"


def test_yara_string_escaping_is_safe():
    assert escape_yara_string('a"b\\c\n') == 'a\\"b\\\\c\\n'


def test_yara_string_escaping_uses_utf8_bytes():
    assert escape_yara_string("龙") == "\\xe9\\xbe\\x99"


def test_generation_is_deterministic_for_same_features():
    image = BinaryLoader().load(PE_FIXTURE)
    features = extract_features(image, (), architecture="x64")
    first = generate_yara_rule(features, source_name=PE_FIXTURE.name)
    second = generate_yara_rule(features, source_name=PE_FIXTURE.name)
    assert first == second


def test_pe_rule_uses_standard_pe_imphash():
    generated = generate_yara_for_file(PE_FIXTURE, architecture="x64")
    assert generated.imports == ("pe",)
    assert generated.metadata["pe_imphash"] == (
        "c1f0cda7bd39190d4154ba8e2d3b3480"
    )
    assert 'pe.imphash() == "c1f0cda7bd39190d4154ba8e2d3b3480"' in (
        generated.condition
    )


def test_pe_rule_records_import_set_hash_as_metadata_only():
    generated = generate_yara_for_file(PE_FIXTURE, architecture="x64")
    assert generated.metadata["import_set_hash"] == (
        "80b4fb3d5cced084a47675fec05e4d48"
    )
    assert "import_set_hash" not in generated.condition


def test_selected_strings_respect_maximum():
    generated = generate_yara_for_file(
        PE_FIXTURE,
        architecture="x64",
        max_strings=3,
    )
    assert 1 <= len(generated.strings) <= 3
    assert [item.identifier for item in generated.strings] == [
        f"s{index}" for index in range(1, len(generated.strings) + 1)
    ]


def test_pe_strings_prefer_clean_import_names():
    generated = generate_yara_for_file(PE_FIXTURE, architecture="x64")
    values = [item.value for item in generated.strings]
    assert set(values[:5]) == {
        "RegOpenKeyExW",
        "CreateFileW",
        "MessageBoxW",
        "connect",
        "printf",
    }
    assert values == [
        item.value
        for item in generate_yara_for_file(PE_FIXTURE, architecture="x64").strings
    ]
    assert all(not value.startswith(("`.", "@.")) for value in values)


def test_raw_rule_uses_two_strings_and_size_bounds(tmp_path: Path):
    data = b"operator-command.example\0unique-config-token-42\0"
    generated = generate_yara_rule(
        _raw_features(data, tmp_path),
        source_name="raw.bin",
    )
    assert generated.imports == ()
    assert "import_set_hash" not in generated.metadata
    assert "2 of ($s*)" in generated.condition
    assert "filesize >=" in generated.condition


def test_exact_hash_fallback_for_feature_poor_binary(tmp_path: Path):
    generated = generate_yara_rule(
        _raw_features(b"\x00\x01\x02\x03", tmp_path),
        source_name="tiny.bin",
    )
    assert generated.imports == ("hash",)
    assert "hash.sha256(0, filesize)" in generated.condition


def test_feature_poor_binary_can_refuse_exact_fallback(tmp_path: Path):
    with pytest.raises(YaraGenerationError, match="not enough stable features"):
        generate_yara_rule(
            _raw_features(b"\x00\x01\x02\x03", tmp_path),
            source_name="tiny.bin",
            exact_fallback=False,
        )


@pytest.mark.parametrize("value", [0, 65])
def test_max_strings_has_hard_bounds(tmp_path: Path, value: int):
    with pytest.raises(YaraGenerationError, match="max_strings"):
        generate_yara_rule(
            _raw_features(b"stable-marker-value", tmp_path),
            source_name="sample.bin",
            max_strings=value,
        )


def test_empty_binary_is_rejected(tmp_path: Path):
    with pytest.raises(YaraGenerationError, match="empty binary"):
        generate_yara_rule(
            _raw_features(b"", tmp_path),
            source_name="empty.bin",
        )


def test_file_loader_preserves_one_hundred_mib_guard(tmp_path: Path):
    oversized = tmp_path / "oversized.bin"
    with oversized.open("wb") as stream:
        stream.seek(MAX_STATIC_FILE_SIZE)
        stream.write(b"\0")
    with pytest.raises(MagicError, match="exceeds 100 MiB"):
        generate_yara_for_file(oversized, architecture="x64")


def test_cli_writes_rule_to_stdout():
    result = CliRunner().invoke(
        cli,
        ["generate-yara", str(PE_FIXTURE), "--arch", "x64"],
    )
    assert result.exit_code == 0, result.output
    assert "rule longyuanai_mini_x64_pe_" in result.output
    assert 'import "pe"' in result.output


def test_cli_writes_rule_file(tmp_path: Path):
    output = tmp_path / "sample.yar"
    result = CliRunner().invoke(
        cli,
        [
            "generate-yara",
            str(PE_FIXTURE),
            "--arch",
            "x64",
            "--rule-name",
            "phase2-fixture",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    assert output.read_text(encoding="utf-8").startswith('import "pe"\n')
    assert "rule phase2_fixture" in output.read_text(encoding="utf-8")


def test_rule_has_balanced_top_level_braces():
    generated = generate_yara_for_file(PE_FIXTURE, architecture="x64")
    assert generated.text.count("{") == 1
    assert generated.text.count("}") == 1
    assert "    meta:\n" in generated.text
    assert "    condition:\n" in generated.text

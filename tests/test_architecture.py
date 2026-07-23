"""Tests for architecture normalization and PE machine detection."""

from __future__ import annotations

import pytest

from ai_reverse_agent.architecture import (
    Architecture,
    Endianness,
    architecture_from_pe_machine,
    resolve_architecture,
)
from ai_reverse_agent.fake_pe import make_fake_pe
from ai_reverse_agent.parsers import parse_pe_bytes


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("x86", Architecture.X86),
        ("x64", Architecture.X64),
        ("arm", Architecture.ARM),
        ("aarch64", Architecture.AARCH64),
        ("mips", Architecture.MIPS),
        ("riscv", Architecture.RISCV),
    ],
)
def test_resolves_all_stage_architectures(name, expected):
    assert resolve_architecture(name).architecture is expected


@pytest.mark.parametrize(
    ("alias", "expected", "bits"),
    [
        ("i686", Architecture.X86, 32),
        ("AMD64", Architecture.X64, 64),
        ("arm64", Architecture.AARCH64, 64),
        ("mips64", Architecture.MIPS, 64),
        ("riscv32", Architecture.RISCV, 32),
    ],
)
def test_resolves_common_aliases(alias, expected, bits):
    spec = resolve_architecture(alias)
    assert spec.architecture is expected
    assert spec.bits == bits


def test_supports_big_endian_mips():
    spec = resolve_architecture("mips", endianness="big")
    assert spec.endianness is Endianness.BIG


def test_rejects_big_endian_x86():
    with pytest.raises(ValueError, match="little-endian"):
        resolve_architecture("x86", endianness="big")


@pytest.mark.parametrize(
    ("machine", "expected", "bits"),
    [
        (0x014C, Architecture.X86, 32),
        (0x8664, Architecture.X64, 64),
        (0x01C4, Architecture.ARM, 32),
        (0xAA64, Architecture.AARCH64, 64),
        (0x0166, Architecture.MIPS, 32),
        (0x5064, Architecture.RISCV, 64),
    ],
)
def test_maps_pe_machine_types(machine, expected, bits):
    spec = architecture_from_pe_machine(machine)
    assert spec.architecture is expected
    assert spec.bits == bits


def test_rejects_unknown_architecture_and_machine():
    with pytest.raises(ValueError, match="Unsupported architecture"):
        resolve_architecture("sparc")
    with pytest.raises(ValueError, match="Unsupported PE machine"):
        architecture_from_pe_machine(0xFFFF)


def test_fake_pe_roundtrip_reports_x64():
    pe = parse_pe_bytes(make_fake_pe())
    assert pe.architecture.architecture is Architecture.X64
    assert pe.architecture.bits == 64
    assert pe.to_prompt_dict()["architecture"] == "x64"

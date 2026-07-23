"""Tests for minimal ELF fixtures and architecture detection."""

from __future__ import annotations

import pytest

from ai_reverse_agent.architecture import Architecture, detect_elf_architecture
from ai_reverse_agent.fake_elf import make_fake_elf


@pytest.mark.parametrize("architecture", list(Architecture))
def test_fake_elf_roundtrips_architecture(architecture):
    fixture = make_fake_elf(architecture)
    spec = detect_elf_architecture(fixture)
    assert fixture.startswith(b"\x7fELF")
    assert spec.architecture is architecture


def test_fake_elf_uses_expected_class_width():
    assert make_fake_elf("x86")[4] == 1
    assert make_fake_elf("aarch64")[4] == 2


def test_detect_elf_rejects_invalid_header():
    with pytest.raises(ValueError, match="Not an ELF"):
        detect_elf_architecture(b"not-elf")

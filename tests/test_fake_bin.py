"""Tests for deterministic raw architecture fixtures."""

from __future__ import annotations

import pytest

from ai_reverse_agent.architecture import Architecture
from ai_reverse_agent.disasm import disassemble
from ai_reverse_agent.fake_bin import FAKE_BINARIES, make_fake_bin, write_fake_bins


def test_fixture_covers_six_architectures():
    assert set(FAKE_BINARIES) == set(Architecture)


@pytest.mark.parametrize("architecture", list(Architecture))
def test_each_fixture_decodes_to_three_instructions(architecture):
    instructions = list(disassemble(make_fake_bin(architecture), architecture))
    assert len(instructions) == 3
    assert instructions[-1].mnemonic in {"ret", "bx", "jr"}


def test_write_fake_bins_creates_six_bin_files(tmp_path):
    paths = write_fake_bins(tmp_path)
    assert len(paths) == 6
    assert all(path.suffix == ".bin" and path.read_bytes() for path in paths)


def test_make_fake_bin_accepts_aliases():
    assert make_fake_bin("amd64") == make_fake_bin("x64")

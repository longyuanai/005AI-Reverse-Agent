"""Package-level import contract and scan-envelope robustness."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import ai_reverse_agent
from ai_reverse_agent.iat import DATABASE_PATH_ENV
from ai_reverse_agent.scan import scan_binary


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
MINI_X64_PE = ROOT / "samples" / "mini_binaries" / "mini_x64_pe.exe"
# Note: a second, different file shares this name under samples/pe/. Only that
# one carries an import directory, so imphash assertions have to use it.
PE_WITH_IMPORTS = ROOT / "samples" / "pe" / "mini_x64_pe.exe"


def test_importing_the_package_does_not_pull_in_shared_llm_core():
    """Regression: eager re-exports made every test module unimportable."""
    probe = (
        "import sys; import ai_reverse_agent; "
        "assert 'shared_llm_core' not in sys.modules, sorted(sys.modules); "
        "print(ai_reverse_agent.__version__)"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"},
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ai_reverse_agent.__version__


def test_importing_the_package_does_not_pull_in_capstone():
    """Lazy exports also keep the import cheap for consumers that only parse."""
    probe = "import sys, ai_reverse_agent; assert 'capstone' not in sys.modules"
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"},
    )

    assert result.returncode == 0, result.stderr


def test_static_analysis_names_resolve_lazily():
    assert ai_reverse_agent.resolve_architecture("amd64").bits == 64
    assert ai_reverse_agent.identify_crypto(b"") == ()
    assert callable(ai_reverse_agent.disassemble)


def test_unknown_attribute_still_raises_attribute_error():
    missing = "not_a_real_name"

    with pytest.raises(AttributeError, match="no attribute 'not_a_real_name'"):
        getattr(ai_reverse_agent, missing)


def test_public_names_are_all_resolvable_or_need_the_suite():
    unresolved = []
    for name in ai_reverse_agent.__all__:
        try:
            getattr(ai_reverse_agent, name)
        except ImportError as exc:
            # Only the three shared-llm-core modules may fail, and they must
            # explain themselves rather than surfacing a bare ModuleNotFound.
            assert "shared-llm-core" in str(exc), name
            unresolved.append(name)

    assert set(unresolved) <= {
        "ReverseProductAdapter",
        "explain_functions",
        "imphash_finding",
    }


def test_scan_survives_an_unavailable_imphash_database(monkeypatch, tmp_path: Path):
    """Regression: a missing fixture DB used to escape as FileNotFoundError."""
    monkeypatch.setenv(DATABASE_PATH_ENV, str(tmp_path / "absent.json"))

    envelope = scan_binary(
        {
            "binary_path": str(PE_WITH_IMPORTS),
            "arch": "x64",
            "enrich": ["imphash"],
        }
    )

    assert envelope["errors"] == []
    summary = envelope["findings"][-1]["metadata"]
    # The digest is still computed; only the comparison is skipped.
    assert summary["imphash"] == "80b4fb3d5cced084a47675fec05e4d48"
    assert "imphash_error" in summary


def test_scan_cli_reports_internal_errors_inside_the_envelope(monkeypatch):
    """The gateway parses stdout as JSON, so nothing may escape as a traceback."""
    from click.testing import CliRunner

    from ai_reverse_agent import cli as cli_module

    def _boom(_payload):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(cli_module, "scan_binary", _boom)
    result = CliRunner().invoke(
        cli_module.cli,
        [
            "scan",
            "--input",
            json.dumps({"binary_path": str(MINI_X64_PE), "arch": "x64"}),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert envelope["findings"] == []
    assert envelope["errors"][0]["code"] == "internal_error"
    assert "synthetic failure" in envelope["errors"][0]["message"]

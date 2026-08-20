"""Contract tests for the decompiler seam."""

from __future__ import annotations

import inspect

import ai_reverse_agent
from ai_reverse_agent.decompiler import decompile_bytes, format_decompilation
from ai_reverse_agent.decompilers.native import NativeDecompilerBackend
from ai_reverse_agent.decompilers.selector import DecompilerSelector


class _UnavailableBackend:
    name = "unavailable"

    def available(self) -> bool:
        return False

    def decompile(self, image, architecture, **kwargs):  # pragma: no cover
        raise AssertionError("unavailable backend must not be called")


class _RecordingBackend:
    name = "recording"

    def __init__(self) -> None:
        self.calls = 0

    def available(self) -> bool:
        return True

    def decompile(self, image, architecture, **kwargs):
        self.calls += 1
        return ()


def test_native_backend_is_always_available() -> None:
    assert NativeDecompilerBackend().available() is True


def test_selector_skips_unavailable_backend() -> None:
    available = _RecordingBackend()
    selector = DecompilerSelector((_UnavailableBackend(), available))

    selector.decompile(b"\xc3", "x64")

    assert available.calls == 1


def test_selector_falls_back_to_native() -> None:
    selector = DecompilerSelector((_UnavailableBackend(), NativeDecompilerBackend()))

    functions = selector.decompile(b"\xc3", "x64")

    assert len(functions) == 1
    assert functions[0].pseudo_c == "void sub_0(void) {\n    /* 0x0 */ return;\n}"


def test_public_api_symbols_unchanged() -> None:
    expected = {
        "DecompiledFunction",
        "FunctionBoundary",
        "StackVariable",
        "decompile_bytes",
        "decompile_function",
        "find_function_boundaries",
        "format_decompilation",
        "identify_stack_variables",
    }
    assert expected <= set(ai_reverse_agent.__all__)
    assert all(hasattr(ai_reverse_agent, name) for name in expected)

    signature = inspect.signature(ai_reverse_agent.decompile_bytes)
    assert tuple(signature.parameters) == (
        "data",
        "architecture",
        "address",
        "bits",
        "endianness",
        "thumb",
        "recognize_libraries",
    )
    assert signature.parameters["address"].kind is inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["address"].default == 0
    assert signature.parameters["bits"].default is None
    assert signature.parameters["thumb"].default is False
    assert signature.parameters["recognize_libraries"].default is True


def test_native_output_matches_pre_refactor() -> None:
    code = bytes.fromhex("55 48 89 e5 48 89 7d f8 48 8b 45 f8 c3")
    expected = """void sub_401000(void) {
    uintptr_t var_8; /* stack offset -0x8 */
    /* 0x401000 */ /* push rbp */
    /* 0x401001 */ rbp = rsp;
    /* 0x401004 */ var_8 = rdi;
    /* 0x401008 */ rax = var_8;
    /* 0x40100c */ return;
}
"""

    actual = format_decompilation(decompile_bytes(code, "x64", address=0x401000))

    assert actual == expected

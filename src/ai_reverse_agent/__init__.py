"""AI-Reverse-Agent: multi-architecture disassembly + LLM function analysis.

Capstone decodes raw binaries for x86, x64, ARM, AArch64, MIPS, and
RISC-V. The original PoC path still parses a synthetic PE fixture,
identifies imported and local functions, asks shared-llm-core for
one-line purposes, and emits a Markdown report.

Public names are resolved lazily (PEP 562). The static-analysis layers
(architecture, disassembly, decompilation, CFG, crypto constants, IAT)
depend only on Capstone, so importing them must not drag in
``shared-llm-core``. Only ``analyzer``, ``adapter``, and ``findings``
need the shared suite package, and they are imported on first access.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

__version__ = "0.1.0"


# Public name -> defining submodule. Attribute access imports the module on
# demand, so `import ai_reverse_agent` never costs a Capstone or LLM import.
_EXPORTS: dict[str, str] = {
    # architecture
    "Architecture": "architecture",
    "ArchitectureSpec": "architecture",
    "Endianness": "architecture",
    "architecture_from_pe_machine": "architecture",
    "detect_elf_architecture": "architecture",
    "resolve_architecture": "architecture",
    # datatypes
    "EnrichedFunction": "datatypes",
    "IdentifiedFunction": "datatypes",
    "PeImage": "datatypes",
    # disassembler
    "DisassembledInstruction": "disassembler",
    "DisassemblyError": "disassembler",
    "DisassemblyResult": "disassembler",
    "disassemble_bytes": "disassembler",
    "disassemble_file": "disassembler",
    "format_disassembly": "disassembler",
    # disasm
    "NormalizedInstruction": "disasm",
    "disassemble": "disasm",
    # decompiler
    "DecompiledFunction": "decompiler",
    "FunctionBoundary": "decompiler",
    "StackVariable": "decompiler",
    "decompile_bytes": "decompiler",
    "decompile_function": "decompiler",
    "find_function_boundaries": "decompiler",
    "format_decompilation": "decompiler",
    "identify_stack_variables": "decompiler",
    # controlflow
    "BasicBlock": "controlflow",
    "ControlFlowEdge": "controlflow",
    "ControlFlowGraph": "controlflow",
    "GraphvizUnavailable": "controlflow",
    "build_cfg": "controlflow",
    "render_png": "controlflow",
    "to_dot": "controlflow",
    # fixtures + PoC pipeline
    "make_fake_pe": "fake_pe",
    "identify_functions": "identifier",
    "parse_pe": "parsers",
    "parse_pe_bytes": "parsers",
    "render_markdown": "reporter",
    # signatures
    "BUILTIN_SIGNATURES": "signatures",
    "LibrarySignature": "signatures",
    "SignatureMatch": "signatures",
    "match_code": "signatures",
    "match_instructions": "signatures",
    "signature_bytes": "signatures",
    # symbolic
    "BinaryExpression": "symbolic",
    "Constant": "symbolic",
    "Constraint": "symbolic",
    "Expression": "symbolic",
    "Symbol": "symbolic",
    "SymbolicBackendUnavailable": "symbolic",
    "SymbolicError": "symbolic",
    "SymbolicSolution": "symbolic",
    "loop_value": "symbolic",
    "solve_branch": "symbolic",
    "symbolic_input": "symbolic",
    # patch diff
    "FunctionDiff": "patch_diff",
    "InstructionDelta": "patch_diff",
    "PatchDiffResult": "patch_diff",
    "diff_binaries": "patch_diff",
    "diff_files": "patch_diff",
    "format_patch_diff": "patch_diff",
    # crypto constants
    "AES_SBOX": "crypto_id",
    "SHA1_INITIAL_STATE": "crypto_id",
    "SHA256_K_PREFIX": "crypto_id",
    "CryptoDetection": "crypto_id",
    "format_crypto_detections": "crypto_id",
    "identify_crypto": "crypto_id",
    "identify_crypto_file": "crypto_id",
    # imports / imphash
    "ImportedSymbol": "iat",
    "MalwareImphashDB": "iat",
    "compute_imphash": "iat",
    "extract_elf_imports": "iat",
    "extract_pe_imports": "iat",
    # --- names below require shared-llm-core ---
    "explain_functions": "analyzer",
    "ReverseProductAdapter": "adapter",
    "imphash_finding": "findings",
}

# Submodules that cannot be imported without the shared suite package.
_SHARED_CORE_MODULES = frozenset({"analyzer", "adapter", "findings"})

__all__ = ["__version__", *sorted(_EXPORTS)]


def __getattr__(name: str) -> object:
    """Import the defining submodule on first access to a public name."""
    try:
        module_name = _EXPORTS[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None

    from importlib import import_module

    try:
        module = import_module(f"{__name__}.{module_name}")
    except ModuleNotFoundError as exc:
        if module_name in _SHARED_CORE_MODULES and exc.name == "shared_llm_core":
            raise ImportError(
                f"{name!r} lives in ai_reverse_agent.{module_name}, which requires "
                "the 'shared-llm-core' package. Install the suite dependency, or use "
                "the static-analysis API (disassemble, decompile_bytes, build_cfg, "
                "identify_crypto, extract_pe_imports), which has no such requirement."
            ) from exc
        raise

    value = getattr(module, name)
    globals()[name] = value  # cache so later lookups skip __getattr__
    return value


def __dir__() -> list[str]:
    return sorted(__all__)


if TYPE_CHECKING:  # pragma: no cover - static typing support only
    from ai_reverse_agent.adapter import ReverseProductAdapter
    from ai_reverse_agent.analyzer import explain_functions
    from ai_reverse_agent.architecture import (
        Architecture,
        ArchitectureSpec,
        Endianness,
        architecture_from_pe_machine,
        detect_elf_architecture,
        resolve_architecture,
    )
    from ai_reverse_agent.controlflow import (
        BasicBlock,
        ControlFlowEdge,
        ControlFlowGraph,
        GraphvizUnavailable,
        build_cfg,
        render_png,
        to_dot,
    )
    from ai_reverse_agent.crypto_id import (
        AES_SBOX,
        SHA1_INITIAL_STATE,
        SHA256_K_PREFIX,
        CryptoDetection,
        format_crypto_detections,
        identify_crypto,
        identify_crypto_file,
    )
    from ai_reverse_agent.datatypes import (
        EnrichedFunction,
        IdentifiedFunction,
        PeImage,
    )
    from ai_reverse_agent.decompiler import (
        DecompiledFunction,
        FunctionBoundary,
        StackVariable,
        decompile_bytes,
        decompile_function,
        find_function_boundaries,
        format_decompilation,
        identify_stack_variables,
    )
    from ai_reverse_agent.disasm import NormalizedInstruction, disassemble
    from ai_reverse_agent.disassembler import (
        DisassembledInstruction,
        DisassemblyError,
        DisassemblyResult,
        disassemble_bytes,
        disassemble_file,
        format_disassembly,
    )
    from ai_reverse_agent.fake_pe import make_fake_pe
    from ai_reverse_agent.findings import imphash_finding
    from ai_reverse_agent.iat import (
        ImportedSymbol,
        MalwareImphashDB,
        compute_imphash,
        extract_elf_imports,
        extract_pe_imports,
    )
    from ai_reverse_agent.identifier import identify_functions
    from ai_reverse_agent.parsers import parse_pe, parse_pe_bytes
    from ai_reverse_agent.patch_diff import (
        FunctionDiff,
        InstructionDelta,
        PatchDiffResult,
        diff_binaries,
        diff_files,
        format_patch_diff,
    )
    from ai_reverse_agent.reporter import render_markdown
    from ai_reverse_agent.signatures import (
        BUILTIN_SIGNATURES,
        LibrarySignature,
        SignatureMatch,
        match_code,
        match_instructions,
        signature_bytes,
    )
    from ai_reverse_agent.symbolic import (
        BinaryExpression,
        Constant,
        Constraint,
        Expression,
        Symbol,
        SymbolicBackendUnavailable,
        SymbolicError,
        SymbolicSolution,
        loop_value,
        solve_branch,
        symbolic_input,
    )

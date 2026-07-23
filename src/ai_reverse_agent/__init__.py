"""AI-Reverse-Agent: multi-architecture disassembly + LLM function analysis.

Capstone decodes raw binaries for x86, x64, ARM, AArch64, MIPS, and
RISC-V. The original PoC path still parses a synthetic PE fixture,
identifies imported and local functions, asks shared-llm-core for
one-line purposes, and emits a Markdown report.
"""

from ai_reverse_agent.analyzer import explain_functions
from ai_reverse_agent.architecture import (
    Architecture,
    ArchitectureSpec,
    Endianness,
    architecture_from_pe_machine,
    detect_elf_architecture,
    resolve_architecture,
)
from ai_reverse_agent.datatypes import (
    EnrichedFunction,
    IdentifiedFunction,
    PeImage,
)
from ai_reverse_agent.disassembler import (
    DisassembledInstruction,
    DisassemblyError,
    DisassemblyResult,
    disassemble_bytes,
    disassemble_file,
    format_disassembly,
)
from ai_reverse_agent.disasm import NormalizedInstruction
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
from ai_reverse_agent.controlflow import (
    BasicBlock,
    ControlFlowEdge,
    ControlFlowGraph,
    GraphvizUnavailable,
    build_cfg,
    render_png,
    to_dot,
)
from ai_reverse_agent.fake_pe import make_fake_pe
from ai_reverse_agent.identifier import identify_functions
from ai_reverse_agent.parsers import parse_pe, parse_pe_bytes
from ai_reverse_agent.reporter import render_markdown
from ai_reverse_agent.signatures import (
    BUILTIN_SIGNATURES,
    LibrarySignature,
    SignatureMatch,
    match_code,
    match_instructions,
    signature_bytes,
)

__version__ = "0.1.0"

__all__ = [
    "Architecture",
    "ArchitectureSpec",
    "BasicBlock",
    "BUILTIN_SIGNATURES",
    "DisassembledInstruction",
    "DisassemblyError",
    "DisassemblyResult",
    "ControlFlowEdge",
    "ControlFlowGraph",
    "DecompiledFunction",
    "Endianness",
    "EnrichedFunction",
    "IdentifiedFunction",
    "LibrarySignature",
    "FunctionBoundary",
    "GraphvizUnavailable",
    "NormalizedInstruction",
    "PeImage",
    "StackVariable",
    "SignatureMatch",
    "__version__",
    "architecture_from_pe_machine",
    "build_cfg",
    "detect_elf_architecture",
    "decompile_bytes",
    "decompile_function",
    "disassemble_bytes",
    "disassemble_file",
    "explain_functions",
    "identify_functions",
    "make_fake_pe",
    "match_code",
    "match_instructions",
    "parse_pe",
    "parse_pe_bytes",
    "render_markdown",
    "render_png",
    "resolve_architecture",
    "signature_bytes",
    "to_dot",
    "format_disassembly",
    "find_function_boundaries",
    "format_decompilation",
    "identify_stack_variables",
]

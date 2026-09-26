"""AI-Reverse-Agent: multi-architecture disassembly + LLM function analysis.

Capstone decodes raw binaries for x86, x64, ARM, AArch64, MIPS, and
RISC-V. The original PoC path still parses a synthetic PE fixture,
identifies imported and local functions, asks shared-llm-core for
one-line purposes, and emits a Markdown report.
"""

from ai_reverse_agent.analyzer import (
    explain_decompiled_function,
    explain_decompiled_functions,
    explain_functions,
)
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
from ai_reverse_agent.patch_diff import (
    FunctionDiff,
    InstructionDelta,
    PatchDiffResult,
    diff_binaries,
    diff_files,
    format_patch_diff,
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
from ai_reverse_agent.adapter import ReverseProductAdapter
from ai_reverse_agent.yara_gen import (
    GeneratedYaraRule,
    YaraGenerationError,
    YaraString,
    generate_yara_for_file,
    generate_yara_rule,
)

__version__ = "0.1.0"

__all__ = [
    "AES_SBOX",
    "BUILTIN_SIGNATURES",
    "SHA1_INITIAL_STATE",
    "SHA256_K_PREFIX",
    "Architecture",
    "ArchitectureSpec",
    "BasicBlock",
    "BinaryExpression",
    "Constant",
    "Constraint",
    "ControlFlowEdge",
    "ControlFlowGraph",
    "CryptoDetection",
    "DecompiledFunction",
    "DisassembledInstruction",
    "DisassemblyError",
    "DisassemblyResult",
    "Endianness",
    "EnrichedFunction",
    "Expression",
    "FunctionBoundary",
    "FunctionDiff",
    "GeneratedYaraRule",
    "GraphvizUnavailable",
    "IdentifiedFunction",
    "InstructionDelta",
    "LibrarySignature",
    "NormalizedInstruction",
    "PatchDiffResult",
    "PeImage",
    "ReverseProductAdapter",
    "SignatureMatch",
    "StackVariable",
    "Symbol",
    "SymbolicBackendUnavailable",
    "SymbolicError",
    "SymbolicSolution",
    "YaraGenerationError",
    "YaraString",
    "__version__",
    "architecture_from_pe_machine",
    "build_cfg",
    "decompile_bytes",
    "decompile_function",
    "detect_elf_architecture",
    "diff_binaries",
    "diff_files",
    "disassemble_bytes",
    "disassemble_file",
    "explain_decompiled_function",
    "explain_decompiled_functions",
    "explain_functions",
    "find_function_boundaries",
    "format_crypto_detections",
    "format_decompilation",
    "format_disassembly",
    "format_patch_diff",
    "generate_yara_for_file",
    "generate_yara_rule",
    "identify_crypto",
    "identify_crypto_file",
    "identify_functions",
    "identify_stack_variables",
    "loop_value",
    "make_fake_pe",
    "match_code",
    "match_instructions",
    "parse_pe",
    "parse_pe_bytes",
    "render_markdown",
    "render_png",
    "resolve_architecture",
    "signature_bytes",
    "solve_branch",
    "symbolic_input",
    "to_dot",
]

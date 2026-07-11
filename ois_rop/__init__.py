"""
OIS-ROP: Offset Instruction Set with Return-Oriented Programming

Expresses arbitrary payloads as coordinate references into signed
system binaries, with optional ROP chain execution using only
gadgets found within those binaries.

Components:
    compiler        - OIS format compiler, assembler, parser, executor
    gadgets         - ROP gadget finder and chain builder (Windows runtime)
    executor        - Complete ROP-based execution engine (Windows runtime)
    scanner         - PE-based gadget scanner (cross-platform, offline)
    taxonomy        - Gadget classification by capability
    chain_compiler  - High-level intent → ROP chain compilation
"""

from .compiler import (
    OISCompiler,
    OISAssembler,
    OISParser,
    OISPayload,
    ByteReference,
    SubstrateManager,
)

from .scanner import PEGadgetScanner, ScannedGadget, ScanResult, scan_pe
from .taxonomy import GadgetClassifier, GadgetClass, Taxonomy, ClassifiedGadget
from .chain_compiler import (
    ChainCompiler, Call, StringArg, RawArg, ReturnValue, StackSlot,
    ConditionalArg, CompiledChain, ChainEntry, compile_chain,
)

# Runtime execution (Windows-only, imported on demand)
try:
    from .runtime import ChainExecutor, execute_chain
except (ImportError, RuntimeError):
    pass  # Not on Windows — runtime module unavailable

__version__ = "2.0.0"
__author__ = "Chris Aziz / Bombadil Systems"

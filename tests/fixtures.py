#!/usr/bin/env python3
"""
OIS-ROP Test Fixtures
======================

Builds minimal valid x64 PE files with known gadgets in .text sections.
Used for cross-platform testing of the scanner, taxonomy, and compiler
without requiring real Windows DLLs.

Author: Chris Aziz / Bombadil Systems
"""

import struct
import os
from pathlib import Path
from typing import Dict, List, Tuple


# =============================================================================
# KNOWN GADGETS — Byte patterns we embed and expect to find
# =============================================================================

KNOWN_GADGETS = {
    # Pop-ret gadgets (x64)
    'pop_rax_ret':     b'\x58\xC3',
    'pop_rcx_ret':     b'\x59\xC3',
    'pop_rdx_ret':     b'\x5A\xC3',
    'pop_rbx_ret':     b'\x5B\xC3',
    'pop_rsi_ret':     b'\x5E\xC3',
    'pop_rdi_ret':     b'\x5F\xC3',
    'pop_r8_ret':      b'\x41\x58\xC3',
    'pop_r9_ret':      b'\x41\x59\xC3',

    # Transfer gadgets
    'mov_rcx_rax_ret': b'\x48\x89\xC1\xC3',  # mov rcx, rax; ret
    'mov_rdx_rax_ret': b'\x48\x89\xC2\xC3',  # mov rdx, rax; ret

    # Zero gadgets
    'xor_rax_rax_ret': b'\x48\x31\xC0\xC3',  # xor rax, rax; ret
    'xor_rcx_rcx_ret': b'\x48\x31\xC9\xC3',  # xor rcx, rcx; ret

    # Stack gadgets
    'add_rsp_8_ret':   b'\x48\x83\xC4\x08\xC3',
    'add_rsp_20_ret':  b'\x48\x83\xC4\x20\xC3',
    'add_rsp_28_ret':  b'\x48\x83\xC4\x28\xC3',

    # Bare ret
    'ret':             b'\xC3',

    # Multi-pop
    'pop_rcx_pop_rdx_ret': b'\x59\x5A\xC3',  # pop rcx; pop rdx; ret

    # NOP-ret
    'nop_ret':         b'\x90\xC3',

    # FLAG_SET gadgets
    'test_eax_eax_ret':      b'\x85\xC0\xC3',          # test eax, eax; ret (register-only, q=1.0)
    'test_mem_rax_edx_ret':  b'\x85\x10\xC3',          # test dword ptr [rax], edx; ret (small offset, q=0.5)

    # CMOV gadgets
    'cmovne_eax_edx_ret':    b'\x0F\x45\xC2\xC3',     # cmovne eax, edx; ret (clean, q=1.0)
    'cmove_eax_edx_ret':     b'\x0F\x44\xC2\xC3',     # cmove eax, edx; ret (for conditional chains)
    'cmovg_eax_eax_ret':     b'\x0F\x4F\xC0\xC3',     # cmovg eax, eax; ret (self-move, q=0.1)

    # WRITE_MEM gadgets
    'mov_qword_rcx_rax_ret': b'\x48\x89\x01\xC3',     # mov qword ptr [rcx], rax; ret (q=1.0)

    # Memory-write side effect gadgets (for testing corruption detection)
    'inc_mem_test_esi_ret':   b'\xFF\x00\x85\xF6\xC3', # inc dword ptr [rax]; test esi, esi; ret
}

# Fake exported functions (name → offset within .text)
# These are just addresses for the compiler to resolve
FAKE_EXPORTS = {
    'WinExec':               0x100,
    'ExitThread':            0x110,
    'Sleep':                 0x120,
    'GetCurrentProcessId':   0x130,
    'Beep':                  0x140,
    'CreateFileA':           0x150,
    'WriteFile':             0x160,
    'CloseHandle':           0x170,
    'VirtualAlloc':          0x180,
    'VirtualFree':           0x190,
}


def build_test_pe(
    gadgets: Dict[str, bytes] = None,
    exports: Dict[str, int] = None,
    text_padding: int = 0x200,
    image_base: int = 0x180000000,
    gadget_start: int = 0x40,
) -> bytes:
    """
    Build a minimal valid x64 PE file with specified gadgets in .text.

    Args:
        gadgets: Dict of name → byte patterns to embed. Defaults to KNOWN_GADGETS.
        exports: Dict of name → RVA for fake exports. Defaults to FAKE_EXPORTS.
        text_padding: Minimum size of .text section.
        image_base: PE image base address.
        gadget_start: Offset within .text where gadgets begin.
                      Change this to produce variant PEs with different addresses.

    Returns:
        Complete PE file as bytes.
    """
    if gadgets is None:
        gadgets = KNOWN_GADGETS
    if exports is None:
        exports = FAKE_EXPORTS

    # Layout constants
    file_alignment = 0x200
    section_alignment = 0x1000
    text_rva = 0x1000
    edata_rva = 0x2000

    # Build .text section content
    text_data = bytearray(b'\xCC' * text_padding)  # INT3 fill

    # Place gadgets at known offsets within .text
    gadget_offsets = {}
    offset = gadget_start

    for name, pattern in gadgets.items():
        gadget_offsets[name] = offset
        text_data[offset:offset + len(pattern)] = pattern
        offset += len(pattern)
        # Small gap between gadgets to avoid false positives
        offset = (offset + 3) & ~3  # Align to 4

    # Pad text to file alignment
    while len(text_data) % file_alignment != 0:
        text_data.append(0xCC)

    # Build export directory (.edata)
    edata = _build_export_directory(exports, text_rva, edata_rva, "test_fixture.dll")
    while len(edata) % file_alignment != 0:
        edata += b'\x00'

    # Build PE headers
    headers = _build_pe_headers(
        text_rva=text_rva,
        text_size=len(text_data),
        text_raw=file_alignment,  # Headers occupy first file_alignment bytes
        edata_rva=edata_rva,
        edata_size=len(edata),
        edata_raw=file_alignment + len(text_data),
        image_base=image_base,
        file_alignment=file_alignment,
        section_alignment=section_alignment,
    )

    # Pad headers to file alignment
    while len(headers) % file_alignment != 0:
        headers += b'\x00'

    return bytes(headers) + bytes(text_data) + bytes(edata)


def _build_pe_headers(
    text_rva, text_size, text_raw,
    edata_rva, edata_size, edata_raw,
    image_base, file_alignment, section_alignment,
) -> bytearray:
    """Build DOS + PE + optional + section headers."""
    buf = bytearray()

    # --- DOS header (64 bytes min) ---
    dos = bytearray(64)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, 64)  # e_lfanew
    buf += dos

    # --- PE signature ---
    buf += b'PE\x00\x00'

    # --- COFF header (20 bytes) ---
    num_sections = 2
    coff = struct.pack('<HHIIIHH',
        0x8664,        # Machine: AMD64
        num_sections,  # NumberOfSections
        0,             # TimeDateStamp
        0,             # PointerToSymbolTable
        0,             # NumberOfSymbols
        240,           # SizeOfOptionalHeader (PE32+ = 240 bytes)
        0x2022,        # Characteristics: EXECUTABLE | LARGE_ADDRESS | DLL
    )
    buf += coff

    # --- Optional header (PE32+, 240 bytes) ---
    # We need 112 bytes of standard fields + 128 bytes of data directories (16 entries × 8 bytes)
    size_of_image = edata_rva + max(edata_size, section_alignment)
    size_of_image = (size_of_image + section_alignment - 1) & ~(section_alignment - 1)

    opt = bytearray(240)
    struct.pack_into('<H', opt, 0, 0x20B)           # Magic: PE32+
    struct.pack_into('<B', opt, 2, 14)              # MajorLinkerVersion
    struct.pack_into('<I', opt, 4, text_size)       # SizeOfCode
    struct.pack_into('<I', opt, 16, text_rva)       # AddressOfEntryPoint
    struct.pack_into('<I', opt, 20, text_rva)       # BaseOfCode
    struct.pack_into('<Q', opt, 24, image_base)     # ImageBase
    struct.pack_into('<I', opt, 32, section_alignment)  # SectionAlignment
    struct.pack_into('<I', opt, 36, file_alignment) # FileAlignment
    struct.pack_into('<H', opt, 40, 6)              # MajorOSVersion
    struct.pack_into('<H', opt, 44, 6)              # MajorSubsystemVersion
    struct.pack_into('<I', opt, 56, size_of_image)  # SizeOfImage
    struct.pack_into('<I', opt, 60, file_alignment) # SizeOfHeaders
    struct.pack_into('<H', opt, 68, 3)              # Subsystem: CONSOLE
    struct.pack_into('<H', opt, 70, 0x8160)         # DllCharacteristics: DYNAMIC_BASE | NX | HIGHENTROPYVA
    struct.pack_into('<Q', opt, 72, 0x100000)       # SizeOfStackReserve
    struct.pack_into('<Q', opt, 80, 0x1000)         # SizeOfStackCommit
    struct.pack_into('<Q', opt, 88, 0x100000)       # SizeOfHeapReserve
    struct.pack_into('<Q', opt, 96, 0x1000)         # SizeOfHeapCommit
    struct.pack_into('<I', opt, 108, 16)            # NumberOfRvaAndSizes

    # Data directory entry 0 = Export Table (index 0, at offset 112)
    struct.pack_into('<II', opt, 112, edata_rva, edata_size)

    buf += opt

    # --- Section headers (40 bytes each) ---
    # .text
    text_sec = bytearray(40)
    text_sec[0:6] = b'.text\x00'
    struct.pack_into('<I', text_sec, 8, text_size)   # VirtualSize
    struct.pack_into('<I', text_sec, 12, text_rva)   # VirtualAddress
    struct.pack_into('<I', text_sec, 16, text_size)  # SizeOfRawData
    struct.pack_into('<I', text_sec, 20, text_raw)   # PointerToRawData
    struct.pack_into('<I', text_sec, 36, 0x60000020) # Characteristics: CODE|EXEC|READ
    buf += text_sec

    # .edata
    edata_sec = bytearray(40)
    edata_sec[0:7] = b'.edata\x00'
    struct.pack_into('<I', edata_sec, 8, edata_size)
    struct.pack_into('<I', edata_sec, 12, edata_rva)
    struct.pack_into('<I', edata_sec, 16, edata_size)
    struct.pack_into('<I', edata_sec, 20, edata_raw)
    struct.pack_into('<I', edata_sec, 36, 0x40000040)  # INITIALIZED_DATA|READ
    buf += edata_sec

    return buf


def _build_export_directory(
    exports: Dict[str, int],
    text_rva: int,
    edata_rva: int,
    dll_name: str,
) -> bytes:
    """Build a minimal export directory for the fake DLL."""
    buf = bytearray()

    # Sort exports by name for binary search compatibility
    sorted_names = sorted(exports.keys())
    num_exports = len(sorted_names)

    # Layout within .edata:
    # [0x00]  Export Directory Table (40 bytes)
    # [0x28]  Address Table (4 * num_exports)
    # [addr]  Name Pointer Table (4 * num_exports)
    # [addr]  Ordinal Table (2 * num_exports)
    # [addr]  Name strings
    # [addr]  DLL name string

    dir_size = 40
    addr_table_offset = dir_size
    addr_table_size = 4 * num_exports
    name_ptr_offset = addr_table_offset + addr_table_size
    name_ptr_size = 4 * num_exports
    ordinal_offset = name_ptr_offset + name_ptr_size
    ordinal_size = 2 * num_exports

    strings_offset = ordinal_offset + ordinal_size
    # Align
    strings_offset = (strings_offset + 3) & ~3

    # Build name strings and compute their RVAs
    name_strings = bytearray()
    name_rvas = []
    for name in sorted_names:
        rva = edata_rva + strings_offset + len(name_strings)
        name_rvas.append(rva)
        name_strings += name.encode('ascii') + b'\x00'

    # DLL name
    dll_name_rva = edata_rva + strings_offset + len(name_strings)
    name_strings += dll_name.encode('ascii') + b'\x00'

    # --- Export Directory Table ---
    export_dir = bytearray(40)
    struct.pack_into('<I', export_dir, 12, 0)                # TimeDateStamp
    struct.pack_into('<I', export_dir, 16, dll_name_rva)     # Name RVA (patched below: actually offset 12 is name)
    # Actually the layout is:
    # 0:  Characteristics (4)
    # 4:  TimeDateStamp (4)
    # 8:  MajorVersion (2) + MinorVersion (2)
    # 12: Name RVA (4)
    # 16: OrdinalBase (4)
    # 20: NumberOfFunctions (4)
    # 24: NumberOfNames (4)
    # 28: AddressOfFunctions RVA (4)
    # 32: AddressOfNames RVA (4)
    # 36: AddressOfNameOrdinals RVA (4)

    export_dir = bytearray(40)
    struct.pack_into('<I', export_dir, 12, dll_name_rva)
    struct.pack_into('<I', export_dir, 16, 1)                      # OrdinalBase
    struct.pack_into('<I', export_dir, 20, num_exports)            # NumberOfFunctions
    struct.pack_into('<I', export_dir, 24, num_exports)            # NumberOfNames
    struct.pack_into('<I', export_dir, 28, edata_rva + addr_table_offset)
    struct.pack_into('<I', export_dir, 32, edata_rva + name_ptr_offset)
    struct.pack_into('<I', export_dir, 36, edata_rva + ordinal_offset)

    buf += export_dir

    # --- Address Table ---
    for name in sorted_names:
        rva = text_rva + exports[name]
        buf += struct.pack('<I', rva)

    # --- Name Pointer Table ---
    for rva in name_rvas:
        buf += struct.pack('<I', rva)

    # --- Ordinal Table ---
    for i in range(num_exports):
        buf += struct.pack('<H', i)

    # --- Padding to strings_offset ---
    while len(buf) < strings_offset:
        buf += b'\x00'

    # --- Name strings ---
    buf += name_strings

    return bytes(buf)


def write_test_pe(
    path: str,
    gadgets: Dict[str, bytes] = None,
    exports: Dict[str, int] = None,
) -> str:
    """Build and write a test PE file. Returns the path."""
    pe_bytes = build_test_pe(gadgets=gadgets, exports=exports)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'wb') as f:
        f.write(pe_bytes)
    return path


def write_variant_pe(
    path: str,
    extra_padding: int = 0x10,
) -> str:
    """
    Build a variant PE with gadgets at DIFFERENT offsets.
    
    This simulates a different DLL version — same gadgets exist
    but at different addresses. Used to test version independence:
    the compiler should produce different chains that accomplish
    the same thing.
    """
    pe_bytes = build_test_pe(
        gadgets=KNOWN_GADGETS,
        exports=FAKE_EXPORTS,
        text_padding=0x200 + extra_padding,
        gadget_start=0x40 + extra_padding,  # Shift all gadgets
    )

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'wb') as f:
        f.write(pe_bytes)
    return path

#!/usr/bin/env python3
"""
OIS-ROP: Runtime Gadget Scanner
================================

Scans PE .text sections for ROP gadgets using pefile + capstone.
Works against PE files on disk — cross-platform.

Given any x64 PE DLL, returns a complete catalog of gadgets found
in executable sections, identified by offset, byte sequence, and
disassembled instructions.

Author: Chris Aziz / Bombadil Systems
"""

import pefile
import capstone
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class ScannedGadget:
    """A gadget discovered in a PE file."""
    offset: int              # Offset from image base (RVA)
    raw_offset: int          # Offset in the file on disk
    bytes: bytes             # Raw byte sequence
    instructions: str        # Disassembled instruction string
    module_path: str         # Source PE file path
    section: str             # Section name (.text, etc.)
    length: int              # Number of bytes

    def __repr__(self):
        return (
            f"ScannedGadget(0x{self.offset:X}, "
            f"{self.bytes.hex()}, "
            f"\"{self.instructions}\")"
        )

    def __hash__(self):
        return hash((self.offset, self.bytes))

    def __eq__(self, other):
        if not isinstance(other, ScannedGadget):
            return False
        return self.offset == other.offset and self.bytes == other.bytes


@dataclass
class ScanResult:
    """Complete scan results for a PE file."""
    module_path: str
    module_name: str
    image_base: int
    gadgets: List[ScannedGadget] = field(default_factory=list)
    sections_scanned: List[str] = field(default_factory=list)
    total_bytes_scanned: int = 0
    scan_errors: List[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.gadgets)

    def by_instructions(self, substring: str) -> List[ScannedGadget]:
        """Filter gadgets by instruction substring."""
        return [g for g in self.gadgets if substring.lower() in g.instructions.lower()]

    def by_bytes(self, pattern: bytes) -> List[ScannedGadget]:
        """Filter gadgets by exact byte pattern."""
        return [g for g in self.gadgets if g.bytes == pattern]

    def by_length(self, max_len: int) -> List[ScannedGadget]:
        """Filter gadgets by maximum byte length."""
        return [g for g in self.gadgets if g.length <= max_len]


# =============================================================================
# PE SCANNER
# =============================================================================

class PEGadgetScanner:
    """
    Scans PE files for ROP gadgets.

    Searches executable sections for instruction sequences ending in
    RET (0xC3). For each RET found, walks backwards up to max_gadget_len
    bytes and attempts disassembly to find valid instruction sequences.
    """

    def __init__(self, max_gadget_len: int = 6):
        """
        Args:
            max_gadget_len: Maximum gadget length in bytes including
                            the trailing RET. Default 6.
        """
        self.max_gadget_len = max_gadget_len
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

    def scan(self, pe_path: str) -> ScanResult:
        """
        Scan a PE file for ROP gadgets.

        Args:
            pe_path: Path to a PE file on disk.

        Returns:
            ScanResult containing all discovered gadgets.
        """
        pe_path = str(pe_path)
        pe = pefile.PE(pe_path, fast_load=False)

        result = ScanResult(
            module_path=pe_path,
            module_name=Path(pe_path).name,
            image_base=pe.OPTIONAL_HEADER.ImageBase,
        )

        # Scan all executable sections
        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            chars = section.Characteristics

            # IMAGE_SCN_MEM_EXECUTE = 0x20000000
            # IMAGE_SCN_CNT_CODE = 0x00000020
            is_executable = bool(chars & 0x20000000) or bool(chars & 0x20)

            if not is_executable:
                continue

            result.sections_scanned.append(name)
            section_data = section.get_data()
            section_rva = section.VirtualAddress
            section_raw = section.PointerToRawData
            result.total_bytes_scanned += len(section_data)

            self._scan_section(
                section_data, section_rva, section_raw,
                name, pe_path, result
            )

        pe.close()
        return result

    def _scan_section(
        self,
        data: bytes,
        section_rva: int,
        section_raw: int,
        section_name: str,
        module_path: str,
        result: ScanResult,
    ):
        """Scan a single section for gadgets ending in RET."""
        seen_offsets: Set[int] = set()

        # Find every RET (0xC3) in the section
        pos = 0
        while True:
            idx = data.find(b'\xC3', pos)
            if idx == -1:
                break

            # Walk backwards from this RET, trying different start positions
            for start_offset in range(1, self.max_gadget_len):
                begin = idx - start_offset
                if begin < 0:
                    continue

                candidate = data[begin:idx + 1]
                rva = section_rva + begin

                if rva in seen_offsets:
                    continue

                # Try to disassemble the candidate
                gadget = self._try_disassemble(
                    candidate, rva, section_raw + begin,
                    section_name, module_path
                )
                if gadget is not None:
                    seen_offsets.add(rva)
                    result.gadgets.append(gadget)

            # Also record the bare RET itself
            ret_rva = section_rva + idx
            if ret_rva not in seen_offsets:
                seen_offsets.add(ret_rva)
                result.gadgets.append(ScannedGadget(
                    offset=ret_rva,
                    raw_offset=section_raw + idx,
                    bytes=b'\xC3',
                    instructions="ret",
                    module_path=module_path,
                    section=section_name,
                    length=1,
                ))

            pos = idx + 1

    def _try_disassemble(
        self,
        candidate: bytes,
        rva: int,
        raw_offset: int,
        section_name: str,
        module_path: str,
    ) -> Optional[ScannedGadget]:
        """
        Attempt to disassemble a candidate byte sequence as a valid gadget.

        A valid gadget must:
        1. Disassemble completely (all bytes consumed)
        2. End with a RET instruction
        3. Contain no control-flow instructions before the final RET
           (no jmp, call, jcc, int, syscall — these break the chain)
        """
        instructions = list(self.md.disasm(candidate, rva))

        if not instructions:
            return None

        # Check all bytes were consumed (no trailing garbage before RET)
        total_decoded = sum(i.size for i in instructions)
        if total_decoded != len(candidate):
            return None

        # Last instruction must be RET
        last = instructions[-1]
        if last.mnemonic != 'ret':
            return None

        # No mid-gadget control flow transfers
        bad_mnemonics = {
            'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
            'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns', 'jp',
            'jnp', 'call', 'int', 'int3', 'syscall', 'sysenter',
            'loop', 'loope', 'loopne', 'jcxz', 'jecxz', 'jrcxz',
            'iret', 'iretd', 'iretq', 'hlt', 'ud2',
        }

        for insn in instructions[:-1]:
            if insn.mnemonic in bad_mnemonics:
                return None

        disasm_str = "; ".join(
            f"{i.mnemonic} {i.op_str}".strip() for i in instructions
        )

        return ScannedGadget(
            offset=rva,
            raw_offset=raw_offset,
            bytes=candidate,
            instructions=disasm_str,
            module_path=module_path,
            section=section_name,
            length=len(candidate),
        )

    def scan_multiple(self, pe_paths: List[str]) -> Dict[str, ScanResult]:
        """Scan multiple PE files and return results keyed by filename."""
        results = {}
        for path in pe_paths:
            name = Path(path).name
            results[name] = self.scan(path)
        return results


# =============================================================================
# CONVENIENCE
# =============================================================================

def scan_pe(pe_path: str, max_gadget_len: int = 6) -> ScanResult:
    """Scan a PE file for gadgets. Convenience wrapper."""
    scanner = PEGadgetScanner(max_gadget_len=max_gadget_len)
    return scanner.scan(pe_path)

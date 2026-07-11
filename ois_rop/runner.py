#!/usr/bin/env python3
"""
OIS-ROP Chain Runner
=====================
Parses .ois chain intent files and executes them through the
OIS-ROP compiler + runtime pipeline.

Format:
    OIS-ROP/1.0
    [SUBSTRATES]
    kernel32.dll
    ntdll.dll
    [CHAIN]
    call kernel32.dll WinExec str:"calc" 1
    [END]

Argument types:
    123         integer literal
    0x40000000  hex literal
    str:"text"  string argument (allocated + written via gadgets)
    cond:test_value:false_val:true_val  conditional argument (CMOV)
    ret         return value from previous call

Usage:
    python -m ois_rop run demo.ois
    python -m ois_rop run demo.ois --execute
    python -m ois_rop run demo.ois --execute --dump
"""

import os
import re
import sys
import time
import argparse
from typing import List, Tuple

from .chain_compiler import (
    Call, StringArg, ConditionalArg, ReturnValue, compile_chain, CompiledChain,
)


K32   = r"C:\Windows\System32\kernel32.dll"
NTDLL = r"C:\Windows\System32\ntdll.dll"

SUBSTRATE_PATHS = {
    "kernel32.dll": K32,
    "ntdll.dll":    NTDLL,
    "user32.dll":   r"C:\Windows\System32\user32.dll",
    "advapi32.dll": r"C:\Windows\System32\advapi32.dll",
    "ws2_32.dll":   r"C:\Windows\System32\ws2_32.dll",
}


def parse_arg(arg_str: str):
    """Parse a single argument token from .ois format."""
    arg_str = arg_str.strip()

    # String argument: str:"value"
    m = re.match(r'^str:"(.*)"$', arg_str)
    if m:
        return StringArg(m.group(1))

    # Conditional argument: cond:test:if_zero:if_nonzero
    m = re.match(r'^cond:(\d+):(\d+):(\d+)$', arg_str)
    if m:
        return ConditionalArg(
            test_value=int(m.group(1)),
            if_zero=int(m.group(2)),
            if_nonzero=int(m.group(3)),
        )

    # Return value from previous call
    if arg_str == "ret":
        return ReturnValue()

    # Hex literal
    if arg_str.startswith("0x") or arg_str.startswith("0X"):
        return int(arg_str, 16)

    # Integer literal
    return int(arg_str)


def parse_chain_line(line: str) -> Call:
    """
    Parse a single chain intent line.
    Format: call <dll> <function> <arg1> <arg2> ...
    """
    # Tokenize respecting quoted strings
    tokens = []
    current = ""
    in_quotes = False

    for ch in line:
        if ch == '"' and not in_quotes:
            in_quotes = True
            current += ch
        elif ch == '"' and in_quotes:
            in_quotes = False
            current += ch
        elif ch == ' ' and not in_quotes:
            if current:
                tokens.append(current)
                current = ""
        else:
            current += ch
    if current:
        tokens.append(current)

    if not tokens or tokens[0] != "call":
        raise ValueError(f"Expected 'call <dll> <func> [args...]', got: {line}")

    if len(tokens) < 3:
        raise ValueError(f"call requires at least dll and function: {line}")

    dll = tokens[1]
    func = tokens[2]
    args = [parse_arg(t) for t in tokens[3:]]

    return Call(dll, func, args)


def parse_ois_file(filepath: str) -> Tuple[List[str], List[Call], dict]:
    """
    Parse an .ois chain intent file.

    Returns (substrate_paths, calls, metadata).
    """
    with open(filepath, 'r') as f:
        content = f.read()

    lines = content.strip().split('\n')
    section = None
    substrates = []
    calls = []
    metadata = {}

    for line in lines:
        line = line.strip()

        if not line or line.startswith('#'):
            continue
        if line.startswith('OIS-ROP/'):
            metadata['version'] = line.split('/')[1]
            continue
        if line == '[SUBSTRATES]':
            section = 'substrates'
            continue
        if line == '[CHAIN]':
            section = 'chain'
            continue
        if line == '[METADATA]':
            section = 'metadata'
            continue
        if line == '[END]':
            break

        if section == 'substrates':
            substrates.append(line)
        elif section == 'chain':
            calls.append(parse_chain_line(line))
        elif section == 'metadata' and ':' in line:
            key, val = line.split(':', 1)
            metadata[key.strip()] = val.strip()

    # Resolve substrate names to paths
    pe_paths = []
    for s in substrates:
        if s in SUBSTRATE_PATHS:
            pe_paths.append(SUBSTRATE_PATHS[s])
        elif os.path.exists(s):
            pe_paths.append(s)
        else:
            pe_paths.append(os.path.join(r"C:\Windows\System32", s))

    if not pe_paths:
        pe_paths = [K32, NTDLL]

    return pe_paths, calls, metadata


def run_ois(filepath: str, execute: bool = False, dump: bool = False):
    """Compile and optionally execute an .ois chain intent file."""
    basename = os.path.basename(filepath)

    print("=" * 60)
    print(f"  OIS-ROP: {basename}")
    print(f"  All execution in signed Microsoft DLL memory")
    print("=" * 60)

    pe_paths, calls, metadata = parse_ois_file(filepath)

    # Display intent
    print(f"\n[1] Loaded {basename}")
    for key, val in metadata.items():
        print(f"    {key}: {val}")
    print(f"    substrates: {len(pe_paths)}")
    print(f"    calls: {len(calls)}")
    for i, c in enumerate(calls):
        arg_strs = []
        for a in c.args:
            if isinstance(a, StringArg):
                arg_strs.append(f'"{a.value}"')
            elif isinstance(a, ConditionalArg):
                arg_strs.append(f'cond({a.test_value},{a.if_zero},{a.if_nonzero})')
            elif isinstance(a, ReturnValue):
                arg_strs.append('ret')
            else:
                arg_strs.append(str(a))
        print(f"    [{i}] {c.module}!{c.function}({', '.join(arg_strs)})")

    # Compile
    print(f"\n[2] Scanning substrates and compiling chain...")
    chain = compile_chain(pe_paths, calls, exit_code=0x42)

    print(f"\n    Chain compiled:")
    print(f"    {chain.qwords} QWORDs  |  {chain.size} bytes  |  {len(chain.calls)} API call(s)")

    if chain.gadgets_used:
        print(f"\n[3] Gadgets selected:")
        for cls, disasm in sorted(chain.gadgets_used.items()):
            print(f"    {cls}: {disasm}")

    if chain.errors:
        print(f"\n    ERRORS:")
        for e in chain.errors:
            print(f"    ! {e}")
        sys.exit(1)

    if dump:
        print(f"\n[*] Full chain dump:")
        print(chain.dump())

    if not execute:
        print("\n" + "=" * 60)
        print("  Dry run complete. Add --execute to run the chain.")
        print("=" * 60)
        return

    # Execute
    print("\n" + "=" * 60)
    print("  EXECUTING")
    print("=" * 60)

    from .runtime import execute_chain as exec_chain
    exec_chain(chain)
    time.sleep(2)
    print(f"\n    Done. Exit code 0x42.")


def main():
    parser = argparse.ArgumentParser(description="OIS-ROP: Run a .ois chain intent file")
    parser.add_argument("file", help="Path to .ois chain intent file")
    parser.add_argument("--execute", action="store_true", help="Execute the chain")
    parser.add_argument("--dump", action="store_true", help="Print full chain dump")
    args = parser.parse_args()

    run_ois(args.file, execute=args.execute, dump=args.dump)


if __name__ == "__main__":
    main()

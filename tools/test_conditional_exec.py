#!/usr/bin/env python3
r"""
OIS-ROP: Conditional Chain Execution Test
===========================================

Proves the FLAG_SET → CMOV conditional chain works at runtime
by using Sleep() with different durations for each path.

Test 1 — nonzero condition (test_value=1):
    Sleep(ConditionalArg(1, if_zero=500, if_nonzero=3000))
    Expected: sleeps ~3 seconds (nonzero path selected)

Test 2 — zero condition (test_value=0):
    Sleep(ConditionalArg(0, if_zero=500, if_nonzero=3000))
    Expected: sleeps ~0.5 seconds (zero path selected)

If both timings match expectations, the conditional chain primitive is
proven at the hardware level: flags set by TEST survive through POP;RET
sequences to reach the CMOV, which selects the correct value.

Usage:
    python tools/test_conditional_exec.py

Author: Chris Aziz / Bombadil Systems
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ois_rop import compile_chain, Call, ConditionalArg
from ois_rop.runtime import execute_chain

DLLS = [
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\ntdll.dll",
]
MODULES = ["kernel32.dll", "ntdll.dll"]

ZERO_MS = 500       # Sleep duration for the zero path
NONZERO_MS = 3000   # Sleep duration for the nonzero path
TOLERANCE = 0.5     # Acceptable timing error (seconds)


def test_nonzero():
    """Test: condition=1 should select if_nonzero (3000ms Sleep)."""
    print("=" * 70)
    print("  TEST 1: Nonzero condition → should sleep ~3 seconds")
    print("=" * 70)

    chain = compile_chain(DLLS, [
        Call("kernel32.dll", "Sleep", [
            ConditionalArg(
                test_value=1,
                if_zero=ZERO_MS,
                if_nonzero=NONZERO_MS,
            ),
        ]),
    ])

    if chain.errors:
        print(f"  COMPILE ERROR: {chain.errors}")
        return False

    print(f"\n{chain.dump()}\n")

    t0 = time.time()
    code = execute_chain(chain, MODULES, verbose=True)
    elapsed = time.time() - t0

    expected = NONZERO_MS / 1000.0
    ok = abs(elapsed - expected) < TOLERANCE and code == 0x99
    label = "PASS" if ok else "FAIL"
    print(f"\n  [{label}] Elapsed: {elapsed:.2f}s (expected ~{expected:.1f}s)")
    print(f"  Exit code: 0x{code:X} (expected 0x99)")
    return ok


def test_zero():
    """Test: condition=0 should select if_zero (500ms Sleep)."""
    print("\n" + "=" * 70)
    print("  TEST 2: Zero condition → should sleep ~0.5 seconds")
    print("=" * 70)

    chain = compile_chain(DLLS, [
        Call("kernel32.dll", "Sleep", [
            ConditionalArg(
                test_value=0,
                if_zero=ZERO_MS,
                if_nonzero=NONZERO_MS,
            ),
        ]),
    ])

    if chain.errors:
        print(f"  COMPILE ERROR: {chain.errors}")
        return False

    print(f"\n{chain.dump()}\n")

    t0 = time.time()
    code = execute_chain(chain, MODULES, verbose=True)
    elapsed = time.time() - t0

    expected = ZERO_MS / 1000.0
    ok = abs(elapsed - expected) < TOLERANCE and code == 0x99
    label = "PASS" if ok else "FAIL"
    print(f"\n  [{label}] Elapsed: {elapsed:.2f}s (expected ~{expected:.1f}s)")
    print(f"  Exit code: 0x{code:X} (expected 0x99)")
    return ok


if __name__ == "__main__":
    print()
    print("OIS-ROP Conditional Chain Execution Test")
    print("Proves FLAG_SET → CMOV path selection at hardware level")
    print()

    r1 = test_nonzero()
    r2 = test_zero()

    print("\n" + "=" * 70)
    print(f"  RESULTS: {'2/2 PASS' if r1 and r2 else 'FAIL'}")
    if r1 and r2:
        print("  Conditional computation via signed DLL gadgets: PROVEN")
    print("=" * 70)

    sys.exit(0 if r1 and r2 else 1)

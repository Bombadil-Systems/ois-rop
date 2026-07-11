#!/usr/bin/env python3
r"""
OIS-ROP Gadget Tier Audit
==========================

Run against real DLLs to see FLAG_SET / CMOV / WRITE_MEM quality
distribution after the tiering fix.

Usage:
    python tools/tier_audit.py
    python tools/tier_audit.py C:\Windows\System32\ntdll.dll
    python tools/tier_audit.py kernel32.dll ntdll.dll

Author: Chris Aziz / Bombadil Systems
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ois_rop.scanner import PEGadgetScanner
from ois_rop.taxonomy import GadgetClassifier, GadgetClass, Taxonomy


def default_dlls():
    sys32 = os.path.join(os.environ.get('SYSTEMROOT', r'C:\Windows'), 'System32')
    return [
        os.path.join(sys32, "kernel32.dll"),
        os.path.join(sys32, "ntdll.dll"),
    ]


def tier_label(q: float) -> str:
    if q >= 0.9:
        return "TIER-1 (clean)"
    elif q >= 0.4:
        return "TIER-2 (controllable)"
    elif q >= 0.15:
        return "TIER-3 (fragile)"
    else:
        return "TIER-4 (no-op/dead)"


def audit(pe_paths):
    scanner = PEGadgetScanner(max_gadget_len=10)
    classifier = GadgetClassifier()
    combined = Taxonomy()

    for path in pe_paths:
        print(f"[*] Scanning {path}...")
        scan = scanner.scan(path)
        tax = classifier.classify_scan(scan)
        combined.merge(tax)
        print(f"    {scan.count} raw gadgets")

    print()

    # --- FLAG_SET ---
    flag_gadgets = combined.get(GadgetClass.FLAG_SET)
    t1 = [g for g in flag_gadgets if g.quality >= 0.9]
    t2 = [g for g in flag_gadgets if 0.4 <= g.quality < 0.9 and 'MEMORY WRITE' not in g.notes]
    t3 = [g for g in flag_gadgets if 0.15 < g.quality < 0.4]
    t_mw = [g for g in flag_gadgets if 'MEMORY WRITE' in g.notes]
    t_dead = [g for g in flag_gadgets if g.quality <= 0.15 and 'MEMORY WRITE' not in g.notes]

    print(f"{'='*70}")
    print(f"  FLAG_SET: {len(flag_gadgets)} total")
    print(f"{'='*70}")
    print(f"  TIER-1 (register-only, can't fault):    {len(t1):4d}")
    print(f"  TIER-2 (small offset, controllable):    {len(t2):4d}")
    print(f"  TIER-3 (large disp, likely artifact):   {len(t3):4d}")
    print(f"  CORRUPTING (memory write side effect):  {len(t_mw):4d}")
    print(f"  DEAD (unusable):                        {len(t_dead):4d}")
    print()

    if t1:
        print("  Best TIER-1 FLAG_SET:")
        for g in t1[:5]:
            print(f"    q={g.quality:.2f}  {g.gadget.instructions:55s}  {g.notes}")
    if t2:
        print("  Best TIER-2 FLAG_SET:")
        for g in t2[:5]:
            print(f"    q={g.quality:.2f}  {g.gadget.instructions:55s}  {g.notes}")
    if t3:
        print("  Sample TIER-3 FLAG_SET (deprioritized):")
        for g in t3[:3]:
            print(f"    q={g.quality:.2f}  {g.gadget.instructions:55s}  {g.notes}")
    print()

    # --- CMOV ---
    cmov_gadgets = combined.get(GadgetClass.CMOV)
    real = [g for g in cmov_gadgets if g.quality >= 0.9]
    mid = [g for g in cmov_gadgets if 0.15 < g.quality < 0.9 and 'MEMORY WRITE' not in g.notes]
    noop = [g for g in cmov_gadgets if g.quality <= 0.15 and 'MEMORY WRITE' not in g.notes]
    cmov_mw = [g for g in cmov_gadgets if 'MEMORY WRITE' in g.notes]

    print(f"{'='*70}")
    print(f"  CMOV: {len(cmov_gadgets)} total")
    print(f"{'='*70}")
    print(f"  Real (q >= 0.9):                        {len(real):4d}")
    print(f"  Reduced (side effects / mem source):    {len(mid):4d}")
    print(f"  No-op (self-move):                      {len(noop):4d}")
    print(f"  CORRUPTING (memory write side effect):  {len(cmov_mw):4d}")
    print()

    if real:
        # Group by condition
        by_cond = {}
        for g in real:
            for part in g.notes.split():
                if part.startswith("condition="):
                    cond = part.split("=")[1]
                    by_cond.setdefault(cond, []).append(g)
        print("  Conditions available (TIER-1):")
        for cond, gs in sorted(by_cond.items()):
            print(f"    {cond:6s}: {len(gs)} gadgets")
    if noop:
        print("  Self-move no-ops (deprioritized):")
        for g in noop[:3]:
            print(f"    q={g.quality:.2f}  {g.gadget.instructions:55s}  {g.notes}")
    print()

    # --- WRITE_MEM ---
    wmem_gadgets = combined.get(GadgetClass.WRITE_MEM_RCX_RAX)
    print(f"{'='*70}")
    print(f"  WRITE_MEM_RCX_RAX: {len(wmem_gadgets)} total")
    print(f"{'='*70}")
    if wmem_gadgets:
        print("  Top 5:")
        for g in wmem_gadgets[:5]:
            print(f"    q={g.quality:.2f}  {g.gadget.instructions:55s}  {g.notes}")
    print()

    # --- Compiler readiness ---
    print(f"{'='*70}")
    print(f"  CONDITIONAL CHAIN READINESS")
    print(f"{'='*70}")
    has_clean_flag = len(t1) > 0
    has_real_cmov = len(real) > 0
    has_wmem = len(wmem_gadgets) > 0
    has_load_rax = combined.has(GadgetClass.LOAD_RAX)
    has_load_rcx = combined.has(GadgetClass.LOAD_RCX)

    checks = [
        ("LOAD_RAX (register priming)", has_load_rax),
        ("LOAD_RCX (write dest priming)", has_load_rcx),
        ("FLAG_SET tier-1 (clean flag set)", has_clean_flag),
        ("CMOV real (conditional select)", has_real_cmov),
        ("WRITE_MEM (arbitrary write)", has_wmem),
    ]
    for name, ok in checks:
        status = "✅" if ok else "❌"
        print(f"  {status}  {name}")

    all_ready = all(ok for _, ok in checks)
    print()
    if all_ready:
        print("  → LOAD_* → FLAG_SET → CMOV → WRITE_MEM chain is VIABLE")
    else:
        missing = [n for n, ok in checks if not ok]
        print(f"  → Missing: {', '.join(missing)}")


if __name__ == "__main__":
    paths = sys.argv[1:] if len(sys.argv) > 1 else default_dlls()
    audit(paths)

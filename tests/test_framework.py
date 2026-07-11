#!/usr/bin/env python3
"""
OIS-ROP — Scanner, Taxonomy, and Compiler Tests

Tests the new framework components against synthetic PE fixtures.
Cross-platform — no Windows or real DLLs required.

Author: Chris Aziz / Bombadil Systems
"""

import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.fixtures import (
    build_test_pe, write_test_pe, write_variant_pe,
    KNOWN_GADGETS, FAKE_EXPORTS,
)
from ois_rop.scanner import PEGadgetScanner, scan_pe
from ois_rop.taxonomy import GadgetClassifier, GadgetClass, Taxonomy
from ois_rop.chain_compiler import (
    ChainCompiler, Call, StringArg, RawArg, ReturnValue, ConditionalArg,
    compile_chain, CompiledChain,
)

passed = 0
failed = 0
errors = []

def test(name: str, condition: bool, detail: str = ""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  \u2705 {name}")
    else:
        failed += 1
        print(f"  \u274c {name}")
        errors.append(name)
    if detail and not condition:
        print(f"       \u2192 {detail}")

def section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# Create temp directory for test PE files
tmpdir = tempfile.mkdtemp(prefix="ois_rop_test_")
test_pe_path = os.path.join(tmpdir, "test.dll")
variant_pe_path = os.path.join(tmpdir, "variant.dll")


try:
    # ========================================================================
    section("0. Fixture Generation")
    # ========================================================================

    write_test_pe(test_pe_path)
    test("Test PE created", os.path.exists(test_pe_path))
    test("Test PE non-empty", os.path.getsize(test_pe_path) > 0,
         f"size={os.path.getsize(test_pe_path)}")

    # Verify it's a valid PE
    import pefile
    try:
        pe = pefile.PE(test_pe_path)
        test("Valid PE file", True)
        test("PE is x64", pe.FILE_HEADER.Machine == 0x8664)
        sections = [s.Name.rstrip(b'\x00').decode() for s in pe.sections]
        test("Has .text section", '.text' in sections, f"sections: {sections}")
        test("Has .edata section", '.edata' in sections)

        # Check exports
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
        )
        export_names = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            export_names = [
                e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols
                if e.name
            ]
        test("Has exports", len(export_names) > 0, f"found {len(export_names)}")
        test("WinExec exported", "WinExec" in export_names)
        test("ExitThread exported", "ExitThread" in export_names)
        pe.close()
    except Exception as e:
        test("Valid PE file", False, str(e))

    write_variant_pe(variant_pe_path)
    test("Variant PE created", os.path.exists(variant_pe_path))

    # ========================================================================
    section("1. Scanner — Basic Operation")
    # ========================================================================

    scanner = PEGadgetScanner(max_gadget_len=6)
    result = scanner.scan(test_pe_path)

    test("Scan returns ScanResult", result is not None)
    test("Module name set", result.module_name == "test.dll")
    test("Scanned .text", ".text" in result.sections_scanned)
    test("Found gadgets", result.count > 0, f"found {result.count}")
    test("Bytes scanned > 0", result.total_bytes_scanned > 0)

    # ========================================================================
    section("2. Scanner — Gadget Discovery")
    # ========================================================================

    # Check that we find the specific gadgets we embedded
    def find_by_bytes(scan_result, pattern):
        return scan_result.by_bytes(pattern)

    pop_rcx = find_by_bytes(result, b'\x59\xC3')
    test("Found pop rcx; ret", len(pop_rcx) > 0)

    pop_rdx = find_by_bytes(result, b'\x5A\xC3')
    test("Found pop rdx; ret", len(pop_rdx) > 0)

    pop_rax = find_by_bytes(result, b'\x58\xC3')
    test("Found pop rax; ret", len(pop_rax) > 0)

    pop_r8 = find_by_bytes(result, b'\x41\x58\xC3')
    test("Found pop r8; ret", len(pop_r8) > 0)

    xor_rax = find_by_bytes(result, b'\x48\x31\xC0\xC3')
    test("Found xor rax, rax; ret", len(xor_rax) > 0)

    add_rsp_28 = find_by_bytes(result, b'\x48\x83\xC4\x28\xC3')
    test("Found add rsp, 0x28; ret", len(add_rsp_28) > 0)

    mov_rcx_rax = find_by_bytes(result, b'\x48\x89\xC1\xC3')
    test("Found mov rcx, rax; ret", len(mov_rcx_rax) > 0)

    # Check that gadgets have proper attributes
    if pop_rcx:
        g = pop_rcx[0]
        test("Gadget has offset", g.offset > 0)
        test("Gadget has instructions", len(g.instructions) > 0,
             f"disasm: {g.instructions}")
        test("Gadget has section", g.section == ".text")
        test("Instructions contain pop", "pop" in g.instructions.lower())

    # ========================================================================
    section("3. Scanner — Instruction Filtering")
    # ========================================================================

    pop_gadgets = result.by_instructions("pop")
    test("Filter by 'pop' finds multiple", len(pop_gadgets) >= 4,
         f"found {len(pop_gadgets)}")

    ret_gadgets = result.by_instructions("ret")
    test("Filter by 'ret' includes all", len(ret_gadgets) >= 1)

    short_gadgets = result.by_length(3)
    test("Filter by length <=3", len(short_gadgets) > 0)

    # ========================================================================
    section("4. Scanner — Consistency")
    # ========================================================================

    result2 = scanner.scan(test_pe_path)
    test("Second scan same count", result2.count == result.count)

    # Check same gadget offsets
    offsets1 = sorted(g.offset for g in result.gadgets)
    offsets2 = sorted(g.offset for g in result2.gadgets)
    test("Second scan same offsets", offsets1 == offsets2)

    # ========================================================================
    section("5. Taxonomy — Classification")
    # ========================================================================

    classifier = GadgetClassifier()
    taxonomy = classifier.classify_scan(result)

    test("Taxonomy created", taxonomy is not None)
    test("Taxonomy has module name", taxonomy.module_name == "test.dll")
    test("Total classified > 0", taxonomy.count() > 0)

    # Check specific classes
    test("Has LOAD_RCX", taxonomy.has(GadgetClass.LOAD_RCX))
    test("Has LOAD_RDX", taxonomy.has(GadgetClass.LOAD_RDX))
    test("Has LOAD_RAX", taxonomy.has(GadgetClass.LOAD_RAX))
    test("Has LOAD_R8", taxonomy.has(GadgetClass.LOAD_R8))
    test("Has LOAD_R9", taxonomy.has(GadgetClass.LOAD_R9))
    test("Has ZERO_RAX", taxonomy.has(GadgetClass.ZERO_RAX))
    test("Has XFER_RAX_RCX", taxonomy.has(GadgetClass.XFER_RAX_RCX))
    test("Has STACK_ALIGN", taxonomy.has(GadgetClass.STACK_ALIGN))
    test("Has RET_SLED", taxonomy.has(GadgetClass.RET_SLED))

    # ========================================================================
    section("6. Taxonomy — Quality Scoring")
    # ========================================================================

    # Best LOAD_RCX should be the simple pop rcx; ret (quality 1.0)
    best_rcx = taxonomy.best(GadgetClass.LOAD_RCX)
    test("Best LOAD_RCX exists", best_rcx is not None)
    if best_rcx:
        test("Best LOAD_RCX quality = 1.0", best_rcx.quality == 1.0,
             f"quality={best_rcx.quality}")
        test("Best LOAD_RCX is pop rcx",
             "pop" in best_rcx.gadget.instructions.lower())

    # Multi-pop should have lower quality
    all_rcx = taxonomy.get(GadgetClass.LOAD_RCX)
    if len(all_rcx) > 1:
        worst = all_rcx[-1]
        test("Multi-pop has lower quality", worst.quality < 1.0,
             f"worst quality={worst.quality}")

    # ========================================================================
    section("7. Taxonomy — Missing Class Detection")
    # ========================================================================

    required = [GadgetClass.LOAD_RCX, GadgetClass.LOAD_RDX, GadgetClass.RET_SLED]
    missing = taxonomy.missing_classes(required)
    test("No missing for basic classes", len(missing) == 0,
         f"missing: {[c.name for c in missing]}")

    # Check for something we know is missing
    unlikely = [GadgetClass.STORE_MEM, GadgetClass.LOAD_MEM]
    missing_unlikely = taxonomy.missing_classes(unlikely)
    test("Missing uncommon classes detected", len(missing_unlikely) > 0)

    # ========================================================================
    section("8. Taxonomy — Stack Align Grouping")
    # ========================================================================

    align_by_delta = taxonomy.stack_align_gadgets()
    test("Stack align gadgets found", len(align_by_delta) > 0)
    test("Has 0x28 skip", 0x28 in align_by_delta)
    test("Has 0x20 skip", 0x20 in align_by_delta)
    test("Has 0x08 skip", 0x08 in align_by_delta)

    # ========================================================================
    section("9. Taxonomy — Summary")
    # ========================================================================

    summary = taxonomy.summary()
    test("Summary is string", isinstance(summary, str))
    test("Summary mentions module", "test.dll" in summary)
    test("Summary mentions LOAD_RCX", "LOAD_RCX" in summary)
    print(f"\n{summary}\n")

    # ========================================================================
    section("10. Compiler — Single Call")
    # ========================================================================

    compiler = ChainCompiler(taxonomy)
    compiler.add_export_table(test_pe_path)

    # Verify export resolution
    winexec_rva = compiler.resolve_function("test.dll", "WinExec")  
    # Our fixture uses "test_fixture.dll" as the internal name but
    # the file is "test.dll" — try the file path name
    if winexec_rva is None:
        # Try with the internal DLL name
        winexec_rva = compiler.resolve_function("test_fixture.dll", "WinExec")
    
    test("WinExec resolved", winexec_rva is not None, 
         f"rva={hex(winexec_rva) if winexec_rva else 'None'}")

    # Compile a simple WinExec("calc", 1)
    # Use the correct module name that was registered
    mod_name = "test.dll"  # This is what add_export_table registers
    chain = compiler.compile([
        Call(mod_name, "WinExec", [StringArg("calc"), 1]),
    ])

    test("Chain compiled", chain is not None)
    test("No errors", len(chain.errors) == 0,
         f"errors: {chain.errors}")
    test("Chain has entries", chain.qwords > 0, f"qwords={chain.qwords}")
    test("Chain has string data", len(chain.strings) > 0)

    if not chain.errors:
        print(f"\n{chain.dump()}\n")

    # ========================================================================
    section("11. Compiler — Chain Builds to Bytes")
    # ========================================================================

    if not chain.errors:
        chain_bytes = chain.build()
        test("Build produces bytes", isinstance(chain_bytes, bytes))
        test("Build size matches", len(chain_bytes) == chain.qwords * 8)
        test("Build non-zero", any(b != 0 for b in chain_bytes))

    # ========================================================================
    section("12. Compiler — Version Independence")
    # ========================================================================

    # Scan the variant PE (same gadgets, different offsets)
    variant_result = scanner.scan(variant_pe_path)
    variant_taxonomy = classifier.classify_scan(variant_result)

    test("Variant has LOAD_RCX", variant_taxonomy.has(GadgetClass.LOAD_RCX))
    test("Variant has LOAD_RDX", variant_taxonomy.has(GadgetClass.LOAD_RDX))

    variant_compiler = ChainCompiler(variant_taxonomy)
    variant_compiler.add_export_table(variant_pe_path)

    variant_mod = "variant.dll"
    variant_chain = variant_compiler.compile([
        Call(variant_mod, "WinExec", [StringArg("calc"), 1]),
    ])

    test("Variant chain compiled", len(variant_chain.errors) == 0,
         f"errors: {variant_chain.errors}")

    if not chain.errors and not variant_chain.errors:
        # Same intent, different DLLs → different addresses
        orig_bytes = chain.build()
        var_bytes = variant_chain.build()
        test("Different DLLs → different chain bytes",
             orig_bytes != var_bytes,
             "chains should differ (different gadget offsets)")
        test("Both chains non-empty",
             len(orig_bytes) > 0 and len(var_bytes) > 0)
        test("Both chains same structure (same qword count)",
             chain.qwords == variant_chain.qwords,
             f"orig={chain.qwords}, variant={variant_chain.qwords}")

    # ========================================================================
    section("13. Compiler — Multi-Call Sequence")
    # ========================================================================

    multi_chain = compiler.compile([
        Call(mod_name, "Sleep", [1000]),
        Call(mod_name, "WinExec", [StringArg("calc"), 1]),
    ])

    test("Multi-call compiled", len(multi_chain.errors) == 0,
         f"errors: {multi_chain.errors}")
    test("Multi-call has more entries than single",
         multi_chain.qwords > chain.qwords,
         f"multi={multi_chain.qwords}, single={chain.qwords}")

    if not multi_chain.errors:
        print(f"\n{multi_chain.dump()}\n")

    # ========================================================================
    section("14. Compiler — Return Value Forwarding")
    # ========================================================================

    # GetCurrentProcessId() returns PID in RAX
    # Then pass it to ExitThread via RCX
    # This tests the XFER_RAX_RCX path
    retval_chain = compiler.compile([
        Call(mod_name, "GetCurrentProcessId", []),
        Call(mod_name, "ExitThread", [ReturnValue()]),
    ], exit_code=None)

    if retval_chain.errors:
        # If XFER not available, it should report that clearly
        test("Return value error is specific",
             any("XFER" in e or "transfer" in e.lower() for e in retval_chain.errors),
             f"errors: {retval_chain.errors}")
    else:
        test("Return value chain compiled", True)
        # Check that a transfer gadget was used
        test("Transfer gadget used",
             any("XFER" in k for k in retval_chain.gadgets_used),
             f"gadgets used: {list(retval_chain.gadgets_used.keys())}")

    # ========================================================================
    section("15. Compiler — Error Handling")
    # ========================================================================

    # Try to compile with a function that doesn't exist
    bad_chain = compiler.compile([
        Call(mod_name, "NonExistentFunction", [42]),
    ])
    test("Missing function → error", len(bad_chain.errors) > 0)
    test("Error mentions function name",
         any("NonExistent" in e for e in bad_chain.errors),
         f"errors: {bad_chain.errors}")

    # ========================================================================
    section("16. Convenience — compile_chain() pipeline")
    # ========================================================================

    convenience_chain = compile_chain(
        test_pe_path,
        [Call("test.dll", "Sleep", [5000])],
    )
    test("Convenience function works", convenience_chain is not None)
    test("Convenience no errors", len(convenience_chain.errors) == 0,
         f"errors: {convenience_chain.errors}")

    # ========================================================================
    section("17. Scanner — scan_pe() convenience")
    # ========================================================================

    conv_result = scan_pe(test_pe_path)
    test("scan_pe works", conv_result.count > 0)

    # ========================================================================
    section("18. FLAG_SET — Operand-Aware Quality Tiering")
    # ========================================================================

    # Scan and classify the PE with new gadgets
    scanner18 = PEGadgetScanner(max_gadget_len=10)
    scan18 = scanner18.scan(test_pe_path)
    classifier18 = GadgetClassifier()
    taxonomy18 = classifier18.classify_scan(scan18)

    # Check FLAG_SET gadgets exist
    flag_set_count = taxonomy18.count(GadgetClass.FLAG_SET)
    test("FLAG_SET gadgets found", flag_set_count > 0,
         f"count={flag_set_count}")

    # Check that register-only test (test eax, eax) gets q=1.0
    flag_gadgets = taxonomy18.get(GadgetClass.FLAG_SET)
    reg_only = [g for g in flag_gadgets if '[' not in g.notes]
    test("Register-only FLAG_SET at q=1.0",
         any(g.quality == 1.0 for g in reg_only),
         f"qualities: {[g.quality for g in reg_only]}")

    # Directly test the tiering helper
    q_reg, _ = classifier18._assess_flag_set_quality("eax, eax")
    test("Tier helper: reg-only → q=1.0", q_reg == 1.0, f"got {q_reg}")

    q_reg_imm, _ = classifier18._assess_flag_set_quality("eax, 0x8b48fffd")
    test("Tier helper: reg+imm → q=1.0", q_reg_imm == 1.0, f"got {q_reg_imm}")

    q_mem_small, _ = classifier18._assess_flag_set_quality("dword ptr [rax], edx")
    test("Tier helper: [rax] small offset → q=0.5", q_mem_small == 0.5, f"got {q_mem_small}")

    q_mem_large, _ = classifier18._assess_flag_set_quality("dword ptr [rbx - 0x75000000], edx")
    test("Tier helper: large disp → q=0.2", q_mem_large == 0.2, f"got {q_mem_large}")

    q_mem_large2, _ = classifier18._assess_flag_set_quality("byte ptr [rdx + rax - 0x7cb80000], cl")
    test("Tier helper: complex large disp → q=0.2", q_mem_large2 == 0.2, f"got {q_mem_large2}")

    # Memory ref inside brackets but imm outside: test [rax], 0x8b4c0000
    q_mem_imm_out, _ = classifier18._assess_flag_set_quality("dword ptr [rax], 0x8b4c0000")
    test("Tier helper: [rax]+large imm outside → q=0.5",
         q_mem_imm_out == 0.5, f"got {q_mem_imm_out}")

    # ========================================================================
    section("19. CMOV — Self-Move Detection")
    # ========================================================================

    cmov_count = taxonomy18.count(GadgetClass.CMOV)
    test("CMOV gadgets found", cmov_count > 0, f"count={cmov_count}")

    cmov_gadgets = taxonomy18.get(GadgetClass.CMOV)
    # Self-move (cmovg eax, eax) should be deprioritized
    self_moves = [g for g in cmov_gadgets if g.quality <= 0.15]
    real_cmovs = [g for g in cmov_gadgets if g.quality >= 0.9]
    test("Self-move CMOV deprioritized",
         len(self_moves) > 0,
         f"self_moves={len(self_moves)}, real={len(real_cmovs)}")
    test("Real CMOV at high quality",
         len(real_cmovs) > 0,
         f"count={len(real_cmovs)}")

    # Helper tests
    q_clean, _ = classifier18._assess_cmov_quality("eax, edx")
    test("CMOV helper: clean → q=1.0", q_clean == 1.0, f"got {q_clean}")

    q_self, _ = classifier18._assess_cmov_quality("eax, eax")
    test("CMOV helper: self-move → q=0.1", q_self == 0.1, f"got {q_self}")

    # ========================================================================
    section("20. WRITE_MEM — Classification")
    # ========================================================================

    wmem_count = taxonomy18.count(GadgetClass.WRITE_MEM_RCX_RAX)
    test("WRITE_MEM gadgets found", wmem_count > 0, f"count={wmem_count}")

    wmem_gadgets = taxonomy18.get(GadgetClass.WRITE_MEM_RCX_RAX)
    test("WRITE_MEM best quality >= 0.8",
         wmem_gadgets[0].quality >= 0.8 if wmem_gadgets else False,
         f"best q={wmem_gadgets[0].quality if wmem_gadgets else 'N/A'}")

    # ========================================================================
    section("21. Memory-Write Side Effect Detection")
    # ========================================================================

    # _has_memory_write helper — test directly via capstone
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    # inc dword ptr [rax] → memory write
    inc_mem = list(md.disasm(b'\xFF\x00', 0))
    test("_has_memory_write: inc [rax] → True",
         classifier18._has_memory_write(inc_mem),
         f"got False for inc [rax]")

    # inc eax → register only, no memory write
    inc_reg = list(md.disasm(b'\xFF\xC0', 0))
    test("_has_memory_write: inc eax → False",
         not classifier18._has_memory_write(inc_reg),
         f"got True for inc eax")

    # add dword ptr [rax], eax → memory write
    add_mem = list(md.disasm(b'\x01\x00', 0))
    test("_has_memory_write: add [rax], eax → True",
         classifier18._has_memory_write(add_mem),
         f"got False for add [rax], eax")

    # dec dword ptr [rdi] → memory write
    dec_mem = list(md.disasm(b'\xFF\x0F', 0))
    test("_has_memory_write: dec [rdi] → True",
         classifier18._has_memory_write(dec_mem),
         f"got False for dec [rdi]")

    # test esi, esi → no write (flag-only)
    test_reg = list(md.disasm(b'\x85\xF6', 0))
    test("_has_memory_write: test esi, esi → False",
         not classifier18._has_memory_write(test_reg),
         f"got True for test esi, esi")

    # _all_modified_regs — inc eax should now be tracked
    test("_all_modified_regs: inc eax tracked",
         'eax' in classifier18._all_modified_regs(inc_reg),
         f"got {classifier18._all_modified_regs(inc_reg)}")

    # _all_modified_regs: inc [rax] should NOT appear (memory, not register)
    test("_all_modified_regs: inc [rax] not in regs",
         len(classifier18._all_modified_regs(inc_mem)) == 0,
         f"got {classifier18._all_modified_regs(inc_mem)}")

    # End-to-end: inc [rax]; test esi, esi; ret → FLAG_SET with quality <= 0.15
    mem_write_flags = [
        g for g in flag_gadgets
        if 'MEMORY WRITE' in g.notes
    ]
    test("Memory-write FLAG_SET gadgets penalized",
         all(g.quality <= 0.15 for g in mem_write_flags) if mem_write_flags else True,
         f"found {len(mem_write_flags)} with MEMORY WRITE, "
         f"qualities: {[g.quality for g in mem_write_flags]}")

    # Verify the specific fixture gadget: inc [rax]; test esi, esi; ret
    # Should be classified as FLAG_SET but capped at 0.15
    low_flag_sets = [g for g in flag_gadgets if g.quality <= 0.15]
    test("Low-quality FLAG_SET exists (memory-write penalty)",
         len(low_flag_sets) > 0,
         f"all FLAG_SET qualities: {[g.quality for g in flag_gadgets]}")

    # ========================================================================
    section("22. Conditional Chain Compilation")
    # ========================================================================

    # Build a conditional chain: WinExec with conditional first arg
    # "If test_value is zero, use 0xAAAA; if nonzero, use 0xBBBB"
    cond_compiler = ChainCompiler(taxonomy18)
    cond_compiler.exports['test.dll'] = FAKE_EXPORTS

    cond_chain = cond_compiler.compile([
        Call("test.dll", "WinExec", [
            ConditionalArg(test_value=1, if_zero=0xAAAA, if_nonzero=0xBBBB),
            1,  # second arg = SW_SHOWNORMAL
        ]),
    ], exit_code=None)

    test("Conditional chain compiled",
         cond_chain is not None and len(cond_chain.entries) > 0,
         f"entries={len(cond_chain.entries) if cond_chain else 0}")

    test("Conditional chain no errors",
         len(cond_chain.errors) == 0,
         f"errors: {cond_chain.errors}")

    # Verify the chain contains FLAG_SET and CMOV gadgets
    roles = [e.role for e in cond_chain.entries]
    has_flag_set = any('FLAG_SET' in r for r in roles)
    has_cmov = any('CMOV' in r for r in roles)
    has_load_cond = any('load condition' in r for r in roles)
    has_default = any('CMOV default' in r for r in roles)
    has_alternate = any('CMOV alternate' in r for r in roles)

    test("Chain has FLAG_SET gadget", has_flag_set,
         f"roles: {[r for r in roles if 'FLAG' in r or 'CMOV' in r]}")
    test("Chain has CMOV gadget", has_cmov)
    test("Chain has condition load", has_load_cond)
    test("Chain has CMOV default value", has_default)
    test("Chain has CMOV alternate value", has_alternate)

    # Verify the conditional values are in the chain
    values = [e.value for e in cond_chain.entries]
    test("Chain contains if_nonzero value (0xBBBB)",
         0xBBBB in values,
         f"values: {[hex(v) for v in values]}")
    test("Chain contains if_zero value (0xAAAA)",
         0xAAAA in values,
         f"values: {[hex(v) for v in values]}")

    # Print the chain for inspection
    if cond_chain.entries:
        print(f"\n{cond_chain.dump()}\n")

    # Test with condition = 0 (should select if_zero path)
    cond_chain_zero = cond_compiler.compile([
        Call("test.dll", "Sleep", [
            ConditionalArg(test_value=0, if_zero=1000, if_nonzero=5000),
        ]),
    ], exit_code=None)
    test("Conditional chain (zero condition) compiled",
         len(cond_chain_zero.errors) == 0,
         f"errors: {cond_chain_zero.errors}")

    # Test ReturnValue condition
    cond_chain_retval = cond_compiler.compile([
        Call("test.dll", "Sleep", [1000]),
        Call("test.dll", "WinExec", [
            ConditionalArg(
                test_value=ReturnValue(),
                if_zero=0xDEAD,
                if_nonzero=0xBEEF,
            ),
            1,
        ]),
    ], exit_code=None)

    # This may or may not compile depending on whether we have an EAX-testing
    # FLAG_SET in the test fixtures. test_eax_eax_ret should provide it.
    retval_compiled = len(cond_chain_retval.errors) == 0
    test("ReturnValue conditional chain compiled",
         retval_compiled,
         f"errors: {cond_chain_retval.errors}")

    if retval_compiled:
        retval_roles = [e.role for e in cond_chain_retval.entries]
        test("ReturnValue chain has FLAG_SET",
             any('FLAG_SET' in r for r in retval_roles))
        if cond_chain_retval.warnings:
            print(f"  Warnings: {cond_chain_retval.warnings}")

    # ========================================================================
    section("23. Conditional Chain — Helper Methods")
    # ========================================================================

    # _parse_flag_set_register
    test("Parse FLAG_SET reg: 'esi, esi'",
         ChainCompiler._parse_flag_set_register("esi, esi") == "esi")
    test("Parse FLAG_SET reg: 'eax, 0x8b48fffd'",
         ChainCompiler._parse_flag_set_register("eax, 0x8b48fffd") == "eax")
    test("Parse FLAG_SET reg: memory ref returns ''",
         ChainCompiler._parse_flag_set_register("memory read [rax]") == "")
    test("Parse FLAG_SET reg: with side effects",
         ChainCompiler._parse_flag_set_register("esi, esi with side effects") == "esi")

    # _parse_cmov_operands
    cond_p, dst_p, src_p = ChainCompiler._parse_cmov_operands(
        "condition=e operands=eax, edx"
    )
    test("Parse CMOV: condition", cond_p == "e", f"got '{cond_p}'")
    test("Parse CMOV: dst", dst_p == "eax", f"got '{dst_p}'")
    test("Parse CMOV: src", src_p == "edx", f"got '{src_p}'")

    cond_p2, dst_p2, src_p2 = ChainCompiler._parse_cmov_operands(
        "condition=ne operands=rax, rcx with side effects"
    )
    test("Parse CMOV with side effects: condition", cond_p2 == "ne")
    test("Parse CMOV with side effects: dst", dst_p2 == "rax")
    test("Parse CMOV with side effects: src", src_p2 == "rcx")

finally:
    # Cleanup
    shutil.rmtree(tmpdir, ignore_errors=True)

# ============================================================================
print(f"\n{'='*60}")
pct = 100 * passed // (passed + failed) if (passed + failed) > 0 else 0
print(f"  RESULTS: {passed}/{passed+failed} passed ({pct}%)")
if errors:
    print(f"  FAILED:")
    for e in errors:
        print(f"    - {e}")
print(f"{'='*60}")

sys.exit(0 if failed == 0 else 1)

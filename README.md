# OIS-ROP

Offset Instruction Set — expresses arbitrary payloads as coordinate references into signed system binaries, with optional ROP chain execution using only gadgets found within those binaries.

**This is a security research tool.** It demonstrates that static byte-pattern scanning can be bypassed by never storing payload bytes — instead storing references to bytes that already exist in signed, trusted binaries on the target system. The "payload" is a list of coordinates. The bytes belong to Microsoft.

## How it works

OIS treats signed Windows DLLs (kernel32.dll, ntdll.dll, etc.) as **substrates**. Every possible byte value (0x00–0xFF) exists somewhere in these binaries. An OIS payload is a sequence of `(substrate, offset)` pairs that, when dereferenced at runtime, reconstruct the original bytes.

The payload on disk or in transit is just text:

```
k32[0x1CC,0x12D7,0x297,0x1055]
```

At runtime, each offset is read from the corresponding DLL to produce the actual bytes.

## Components

**compiler.py** — Compiles arbitrary binary payloads into OIS format. Analyzes substrate coverage, selects offsets, outputs in compact, JSON, or OIS file format. Also includes the assembler (OIS → bytes) and executor.

**gadgets.py** — ROP gadget finder. Scans loaded modules for useful instruction sequences (pop/ret, mov, syscall patterns) and builds ROP chains that execute entirely within signed module memory.

**executor.py** — Complete ROP-based execution engine. Chains gadgets from kernel32/ntdll to perform operations (e.g., WinExec) without allocating executable private memory.

## OIS Format

See `OIS_SPECIFICATION.md` for the full format specification.

### Quick example

```python
from ois_rop import OISCompiler, OISAssembler, OISParser

# Compile bytes to OIS (requires Windows for substrate access)
compiler = OISCompiler(substrate_ids=['k32', 'ntdll'])
payload = compiler.compile(b'\x48\x31\xC0\xC3')
print(payload.to_compact())  # → k32[0x1CC,0x12D7,0x297,0x1055]

# Parse OIS from string (cross-platform)
parsed = OISParser.parse_compact("k32[0x1CC,0x12D7,0x297,0x1055]")

# Assemble back to bytes (requires Windows for substrate access)
assembler = OISAssembler()
shellcode = assembler.assemble(parsed)
```

### CLI

```bash
# Compile a payload to OIS
ois compile payload.bin -o payload.ois

# Analyze substrate coverage
ois analyze --substrates k32,ntdll

# Validate an OIS file
ois validate payload.ois

# Assemble OIS back to bytes
ois assemble payload.ois -o output.bin
```

## Platform requirements

The compiler, assembler, and executor require Windows (they read from system DLLs and use Win32 APIs). The format parser and serializer are cross-platform.

## Tests

```bash
python tests/test_format.py    # Format parsing and serialization (59 tests)
```

## License

MIT — see `LICENSE`.

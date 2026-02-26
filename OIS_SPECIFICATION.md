# Offset Instruction Set (OIS) Specification
## Version 1.0

### Overview

The Offset Instruction Set (OIS) is a projection-based execution format that expresses arbitrary payloads as coordinate references into legitimate signed binaries.

**Core Principle:** No payload bytes are stored or transmitted. Only references to bytes that already exist in signed system binaries.

**Result:** The "malware" is a list of numbers. The bytes are OS's.

---

## 1. Format Specification

### 1.1 Basic Syntax

An OIS payload is a sequence of **byte references**, where each reference points to a location in a **substrate** (a signed binary).

```
<substrate_id>:<offset>[,<substrate_id>:<offset>...]
```

**Example:**
```
k32:0x1055,k32:0x12D7,k32:0x297,k32:0x1CC
```

This produces 4 bytes, each read from kernel32.dll at the specified offsets.

### 1.2 Substrate Identifiers

Standard substrate IDs for Windows:

| ID | Binary | Path |
|----|--------|------|
| `k32` | kernel32.dll | C:\Windows\System32\kernel32.dll |
| `ntdll` | ntdll.dll | C:\Windows\System32\ntdll.dll |
| `u32` | user32.dll | C:\Windows\System32\user32.dll |
| `gdi32` | gdi32.dll | C:\Windows\System32\gdi32.dll |
| `advapi` | advapi32.dll | C:\Windows\System32\advapi32.dll |
| `ws2` | ws2_32.dll | C:\Windows\System32\ws2_32.dll |
| `crypt` | crypt32.dll | C:\Windows\System32\crypt32.dll |
| `shell` | shell32.dll | C:\Windows\System32\shell32.dll |
| `ole32` | ole32.dll | C:\Windows\System32\ole32.dll |
| `msvcrt` | msvcrt.dll | C:\Windows\System32\msvcrt.dll |

Custom substrates can be defined in the header (see Section 2).

### 1.3 Offset Format

Offsets can be expressed as:

- **Hex:** `0x1055` or `0x1055`
- **Decimal:** `4181`
- **Relative:** `+0x10` (relative to previous offset in same substrate)

### 1.4 Compact Notation

For sequences from the same substrate, use grouping:

```
k32[0x1055,0x12D7,0x297,0x1CC]
```

Equivalent to:
```
k32:0x1055,k32:0x12D7,k32:0x297,k32:0x1CC
```

### 1.5 Range Notation

For consecutive bytes:

```
k32:0x1000-0x1010
```

Reads 17 bytes from offset 0x1000 through 0x1010 (inclusive).

### 1.6 Relative Offsets

For compression, use relative offsets after the first:

```
k32:0x1000,+5,+3,+12
```

Equivalent to:
```
k32:0x1000,k32:0x1005,k32:0x1008,k32:0x1014
```

---

## 2. File Format

### 2.1 OIS File Structure

```
OIS/1.0
[SUBSTRATES]
<custom substrate definitions>
[METADATA]
<optional metadata>
[PROJECTION]
<byte references>
[END]
```

### 2.2 Example File

```
OIS/1.0
[SUBSTRATES]
# Using default Windows substrates
[METADATA]
name: calc_spawner
arch: x64
size: 42
author: anonymous
[PROJECTION]
k32[0x1CC,0x100F,0x17D,0x278]
k32[0x1D8,0x10,0x5B,0x58,0x313,0xE2]
k32[0x1055,0x12D7,0x297]
ntdll[0x4420,0x4421,0x4422]
k32[0x1008,0x101A,0x1055]
[END]
```

### 2.3 Binary Format (Compact)

For size-sensitive applications, OIS supports a binary format:

```
Header (8 bytes):
  Magic:    "OIS\x00" (4 bytes)
  Version:  0x0100 (2 bytes, little-endian)
  Flags:    0x0000 (2 bytes)

Substrate Table:
  Count:    uint16
  Entries:  [id: uint8, path_len: uint8, path: utf8]...

Projection:
  Count:    uint32 (number of byte references)
  Entries:  [substrate_id: uint8, offset: uint32]...
```

---

## 3. Runtime Specification

### 3.1 Projection Process

```
function project(ois_payload):
    result = []
    for reference in ois_payload:
        substrate = load_substrate(reference.substrate_id)
        byte = substrate[reference.offset]
        result.append(byte)
    return bytes(result)
```

### 3.2 Substrate Loading

Substrates MUST be:
1. Loaded from the local system (not embedded)
2. Verified as signed (optional, for validation)
3. Cached for performance

### 3.3 Execution

After projection, the assembled bytes can be:
1. Written to executable memory and executed directly
2. Passed to a loader (VeriductNativeLoader)
3. Interpreted by a VM
4. Written to disk (loses provenance benefits)

---

## 4. Tooling Requirements

### 4.1 OIS Compiler

Converts arbitrary binary payload → OIS format:

```
ois-compile payload.bin -o payload.ois
ois-compile payload.bin --substrates k32,ntdll -o payload.ois
```

### 4.2 OIS Assembler

Converts OIS format → executable bytes at runtime:

```python
assembler = OISAssembler()
shellcode = assembler.assemble("payload.ois")
```

### 4.3 OIS Validator

Verifies OIS payload can be projected on target system:

```
ois-validate payload.ois
```

Checks:
- All referenced substrates exist
- All offsets are within bounds
- All byte values match expected (optional)

---

## 5. Security Considerations

### 5.1 Properties

1. **No payload bytes on disk** — the file contains only coordinate references
2. **Byte provenance** — all assembled bytes trace to signed binaries
3. **No static byte patterns** — scanners see numbers, not executable code
4. **Substrate is pre-deployed** — Windows DLLs are already present on target
5. **Format-agnostic** — OIS references are plain text and can be serialized in any container

### 5.2 Detection Vectors

1. **OIS runtime detection** - the assembler/executor itself
2. **Behavioral analysis** - execution patterns remain detectable
3. **Memory scanning** - assembled bytes in memory could be scanned
4. **Substrate access patterns** - unusual read patterns from system DLLs

### 5.3 Adversary Evasion Vectors (Threat Model)

An adversary using this technique could attempt to:

1. Embed the OIS runtime within a legitimate application to avoid standalone detection
2. Use indirect execution methods (callback-based APIs) to obscure the call chain
3. Spread substrate reads over time to avoid anomalous burst access patterns
4. Distribute reads across multiple substrates to reduce per-module access volume

These vectors inform what defenders should monitor for. See Section 5.2 for corresponding detection strategies.

---

## 6. Encoding Variants

OIS payloads can be encoded in various formats for transport:

### 6.1 JSON
```json
{
  "version": "1.0",
  "projection": [
    {"s": "k32", "o": 4181},
    {"s": "k32", "o": 4823},
    {"s": "ntdll", "o": 17440}
  ]
}
```

### 6.2 Base64 Coordinates
```
azMyOjB4MTA1NSxrMzI6MHgxMkQ3LGszMjoweDI5Nw==
```

### 6.3 Other Transports

Because OIS payloads are plain text (coordinate references), they can be embedded in any data channel that carries text or structured data. This is not unique to OIS — any sufficiently small payload can be encoded in arbitrary formats. The point is that OIS payloads are *inherently* text, requiring no additional encoding step to transit text-based channels.

---

## 7. Implementation Notes

### 7.1 Byte Coverage

Before compiling to OIS, verify all required byte values exist in chosen substrates:

```python
def verify_coverage(payload: bytes, substrates: list) -> bool:
    available = set()
    for substrate in substrates:
        available.update(set(substrate))
    required = set(payload)
    return required.issubset(available)
```

Most Windows system DLLs contain all 256 byte values.

### 7.2 Offset Selection Strategy

When multiple offsets contain the same byte value, selection can be:
1. **Sequential** - use each offset in order
2. **Random** - randomize for varied projection
3. **Distributed** - spread across substrate to look like legitimate access
4. **Semantic** - prefer offsets in code vs data sections

### 7.3 Version Tolerance

Substrate offsets may change between Windows versions. Options:
1. **Version-specific payloads** - compile for target Windows version
2. **Signature-based location** - find bytes by surrounding pattern
3. **Multiple fallback offsets** - try alternatives if primary fails

---

## 8. Example: Complete Workflow

### 8.1 Create Payload

```python
# Original shellcode
shellcode = bytes([0x48, 0x31, 0xC0, 0xC3])  # xor rax,rax; ret
```

### 8.2 Compile to OIS

```python
compiler = OISCompiler(substrates=['k32', 'ntdll'])
ois_payload = compiler.compile(shellcode)
# Result: "k32:0x1CC,k32:0x12D7,k32:0x297,k32:0x1055"
```

### 8.3 Distribute

Send the string `"k32:0x1CC,k32:0x12D7,k32:0x297,k32:0x1055"` via any channel.

### 8.4 Execute on Target

```python
assembler = OISAssembler()
shellcode = assembler.assemble("k32:0x1CC,k32:0x12D7,k32:0x297,k32:0x1055")
# shellcode is now bytes([0x48, 0x31, 0xC0, 0xC3])
# Execute via preferred method
```

---

## 9. Future Extensions

### 9.1 OIS/2.0 Considerations

- **Multi-byte references** - reference sequences, not just single bytes
- **Compression** - dictionary-based offset compression
- **Polymorphism** - automatic offset rotation per execution
- **Cross-platform** - Linux ELF substrates (libc.so, ld.so)

### 9.2 Tooling Roadmap

1. `ois-compile` - Payload to OIS compiler
2. `ois-asm` - OIS to bytes assembler
3. `ois-exec` - Direct OIS executor
4. `ois-validate` - Payload validator
5. `ois-analyze` - Substrate analyzer (find all byte locations)
6. `ois-polymorph` - Generate equivalent alternative projections

---

## 10. Legal Notice

This specification describes a data format. The format itself is not malicious.
Use of this format to create, distribute, or execute malicious code may violate
applicable laws. This specification is provided for research and educational
purposes.

---

## Appendix A: Quick Reference

### Syntax Summary

```
# Basic reference
k32:0x1055

# Multiple from same substrate  
k32[0x1055,0x12D7,0x297]

# Range
k32:0x1000-0x1010

# Relative
k32:0x1000,+5,+3,+12

# Multi-substrate
k32:0x1055,ntdll:0x4420,k32:0x297
```

### Standard Substrates

```
k32     = kernel32.dll
ntdll   = ntdll.dll
u32     = user32.dll
gdi32   = gdi32.dll
advapi  = advapi32.dll
ws2     = ws2_32.dll
```

---

*OIS Specification v1.0 - Bombadil Systems*

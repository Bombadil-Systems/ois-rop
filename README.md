# OIS-ROP - Offset Instruction Set / Return-Oriented Programming
Obfuscates arbitrary binary payloads by expressing them as coordinate references into legitimate signed Windows system binaries (DLLs). The payload becomes "a list of numbers" while the bytes belong to the OS.

## Tech Stack

- **Language:** Python 3.10+
- **Dependencies:** None (core is dependency-free)
- **Platform:** Windows (compiler/assembler/executor), cross-platform (parser)

## How It Works

Instead of storing payload bytes, OIS stores offsets pointing to bytes that already exist in trusted system DLLs like kernel32.dll and ntdll.dll. At runtime, the assembler reads those bytes from the actual DLLs to reconstruct the payload.

## Components

- **OISCompiler** - Converts bytes to OIS coordinate references
- **OISParser** - Parses compact, JSON, and file format OIS
- **OISAssembler** - Reads DLLs to reconstruct bytes from coordinates
- **OISExecutor** - Executes assembled shellcode via Windows APIs
- **GadgetFinder** - Discovers ROP gadgets in loaded modules
- **ROPChain** - Builds and executes return-oriented programming chains

## Usage

```bash
pip install -e .

# Compile payload to OIS format
ois compile payload.bin -o payload.ois --substrates k32,ntdll

# Assemble back to binary (Windows)
ois assemble payload.ois -o shellcode.bin

# Execute OIS payload (Windows)
ois execute payload.ois

# Analyze byte coverage
ois analyze --substrates k32,ntdll,u32

# Validate OIS file
ois validate payload.ois
```

## OIS Format Example

```
OIS/1.0
[SUBSTRATES]
# Using default Windows substrates
[METADATA]
name: example
arch: x64
[PROJECTION]
k32[0x1CC,0x12D7,0x297,0x1055]
ntdll[0x4420,0x4421]
[END]
```

## Standard Substrates

`k32` (kernel32), `ntdll`, `u32` (user32), `gdi32`, `advapi`, `ws2` (ws2_32), `crypt` (crypt32), `shell` (shell32), `ole32`, `msvcrt`

## Testing

59 format tests:
```bash
python tests/test_format.py
```

## Author

Chris Aziz — Bombadil Systems LLC (MIT License)

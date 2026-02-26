"""
OIS-ROP — Format Tests

Tests OIS payload construction, parsing, and serialization.
These tests are cross-platform (no Windows substrate access required).
"""

import sys
import os
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ois_rop.compiler import ByteReference, OISPayload, OISParser

passed = 0
failed = 0

def test(name: str, condition: bool, detail: str = ""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")
    if detail:
        print(f"       → {detail}")

def test_section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# ============================================================================
test_section("1. ByteReference")
# ============================================================================

ref = ByteReference(substrate_id="k32", offset=0x1055)
test("ByteReference creates", ref is not None)
test("substrate_id correct", ref.substrate_id == "k32")
test("offset correct", ref.offset == 0x1055)
test("str format", str(ref) == "k32:0x1055", f"got '{str(ref)}'")

ref2 = ByteReference(substrate_id="ntdll", offset=0x4420)
test("Different substrate", str(ref2) == "ntdll:0x4420")

ref_zero = ByteReference(substrate_id="k32", offset=0)
test("Zero offset", str(ref_zero) == "k32:0x0", f"got '{str(ref_zero)}'")


# ============================================================================
test_section("2. OISPayload Construction")
# ============================================================================

payload = OISPayload(
    version="1.0",
    metadata={"name": "test"},
    references=[
        ByteReference("k32", 0x1CC),
        ByteReference("k32", 0x12D7),
        ByteReference("k32", 0x297),
    ]
)
test("Payload creates", payload is not None)
test("Version set", payload.version == "1.0")
test("Metadata set", payload.metadata["name"] == "test")
test("References count", len(payload.references) == 3)

# Empty payload
empty = OISPayload()
test("Empty payload", len(empty.references) == 0)
test("Default version", empty.version == "1.0")


# ============================================================================
test_section("3. OISPayload to_compact")
# ============================================================================

compact = payload.to_compact()
test("Compact is string", isinstance(compact, str))
test("Contains substrate", "k32" in compact)
test("Contains offsets", "1CC" in compact.upper())

# Single reference
single = OISPayload(references=[ByteReference("k32", 0x1055)])
single_compact = single.to_compact()
test("Single ref compact", "k32" in single_compact and "1055" in single_compact.upper(),
     f"got '{single_compact}'")

# Multi-substrate
multi = OISPayload(references=[
    ByteReference("k32", 0x1CC),
    ByteReference("ntdll", 0x4420),
    ByteReference("k32", 0x297),
])
multi_compact = multi.to_compact()
test("Multi-substrate compact", "k32" in multi_compact and "ntdll" in multi_compact,
     f"got '{multi_compact}'")


# ============================================================================
test_section("4. OISPayload to_json")
# ============================================================================

j = payload.to_json()
test("JSON is string", isinstance(j, str))

data = json.loads(j)
test("JSON parseable", isinstance(data, dict))
test("JSON has version", data.get("version") == "1.0")
test("JSON has projection", "projection" in data)
test("Projection count", len(data["projection"]) == 3)
test("Projection has substrate",
     data["projection"][0].get("s") == "k32")
test("Projection has offset",
     data["projection"][0].get("o") == 0x1CC)


# ============================================================================
test_section("5. OISPayload to_file_format")
# ============================================================================

ff = payload.to_file_format()
test("File format is string", isinstance(ff, str))
test("Starts with OIS/1.0", ff.startswith("OIS/1.0"))
test("Has SUBSTRATES section", "[SUBSTRATES]" in ff)
test("Has METADATA section", "[METADATA]" in ff)
test("Has PROJECTION section", "[PROJECTION]" in ff)
test("Has END", "[END]" in ff)


# ============================================================================
test_section("6. OISParser.parse_compact — Grouped")
# ============================================================================

parsed = OISParser.parse_compact("k32[0x1CC,0x12D7,0x297]")
test("Parsed is OISPayload", isinstance(parsed, OISPayload))
test("3 references", len(parsed.references) == 3)
test("First ref substrate", parsed.references[0].substrate_id == "k32")
test("First ref offset", parsed.references[0].offset == 0x1CC)
test("Second ref offset", parsed.references[1].offset == 0x12D7)
test("Third ref offset", parsed.references[2].offset == 0x297)


# ============================================================================
test_section("7. OISParser.parse_compact — Single refs")
# ============================================================================

parsed_single = OISParser.parse_compact("k32:0x1055,k32:0x12D7,ntdll:0x4420")
test("3 references", len(parsed_single.references) == 3)
test("First substrate", parsed_single.references[0].substrate_id == "k32")
test("First offset", parsed_single.references[0].offset == 0x1055)
test("Third substrate", parsed_single.references[2].substrate_id == "ntdll")
test("Third offset", parsed_single.references[2].offset == 0x4420)


# ============================================================================
test_section("8. OISParser.parse_compact — Mixed")
# ============================================================================

mixed = OISParser.parse_compact("k32[0x1CC,0x12D7],ntdll:0x4420,k32:0x297")
test("4 references from mixed", len(mixed.references) == 4,
     f"got {len(mixed.references)}")
test("Substrates correct",
     [r.substrate_id for r in mixed.references] == ["k32", "k32", "ntdll", "k32"])


# ============================================================================
test_section("9. OISParser.parse_json")
# ============================================================================

json_str = json.dumps({
    "version": "1.0",
    "projection": [
        {"s": "k32", "o": 0x1055},
        {"s": "ntdll", "o": 0x4420},
    ]
})
parsed_json = OISParser.parse_json(json_str)
test("Parsed JSON", isinstance(parsed_json, OISPayload))
test("Version", parsed_json.version == "1.0")
test("2 references", len(parsed_json.references) == 2)
test("First ref", parsed_json.references[0].offset == 0x1055)


# ============================================================================
test_section("10. OISParser.parse_file")
# ============================================================================

file_content = """OIS/1.0
[SUBSTRATES]
# Using default Windows substrates
[METADATA]
name: test_payload
size: 5
[PROJECTION]
k32[0x1CC,0x12D7,0x297,0x1055,0x100]
[END]
"""

parsed_file = OISParser.parse_file(file_content)
test("Parsed file", isinstance(parsed_file, OISPayload))
test("Version from file", parsed_file.version == "1.0")
test("5 references", len(parsed_file.references) == 5,
     f"got {len(parsed_file.references)}")
test("Metadata parsed", parsed_file.metadata.get("name") == "test_payload")


# ============================================================================
test_section("11. Roundtrip: Compact")
# ============================================================================

original = OISPayload(references=[
    ByteReference("k32", 0x1CC),
    ByteReference("k32", 0x12D7),
    ByteReference("k32", 0x297),
])
compact_str = original.to_compact()
roundtripped = OISParser.parse_compact(compact_str)
test("Same ref count", len(roundtripped.references) == len(original.references))
test("Same offsets",
     [r.offset for r in roundtripped.references] == [r.offset for r in original.references])
test("Same substrates",
     [r.substrate_id for r in roundtripped.references] == [r.substrate_id for r in original.references])


# ============================================================================
test_section("12. Roundtrip: JSON")
# ============================================================================

json_str = original.to_json()
roundtripped_json = OISParser.parse_json(json_str)
test("JSON roundtrip count",
     len(roundtripped_json.references) == len(original.references))
test("JSON roundtrip offsets",
     [r.offset for r in roundtripped_json.references] == [r.offset for r in original.references])


# ============================================================================
test_section("13. Example file parse")
# ============================================================================

example_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "examples", "test.ois")
if os.path.exists(example_path):
    with open(example_path) as f:
        content = f.read()
    parsed_example = OISParser.parse_file(content)
    test("Example file parses", isinstance(parsed_example, OISPayload))
    test("Example has references", len(parsed_example.references) == 8,
         f"got {len(parsed_example.references)}")
    test("Example metadata has size",
         parsed_example.metadata.get("size") == "8")
else:
    test("Example file exists", False, f"not found at {example_path}")


# ============================================================================
print(f"\n{'='*60}")
print(f"  RESULTS: {passed}/{passed+failed} passed ({100*passed//(passed+failed)}%)")
print(f"{'='*60}")

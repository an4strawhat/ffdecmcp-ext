"""Opt-in proof of concept, NOT MCP tool registration.

Requires Java 17+ JDK and an installed FFDec JAR. Uses only synthetic fixtures
and caller-supplied local assets; no game paths/content are committed.
Run: python tests/prototypes/verify_avm2.py --ffdec-jar PATH --assets PATH
"""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib


def u30(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def fixture(value=7, dynamic=False, nested=False, reindexed=False, method_code=None):
    """Minimal ABC with a known class, initializer, and property-write method."""
    strings = ["", "Probe", "Object", "value", "writeValue"]
    abc = struct.pack("<HH", 16, 46)
    abc += b"\x01\x01\x01"  # int, uint, double pools
    abc += u30(len(strings)) + b"".join(u30(len(s)) + s.encode() for s in strings[1:])
    abc += b"\x02\x16\x00"  # public namespace with empty name
    abc += b"\x01"  # namespace-set pool
    # Four QNames; optionally a runtime-computed multiname.
    abc += u30(6 if dynamic else 5)
    order = [1, 2, 4, 3] if reindexed else range(1, 5)
    abc += b"".join(b"\x07\x01" + u30(i) for i in order)
    if dynamic:
        abc += b"\x11"  # RTQNameL: namespace and name on stack
    count = 5 if nested else 4
    abc += u30(count) + b"\x00\x00\x00\x00" * count  # method_info
    abc += b"\x00"  # metadata
    abc += b"\x01\x01\x02\x01\x00\x00\x01"  # class, name, super, flags, interfaces, iinit, traits
    abc += bytes([3 if reindexed else 4]) + b"\x01\x00\x02"  # writeValue -> method 2
    abc += b"\x01\x00"  # class_info cinit=1, no traits
    abc += b"\x01\x03\x01\x01\x04\x01\x00"  # script init=3 + class trait
    codes = [b"\xd0\x30\xd0\x49\x00\x47", b"\x47",
             b"\xd0\x24" + bytes([value]) + b"\x61\x03\x47", b"\x47"]
    if dynamic:
        codes[2] = b"\xd0\x20\x2c\x03\x24" + bytes([value]) + b"\x61\x05\x47"
    if reindexed:
        codes[2] = b"\xd0\x24" + bytes([value]) + b"\x61\x04\x47"
    if nested:
        codes.append(codes[2])
        codes[2] = b"\x40\x04\x29\x47"  # newfunction method4, pop, returnvoid
    if method_code is not None:
        codes[2] = method_code
    abc += u30(count)
    for i, code in enumerate(codes):
        abc += u30(i) + b"\x04\x01\x00\x01" + u30(len(code)) + code + b"\x00\x00"
    payload = struct.pack("<I", 0) + b"\x00" + abc
    tag = struct.pack("<HI", (82 << 6) | 63, len(payload)) + payload
    body = b"\x08\x00\x00\x18\x01\x00"  # RECT, 24 fps, 1 frame
    body += struct.pack("<H", (69 << 6) | 4) + struct.pack("<I", 8)  # AS3
    body += tag + b"\x40\x00\x00\x00"
    return b"FWS\x09" + struct.pack("<I", 8 + len(body)) + body


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ffdec-jar", required=True, type=Path)
    parser.add_argument("--assets", required=True, type=Path)
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="avm2-verification-", dir=os.environ.get("TEMP")))
    classes = work / "bridge"
    classes.mkdir()
    source = Path(__file__).with_name("Avm2Probe.java")
    subprocess.run(["javac", "-cp", str(args.ffdec_jar), "-d", str(classes), str(source)], check=True)
    cp = os.pathsep.join([str(classes), str(args.ffdec_jar)])
    checks = []

    def check(name, condition):
        checks.append({"check": name, "pass": bool(condition)})
        print(f"{'PASS' if condition else 'FAIL'} {name}", flush=True)

    def inspect(path):
        before = digest(path)
        # The Java bridge runs in an empty directory: any export would be visible.
        scratch = work / ("readonly-" + str(len(list(work.glob("readonly-*")))))
        scratch.mkdir()
        result = subprocess.run(["java", "-Djava.awt.headless=true", "-cp", cp,
                                 "Avm2Probe", str(path.resolve())],
                                cwd=scratch, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=180, check=True)
        records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        check("read-only input hash and no export", digest(path) == before and not list(scratch.iterdir()))
        return records

    base = work / "probe.swf"
    base.write_bytes(fixture())
    records = inspect(base)
    writes = [r for r in records if r["type"] == "instruction" and r["opcode"] == "setproperty"]
    check("known property write -> exact owning method", len(writes) == 1
          and writes[0]["property"] == "value" and writes[0]["method_id"] == 2
          and any("Probe" in o and "writeValue" in o for o in writes[0]["owners"]))
    check("known bytecode offset", writes[0]["offset"] == 3)
    check("class inventory and initializer ids", any(
        r["type"] == "class" and r["iinit"] == 0 and r["cinit"] == 1 for r in records))
    method = next(r for r in records if r["type"] == "method" and r["method_id"] == 2)
    check("method inspection returns expected bytes", method["code_hex"] == "d02407610347")
    check("reference search resolves instruction owner", writes[0]["multiname_id"] == 3
          and bool(writes[0]["owners"]))

    changed = work / "changed.swf"
    changed.write_bytes(fixture(value=8))
    other = inspect(changed)
    methods = lambda rs: {(r["abc"], r["method_id"]): r["code_hex"]
                          for r in rs if r["type"] == "method"}
    a, b = methods(records), methods(other)
    check("compare detects precisely one changed method",
          [key for key in a if a[key] != b[key]] == [(0, 2)])
    dynamic = work / "dynamic.swf"
    dynamic.write_bytes(fixture(dynamic=True))
    dyn = inspect(dynamic)
    check("runtime property name explicitly unresolved", any(
        r["type"] == "instruction" and r["opcode"] == "setproperty"
        and r["runtime_name"] and r["property"] == "" for r in dyn))
    compressed = work / "compressed.swf"
    raw = fixture()
    compressed.write_bytes(b"CWS" + raw[3:8] + zlib.compress(raw[8:]))
    check("compressed input same property evidence",
          [r for r in inspect(compressed) if r["type"] == "instruction"
           and r["opcode"] == "setproperty"] == writes)

    asset_summary = []
    candidates = ["academy.swf", "network_library.swf", "code_library.swf"]
    for filename in candidates:
        path = next(args.assets.rglob(filename), None)
        if path is None:
            check("representative asset available: " + filename, False)
            continue
        rs = inspect(path)
        ins = [r for r in rs if r["type"] == "instruction"]
        ws = [r for r in ins if r["opcode"] in ("setproperty", "initproperty", "setsuper")]
        owned = [r for r in ws if r["owners"]]
        sample = owned[:3]
        check("real asset contains owner-resolved property writes", bool(owned))
        check("method evidence cross-check", all(any(
            m["type"] == "method" and m["abc"] == r["abc"]
            and m["method_id"] == r["method_id"] and m["owners"] == r["owners"]
            for m in rs) for r in sample))
        # Independent baseline only: export a CSV into the test scratch area.
        # The inspection path above never invokes an exporter.
        csv_dir = work / ("baseline-linkage-" + str(len(asset_summary)))
        subprocess.run(["java", "-Djava.awt.headless=true", "-jar",
            str(args.ffdec_jar), "-export", "symbolClass", str(csv_dir), str(path)],
            capture_output=True, text=True, timeout=180, check=True)
        expected = set()
        for csv_path in csv_dir.rglob("*.csv"):
            with csv_path.open(encoding="utf-8-sig", newline="") as fh:
                for row in csv.reader(fh, delimiter=";"):
                    if len(row) >= 2:
                        expected.add((int(row[0]), row[1]))
        actual = {(r["id"], cls) for r in rs if r["type"] == "character"
                  for cls in r["classes"]}
        check("in-memory linkage matches CSV oracle (including empty mappings)",
              actual == expected)
        method_index = {(r["abc"], r["method_id"]): bytes.fromhex(r["code_hex"])
                        for r in rs if r["type"] == "method"}
        opbytes = {"setproperty": 0x61, "initproperty": 0x68, "setsuper": 0x05}
        check("reported writes agree with raw bytecode offsets", all(
            method_index[(r["abc"], r["method_id"])][r["offset"]] == opbytes[r["opcode"]]
            for r in ws))
        page = owned[:10]
        check("bounded property query fits transport budget",
              len(json.dumps(page).encode()) < 100_000 and len(page) <= 10)
        # Baseline CLI outputs intentionally stay in memory.
        def cli(command):
            return subprocess.run(["java", "-Djava.awt.headless=true", "-jar",
                str(args.ffdec_jar), command, str(path)], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=180, check=True).stdout
        dump = cli("-dumpAS3")
        report = cli("-linkReport")
        check("baseline lacks bytecode write locations",
              "setproperty" not in dump and "<instruction" not in report)
        asset_summary.append({"asset_role": "sample_" + str(len(asset_summary)+1),
            "classes": sum(r["type"] == "class" for r in rs),
            "methods": sum(r["type"] == "method" for r in rs),
            "property_writes": len(ws), "writes_with_direct_owner": len(owned),
            "unresolved_owner_writes": len(ws)-len(owned),
            "symbol_class_mappings": len(actual),
            "samples": sample, "json_bytes": len(json.dumps(rs).encode())})

    output = {"checks": checks, "assets": asset_summary,
        "limitations": ["Prototype only; not MCP registration or production pagination",
            "Direct trait/initializer ownership only; nested closures may lack owners",
            "No receiver-type inference, slot resolution, or reachability proof",
            "Comparison by method id only, not robust to reordered ABC indices",
            "Linkage includes character/class mapping and dependencies, not timeline placements"]}
    (work / "results.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    print("REPORT", work / "results.json")
    print("RESULT", sum(c["pass"] for c in checks), "/", len(checks))
    raise SystemExit(0 if all(c["pass"] for c in checks) else 1)


if __name__ == "__main__":
    main()

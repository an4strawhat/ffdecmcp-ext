"""Controlled experiments for selected proposed mitigations, not MCP features.

Only the cases explicitly asserted here are verified. No receiver inference,
general CFG, timeline walker or version compatibility layer is implemented.
"""
import argparse
from collections import defaultdict, deque
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from verify_avm2 import fixture, digest
from strict_swf import validate_swf


def enclosing_contexts(records):
    """Follow newfunction edges without assuming a unique lexical owner."""
    owners = defaultdict(set)
    children = defaultdict(set)
    for r in records:
        key = (r["abc"], r["method_id"]) if "method_id" in r else None
        if key:
            owners[key].update(r.get("owners", []))
        if r["type"] == "instruction" and r["opcode"] == "newfunction":
            children[key].add((r["abc"], r["operands"][0]))
    queue = deque(owners)
    while queue:
        parent = queue.popleft()
        for child in children[parent]:
            combined = owners[child] | owners[parent]
            if combined != owners[child]:
                owners[child] = combined
                queue.append(child)
    return owners


def page(rows, start, count, byte_budget):
    """Reference pagination algorithm measuring the complete JSON envelope."""
    result = []
    for row in rows[start: start + count]:
        trial = {"results": result + [row], "next_offset": start + len(result) + 1}
        if len(json.dumps(trial, ensure_ascii=True).encode("utf-8")) > byte_budget:
            break
        result.append(row)
    return {"results": result, "next_offset": start + len(result)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ffdec-jar", type=Path, required=True)
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="avm2-limits-", dir=os.environ.get("TEMP")))
    classes = work / "classes"
    classes.mkdir()
    subprocess.run(["javac", "-cp", str(args.ffdec_jar), "-d", str(classes),
                    str(Path(__file__).with_name("Avm2Probe.java"))], check=True)
    cp = os.pathsep.join([str(classes), str(args.ffdec_jar)])
    checks = []

    def check(name, value):
        checks.append({"check": name, "passed": bool(value)})
        print(("PASS " if value else "FAIL ") + name, flush=True)

    def inspect(label, data):
        path = work / (label + ".swf")
        path.write_bytes(data)
        scratch = work / label
        scratch.mkdir()
        before = digest(path)
        try:
            validate_swf(data)
        except ValueError as exc:
            check(label + ": rejected before launching FFDec", True)
            check(label + ": rejected source unchanged", digest(path) == before)
            return subprocess.CompletedProcess([], 2, "", str(exc)), []
        proc = subprocess.run(["java", "-Xmx128m", "-Djava.awt.headless=true", "-cp",
                               cp, "Avm2Probe", str(path)], cwd=scratch,
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=30)
        check(label + ": source unchanged and no exports",
              digest(path) == before and not list(scratch.iterdir()))
        return proc, [json.loads(line) for line in proc.stdout.splitlines()
                      if line.startswith("{")]

    proc, nested = inspect("nested", fixture(nested=True))
    check("nested fixture parses under 128 MiB heap", proc.returncode == 0)
    child = next(r for r in nested if r["type"] == "method" and r["method_id"] == 4)
    contexts = enclosing_contexts(nested)
    check("unmapped nested method gains enclosing context through newfunction",
          child["owners"] == [] and any("writeValue" in s for s in contexts[(0, 4)]))
    # Deliberately model two possible parents and a back-edge. These are graph
    # unit tests, not claims that these edges exist in the real asset corpus.
    graph = [
        {"type": "method", "abc": 0, "method_id": 1, "owners": ["A::a"]},
        {"type": "method", "abc": 0, "method_id": 2, "owners": ["B::b"]},
        *[{"type": "instruction", "abc": 0, "method_id": p, "opcode": "newfunction",
           "operands": [c], "owners": []} for p, c in [(1, 3), (2, 3), (3, 1)]]]
    check("ownership graph preserves ambiguity and terminates on cycles",
          enclosing_contexts(graph)[(0, 3)] == {"A::a", "B::b"})

    _, dynamic = inspect("dynamic", fixture(dynamic=True))
    write = next(r for r in dynamic if r["type"] == "instruction" and r["opcode"] == "setproperty")
    check("dynamic name and namespace remain explicit, not inferred",
          write["runtime_name"] and write["runtime_namespace"] and not write["property"])
    check("no false receiver-type claim in prototype record", "receiver_type" not in write)
    _, slots = inspect("slots", fixture(method_code=b"\xd0\x24\x07\x6d\x01\x47"))
    slot = next(r for r in slots if r["type"] == "instruction" and r["opcode"] == "setslot")
    check("slot writes retain slot id without inventing property names",
          slot["operands"] == [1] and not slot["property"] and slot["multiname_id"] == 0)

    # Straight-line unreachable tail after returnvoid. This does NOT implement
    # general reachability (branches, switches or exception edges).
    _, dead = inspect("unreachable", fixture(method_code=b"\x47\xd0\x24\x07\x61\x03\x47"))
    ins = [r for r in dead if r["type"] == "instruction" and r["method_id"] == 2]
    check("unreachable fixture proves presence is not execution",
          ins[0]["opcode"] == "returnvoid" and any(r["opcode"] == "setproperty" for r in ins[1:]))

    _, original = inspect("original", fixture())
    _, reordered = inspect("reindexed", fixture(reindexed=True))
    method_hex = lambda rs: next(r["code_hex"] for r in rs
                                if r["type"] == "method" and r["method_id"] == 2)
    def normalized(rs):
        return [(r["opcode"], r["multiname"] if r["multiname_id"] else r["operands"])
                for r in rs if r["type"] == "instruction" and r["method_id"] == 2]
    check("raw byte diff changes on constant-pool reindexing",
          method_hex(original) != method_hex(reordered))
    check("multiname normalization removes the controlled false-positive",
          normalized(original) == normalized(reordered))

    rows = [{"property": "\U0001f600" * 100, "offset": i} for i in range(100)]
    offset, returned = 0, []
    pages_ok = True
    while offset < len(rows):
        p = page(rows, offset, 7, 4096)
        pages_ok &= len(json.dumps(p, ensure_ascii=True).encode()) <= 4096
        if p["next_offset"] == offset:
            pages_ok = False
            break
        returned.extend(p["results"])
        offset = p["next_offset"]
    check("byte-budget pagination accounts for Unicode JSON escaping", pages_ok)
    check("pagination has no missing or repeated records", returned == rows)
    check("oversized single result is detectable, not silently sent",
          page(rows, 0, 1, 50)["results"] == [])
    fingerprint = lambda b: hashlib.sha256(b).hexdigest()
    cursor_hash = fingerprint(fixture())
    check("artifact fingerprint invalidates stale cursor",
          cursor_hash != fingerprint(fixture(value=8)))

    # Error paths tested in separate processes, so parser errors cannot take
    # down the test host or an MCP transport.
    for label, data in [("short", b"FWS"), ("broken", fixture()[:40])]:
        proc, _ = inspect(label, data)
        check(label + ": invalid input rejected", proc.returncode != 0)
    try:
        subprocess.run(["java", "-cp", cp, "Avm2Probe", str(work / "original.swf")],
                       capture_output=True, timeout=0.001)
        timed_out = False
    except subprocess.TimeoutExpired:
        timed_out = True
    check("subprocess timeout interrupts inspection", timed_out)

    report = {"checks": checks, "not_verified": [
        "Production Java-side filtering/pagination and actual MCP stdio budget",
        "Receiver data-flow inference and constant propagation",
        "Trait-resolved slots and global slots",
        "Branch/switch/exception-aware reachability",
        "Timeline placement traversal",
        "Stable method matching across rebuilt or reordered classes",
        "Full ABC validation/fuzzing, ZWS preflight, resource-exhaustion and process-tree cleanup",
        "FFDec version handshake and cross-version compatibility",
        "Nested-function ownership on all real assets",
    ]}
    (work / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("REPORT", work / "results.json")
    print("RESULT", sum(c["passed"] for c in checks), "/", len(checks))
    raise SystemExit(0 if all(c["passed"] for c in checks) else 1)


if __name__ == "__main__":
    main()

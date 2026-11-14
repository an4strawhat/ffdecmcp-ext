"""Verify strict preflight, real closure evidence, and bounded stdio experiment."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib

from strict_swf import validate_swf
from verify_avm2 import fixture, digest
from verify_limitations import enclosing_contexts


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ffdec-jar", required=True, type=Path)
    p.add_argument("--assets", required=True, type=Path)
    args = p.parse_args()
    work = Path(tempfile.mkdtemp(prefix="avm2-hardening-", dir=os.environ.get("TEMP")))
    checks, samples = [], []

    def check(name, ok):
        checks.append({"check": name, "passed": bool(ok)})
        print(("PASS " if ok else "FAIL ") + name, flush=True)

    raw = fixture()
    cws = b"CWS" + raw[3:8] + zlib.compress(raw[8:])
    check("preflight accepts valid FWS and CWS",
          validate_swf(raw) == validate_swf(cws))
    # Retain a correctly sized SWF header while cutting the long DoABC payload.
    cut = bytearray(raw[:40])
    struct.pack_into("<I", cut, 4, len(cut))
    cases = {
        "truncated header": b"FWS",
        "wrong file size": raw[:-4],
        "truncated tag with matching file size": bytes(cut),
        "truncated compression stream": cws[:-2],
        "trailing compressed bytes": cws + b"junk",
        "unsupported signature": b"XYZ" + raw[3:],
        "missing End tag": raw[:-2][:4] + struct.pack("<I", len(raw)-2) + raw[8:-2],
        "oversized declared output": raw[:4] + struct.pack("<I", 2**31) + raw[8:],
    }
    for label, data in cases.items():
        try:
            validate_swf(data)
            rejected = False
        except ValueError:
            rejected = True
        check("preflight rejects " + label, rejected)
    try:
        validate_swf(cws, max_decoded=32)
        limited = False
    except ValueError:
        limited = True
    check("decoded-size budget enforced", limited)
    # Nested DefineSprite with no nested End tag, despite a valid outer End.
    header_end = 14
    nested = b"\x01\x00\x01\x00\x40\x00"  # id, frames, ShowFrame, no End
    body = raw[8:header_end] + struct.pack("<H", (39 << 6) | len(nested)) + nested + b"\x00\x00"
    malformed_sprite = b"FWS\x09" + struct.pack("<I", 8+len(body)) + body
    try:
        validate_swf(malformed_sprite)
        rejected = False
    except ValueError:
        rejected = True
    check("preflight validates nested sprite End tags", rejected)

    classes = work / "bridge"
    classes.mkdir()
    subprocess.run(["javac", "-cp", str(args.ffdec_jar), "-d", str(classes),
                    str(Path(__file__).with_name("Avm2Probe.java"))], check=True)
    cp = os.pathsep.join([str(classes), str(args.ffdec_jar)])
    for filename in ["academy.swf", "network_library.swf", "code_library.swf"]:
        path = next(args.assets.rglob(filename))
        before = digest(path)
        preflight = validate_swf(path.read_bytes())
        check("strict validation accepts representative real asset", preflight["tags"] > 0)
        sandbox = work / f"sandbox-{len(samples)}"
        sandbox.mkdir()
        proc = subprocess.run(["java", "-Xmx256m", "-Djava.awt.headless=true",
                               "-cp", cp, "Avm2Probe", str(path)], cwd=sandbox,
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=120, check=True)
        rs = [json.loads(line) for line in proc.stdout.splitlines() if line.startswith("{")]
        contexts = enclosing_contexts(rs)
        writes = [r for r in rs if r["type"] == "instruction"
                  and r["opcode"] in ("setproperty", "initproperty", "setsuper")]
        before_unmapped = [r for r in writes if not r["owners"]]
        after_unmapped = [r for r in writes
                          if not contexts[(r["abc"], r["method_id"])]]
        check("ownership propagation never drops known contexts", all(
            set(r["owners"]) <= contexts[(r["abc"], r["method_id"])]
            for r in writes))
        check("real inspection is read-only and export-free",
              digest(path) == before and not list(sandbox.iterdir()))
        samples.append({"sample": len(samples)+1, "unmapped_writes_before": len(before_unmapped),
                        "unmapped_writes_after": len(after_unmapped),
                        "tags_validated": preflight["tags"]})

    async def transport():
        from fastmcp import Client
        from fastmcp.client.transports import PythonStdioTransport
        from mcp.types import CallToolResult
        script = Path(__file__).with_name("stdio_fixture.py")
        transport = PythonStdioTransport(script, cwd=str(script.parent))
        seen, largest = [], 0
        async with Client(transport, timeout=30) as client:
            offset = 0
            while offset < 100:
                response = await client.call_tool("bounded_page", {"offset": offset})
                wire_result = CallToolResult(content=response.content,
                    structuredContent=response.structured_content, isError=response.is_error)
                largest = max(largest, len(wire_result.model_dump_json().encode()))
                payload = response.structured_content
                if payload is None:
                    payload = json.loads(response.content[0].text)
                seen.extend(r["offset"] for r in payload["results"])
                if payload["next_offset"] <= offset:
                    raise AssertionError("Pagination stalled")
                offset = payload["next_offset"]
            # A deliberate tool error must not disconnect the transport.
            try:
                await client.call_tool("bounded_page", {"offset": -1})
            except Exception:
                pass
            alive = await client.call_tool("bounded_page", {"offset": 100})
            check("stdio remains connected after tool error", not alive.is_error)
        check("actual stdio pagination returns every record exactly once", seen == list(range(100)))
        check("actual MCP result envelope is bounded in controlled test", largest < 32_768)
        return {"largest_measured_client_result_bytes": largest,
                "scope": "Test-only Python paging server, not production Java bridge"}

    stdio = asyncio.run(transport())
    report = {"checks": checks, "real_asset_closure_results": samples,
              "stdio": stdio,
              "validation_scope": "SWF header, FWS/CWS stream and tag envelopes only; not full ABC verification",
              "still_unverified": [
                  "ZWS/encrypted preflight and full ABC/operand validity",
                  "Receiver-type inference, slot-trait resolution, constant propagation",
                  "Branch/switch/exception reachability and complete timeline inspection",
                  "Cross-build method matching and cross-version FFDec compatibility",
                  "Production Java filtering/pagination and hostile-resource/process-tree tests"]}
    (work / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("SAMPLES", json.dumps(samples))
    print("STDIO", json.dumps(stdio))
    print("REPORT", work / "results.json")
    print("RESULT", sum(c["passed"] for c in checks), "/", len(checks))
    raise SystemExit(0 if all(c["passed"] for c in checks) else 1)


if __name__ == "__main__":
    main()

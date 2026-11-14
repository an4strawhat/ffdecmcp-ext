"""Supervised, bounded, read-only access to FFDec's Java library.

This layer deliberately supports FFDec 26.4.0 JAR mode and FWS/CWS only.
It never exports decompiled source or modifies the inspected artifact.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import threading
import zlib

from .config import FFDecMode, get_config


class InspectionError(ValueError):
    """Actionable inspection failure."""


MAX_INPUT = 64 * 1024 * 1024
SUPPORTED_FFDEC = "26.4.0"


def validate_container(data: bytes) -> dict:
    """Validate container/tag envelopes, not the full AVM2 verifier grammar."""
    if len(data) < 8:
        raise InspectionError("Truncated SWF header")
    size = struct.unpack_from("<I", data, 4)[0]
    if not 12 <= size <= MAX_INPUT:
        raise InspectionError("Declared decoded size must be between 12 bytes and 64 MiB")
    if data[:3] == b"FWS":
        raw = data
    elif data[:3] == b"CWS":
        dec = zlib.decompressobj()
        try:
            body = dec.decompress(data[8:], MAX_INPUT - 8 + 1)
        except zlib.error as exc:
            raise InspectionError("Invalid zlib stream") from exc
        if len(body) > MAX_INPUT - 8 or dec.unconsumed_tail:
            raise InspectionError("Decoded input exceeds 64 MiB")
        if not dec.eof or dec.unused_data:
            raise InspectionError("Incomplete zlib stream or trailing compressed data")
        raw = b"FWS" + data[3:8] + body
    else:
        raise InspectionError("Inspection supports FWS/CWS only; ZWS/GFX/encrypted input is not supported yet")
    if len(raw) != size:
        raise InspectionError("Declared SWF size does not match decoded size")
    start = 8 + (5 + (raw[8] >> 3) * 4 + 7) // 8 + 4
    if start > len(raw):
        raise InspectionError("Truncated frame header")
    count = 0

    def tags(pos, end, depth):
        nonlocal count
        if depth > 64:
            raise InspectionError("Nested sprite depth exceeds 64")
        while pos < end:
            if end - pos < 2:
                raise InspectionError("Truncated tag header")
            val = struct.unpack_from("<H", raw, pos)[0]
            pos += 2
            code, length = val >> 6, val & 63
            if length == 63:
                if end - pos < 4:
                    raise InspectionError("Truncated long tag header")
                length = struct.unpack_from("<I", raw, pos)[0]
                pos += 4
            stop = pos + length
            if stop > end:
                raise InspectionError("Tag payload exceeds its enclosing stream")
            count += 1
            if code == 0:
                if length or stop != end:
                    raise InspectionError("Invalid End tag or trailing tag data")
                return
            if code == 39:
                if length < 6:
                    raise InspectionError("Truncated sprite")
                tags(pos + 4, stop, depth + 1)
            pos = stop
        raise InspectionError("Missing End tag")

    tags(start, len(raw), 0)
    return {"decoded_size": size, "tag_count": count, "scope": "container_and_tag_envelopes"}


def _terminate_tree(proc):
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if proc.poll() is None:
        proc.kill()


def _run(command, timeout, output_limit):
    """Drain both pipes concurrently with hard capture bounds and a deadline."""
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
    except FileNotFoundError as exc:
        raise InspectionError("Java JDK not found; install Java 17+ with source-file launch support") from exc
    exceeded = threading.Event()
    output, errors = bytearray(), bytearray()

    def drain(stream, dest, cap):
        while True:
            data = stream.read(4096)
            if not data:
                break
            room = max(0, cap - len(dest))
            dest.extend(data[:room])
            if len(data) > room:
                exceeded.set()
                proc.kill()
                break
        stream.close()

    threads = [threading.Thread(target=drain, args=(proc.stdout, output, output_limit), daemon=True),
               threading.Thread(target=drain, args=(proc.stderr, errors, 32_768), daemon=True)]
    for thread in threads:
        thread.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _terminate_tree(proc)
        proc.wait(timeout=10)
        raise InspectionError("Inspection deadline exceeded; narrow the query or increase timeout") from exc
    finally:
        for thread in threads:
            thread.join(timeout=10)
    if exceeded.is_set():
        raise InspectionError("Bridge output exceeded the capture budget")
    if proc.returncode:
        raise InspectionError("Bridge failed: " + errors.decode("utf-8", "replace")[:2000])
    return output.decode("utf-8", "strict")


def inspect_avm2(operation, swf_path, *, abc_index=None, method_id=None,
                 property_name="", access="write", offset=0, limit=50,
                 max_bytes=65_536, expected_sha256=None, timeout=60):
    """Execute one bounded query. Offset cursors must be paired with SHA-256."""
    if operation not in {"classes", "method", "accesses"}:
        raise InspectionError("Unsupported inspection operation")
    if not 1 <= limit <= 200 or not 4096 <= max_bytes <= 131_072:
        raise InspectionError("limit must be 1..200 and max_bytes 4096..131072")
    if offset < 0 or not 1 <= timeout <= 300:
        raise InspectionError("offset must be nonnegative and timeout 1..300 seconds")
    if abc_index is not None and abc_index < 0 or method_id is not None and method_id < 0:
        raise InspectionError("ABC and method indices must be nonnegative")
    if operation == "method" and (abc_index is None or method_id is None):
        raise InspectionError("Method inspection requires abc_index and method_id")
    if access not in {"read", "write", "all"}:
        raise InspectionError("access must be read, write or all")
    if len(property_name) > 512:
        raise InspectionError("property_name is limited to 512 characters")
    if offset and not expected_sha256:
        raise InspectionError("Pagination requires expected_sha256 from the first response")
    path = Path(swf_path).resolve()
    if not path.is_file():
        raise InspectionError("SWF file does not exist")
    if path.stat().st_size > MAX_INPUT:
        raise InspectionError("Input file exceeds 64 MiB")
    with path.open("rb") as stream:
        data = stream.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise InspectionError("Input file exceeds 64 MiB")
    fingerprint = hashlib.sha256(data).hexdigest()
    if expected_sha256 and expected_sha256 != fingerprint:
        raise InspectionError("Artifact changed; restart inspection with offset=0")
    validation = validate_container(data)
    config = get_config()
    if config.mode != FFDecMode.JAR:
        raise InspectionError("Inspection requires JAR mode; set FFDEC_PATH to ffdec.jar")
    jar = Path(config.path).resolve()
    # Keep detection explicit; do not silently use an untested library API.
    banner = _run(["java", "-Xmx512m", "-Djava.awt.headless=true", "-jar",
                   str(jar), "-help"], min(timeout, 15), 65_536)
    if "v." + SUPPORTED_FFDEC not in banner:
        raise InspectionError("Inspection currently supports FFDec 26.4.0 only")
    source = Path(__file__).with_name("java") / "InspectionBridge.java"
    payload = _run(["java", "-Xmx512m", "-Djava.awt.headless=true", "-cp",
        str(jar), str(source), operation, str(path),
        str(abc_index if abc_index is not None else -1),
        str(method_id if method_id is not None else -1), property_name, access,
        str(offset), str(limit), str(max_bytes)], timeout, max_bytes)
    # Detect concurrent changes; never return evidence under a stale digest.
    with path.open("rb") as stream:
        after = hashlib.file_digest(stream, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else hashlib.sha256(stream.read(MAX_INPUT + 1)).hexdigest()
    if fingerprint != after:
        raise InspectionError("Input changed while inspecting; results discarded")
    result = json.loads(payload)
    result.update(success=True, sha256=fingerprint, ffdec_version=SUPPORTED_FFDEC,
        validation=validation, limitations=[
            "Property access search resolves named catch slots, explicit activation slots and directly declared class slots when supported control flow establishes the receiver. Inherited and automatic slot layouts are not inferred.",
            "Enclosing contexts are not proof of unique ownership or runtime execution.",
            "Container validation is not full ABC verification.",
            "Exact property-name filters omit unresolved runtime names and slots; use an empty filter to include them.",
        ])
    # A conservative result cap also bounds duplicated MCP text/structured data.
    if len(json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode()) > max_bytes:
        raise InspectionError("Response envelope exceeds max_bytes; narrow the query")
    return result

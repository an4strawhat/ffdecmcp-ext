"""Supervised, bounded, read-only access to FFDec's Java library.

This layer supports FFDec 26.4.0 and 26.5.0 in JAR mode with FWS, CWS and ZWS.
It never exports decompiled source or modifies the inspected artifact.
"""
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import threading
import zlib

from .config import FFDecMode, get_config


class InspectionError(ValueError):
    """Actionable inspection failure."""


MAX_INPUT = 64 * 1024 * 1024
SUPPORTED_FFDEC_VERSIONS = ("26.4.0", "26.5.0")


def _decode_zws_body(data: bytes, body_size: int) -> bytes:
    # ZWS stores the compressed length separately from the five LZMA properties.
    if len(data) < 17:
        raise InspectionError("Truncated ZWS compression header")
    compressed_size, = struct.unpack_from("<I", data, 8)
    if compressed_size != len(data) - 17:
        raise InspectionError("Declared ZWS compressed size does not match payload")
    properties = data[12]
    lc, lp, pb = properties % 9, (properties // 9) % 5, properties // 45
    if pb > 4 or lc + lp > 4:
        raise InspectionError("Unsupported ZWS LZMA properties")
    dictionary, = struct.unpack_from("<I", data, 13)
    if dictionary > MAX_INPUT:
        raise InspectionError("ZWS LZMA dictionary exceeds 64 MiB")
    try:
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[{
            "id": lzma.FILTER_LZMA1, "dict_size": max(4096, dictionary),
            "lc": lc, "lp": lp, "pb": pb,
        }])
        body = decoder.decompress(memoryview(data)[17:], max_length=body_size + 1)
    except (lzma.LZMAError, ValueError) as exc:
        raise InspectionError("Invalid ZWS LZMA stream") from exc
    # Length-terminated streams may omit the LZMA end marker.
    if len(body) != body_size:
        raise InspectionError("Declared SWF size does not match decoded ZWS size")
    if decoder.unused_data:
        raise InspectionError("Trailing data after ZWS LZMA stream")
    return body


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
    elif data[:3] == b"ZWS":
        raw = b"FWS" + data[3:8] + _decode_zws_body(data, size - 8)
    else:
        raise InspectionError("Inspection supports FWS, CWS and ZWS; GFX and encrypted input are unsupported")
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


def _validated_input(swf_path, expected_sha256):
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
    if expected_sha256 is not None:
        if re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256) is None:
            raise InspectionError("expected_sha256 must be exactly 64 hexadecimal characters")
        if expected_sha256.lower() != fingerprint:
            raise InspectionError("Artifact changed; restart inspection with offset=0")
    return path, fingerprint, validate_container(data)


def _check_input_digest(path, fingerprint):
    with path.open("rb") as stream:
        after = hashlib.file_digest(stream, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else hashlib.sha256(stream.read(MAX_INPUT + 1)).hexdigest()
    if fingerprint != after:
        raise InspectionError("Input changed while inspecting; results discarded")


def _inspection_version(banner):
    match = re.search(r"^[ \t]*JPEXS Free Flash Decompiler v\.([\w.+-]+)[ \t\r]*$",
                      banner, flags=re.MULTILINE)
    version = match.group(1) if match else None
    if version not in SUPPORTED_FFDEC_VERSIONS:
        detected = version or "unknown version"
        supported = " or ".join(SUPPORTED_FFDEC_VERSIONS)
        raise InspectionError(f"Inspection requires FFDec {supported}; detected {detected}")
    return version


def _bridge_command(timeout):
    config = get_config()
    if config.mode != FFDecMode.JAR:
        raise InspectionError("Inspection requires JAR mode; set FFDEC_PATH to ffdec.jar")
    jar = Path(config.path).resolve()
    # Keep detection explicit; do not silently use an untested library API.
    banner = _run(["java", "-Xmx512m", "-Djava.awt.headless=true", "-jar",
                   str(jar), "-help"], min(timeout, 15), 65_536)
    version = _inspection_version(banner)
    source = Path(__file__).with_name("java") / "InspectionBridge.java"
    return ["java", "-Xmx512m", "-Djava.awt.headless=true", "-cp", str(jar), str(source)], version


def _check_page(offset, limit, max_bytes, timeout):
    if not 1 <= limit <= 200 or not 4096 <= max_bytes <= 131_072:
        raise InspectionError("limit must be 1..200 and max_bytes 4096..131072")
    if offset < 0 or not 1 <= timeout <= 300:
        raise InspectionError("offset must be nonnegative and timeout 1..300 seconds")


def _bounded_result(result, max_bytes):
    if len(json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode()) > max_bytes:
        raise InspectionError("Response envelope exceeds max_bytes; narrow the query")
    return result


def compare_avm2(original_swf_path, patched_swf_path, *, include_unchanged=False,
                 offset=0, limit=50, max_bytes=65_536, timeout=60,
                 expected_original_sha256=None, expected_patched_sha256=None,
                 instruction_offset=0):
    """Compare two validated SWFs through the same bounded read-only bridge."""
    _check_page(offset, limit, max_bytes, timeout)
    if not 0 <= instruction_offset <= MAX_INPUT:
        raise InspectionError("instruction_offset is outside the supported range")
    if (offset or instruction_offset) and (expected_original_sha256 is None or expected_patched_sha256 is None):
        raise InspectionError("Pagination requires both expected SHA-256 values")
    original, original_sha, original_validation = _validated_input(original_swf_path, expected_original_sha256)
    patched, patched_sha, patched_validation = _validated_input(patched_swf_path, expected_patched_sha256)
    bridge, version = _bridge_command(timeout)
    command = bridge + ["compare", str(original), "-1", "-1", "", "write",
        str(offset), str(limit), str(max_bytes), str(patched), str(include_unchanged).lower(),
        str(instruction_offset)]
    result = json.loads(_run(command, timeout, max_bytes))
    _check_input_digest(original, original_sha)
    _check_input_digest(patched, patched_sha)
    result.update(success=True, ffdec_version=version,
        original_sha256=original_sha, patched_sha256=patched_sha,
        original_validation=original_validation, patched_validation=patched_validation)
    return _bounded_result(result, max_bytes)


def inspect_avm2(operation, swf_path, *, abc_index=None, method_id=None,
                 property_name="", access="write", offset=0, limit=50,
                 max_bytes=65_536, expected_sha256=None, timeout=60,
                 linkage_kind="all", character_id=None, timeline="all"):
    """Execute one bounded query. Offset cursors must be paired with SHA-256."""
    if operation not in {"classes", "method", "accesses", "linkage"}:
        raise InspectionError("Unsupported inspection operation")
    _check_page(offset, limit, max_bytes, timeout)
    if abc_index is not None and abc_index < 0 or method_id is not None and method_id < 0:
        raise InspectionError("ABC and method indices must be nonnegative")
    if operation == "method" and (abc_index is None or method_id is None):
        raise InspectionError("Method inspection requires abc_index and method_id")
    if access not in {"read", "write", "all"}:
        raise InspectionError("access must be read, write or all")
    if len(property_name) > 512:
        raise InspectionError("property_name is limited to 512 characters")
    if operation == "linkage":
        if linkage_kind not in {"all", "symbol_class", "export_asset", "placement"}:
            raise InspectionError("Invalid linkage kind")
        if character_id is not None and not 0 <= character_id <= 65535:
            raise InspectionError("character_id must be 0..65535")
        if timeline not in {"all", "root", "nested"}:
            raise InspectionError("Invalid timeline filter")
    if offset and expected_sha256 is None:
        raise InspectionError("Pagination requires expected_sha256 from the first response")
    path, fingerprint, validation = _validated_input(swf_path, expected_sha256)
    bridge, version = _bridge_command(timeout)
    command = bridge + [operation, str(path),
        str(abc_index if abc_index is not None else -1),
        str(method_id if method_id is not None else -1), property_name, access,
        str(offset), str(limit), str(max_bytes)]
    if operation == "linkage":
        command.extend([linkage_kind, str(character_id if character_id is not None else -1), timeline])
    payload = _run(command, timeout, max_bytes)
    _check_input_digest(path, fingerprint)
    result = json.loads(payload)
    result.update(success=True, sha256=fingerprint, ffdec_version=version,
        validation=validation, limitations=[
            "Placements are raw tag events. Display-list state and inherited fields are not reconstructed.",
        ] if operation == "linkage" else [
            "Property access search resolves named catch slots, explicit activation slots and directly declared class slots when supported control flow establishes the receiver. Inherited and automatic slot layouts are not inferred.",
            "Enclosing contexts are not proof of unique ownership or runtime execution.",
            "Container validation is not full ABC verification.",
            "Exact property-name filters omit unresolved runtime names and slots; use an empty filter to include them.",
        ])
    return _bounded_result(result, max_bytes)

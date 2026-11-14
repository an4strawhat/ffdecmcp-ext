"""Experimental fail-closed SWF envelope/tag preflight, not an ABC verifier.

FWS and CWS only. Other signatures require a separately verified decoder.
Limits bound the decoded input and nested sprite recursion before FFDec runs.
"""
import struct
import zlib


def validate_swf(data, max_decoded=64 * 1024 * 1024, max_depth=64):
    if len(data) < 8:
        raise ValueError("SWF header is truncated")
    sig = data[:3]
    size = struct.unpack_from("<I", data, 4)[0]
    if size < 12 or size > max_decoded:
        raise ValueError("Declared size is outside the allowed range")
    if sig == b"FWS":
        raw = data
    elif sig == b"CWS":
        decoder = zlib.decompressobj()
        try:
            body = decoder.decompress(data[8:], max_decoded - 8 + 1)
        except zlib.error as exc:
            raise ValueError("Invalid zlib stream") from exc
        if len(body) > max_decoded - 8 or decoder.unconsumed_tail:
            raise ValueError("Decompressed size exceeds limit")
        if not decoder.eof:
            raise ValueError("Compressed stream is truncated")
        if decoder.unused_data:
            raise ValueError("Trailing compressed data is not permitted")
        raw = b"FWS" + data[3:8] + body
    else:
        raise ValueError("Preflight supports only FWS/CWS; unsupported signature")
    if len(raw) != size:
        raise ValueError("Declared SWF length does not match decoded length")
    nbits = raw[8] >> 3
    rect_len = (5 + nbits * 4 + 7) // 8
    start = 8 + rect_len + 4
    if start > len(raw):
        raise ValueError("Frame header is truncated")
    counts = {"tags": 0, "sprites": 0}

    def tags(start, end, depth):
        if depth > max_depth:
            raise ValueError("Sprite recursion exceeds limit")
        pos = start
        while pos < end:
            if end - pos < 2:
                raise ValueError("Tag header is truncated")
            value = struct.unpack_from("<H", raw, pos)[0]
            pos += 2
            code, length = value >> 6, value & 63
            if length == 63:
                if end - pos < 4:
                    raise ValueError("Long tag length is truncated")
                length = struct.unpack_from("<I", raw, pos)[0]
                pos += 4
            limit = pos + length
            if limit > end:
                raise ValueError("Tag payload extends beyond enclosing stream")
            counts["tags"] += 1
            if code == 0:
                if length != 0 or limit != end:
                    raise ValueError("Invalid End tag or data after End tag")
                return
            if code == 39:
                if length < 6:
                    raise ValueError("Sprite payload is truncated")
                counts["sprites"] += 1
                tags(pos + 4, limit, depth + 1)
            pos = limit
        raise ValueError("Missing End tag")

    tags(start, len(raw), 0)
    return {"decoded_size": len(raw), **counts}

"""Tests for HARMAN Air SWF encryption."""

import struct

import pytest

from ffdecmcp.aircrypto import harman_decrypt, harman_encrypt, is_encrypted


def make_swf(body: bytes = b"\x40\x00\x00\x00") -> bytes:
    header = b"CWS" + bytes([6]) + struct.pack("<I", 8 + len(body))
    return header + body


def test_roundtrip():
    data = make_swf(b"\x01\x02\x03" * 100)
    assert not is_encrypted(data)
    encrypted = harman_encrypt(data)
    assert is_encrypted(encrypted)
    assert encrypted != data
    assert harman_decrypt(encrypted) == data


def test_roundtrip_exact_block_sizes():
    for size in range(0, 70):
        data = make_swf(bytes(range(size)))
        assert harman_decrypt(harman_encrypt(data)) == data


def test_encrypt_already_encrypted():
    data = harman_encrypt(make_swf(b"abc"))
    with pytest.raises(ValueError, match="already Air-encrypted"):
        harman_encrypt(data)


def test_decrypt_not_encrypted():
    with pytest.raises(ValueError, match="not Air-encrypted"):
        harman_decrypt(make_swf(b"abc" * 20))


def test_too_short():
    with pytest.raises(ValueError):
        harman_encrypt(b"CWS\x06")

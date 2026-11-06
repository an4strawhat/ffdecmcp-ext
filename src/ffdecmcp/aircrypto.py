"""HARMAN Air SWF encryption/decryption.

Port of FFDec's HarmanSwfEncrypt (LGPL, by JPEXS; based on swfdecrypt.py by
NathaanTFM). Used because FFDec 26.4.0's ``-encrypt`` CLI command is broken
(it dispatches to the decrypt parser).

Format produced/consumed:
    [8-byte SWF header, first signature byte lowercased]
    [4 bytes little-endian: body length XOR key]
    [AES-256-CBC encrypted body, zero padded to a multiple of 32 bytes]
    [32 bytes obfuscated AES key]
"""

import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

GLOBAL_KEY = (
    "Adobe AIR SDK (c) 2021 HARMAN Internation Industries Incorporated"
)

_ENCRYPTED_SIGNATURES = b"czf"


def _key(header: bytes) -> int:
    """Derive the 32-bit file key from the (uppercase) SWF header."""
    dsum = sum(header)
    dmod = dsum % len(GLOBAL_KEY)
    rotated = GLOBAL_KEY[dmod:] + GLOBAL_KEY[:dmod]
    material = rotated + " EncryptSWF " + str(dsum)

    value = 0
    for char in material:
        value = (value * 31 + ord(char)) & 0xFFFFFFFFFFFFFFFF
    return value & 0xFFFFFFFF


def _pack(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def _unpack(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _iv(header: bytes, encrypted_length_bytes: bytes, key: int) -> bytes:
    iv = bytearray(header + encrypted_length_bytes + _pack(key))
    for i in range(16):
        iv[i] ^= ord(GLOBAL_KEY[i])
    return bytes(iv)


def is_encrypted(data: bytes) -> bool:
    """Return True when the SWF header signature is lowercase (Air-encrypted)."""
    return len(data) >= 8 and data[0:1] in (b"c", b"z", b"f")


def harman_encrypt(data: bytes) -> bytes:
    """Encrypt a SWF file's bytes with HARMAN Air encryption."""
    if len(data) < 8:
        raise ValueError("File is too short to be a SWF")
    if is_encrypted(data):
        raise ValueError("File is already Air-encrypted")

    header = bytearray(data[:8])
    body = data[8:]

    key = _key(bytes(header))
    encrypted_length_bytes = _pack(len(body) ^ key)

    padded_length = (len(body) + 0x1F) & ~0x1F
    padded = body + b"\x00" * (padded_length - len(body))

    iv = _iv(bytes(header), encrypted_length_bytes, key)
    aes_key = os.urandom(32)

    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    header[0] += 32  # lowercase signature

    aes_key_data = bytearray(32)
    for i in range(0, 32, 4):
        value = _unpack(aes_key, i)
        value = value + key if (i & 4) else value - key
        aes_key_data[i : i + 4] = _pack(value)

    return bytes(header) + encrypted_length_bytes + ciphertext[:padded_length] + bytes(aes_key_data)


def harman_decrypt(data: bytes) -> bytes:
    """Decrypt HARMAN Air encrypted SWF bytes back to a normal SWF."""
    if len(data) < 8 + 4 + 32:
        raise ValueError("File is too short to be an encrypted SWF")
    if not is_encrypted(data):
        raise ValueError("File is not Air-encrypted")

    header = bytearray(data[:8])
    header[0] -= 32  # uppercase signature

    key = _key(bytes(header))

    encrypted_length_bytes = data[8:12]
    decrypted_length = _unpack(encrypted_length_bytes, 0) ^ key
    padded_length = (decrypted_length + 0x1F) & ~0x1F

    offset = 12
    ciphertext = data[offset : offset + padded_length]
    aes_key_data = data[offset + padded_length : offset + padded_length + 32]
    if len(ciphertext) != padded_length or len(aes_key_data) != 32:
        raise ValueError("Encrypted file is truncated")

    iv = _iv(bytes(header), encrypted_length_bytes, key)

    aes_key = bytearray(32)
    for i in range(0, 32, 4):
        value = _unpack(aes_key_data, i)
        value = value - key if (i & 4) else value + key
        aes_key[i : i + 4] = _pack(value)

    decryptor = Cipher(algorithms.AES(bytes(aes_key)), modes.CBC(iv)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return bytes(header) + plaintext[:decrypted_length]

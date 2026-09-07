"""
RNCryptor v3 - the symmetric format SEB uses for password-encrypted .seb files.

Layout (network byte order, nothing is length-prefixed):

    [version:1][options:1][enc_salt:8][hmac_salt:8][iv:16][ciphertext:n][hmac:32]

The encryption key and the HMAC key are derived separately from the password
with PBKDF2, 10000 iterations, 32-byte output.

One deliberate wrinkle: the published SEB file-format note says the PBKDF2 PRF
is SHA-256, while the upstream RNCryptor v3 specification says SHA-1, and
implementations in the wild follow one or the other. Rather than guess,
`decrypt` tries both and reports which one authenticated the payload, so an
audit never fails on a file that is actually fine.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ITERATIONS = 10_000
KEY_LEN = 32
SALT_LEN = 8
IV_LEN = 16
HMAC_LEN = 32
HEADER_LEN = 2 + SALT_LEN + SALT_LEN + IV_LEN  # 34

# Tried in order when decrypting; the first that authenticates wins.
PRF_CANDIDATES = ("sha1", "sha256")


class RNCryptorError(Exception):
    """Raised when a payload is malformed, or the password/HMAC does not match."""


@dataclass(frozen=True)
class DecryptResult:
    plaintext: bytes
    prf: str  # which PBKDF2 hash actually authenticated the payload


def _derive(password: str, salt: bytes, prf: str) -> bytes:
    return hashlib.pbkdf2_hmac(prf, password.encode("utf-8"), salt, ITERATIONS, KEY_LEN)


def _pkcs7_pad(data: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise RNCryptorError("ciphertext is not a whole number of AES blocks")
    pad = data[-1]
    if not 1 <= pad <= 16 or data[-pad:] != bytes([pad]) * pad:
        raise RNCryptorError("invalid PKCS#7 padding")
    return data[:-pad]


def _aes_cbc(key: bytes, iv: bytes) -> Cipher:
    return Cipher(algorithms.AES(key), modes.CBC(iv))


def encrypt(plaintext: bytes, password: str, *, prf: str = "sha1") -> bytes:
    """Encrypt `plaintext` into an RNCryptor v3 payload."""
    enc_salt = os.urandom(SALT_LEN)
    hmac_salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)

    enc_key = _derive(password, enc_salt, prf)
    hmac_key = _derive(password, hmac_salt, prf)

    encryptor = _aes_cbc(enc_key, iv).encryptor()
    ciphertext = encryptor.update(_pkcs7_pad(plaintext)) + encryptor.finalize()

    # version 3, options 1 (password-based key derivation)
    body = bytes([3, 1]) + enc_salt + hmac_salt + iv + ciphertext
    return body + hmac.new(hmac_key, body, hashlib.sha256).digest()


def decrypt(payload: bytes, password: str) -> DecryptResult:
    """Authenticate and decrypt an RNCryptor v3 payload, auto-detecting the PRF."""
    if len(payload) < HEADER_LEN + HMAC_LEN:
        raise RNCryptorError("payload too short to be an RNCryptor v3 message")

    version = payload[0]
    if version != 3:
        raise RNCryptorError(f"unsupported RNCryptor version {version} (expected 3)")

    enc_salt = payload[2:10]
    hmac_salt = payload[10:18]
    iv = payload[18:34]
    ciphertext = payload[HEADER_LEN:-HMAC_LEN]
    expected_mac = payload[-HMAC_LEN:]
    body = payload[:-HMAC_LEN]

    last_error = "no PBKDF2 variant authenticated the payload"
    for prf in PRF_CANDIDATES:
        hmac_key = _derive(password, hmac_salt, prf)
        actual_mac = hmac.new(hmac_key, body, hashlib.sha256).digest()
        if not hmac.compare_digest(actual_mac, expected_mac):
            last_error = "HMAC mismatch - wrong password, or the file is corrupt"
            continue
        enc_key = _derive(password, enc_salt, prf)
        decryptor = _aes_cbc(enc_key, iv).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        return DecryptResult(plaintext=_pkcs7_unpad(padded), prf=prf)

    raise RNCryptorError(last_error)

"""
Reading and writing .seb configuration files.

A .seb file is an Apple XML property list, compressed and optionally encrypted,
then compressed again:

    write:  gzip( PREFIX + payload )      where payload is
              "plnd" -> gzip(xml)
              "pswd" -> RNCryptor(gzip(xml), password)      # exam config
              "pwcc" -> RNCryptor(gzip(xml), password)      # client config
              "phsk" -> certificate-encrypted (read-only support here)

    read:   reverse of the above

The outer gzip layer is occasionally absent on hand-edited files, and the inner
payload of a "plnd" file is sometimes plain XML rather than gzipped XML. Both
are detected rather than assumed, so auditing a teacher's existing file does not
fail on a cosmetic difference.
"""

from __future__ import annotations

import gzip
import plistlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import rncryptor

GZIP_MAGIC = b"\x1f\x8b"

PREFIX_PLAIN = b"plnd"
PREFIX_PASSWORD = b"pswd"
PREFIX_CLIENT_CONFIG = b"pwcc"
PREFIX_PUBLIC_KEY = b"pkhs"
PREFIX_PUBLIC_KEY_SYMMETRIC = b"phsk"

KNOWN_PREFIXES = {
    PREFIX_PLAIN: "unencrypted",
    PREFIX_PASSWORD: "password-encrypted (exam config)",
    PREFIX_CLIENT_CONFIG: "password-encrypted (client config)",
    PREFIX_PUBLIC_KEY: "certificate-encrypted (legacy)",
    PREFIX_PUBLIC_KEY_SYMMETRIC: "certificate-encrypted",
}

# sebConfigPurpose values
PURPOSE_START_EXAM = 0
PURPOSE_CONFIGURE_CLIENT = 1


class SebFileError(Exception):
    """Raised when a .seb file cannot be parsed or decrypted."""


class PasswordRequired(SebFileError):
    """Raised when a file is encrypted and no (or a wrong) password was supplied."""


@dataclass
class LoadedConfig:
    """A decoded .seb file plus how it was encoded."""

    settings: dict[str, Any]
    prefix: bytes
    encrypted: bool
    outer_gzip: bool
    inner_gzip: bool
    prf: str | None = None  # PBKDF2 variant, when password-encrypted
    notes: list[str] = field(default_factory=list)

    @property
    def encoding_description(self) -> str:
        return KNOWN_PREFIXES.get(self.prefix, f"unknown prefix {self.prefix!r}")


def _maybe_gunzip(data: bytes) -> tuple[bytes, bool]:
    """Decompress `data` if it is gzipped. Returns (data, was_gzipped)."""
    if data[:2] != GZIP_MAGIC:
        return data, False
    try:
        return gzip.decompress(data), True
    except OSError as exc:
        raise SebFileError(f"gzip layer is corrupt: {exc}") from exc


def loads(raw: bytes, password: str | None = None) -> LoadedConfig:
    """Decode the bytes of a .seb file into its settings dictionary."""
    if not raw:
        raise SebFileError("file is empty")

    notes: list[str] = []
    body, outer_gzip = _maybe_gunzip(raw)
    if not outer_gzip:
        notes.append("File was not gzip-compressed at the outer layer.")

    prefix = body[:4]
    if prefix not in KNOWN_PREFIXES:
        # Some very old or hand-made files are bare XML with no prefix at all.
        if body.lstrip()[:5] == b"<?xml":
            notes.append("File is bare XML with no SEB prefix header.")
            return LoadedConfig(
                settings=_parse_plist(body),
                prefix=b"",
                encrypted=False,
                outer_gzip=outer_gzip,
                inner_gzip=False,
                notes=notes,
            )
        raise SebFileError(
            f"unrecognised SEB prefix {prefix!r} - this does not look like a .seb file"
        )

    payload = body[4:]

    if prefix in (PREFIX_PUBLIC_KEY, PREFIX_PUBLIC_KEY_SYMMETRIC):
        raise SebFileError(
            "This file is encrypted with a cryptographic identity (certificate). "
            "Open it in SEB Config Tool on the machine holding the private key and "
            "re-save it with a password instead."
        )

    prf = None
    if prefix in (PREFIX_PASSWORD, PREFIX_CLIENT_CONFIG):
        if not password:
            raise PasswordRequired(
                "This configuration is password-encrypted. Supply the settings password."
            )
        try:
            result = rncryptor.decrypt(payload, password)
        except rncryptor.RNCryptorError as exc:
            raise PasswordRequired(str(exc)) from exc
        payload, prf = result.plaintext, result.prf

    xml, inner_gzip = _maybe_gunzip(payload)
    if not inner_gzip:
        notes.append("Inner payload was not gzip-compressed.")

    return LoadedConfig(
        settings=_parse_plist(xml),
        prefix=prefix,
        encrypted=prefix in (PREFIX_PASSWORD, PREFIX_CLIENT_CONFIG),
        outer_gzip=outer_gzip,
        inner_gzip=inner_gzip,
        prf=prf,
        notes=notes,
    )


def _parse_plist(xml: bytes) -> dict[str, Any]:
    try:
        settings = plistlib.loads(xml)
    except Exception as exc:
        raise SebFileError(f"configuration is not a valid XML property list: {exc}") from exc
    if not isinstance(settings, dict):
        raise SebFileError("configuration root element is not a dictionary")
    return settings


def load(path: str | Path, password: str | None = None) -> LoadedConfig:
    """Read and decode a .seb file from disk."""
    return loads(Path(path).read_bytes(), password)


def to_plist_xml(settings: dict[str, Any]) -> bytes:
    """Serialise settings to the XML property list SEB expects."""
    return plistlib.dumps(settings, fmt=plistlib.FMT_XML, sort_keys=True)


def dumps(
    settings: dict[str, Any],
    password: str | None = None,
    *,
    purpose: int = PURPOSE_START_EXAM,
) -> bytes:
    """Encode settings into .seb file bytes.

    With no password the file is written unencrypted ("plnd"), which is what
    Moodle expects for an uploaded exam configuration - Moodle serves the file
    to students itself, so file-level encryption adds nothing while making the
    config harder to inspect and re-verify later.
    """
    inner = gzip.compress(to_plist_xml(settings))

    if password:
        prefix = PREFIX_CLIENT_CONFIG if purpose == PURPOSE_CONFIGURE_CLIENT else PREFIX_PASSWORD
        payload = rncryptor.encrypt(inner, password)
    else:
        prefix = PREFIX_PLAIN
        payload = inner

    return gzip.compress(prefix + payload)


def dump(
    settings: dict[str, Any],
    path: str | Path,
    password: str | None = None,
    *,
    purpose: int = PURPOSE_START_EXAM,
) -> Path:
    """Write settings to a .seb file on disk and return the path."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(dumps(settings, password, purpose=purpose))
    return target

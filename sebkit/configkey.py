"""
Config Key computation.

The Config Key is the value Moodle uses to prove that a student's SEB is running
*your* configuration. SEB sends, on every request:

    X-SafeExamBrowser-ConfigKeyHash: SHA256( absolute_url_without_fragment + config_key )

and Moodle recomputes the same hash from the Config Key stored on the quiz. If
they differ, the attempt is refused. This is the only control in the whole
system that still holds on hardware you do not own, which is why getting it
byte-exact matters.

Algorithm (per the SEB Config Key specification):

  1. Take the decrypted settings dictionary.
  2. Drop the "originatorVersion" key - it is metadata and varies by tool.
  3. Drop empty dictionaries.
  4. Sort every dictionary's keys alphabetically, case-insensitively, using
     culture-invariant ordering, recursively.
  5. Serialise to JSON with no whitespace and no character escaping.
     <data> becomes base64, <date> becomes ISO 8601, reals are shortest-round-trip.
  6. SHA-256 the UTF-8 bytes, and render as lowercase base16.

Step 5's "no character escaping" is genuinely unusual - backslashes inside URL
filter regular expressions are emitted raw. That is what the specification calls
for, and it is why a generic `json.dumps` produces the wrong key.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
from typing import Any

EXCLUDED_KEYS = ("originatorVersion",)


def _format_real(value: float) -> str:
    """Shortest representation that round-trips, matching the spec's rounding note."""
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError(f"cannot serialise non-finite real {value!r} into a Config Key")
    if value == int(value) and abs(value) < 1e16:
        # SEB emits whole reals without a trailing ".0"
        return str(int(value))
    return repr(value)


def _format_date(value: _dt.datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=_dt.timezone.utc)
    return value.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _serialise(value: Any) -> str:
    # bool must precede int: in Python, bool is a subclass of int.
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, dict):
        return _serialise_dict(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialise(item) for item in value) + "]"
    if isinstance(value, (bytes, bytearray)):
        return '"' + base64.b64encode(bytes(value)).decode("ascii") + '"'
    if isinstance(value, _dt.datetime):
        return '"' + _format_date(value) + '"'
    if isinstance(value, float):
        return _format_real(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        # Deliberately unescaped, per the specification. Only a literal double
        # quote would break the grammar, so that alone is escaped.
        return '"' + value.replace('"', '\\"') + '"'
    raise TypeError(f"unsupported value type in configuration: {type(value).__name__}")


def _is_empty_dict(value: Any) -> bool:
    return isinstance(value, dict) and not value


def _serialise_dict(settings: dict[str, Any]) -> str:
    items = [
        (key, value)
        for key, value in settings.items()
        if key not in EXCLUDED_KEYS and not _is_empty_dict(value)
    ]
    # Case-insensitive, culture-invariant ordering. The secondary sort on the
    # raw key keeps the result deterministic when two keys differ only in case.
    items.sort(key=lambda kv: (kv[0].lower(), kv[0]))
    return "{" + ",".join(f'"{key}":{_serialise(value)}' for key, value in items) + "}"


def config_key_json(settings: dict[str, Any]) -> str:
    """Return the canonical SEB-JSON string the Config Key is hashed from.

    Exposed separately because when a key mismatch has to be debugged, diffing
    this string against SEB's own is the only practical way to find the culprit.
    """
    return _serialise_dict(settings)


def compute_config_key(settings: dict[str, Any]) -> str:
    """Compute the Config Key (lowercase base16 SHA-256) for a settings dict."""
    return hashlib.sha256(config_key_json(settings).encode("utf-8")).hexdigest()


def request_hash(url: str, config_key: str) -> str:
    """Reproduce the X-SafeExamBrowser-ConfigKeyHash header value for a URL.

    Useful for testing a Moodle integration end to end without a student client:
    if this matches what the server computes, the plumbing is correct.
    """
    url = url.split("#", 1)[0]
    return hashlib.sha256((url + config_key).encode("utf-8")).hexdigest()


def browser_exam_key_request_hash(url: str, browser_exam_key: str) -> str:
    """Same construction, for the X-SafeExamBrowser-RequestHash (BEK) header."""
    url = url.split("#", 1)[0]
    return hashlib.sha256((url + browser_exam_key).encode("utf-8")).hexdigest()

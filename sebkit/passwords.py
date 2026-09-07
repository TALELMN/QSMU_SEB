"""
Password generation and hashing for SEB configurations.

Two passwords matter in a .seb file, and they are stored as SHA-256 hashes:

  hashedAdminPassword - unlocks the settings. Without it, any student can open
      the .seb in SEB Config Tool and read the URL allowlist, the permitted
      applications and the quit password. This is the single most commonly
      omitted setting, and omitting it hands away the entire exam policy.

  hashedQuitPassword - required to quit SEB. Without it a student can simply
      leave the locked-down session at will.

Both must be unique per exam. Reused passwords leak between cohorts, and a
password a student saw last semester is not a password.
"""

from __future__ import annotations

import hashlib
import secrets
import string
from dataclasses import dataclass

# SEB hashes passwords with SHA-256 and stores the digest as a base16 string.
#
# The published specification does not state the hex case. Settled by inspecting
# SEB Config Tool 3.10.2: the only hex format literal in its .NET user-string
# heap is the lowercase "{0:x2}", with zero UTF-16 occurrences of "X2". So SEB
# writes lowercase. `verify_hash` still compares case-insensitively, so an audit
# of a file produced by some other tool never raises a false alarm.
HASH_UPPERCASE = False

# Ambiguous characters removed: a teacher reads these aloud or types them
# from a printed sheet under time pressure.
_ALPHABET = "".join(
    c for c in (string.ascii_letters + string.digits) if c not in "O0oIl1S5B8Z2"
)


@dataclass(frozen=True)
class ExamPasswords:
    """The passwords for a single exam. Generated fresh every time."""

    admin: str
    quit: str

    @property
    def hashed_admin(self) -> str:
        return hash_password(self.admin)

    @property
    def hashed_quit(self) -> str:
        return hash_password(self.quit)


def hash_password(password: str) -> str:
    """Hash a password the way SEB stores it."""
    if not password:
        return ""
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return digest.upper() if HASH_UPPERCASE else digest


def verify_hash(password: str, stored_hash: str) -> bool:
    """Check a password against a stored hash, tolerating either hex case."""
    if not stored_hash:
        return False
    return hashlib.sha256(password.encode("utf-8")).hexdigest().lower() == stored_hash.lower()


def generate_password(length: int = 14) -> str:
    """Generate a readable, high-entropy password.

    14 characters from a 48-symbol alphabet is roughly 78 bits - far beyond
    anything that matters here, while still being transcribable by hand.
    """
    if length < 8:
        raise ValueError("exam passwords must be at least 8 characters")
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def generate_exam_passwords(length: int = 14) -> ExamPasswords:
    """Generate a fresh, unique admin/quit password pair for one exam."""
    admin = generate_password(length)
    quit_pw = generate_password(length)
    while quit_pw == admin:  # astronomically unlikely; cheap to rule out
        quit_pw = generate_password(length)
    return ExamPasswords(admin=admin, quit=quit_pw)


# Passwords seen often enough in real exam configurations to be worth naming.
WEAK_PASSWORDS = {
    "", "seb", "exam", "test", "admin", "password", "passwd", "1234", "12345",
    "123456", "1234567", "12345678", "0000", "1111", "quit", "quitpassword",
    "medtech", "student", "teacher", "prof", "esprit", "insat", "univ",
    "azerty", "qwerty", "letmein", "changeme", "default", "secret",
}


def looks_weak(password: str) -> str | None:
    """Return a reason if `password` is too weak to protect an exam, else None."""
    if not password:
        return "no password is set"
    if password.lower() in WEAK_PASSWORDS:
        return "it is one of the most commonly guessed exam passwords"
    if len(password) < 10:
        return f"it is only {len(password)} characters long"
    if password.isdigit():
        return "it is digits only"
    if password.isalpha() and password.islower():
        return "it is lowercase letters only"
    return None

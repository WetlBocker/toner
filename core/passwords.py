"""Rules a new Toner password must meet: length, not a common password, no username in it.

The common-password list (core/data/common-passwords.txt) is the 10,000 most common passwords from SecLists,
Passwords/Common-Credentials/10k-most-common.txt, MIT licence (core/data/common-passwords.LICENSE).
https://github.com/danielmiessler/SecLists  It is read as plain text lines only. It has no comment lines.
"""
import functools
import os

MIN_LENGTH = 12
_LIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "common-passwords.txt")


@functools.lru_cache(maxsize=1)
def _common() -> frozenset:
    with open(_LIST, encoding="utf-8", errors="replace") as f:
        return frozenset(s for s in (line.strip().lower() for line in f) if s)


def _too_common(password: str) -> bool:
    p, common = password.strip().lower(), _common()
    # A list entry followed only by digits counts: "password1234" is "password" + 1234.
    return any(p[:i] in common for i in range(len(p), 0, -1) if p[i:].isdigit() or i == len(p))


def problem(password: str, username: str = "") -> "str | None":
    """None when the password is fine, otherwise the sentence to show. Never includes the password itself."""
    if len(password) < MIN_LENGTH:
        return f"Use at least {MIN_LENGTH} characters."
    if _too_common(password):
        return "That password is too common. Choose one that's harder to guess."
    if username and username.lower() in password.lower():
        return "Don't include your username in your password."
    return None

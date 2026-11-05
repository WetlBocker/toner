"""Files outside the databases (session logs, saved host keys), sealed with the same data key as the databases.

Format: MAGIC, then frames of (4-byte big-endian length, 12-byte nonce, AES-GCM ciphertext).
"""
import os
import struct
import tempfile
import threading
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core import sqldb

MAGIC = b"TONERSEAL1\n"
_replace_lock = threading.Lock()


class Locked(RuntimeError):
    pass


def _aead(path):
    key = sqldb.current_key()  # read each time so signing out locks the files at once
    if key is None:
        raise Locked("Sign in to open this file.")
    return AESGCM(key), b"toner-file:" + Path(path).name.encode()


def _frame(aead, aad, data):
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, data, aad)
    return struct.pack(">I", len(ct) + 12) + nonce + ct


def is_sealed(path):
    try:
        with open(path, "rb") as f:
            return f.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def _frames(raw):
    """Complete frames and the offset where they end; a crash mid-append leaves a short last frame after it."""
    bodies, i = [], len(MAGIC)
    while i + 4 <= len(raw):
        n = struct.unpack(">I", raw[i:i + 4])[0]
        if i + 4 + n > len(raw):
            break
        bodies.append(raw[i + 4:i + 4 + n])
        i += 4 + n
    return bodies, i


def read_bytes(path):
    with _replace_lock:                               # an open reader makes Windows refuse a swap (see replace_bytes)
        raw = Path(path).read_bytes()
    if not raw.startswith(MAGIC):
        return raw
    aead, aad = _aead(path)
    out = []
    for body in _frames(raw)[0]:
        try:
            out.append(aead.decrypt(body[:12], body[12:], aad))
        except (InvalidTag, ValueError):
            raise ValueError("This file is damaged or was changed outside Toner.") from None
    return b"".join(out)


def replace_bytes(path, blob):
    """Write `blob` to `path` in one step: a crash leaves the old file or the new one. The temp file is unique, so two threads
    writing the same file (host keys saved from two SSH connections) never share one."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=p.name + ".", suffix=".tmp")
    try:
        with open(fd, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        # shortcut: one swap at a time within this process (Windows refuses two at once onto one file); another Toner process
        # swapping the same file at that instant can still fail with an OSError the caller sees, upgrade to a FileLock if seen.
        with _replace_lock:
            os.replace(tmp, p)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write_bytes(path, data):
    aead, aad = _aead(path)
    replace_bytes(path, MAGIC + _frame(aead, aad, data))


def keyed():
    """Whether side files are written sealed. Until a data key is open (no one has set up sign-in) Toner writes them plain, as it
    always has; once one is, sealed. Readers take both, and core/lockdown.py seals what was written plain."""
    return sqldb.current_key() is not None


def save_bytes(path, data):
    """write_bytes when a data key is open, else a plain file (see keyed)."""
    if keyed():
        write_bytes(path, data)
    else:
        replace_bytes(path, data)


def save_text(path, text):
    save_bytes(path, text.encode("utf-8"))


def read_text(path):
    return read_bytes(path).decode("utf-8")


def write_text(path, text):
    write_bytes(path, text.encode("utf-8"))


def seal_existing(path):
    if not Path(path).is_file() or is_sealed(path):
        return False
    write_bytes(path, Path(path).read_bytes())
    return True


class Appender:
    def __init__(self, path):
        _aead(path)  # refuse early when signed out
        p = Path(path)
        self._path = p
        if p.exists() and p.stat().st_size and not is_sealed(p):
            raise Locked("This file isn't sealed yet, so Toner won't add to it.")
        p.parent.mkdir(parents=True, exist_ok=True)
        self._f = open(p, "ab")
        if self._f.tell() == 0:
            self._f.write(MAGIC)
            self._f.flush()
        else:
            # appending after a torn tail would hide or corrupt every later frame
            end = _frames(p.read_bytes())[1]
            if end < self._f.tell():
                self._f.truncate(end)
                self._f.flush()
                os.fsync(self._f.fileno())

    def write(self, text):
        aead, aad = _aead(self._path)  # read the key each time so signing out stops writes at once
        self._f.write(_frame(aead, aad, text.encode("utf-8")))
        self._f.flush()

    def close(self):
        self._f.close()

"""Files outside the databases (session logs, saved host keys), sealed with the same data key as the databases.

Format: MAGIC, then frames of (4-byte big-endian length, 12-byte nonce, AES-GCM ciphertext).
"""
import os
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core import sqldb

MAGIC = b"TONERSEAL1\n"


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


def write_bytes(path, data):
    p = Path(path)
    aead, aad = _aead(p)
    blob = MAGIC + _frame(aead, aad, data)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)


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

"""Every SQLite connection in Toner opens here, so one place decides whether the file is encrypted (SQLCipher 4) and with what.
`set_key` is called at sign-in with the 32-byte data key; until then (and with no key) files are plain, as before."""
import os
from pathlib import Path

try:
    import sqlcipher3.dbapi2 as sqlite3
except ImportError:                                   # shortcut: plain sqlite3 only until sqlcipher3 is installed, then remove
    import sqlite3

_key = None
_PLAIN = b"SQLite format 3\x00"


def set_key(key):
    global _key
    _key = key


def current_key():
    return _key


def _raw(key):
    return "x'%s'" % key.hex()                        # a raw 256-bit key: SQLCipher skips its passphrase KDF


def connect(path, **kw):
    """sqlite3.connect, then the data key when one is set. A wrong key fails here, not at the first query."""
    c = sqlite3.connect(path, **kw)
    if _key is not None:
        try:
            c.execute('PRAGMA key = "%s"' % _raw(_key))
            c.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except BaseException:
            c.close()
            raise                                      # the driver's own DatabaseError, which never carries the key
    return c


def is_encrypted(path):
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except OSError:
        return False
    return len(head) == 16 and head != _PLAIN


def encrypt_file(path, key):
    """Replace a plain database file with an encrypted copy of itself (written beside it, then swapped in)."""
    path = Path(path)
    tmp = path.with_name(path.name + ".encrypting")
    tmp.unlink(missing_ok=True)
    c = sqlite3.connect(path)
    try:
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        ver = c.execute("PRAGMA user_version").fetchone()[0]
        c.execute("ATTACH DATABASE ? AS enc KEY ?", (str(tmp), _raw(key)))
        c.execute("SELECT sqlcipher_export('enc')")
        c.execute("PRAGMA enc.user_version = %d" % ver)   # sqlcipher_export does not copy it
        c.execute("DETACH DATABASE enc")
    except BaseException:
        c.close()
        tmp.unlink(missing_ok=True)
        raise
    c.close()
    fd = os.open(tmp, os.O_RDWR)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    for suffix in ("-wal", "-shm"):
        path.with_name(path.name + suffix).unlink(missing_ok=True)
    os.replace(tmp, path)


def export_copy(src_conn, dest, passphrase):
    """Write a copy of an open database encrypted with a passphrase (SQLCipher's own KDF), for a backup the owner can open elsewhere."""
    dest = Path(dest)
    dest.unlink(missing_ok=True)
    src_conn.execute("ATTACH DATABASE ? AS exp KEY ?", (str(dest), passphrase))
    try:
        src_conn.execute("SELECT sqlcipher_export('exp')")
    finally:
        src_conn.execute("DETACH DATABASE exp")

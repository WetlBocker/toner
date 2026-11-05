"""Every SQLite connection in Toner opens here, so one place decides whether the file is encrypted (SQLCipher 4) and with what.
`set_key` is called at sign-in with the 32-byte data key; until then (and with no key) files are plain, as before."""
import os
from pathlib import Path

import sqlcipher3.dbapi2 as sqlite3                   # no fallback: stdlib sqlite3 ignores PRAGMA key and would write plaintext

_key = None
_PLAIN = b"SQLite format 3\x00"


def set_key(key):
    global _key
    if key is not None and not (isinstance(key, (bytes, bytearray)) and len(key) == 32):
        raise ValueError("The data key must be 32 bytes.")
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
            if c.execute("PRAGMA cipher_version").fetchone() is None:
                raise sqlite3.DatabaseError("this SQLite driver has no SQLCipher: refusing to write an unencrypted database")
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
    """Replace a plain database file with an encrypted copy of itself (written beside it, then swapped in). Raises, leaving the
    plain file as it was, when another connection holds it."""
    path = Path(path)
    tmp = path.with_name(path.name + ".encrypting")
    tmp.unlink(missing_ok=True)                       # left by a crash: never trusted, made again
    c = None
    try:
        c = sqlite3.connect(path, timeout=1)
        busy = c.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]
        try:                                          # SQLite leaves WAL only when no other connection has the file open
            mode = None if busy else c.execute("PRAGMA journal_mode = DELETE").fetchone()[0]
        except sqlite3.OperationalError:
            mode = None
        if mode != "delete":                          # another connection: on POSIX it would go on writing to the old file
            raise sqlite3.OperationalError(f"{path.name} is in use by another connection")
        c.execute("PRAGMA locking_mode = EXCLUSIVE")  # held from here to the swap: no one can write what the copy would miss
        c.execute("BEGIN EXCLUSIVE")
        c.commit()
        ver = c.execute("PRAGMA user_version").fetchone()[0]
        c.execute("ATTACH DATABASE ? AS enc KEY ?", (str(tmp), _raw(key)))
        c.execute("SELECT sqlcipher_export('enc')")
        c.execute("PRAGMA enc.user_version = %d" % ver)   # sqlcipher_export does not copy it
        c.execute("PRAGMA enc.journal_mode = WAL")        # nor the WAL setting, which Toner's readers-while-writing rely on
        c.execute("DETACH DATABASE enc")
        fd = os.open(tmp, os.O_RDWR)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        for suffix in ("-wal", "-shm"):
            path.with_name(path.name + suffix).unlink(missing_ok=True)
        if os.name != "nt":
            os.replace(tmp, path)                     # still holding the lock
        c.close()
        c = None
        if os.name == "nt":
            # shortcut: Windows can't replace a file this process has open, so the lock goes just before the swap; a process
            # that opens, writes and closes it in that instant is lost (one still holding it makes the swap fail). Rare at sign-in.
            os.replace(tmp, path)
    except BaseException:
        if c is not None:
            c.close()
        tmp.unlink(missing_ok=True)
        raise


def export_copy(src_conn, dest, passphrase):
    """Write a copy of an open database encrypted with a passphrase (SQLCipher's own KDF), for a backup the owner can open elsewhere.
    The copy is one portable file (DELETE journal mode). On any failure nothing is left at dest."""
    if not passphrase:
        raise ValueError("A backup needs a password.")   # SQLCipher treats an empty KEY as no encryption
    dest = Path(dest)
    dest.unlink(missing_ok=True)
    try:
        src_conn.execute("ATTACH DATABASE ? AS exp KEY ?", (str(dest), passphrase))
        try:
            src_conn.execute("SELECT sqlcipher_export('exp')")
        finally:
            try:
                src_conn.execute("DETACH DATABASE exp")
            except sqlite3.Error:
                pass                                      # never hides the export's own error
    except BaseException:
        for suffix in ("", "-journal", "-wal", "-shm"):
            dest.with_name(dest.name + suffix).unlink(missing_ok=True)
        raise

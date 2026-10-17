"""Toner's password vault: every password, API token and community string Toner keeps, in one encrypted file next to its database.

The vault replaced Windows Credential Manager, which holds only so many entries per Windows user (an import of thousands of sessions
filled it, and then no program could save a credential). The file is sealed with AES-256-GCM under a random data key; that key is
itself sealed with a key made from the master password (scrypt), so changing the master password only re-seals the data key.

Remember on this computer keeps the data key protected by Windows (DPAPI, this Windows user only) in a file beside the vault, so
Toner and its scheduled service open the vault without asking. Without it, Toner asks for the master password when it starts.

Everything in Toner reaches the vault through `keyring` (install() makes the vault keyring's store), so the rest of the code is
unchanged: keyring.get_password(db.SERVICE, name) reads the vault's entry `name`.
"""
import base64
import json
import os
import threading
from contextlib import contextmanager

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from core import db

MIN_MASTER = 12
FORMAT = "toner-vault"
KEY_AAD, DATA_AAD = b"toner-vault-key", b"toner-vault-data"
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}
DPAPI_ENTROPY = b"Toner vault key"

_lock = threading.RLock()
_key = None                     # the data key while the vault is open
_data = None                    # {name: secret} while it is open
_seen = None                    # (mtime, size) of the file when last read or written, to notice another process's writes
_batch = 0                      # inside batch(): changes wait in memory...
_pending = []                   # ...as (name, secret or None to remove), written together when the batch ends


class Locked(RuntimeError):
    """The vault has not been opened (no master password given, and it is not remembered on this computer)."""


class WrongPassword(ValueError):
    pass


# ---------------------------------------------------------------- where it lives
def path():
    return db.base_path().with_suffix(".vault")


def key_path():
    p = path()
    return p.with_name(p.name + "-key")


def exists():
    return path().exists()


def is_open():
    return _key is not None


def remembered():
    return key_path().exists()


def check_master(master):
    """Raises ValueError with what to fix."""
    if len(master or "") < MIN_MASTER:
        raise ValueError(f"Use at least {MIN_MASTER} characters.")


# ---------------------------------------------------------------- the file
def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _unb64(s):
    return base64.b64decode(s.encode("ascii"))


def _kek(master, salt, kdf=SCRYPT):
    return Scrypt(salt=salt, length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(master.encode("utf-8"))


def _read_file():
    with open(path(), encoding="utf-8") as f:
        doc = json.load(f)
    if doc.get("format") != FORMAT:
        raise ValueError("this is not a Toner vault")
    return doc


def _stat():
    try:
        st = path().stat()
        return st.st_mtime_ns, st.st_size
    except OSError:
        return None


def _seal(key, data):
    nonce = os.urandom(12)
    return _b64(nonce + AESGCM(key).encrypt(nonce, json.dumps(data).encode("utf-8"), DATA_AAD))


def _unseal(key, blob):
    raw = _unb64(blob)
    return json.loads(AESGCM(key).decrypt(raw[:12], raw[12:], DATA_AAD))


def _wrap(master, key):
    salt, nonce = os.urandom(16), os.urandom(12)
    return {"name": "scrypt", "salt": _b64(salt), **SCRYPT}, _b64(nonce + AESGCM(_kek(master, salt)).encrypt(nonce, key, KEY_AAD))


def _unwrap(master, doc):
    kdf, raw = doc["kdf"], _unb64(doc["key"])
    try:
        return AESGCM(_kek(master, _unb64(kdf["salt"]), kdf)).decrypt(raw[:12], raw[12:], KEY_AAD)
    except InvalidTag:
        raise WrongPassword("That master password isn't right.") from None


def _write(doc):
    """Replace the file in one step (a crash leaves the old file or the new one, never half of one)."""
    global _seen
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)
    _seen = _stat()


class _FileLock:
    """Toner's window and its scheduled service may both write: one at a time (a lock file beside the vault)."""

    def __enter__(self):
        import msvcrt
        self.f = open(path().with_name(path().name + ".lock"), "a+b")
        for _ in range(50):
            try:
                self.f.seek(0)
                msvcrt.locking(self.f.fileno(), msvcrt.LK_NBLCK, 1)
                return self
            except OSError:
                import time
                time.sleep(0.1)
        return self                                       # 5 s: go ahead rather than hang

    def __exit__(self, *exc):
        import msvcrt
        try:
            self.f.seek(0)
            msvcrt.locking(self.f.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        self.f.close()


def _fresh():
    """Read the file again when another process changed it since we last looked (not in the middle of a batch: its changes are
    only in memory until it ends)."""
    global _data, _seen
    if _batch:
        return
    now = _stat()
    if now is not None and now != _seen:
        _data = _unseal(_key, _read_file()["data"])
        _seen = now


# ---------------------------------------------------------------- opening and closing
def create(master, remember=True, carry=None):
    """A new, empty vault (replacing any that is there) locked with `master`, and opened. `carry`: {name: secret} to put in it."""
    global _key, _data
    check_master(master)
    with _lock, _FileLock():
        key = os.urandom(32)
        kdf, wrapped = _wrap(master, key)
        data = dict(carry or {})
        _write({"format": FORMAT, "version": 1, "kdf": kdf, "key": wrapped, "data": _seal(key, data)})
        _key, _data = key, data
        set_remembered(remember)


def unlock(master):
    """Open the vault with the master password. Raises WrongPassword."""
    global _key, _data, _seen
    with _lock:
        doc = _read_file()
        key = _unwrap(master or "", doc)
        _data, _key, _seen = _unseal(key, doc["data"]), key, _stat()


def unlock_remembered():
    """Open the vault with the key Windows keeps for this user (Remember on this computer). True when it opened."""
    global _key, _data, _seen
    if not (exists() and remembered()):
        return False
    try:
        with open(key_path(), "rb") as f:
            key = dpapi_unprotect(f.read())
        with _lock:
            doc = _read_file()
            _data, _key, _seen = _unseal(key, doc["data"]), key, _stat()
        return True
    except Exception:
        return False                                      # another Windows user, another computer, or a vault made again since


def lock():
    """Close the vault: nothing can be read until the master password is given again."""
    global _key, _data
    with _lock:
        _key, _data = None, None


def set_remembered(on):
    """Remember on this computer: keep the data key, protected by Windows for this user, beside the vault (or forget it)."""
    if on:
        if _key is None:
            raise Locked("The vault is locked.")
        with open(key_path(), "wb") as f:
            f.write(dpapi_protect(_key))
    else:
        try:
            key_path().unlink()
        except FileNotFoundError:
            pass


def change_master(master):
    """Lock the vault with a new master password (the passwords in it stay as they are)."""
    check_master(master)
    with _lock, _FileLock():
        if _key is None:
            raise Locked("The vault is locked.")
        doc = _read_file()
        doc["kdf"], doc["key"] = _wrap(master, _key)
        _write(doc)


# ---------------------------------------------------------------- the entries
def get(name):
    with _lock:
        if _key is None:
            raise Locked("The vault is locked.")
        _fresh()
        return _data.get(name)


def _change(fn):
    with _lock, _FileLock():
        if _key is None:
            raise Locked("The vault is locked.")
        _fresh()
        result = fn(_data)
        doc = _read_file()
        doc["data"] = _seal(_key, _data)
        _write(doc)
        return result


def _apply(ops):
    def run(d):
        for name, secret in ops:
            if secret is None:
                d.pop(name, None)
            else:
                d[name] = secret
    return run


def put(name, secret):
    if _queued(name, secret):
        return
    _change(lambda d: d.__setitem__(name, secret))


def put_many(items):
    """Several at once: one write of the file."""
    _change(lambda d: d.update(items))


def remove(name):
    """True when there was one."""
    with _lock:
        if _batch and _key is not None:
            had = name in _data
            _queued(name, None)
            return had
    return _change(lambda d: d.pop(name, None) is not None)


def _queued(name, secret):
    """Inside batch(): change the copy in memory and remember to write it. True when queued."""
    with _lock:
        if not _batch or _key is None:
            return False
        _pending.append((name, secret))
        _apply([(name, secret)])(_data)
        return True


@contextmanager
def batch():
    """Many changes, one write of the file at the end (an import of thousands of sessions with their passwords)."""
    global _batch
    with _lock:
        _batch += 1
    try:
        yield
    finally:
        with _lock:
            _batch -= 1
            if not _batch and _pending:
                ops = list(_pending)
                _pending.clear()
                _change(_apply(ops))               # re-reads what another process wrote meanwhile, then applies ours on top


def names():
    with _lock:
        if _key is None:
            raise Locked("The vault is locked.")
        _fresh()
        return sorted(_data)


# ---------------------------------------------------------------- Windows' protection of the remembered key (DPAPI)
def _dpapi(data, protect):
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def blob(b):
        buf = ctypes.create_string_buffer(b, len(b))
        return Blob(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    src, keep = blob(data)
    ent, keep2 = blob(DPAPI_ENTROPY)
    out = Blob()
    crypt32 = ctypes.windll.crypt32
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    args = (ctypes.byref(src), "Toner vault" if protect else None, ctypes.byref(ent), None, None, 0x1, ctypes.byref(out))
    if not fn(*args):                                     # 0x1: never show a prompt
        raise OSError(ctypes.get_last_error() or "Windows could not protect the vault key")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def dpapi_protect(data):
    return _dpapi(data, True)


def dpapi_unprotect(data):
    return _dpapi(data, False)


# ---------------------------------------------------------------- keyring's store
_old_backend = None


def install():
    """From now on keyring reads and writes the vault (Toner's code keeps calling keyring)."""
    global _old_backend
    import keyring
    import keyring.backend
    import keyring.errors

    class VaultKeyring(keyring.backend.KeyringBackend):
        priority = 10

        def get_password(self, service, username):
            ext = _memory_only(username)
            return ext.mem_get(username) if ext else get(username)

        def set_password(self, service, username, password):
            ext = _memory_only(username)
            if ext:
                ext.mem_put(username, password)              # only in the password manager (Keep a copy is off)
                return
            put(username, password)
            _tell_manager(username, "put")

        def delete_password(self, service, username):
            ext = _memory_only(username)
            if ext:
                if not ext.mem_remove(username):
                    raise keyring.errors.PasswordDeleteError("not in the password manager")
                return
            if not remove(username):
                raise keyring.errors.PasswordDeleteError("not in the vault")
            _tell_manager(username, "delete")

    current = keyring.get_keyring()
    if current.__class__.__name__ != "VaultKeyring":
        _old_backend = current
    keyring.set_keyring(VaultKeyring())


def _memory_only(name):
    """core.extstore when this password lives only in the password manager (and in memory), else None."""
    try:
        from core import extstore
        return extstore if extstore.memory_only() and not extstore.is_internal(name) else None
    except Exception:
        return None


def _tell_manager(name, op):
    """With a password manager chosen, every change also goes into the queue that is sent to it (core/extstore.py)."""
    try:
        from core import extstore
        extstore.queue(name, op)
    except Exception:
        pass


def left_in_credential_manager():
    """{name: secret} of the passwords an older Toner kept in Windows Credential Manager (read before the vault takes over)."""
    from core import vault
    backend = _old_backend
    if backend is None:
        return {}
    out = {}
    for name in vault.known_names():
        try:
            value = backend.get_password(db.SERVICE, name)
        except Exception:
            value = None
        if value:
            out[name] = value
    return out


def forget_credential_manager(names_):
    """Remove the moved passwords from Credential Manager (each one only once it is in the vault)."""
    for name in names_:
        try:
            _old_backend.delete_password(db.SERVICE, name)
        except Exception:
            pass

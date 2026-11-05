"""Toner's password vault: every password, API token and community string Toner keeps, in one encrypted file next to its database.

The vault replaced Windows Credential Manager, which holds only so many entries per Windows user (an import of thousands of sessions
filled it, and then no program could save a credential). The file is sealed with AES-256-GCM under a random data key; that key is
itself sealed with AES-GCM under Toner's data key (core/datakey.py), so signing in to Toner opens the vault (open_with).

An older Toner sealed that key with a master password (scrypt) and could remember it on this computer (DPAPI, or the system's
keyring, with a "-key" file beside the vault). create, unlock and unlock_remembered still read and make such a vault, so the
upgrade can open it and adopt() it: re-seal its key under the data key and delete the remembered copy. Nothing seals it under a
master password again.

Everything in Toner reaches the vault through `keyring` (install() makes the vault keyring's store), so the rest of the code is
unchanged: keyring.get_password(db.SERVICE, name) reads the vault's entry `name`.
"""
import base64
import json
import os
import sys
import threading
from contextlib import contextmanager

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from core import db
from core import quiet

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
    """The vault has not been opened (nobody signed in), or it is an older master-password vault the upgrade has not adopted."""


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


def uses_master():
    """True for a vault still sealed by a master password (an older Toner's, not yet adopted)."""
    try:
        return _read_file()["kdf"].get("name") == "scrypt"
    except FileNotFoundError:
        return False


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
    if kdf.get("name") != "scrypt":
        raise Locked("The vault opens when you sign in to Toner.")
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


def _FileLock():
    """Toner's window and its scheduled service may both write: one at a time (a lock file beside the vault)."""
    from core.platforms import FileLock
    return FileLock(path().with_name(path().name + ".lock"))


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
    """An older Toner's vault: new, empty (replacing any that is there), locked with `master`, and opened. Kept for the
    upgrade and its tests; new vaults come from open_with. `carry`: {name: secret} to put in it.
    Returns False when it was to be remembered but this computer has no keyring for it (Linux or macOS), else True."""
    global _key, _data
    from core import datakey
    if datakey.exists():
        raise FileExistsError("Toner's accounts are already set up.")    # it would replace the vault the data key opens
    check_master(master)
    with _lock, _FileLock():
        key = os.urandom(32)
        kdf, wrapped = _wrap(master, key)
        data = dict(carry or {})
        _write({"format": FORMAT, "version": 1, "kdf": kdf, "key": wrapped, "data": _seal(key, data)})
        _key, _data = key, data
    _forget_remembered()
    if remember:
        try:
            with open(key_path(), "wb") as f:
                f.write(_protect(key))
        except NoKeyring:
            return False
    return True


def _wrap_with(datakey, key):
    nonce = os.urandom(12)
    return _b64(nonce + AESGCM(datakey).encrypt(nonce, key, KEY_AAD))


def open_with(datakey):
    """Open the vault with Toner's data key (at sign-in), making an empty one when there is none. Raises WrongPassword for
    another key, and Locked for an older master-password vault (the upgrade adopts it first; it is never replaced here)."""
    global _key, _data, _seen
    with _lock, _FileLock():
        if not exists():
            key, data = os.urandom(32), {}
            _write({"format": FORMAT, "version": 1, "kdf": {"name": "datakey"}, "key": _wrap_with(datakey, key),
                    "data": _seal(key, data)})
            _key, _data = key, data
            return
        doc = _read_file()
        if doc["kdf"].get("name") != "datakey":
            raise Locked("The vault still has an older Toner's master password: the upgrade has to open it first.")
        raw = _unb64(doc["key"])
        try:
            key = AESGCM(datakey).decrypt(raw[:12], raw[12:], KEY_AAD)
            data = _unseal(key, doc["data"])
        except InvalidTag:
            raise WrongPassword("The vault was sealed with another data key.") from None
        _data, _key, _seen = data, key, _stat()
    if remembered():
        _forget_remembered()                              # an adopt that stopped before deleting the remembered copy


def adopt(datakey):
    """Move the open (older, master-password) vault onto the data key: its passwords re-sealed under a new inner key, that
    key sealed by the data key, in one write; then delete the copy Remember on this computer kept. A new inner key means
    the old master password, a leftover remembered key or a backed-up -key file open nothing written from now on."""
    global _key, _data
    with _lock, _FileLock():
        if _key is None:
            raise Locked("The vault is locked.")
        doc = _read_file()
        try:
            data = _unseal(_key, doc["data"])           # the file must still be the vault we opened (not made again since)
        except InvalidTag:
            raise Locked("The vault changed after it was opened. Open it again, then try again.") from None
        if _batch:
            data = _data                                # changes still waiting in memory (they are in _data already)
        key = os.urandom(32)
        _write({**doc, "kdf": {"name": "datakey"}, "key": _wrap_with(datakey, key), "data": _seal(key, data)})
        _key, _data = key, data
    _forget_remembered()


def unlock(master):
    """Open an older Toner's vault with its master password (the upgrade, before adopt). Raises WrongPassword, or Locked for
    a vault that opens with the data key."""
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
            key = _unprotect(f.read())
        with _lock:
            doc = _read_file()
            _data, _key, _seen = _unseal(key, doc["data"]), key, _stat()
        return True
    except Exception:
        return False                                      # another user, another computer, no keyring, or a vault made again since


def lock():
    """Close the vault: nothing can be read until it is opened again."""
    global _key, _data
    with _lock:
        _key, _data = None, None


class NoKeyring(RuntimeError):
    """Linux or macOS without a keyring Toner can use (no Secret Service running, say): the vault can't be remembered."""


def _forget_remembered():
    """Delete what Remember on this computer left: the key file and, on Linux and macOS, the key in the system's keyring."""
    try:
        with open(key_path(), "rb") as f:
            if f.read().startswith(KEYRING_MARK):
                _native_keyring().delete_password(NATIVE_SERVICE, str(path()))
    except Exception:
        quiet.ignored()
    try:
        key_path().unlink()
    except FileNotFoundError:
        pass


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


# ---------------------------------------------------------------- keeping the remembered key: DPAPI, or the system's keyring
KEYRING_MARK = b"toner-keyring\n"          # the key file on Linux and macOS: the key itself is in the keyring
NATIVE_SERVICE = "Toner vault"


def _native_keyring():
    """The system's own keyring (not Toner's vault, which keyring is pointed at once the vault is installed)."""
    try:
        if sys.platform == "darwin":
            from keyring.backends import macOS
            kr = macOS.Keyring()
        else:
            from keyring.backends import SecretService
            kr = SecretService.Keyring()
        kr.priority                                     # raises when it can't be used here
        return kr
    except Exception as e:
        raise NoKeyring(str(e) or "no keyring") from None


def _protect(key):
    if sys.platform == "win32":
        return dpapi_protect(key)
    _native_keyring().set_password(NATIVE_SERVICE, str(path()), base64.b64encode(key).decode())
    return KEYRING_MARK


def _unprotect(blob):
    if blob.startswith(KEYRING_MARK):
        stored = _native_keyring().get_password(NATIVE_SERVICE, str(path()))
        if not stored:
            raise NoKeyring("the keyring has no key for this vault")
        return base64.b64decode(stored)
    return dpapi_unprotect(blob)


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
        quiet.ignored()


class Unreadable(RuntimeError):
    """Credential Manager couldn't be read (no backend for it, or a read failed). `found`: what was read all the same."""

    def __init__(self, found):
        super().__init__("Windows Credential Manager couldn't be read.")
        self.found = found


def left_in_credential_manager():
    """{name: secret} of the passwords an older Toner kept in Windows Credential Manager (read before the vault takes over).
    Raises Unreadable on Windows when it couldn't be read in full, so an empty answer always means there are none."""
    from core import vault
    if sys.platform != "win32":                          # (only Windows' Toner ever used Credential Manager)
        return {}
    backend = _old_backend
    if backend is None:
        raise Unreadable({})
    out, failed = {}, False
    for name in vault.known_names():
        try:
            value = backend.get_password(db.SERVICE, name)
        except Exception:
            value, failed = None, True
        if value:
            out[name] = value
    if failed:
        raise Unreadable(out)
    return out


def forget_credential_manager(names_):
    """Remove the moved passwords from Credential Manager (each one only once it is in the vault)."""
    for name in names_:
        try:
            _old_backend.delete_password(db.SERVICE, name)
        except Exception:
            quiet.ignored()

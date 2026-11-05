"""The data key: one random 32-byte key that encrypts everything Toner keeps (core/sqldb.py hands it to SQLCipher).

It is never stored as it is. netcheck.keys, beside netcheck.db, holds it sealed once for each local account (scrypt over the
password, then AES-GCM) and once under a recovery key shown when Toner is set up. Changing a password re-seals only that
account's copy. Copying netcheck.db and netcheck.keys together moves everything; either one alone is useless.

Wrong passwords are counted in the file, one count for every name (and one for the recovery key), so a restart doesn't reset
it and the answers never show which names exist: five are free, then each one makes the next try wait, 30 seconds and
doubling up to 15 minutes.
"""
import base64
import json
import math
import os
import threading
import time
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from core import db, passwords, sqldb

FORMAT = "toner-keys"
PASSWORD_KDF = {"n": 2 ** 16, "r": 8, "p": 1}
RECOVERY_KDF = {"n": 2 ** 14, "r": 8, "p": 1}
RECOVERY_AAD = b"toner-datakey:recovery"
FREE_TRIES, FIRST_WAIT, MAX_WAIT = 5, 30, 900
_DUMMY_SALT = b"toner-datakey:no-such-account"     # an unknown name still runs scrypt, so timing doesn't tell names apart
WRONG = "That username or password isn't right."
WRONG_RECOVERY = "That recovery key isn't right."

_lock = threading.RLock()
# shortcut: the key is immutable bytes, so close() drops it but can't zero the memory; upgrade if Python gains a wipeable buffer.
_key = None


class WrongPassword(ValueError):
    pass


class Throttled(Exception):
    def __init__(self, seconds):
        self.seconds = int(seconds)
        super().__init__(f"Too many tries. Wait {self.seconds} seconds, then try again.")


class Locked(RuntimeError):
    """No one is signed in: the data key isn't open."""


class NameTaken(ValueError):
    pass


class LastAccount(ValueError):
    pass


# ---------------------------------------------------------------- where it lives
def path():
    return db.base_path().with_suffix(".keys")


def exists():
    return path().exists()


def is_open():
    return _key is not None


# ---------------------------------------------------------------- the file
def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _unb64(s):
    return base64.b64decode(s.encode("ascii"))


def _kek(secret, salt, kdf):
    return Scrypt(salt=salt, length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(secret.encode("utf-8"))


def _seal(secret, key, aad, kdf):
    salt, nonce = os.urandom(16), os.urandom(12)
    return {"kdf": {"name": "scrypt", "salt": _b64(salt), **kdf},
            "key": _b64(nonce + AESGCM(_kek(secret, salt, kdf)).encrypt(nonce, key, aad))}


def _unseal(secret, rec, aad):
    """The data key, or InvalidTag when the secret is wrong."""
    kdf, raw = rec["kdf"], _unb64(rec["key"])
    return AESGCM(_kek(secret, _unb64(kdf["salt"]), kdf)).decrypt(raw[:12], raw[12:], aad)


def _aad(name):
    return b"toner-datakey:" + name.encode("utf-8")


def _read():
    with open(path(), encoding="utf-8") as f:
        doc = json.load(f)
    if doc.get("format") != FORMAT:
        raise ValueError("this is not a Toner keys file")
    return doc


def _write(doc):
    """Replace the file in one step (a crash leaves the old file or the new one, never half of one)."""
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)
    from core.platforms import fsync_dir
    fsync_dir(p.parent)


def _FileLock():
    """Toner's window and its scheduled service may both write (and count failures): one at a time."""
    from core.platforms import FileLock
    return FileLock(path().with_name(path().name + ".lock"))


# ---------------------------------------------------------------- names, passwords, recovery keys
def _clean(name):
    name = (name or "").strip()
    if not name:
        raise ValueError("Enter a username.")
    return name


def _find(doc, name):
    """The stored spelling of `name` (names match whatever their case), or None."""
    folded = name.casefold()
    return next((n for n in doc["accounts"] if n.casefold() == folded), None)


def _check(password, name):
    p = passwords.problem(password, name)
    if p is not None:
        raise ValueError(p)


def _account(name, password, key, created=None):
    return {"kind": "local", **_seal(password, key, _aad(name), PASSWORD_KDF),
            "created": created or datetime.now(timezone.utc).isoformat(timespec="seconds")}


def _new_recovery(key):
    """(what to show, the seal): 160 random bits as 32 base32 characters in groups of four."""
    code = base64.b32encode(os.urandom(20)).decode("ascii")
    return "-".join(code[i:i + 4] for i in range(0, 32, 4)), {**_seal(code, key, RECOVERY_AAD, RECOVERY_KDF), "fails": 0, "until": 0}


def _wait(over):
    """Seconds to wait after the `over`th failure past the free ones."""
    return min(FIRST_WAIT * 2 ** min(over - 1, 5), MAX_WAIT)


def _attempt(name, secret):
    """The data key from `name`'s seal (None: the recovery seal). Every password try, for any name, real or not, counts against
    one shared counter (per-name counts would show which names exist); the recovery key has its own. The count is read, changed
    and written under the file lock, so two Toner processes can't race it. Raises Throttled while a wait runs (without
    checking), else WrongPassword."""
    with _lock, _FileLock():
        doc = _read()
        counter = doc["recovery"] if name is None else doc.setdefault("throttle", {"fails": 0, "until": 0})
        now = time.time()
        if counter.get("until", 0) - now > MAX_WAIT:          # the clock went back: don't let that stretch the wait
            counter["until"] = now + MAX_WAIT
            _write(doc)
        if now < counter.get("until", 0):
            raise Throttled(math.ceil(counter["until"] - now))
        key = None
        stored = None if name is None else _find(doc, name)
        try:
            if name is None:
                key = _unseal(secret, doc["recovery"], RECOVERY_AAD)
            elif stored is None:
                _kek(secret, _DUMMY_SALT, PASSWORD_KDF)       # an unknown name costs what a real check costs
            else:
                key = _unseal(secret, doc["accounts"][stored], _aad(stored))
        except InvalidTag:
            pass
        if key is None:
            counter["fails"] = counter.get("fails", 0) + 1
            over = counter["fails"] - FREE_TRIES
            if over > 0:
                counter["until"] = now + _wait(over)
            _write(doc)
            if over > 0:
                raise Throttled(_wait(over))
            raise WrongPassword(WRONG_RECOVERY if name is None else WRONG)
        if counter.get("fails") or counter.get("until"):
            counter["fails"], counter["until"] = 0, 0
            _write(doc)
        return key


def _open(key):
    global _key
    sqldb.set_key(key)
    _key = key


def _change(fn):
    """Read, change and write the file under its lock, with the key open."""
    with _lock, _FileLock():
        if _key is None:
            raise Locked("Sign in first.")
        doc = _read()
        result = fn(doc)
        _write(doc)
        return result


def _stored(doc, name):
    stored = _find(doc, _clean(name))
    if stored is None:
        raise ValueError("There's no account with that username.")
    return stored


# ---------------------------------------------------------------- the API
def create(name, password):
    """A new data key, the first account and the recovery seal; opens the key. Returns the recovery key to show once."""
    name = _clean(name)
    _check(password, name)
    with _lock, _FileLock():
        if exists():
            raise FileExistsError("Toner's accounts are already set up.")    # a new key would orphan the data under the old one
        key = os.urandom(32)
        shown, recovery = _new_recovery(key)
        _write({"format": FORMAT, "version": 1, "accounts": {name: _account(name, password, key)}, "recovery": recovery,
                "throttle": {"fails": 0, "until": 0}})
        _open(key)
    return shown


def open_with_password(name, password):
    _open(_attempt(_clean(name), password or ""))


def open_with_recovery(recovery):
    _open(_attempt(None, (recovery or "").upper().replace(" ", "").replace("-", "")))


def check_password(name, password):
    """True when the password is right (for unlocking). Raises Throttled the same way opening does."""
    try:
        _attempt(_clean(name), password or "")
        return True
    except WrongPassword:
        return False


def add_local(name, password):
    name = _clean(name)
    _check(password, name)

    def add(doc):
        if _find(doc, name) is not None:
            raise NameTaken("That username is already taken.")
        doc["accounts"][name] = _account(name, password, _key)
    _change(add)


def set_password(name, password):
    """Also clears the password tries' wait: whoever sets a password has the key open (a password or the recovery key), and the
    new password must work at once (the reset after a recovery-key sign-in signs in with it straight away)."""
    def reseal(doc):
        stored = _stored(doc, name)
        _check(password, stored)
        doc["accounts"][stored] = _account(stored, password, _key, doc["accounts"][stored].get("created"))
        doc["throttle"] = {"fails": 0, "until": 0}
    _change(reseal)


def remove(name):
    def drop(doc):
        stored = _stored(doc, name)
        if len(doc["accounts"]) == 1:
            raise LastAccount("Toner needs at least one account.")
        del doc["accounts"][stored]
    _change(drop)


def accounts():
    with _lock, _FileLock():  # (a writer's os.replace fails on Windows while this file is open)
        return sorted(({"name": n, "kind": a["kind"], "created": a["created"]} for n, a in _read()["accounts"].items()),
                      key=lambda a: a["name"].casefold())


def new_recovery():
    """Replace the recovery seal; the old recovery key stops working. Returns the new one to show once."""
    def swap(doc):
        shown, doc["recovery"] = _new_recovery(_key)
        return shown
    return _change(swap)


def close():
    global _key
    with _lock:
        _key = None
        sqldb.set_key(None)

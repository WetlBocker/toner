"""The data key: one random 32-byte key that encrypts everything Toner keeps (core/sqldb.py hands it to SQLCipher).

It is never stored as it is. netcheck.keys, beside netcheck.db, holds it sealed once for each local account (scrypt over the
password, then AES-GCM) and once under a recovery key shown when Toner is set up. Changing a password re-seals only that
account's copy. Copying netcheck.db and netcheck.keys together moves everything; either one alone is useless.

Wrong passwords are counted in the file, one count for every name (and one for the recovery key), so a restart doesn't reset
it and the answers never show which names exist: five are free, then each one makes the next try wait, 30 seconds and
doubling up to 15 minutes.
"""
import base64
import copy
import json
import math
import os
import threading
import time
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from core import db, envelope, passwords, sqldb

FORMAT = "toner-keys"
PASSWORD_KDF = {"n": 2 ** 16, "r": 8, "p": 1}
RECOVERY_KDF = {"n": 2 ** 14, "r": 8, "p": 1}
RECOVERY_AAD = b"toner-datakey:recovery"
ROLES = ("Admin", "Engineer", "Tech")
FREE_TRIES, FIRST_WAIT, MAX_WAIT = 5, 30, 900
_DUMMY_SALT = b"toner-datakey:no-such-account"     # an unknown name still runs scrypt, so timing doesn't tell names apart
WRONG = "That username or password isn't right."
WRONG_RECOVERY = "That recovery key isn't right."
MISSING = ("Toner's data is encrypted, but netcheck.keys is missing from its data folder. Put netcheck.keys back next to netcheck.db, "
           "then start Toner again.")

_lock = threading.RLock()
# shortcut: the keys are immutable bytes, so close() drops them but can't zero the memory; upgrade if Python gains a wipeable buffer.
_key = None
_box = None       # the signed-in account's (or the recovery key's) private box key
_name = None      # the signed-in account's stored spelling; None for the recovery key
# core/roles sets this (it reads this module, so this one can't import it): fn(before, after) inside each write that adds, removes or
# re-keys an account or the recovery key. It drops grants made for a box key that is gone, re-signs the rules, and may refuse. It
# may return a function to run once the write has landed.
accounts_changed = None
# core/roles sets this too: fn(landed) after every change, True once its write has landed (or it changed nothing), False when it failed.
written = None


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


def missing():
    """True when there is no keys file but Toner's data is already encrypted (the database, or a vault on the data key): the key
    is lost with the file, so a new one must never be made over it."""
    if exists():
        return False
    from core import passvault
    try:
        adopted = passvault.exists() and not passvault.uses_master()
    except (OSError, ValueError, KeyError):
        adopted = False                                       # a damaged vault: the database decides
    return sqldb.is_encrypted(db.base_path()) or adopted


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
    """The payload (the data key, then the box private), or InvalidTag when the secret is wrong. A Part 1 seal (the data key
    alone) gains a box key here, re-sealed in `rec` under the same KEK (so still one scrypt); the caller writes it."""
    kdf, raw = rec["kdf"], _unb64(rec["key"])
    aes = AESGCM(_kek(secret, _unb64(kdf["salt"]), kdf))
    payload = aes.decrypt(raw[:12], raw[12:], aad)
    if len(payload) == 32:
        private, public = envelope.new_box_key()
        payload, nonce = payload + private, os.urandom(12)
        rec["key"], rec["box_pub"] = _b64(nonce + aes.encrypt(nonce, payload, aad)), _b64(public)
    return payload


def _boxed(secret, key, aad, kdf):
    """(a seal of the data key and a new box private, with its box_pub; that private)."""
    private, public = envelope.new_box_key()
    return {**_seal(secret, key + private, aad, kdf), "box_pub": _b64(public)}, private


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


def _account(name, password, key, created=None, role="Admin"):
    """(the record, its box private): always a new box key."""
    if role not in ROLES:
        raise ValueError("unknown role")
    sealed, private = _boxed(password, key, _aad(name), PASSWORD_KDF)
    return {"kind": "local", **sealed, "role": role,
            "created": created or datetime.now(timezone.utc).isoformat(timespec="seconds")}, private


def _new_recovery(key):
    """(what to show, the seal, its box private): 160 random bits as 32 base32 characters in groups of four."""
    code = base64.b32encode(os.urandom(20)).decode("ascii")
    sealed, private = _boxed(code, key, RECOVERY_AAD, RECOVERY_KDF)
    return "-".join(code[i:i + 4] for i in range(0, 32, 4)), {**sealed, "fails": 0, "until": 0}, private


def _wait(over):
    """Seconds to wait after the `over`th failure past the free ones."""
    return min(FIRST_WAIT * 2 ** min(over - 1, 5), MAX_WAIT)


def _attempt(name, secret):
    """(the payload of `name`'s seal (None: the recovery seal), the stored name, the failed tries counted before it). A Part 1
    seal gains its box key in the same write that clears the count. Every password try, for any name, real or not, counts against
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
        rec = doc["recovery"] if name is None else doc["accounts"].get(stored)
        upgrade = rec is not None and "box_pub" not in rec
        try:
            if name is None:
                key = _unseal(secret, rec, RECOVERY_AAD)
            elif stored is None:
                _kek(secret, _DUMMY_SALT, PASSWORD_KDF)       # an unknown name costs what a real check costs
            else:
                key = _unseal(secret, rec, _aad(stored))
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
        fails = counter.get("fails", 0)
        if fails or counter.get("until") or upgrade:
            counter["fails"], counter["until"] = 0, 0
            _write(doc)
        return key, stored, fails


def _open(payload, name):
    global _key, _box, _name
    sqldb.set_key(payload[:32])
    _key, _box, _name = payload[:32], payload[32:], name


def _change(fn, accounts=False):
    """Read, change and write the file under its lock, with the key open. `accounts`: fn changes the accounts or a box key, so
    the roles hook sees the file before and after. A change that leaves the file as it was writes nothing."""
    with _lock, _FileLock():
        try:
            if _key is None:
                raise Locked("Sign in first.")
            doc = _read()
            before = copy.deepcopy(doc)
            result = fn(doc)
            done = accounts_changed(before, doc) if accounts and accounts_changed is not None else None
            if doc != before:
                _write(doc)
        except BaseException:
            if written is not None:
                written(False)
            raise
        if written is not None:
            try:
                written(True)                       # the file has landed: keep what it signed
            except BaseException:
                try:
                    if doc != before:
                        _write(before)              # not kept: the old file goes back, still under the lock, so the two agree
                finally:
                    written(False)
                raise
        if done is not None:
            done()
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
        if missing():
            raise FileExistsError(MISSING)
        key = os.urandom(32)
        shown, recovery, _ = _new_recovery(key)
        account, private = _account(name, password, key)
        _write({"format": FORMAT, "version": 1, "accounts": {name: account}, "recovery": recovery,
                "throttle": {"fails": 0, "until": 0}})
        _open(key + private, name)
    return shown


def open_with_password(name, password):
    """Opens the key; returns how many password tries failed (for any name) since the last one that worked."""
    key, stored, fails = _attempt(_clean(name), password or "")
    _open(key, stored)
    return fails


def open_with_recovery(recovery):
    """Opens the key; returns how many recovery-key tries failed since the last one that worked."""
    key, _, fails = _attempt(None, (recovery or "").upper().replace(" ", "").replace("-", ""))
    _open(key, None)
    return fails


def check_password(name, password):
    """True when the password is right (for unlocking). Raises Throttled the same way opening does."""
    try:
        _attempt(_clean(name), password or "")
        return True
    except WrongPassword:
        return False


def add_local(name, password, role="Admin"):
    name = _clean(name)
    _check(password, name)

    def add(doc):
        if _find(doc, name) is not None:
            raise NameTaken("That username is already taken.")
        doc["accounts"][name] = _account(name, password, _key, role=role)[0]
    _change(add, accounts=True)


def set_password(name, password):
    """Also clears the password tries' wait: whoever sets a password has the key open (a password or the recovery key), and the
    new password must work at once (the reset after a recovery-key sign-in signs in with it straight away)."""
    global _box
    def reseal(doc):
        stored = _stored(doc, name)
        _check(password, stored)
        old = doc["accounts"][stored]
        doc["accounts"][stored], private = _account(stored, password, _key, old.get("created"), old.get("role", "Admin"))
        doc["throttle"] = {"fails": 0, "until": 0}
        return stored, private
    stored, private = _change(reseal, accounts=True)
    if stored == _name:                 # your own password: hold the new box key (only once the write has landed)
        _box = private


def remove(name):
    def drop(doc):
        stored = _stored(doc, name)
        if len(doc["accounts"]) == 1:
            raise LastAccount("Toner needs at least one account.")
        del doc["accounts"][stored]
    _change(drop, accounts=True)


def accounts():
    with _lock, _FileLock():  # (a writer's os.replace fails on Windows while this file is open)
        return sorted(({"name": n, "kind": a["kind"], "created": a["created"], "role": a.get("role", "Admin")}
                       for n, a in _read()["accounts"].items()), key=lambda a: a["name"].casefold())


def read():
    """The whole file, freshly parsed under the lock (so a copy the caller may change)."""
    with _lock, _FileLock():
        return _read()


edit = _change


def box_private():
    return _box


def box_public(name):
    """The account's public box key (None as the name: the recovery key's), or None for a Part 1 record."""
    doc = read()
    rec = doc["recovery"] if name is None else doc["accounts"][_stored(doc, name)]
    return _unb64(rec["box_pub"]) if "box_pub" in rec else None


def signed_in_name():
    return _name


def new_recovery():
    """Replace the recovery seal; the old recovery key stops working. Returns the new one to show once."""
    global _box
    def swap(doc):
        shown, doc["recovery"], private = _new_recovery(_key)
        return shown, private
    shown, private = _change(swap, accounts=True)
    if _name is None:                   # signed in with the recovery key: hold the new one's box key
        _box = private
    return shown


def close():
    global _key, _box, _name
    with _lock:
        _key = _box = _name = None
        sqldb.set_key(None)

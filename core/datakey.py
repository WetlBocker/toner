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
import secrets
import threading
import time
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from core import audit, db, envelope, passwords, quiet, sqldb

FORMAT = "toner-keys"
PASSWORD_KDF = {"n": 2 ** 16, "r": 8, "p": 1}
RECOVERY_KDF = {"n": 2 ** 14, "r": 8, "p": 1}
RECOVERY_AAD = b"toner-datakey:recovery"
KEYS_AAD, KEY_INFO, KEYED_INFO = b"toner-datakey-keys:", b"toner-datakey:key", b"toner-datakey:keyed"
DIR_KEYED_INFO = b"toner-datakey:keyed:"           # + the name: a keyed directory seal's K2 key
ROLES = ("Admin", "Engineer", "Tech")
FREE_TRIES, FIRST_WAIT, MAX_WAIT = 5, 30, 900
_DUMMY_SALT = b"toner-datakey:no-such-account"     # an unknown name still runs scrypt, so timing doesn't tell names apart
WRONG = "That username or password isn't right."
WRONG_RECOVERY = "That recovery key isn't right."
KEYS_HELPER_ON = "Security keys can't be added to this account while \"Let group members sign in without approval\" is on."
MISSING = ("Toner's data is encrypted, but netcheck.keys is missing from its data folder. Put netcheck.keys back next to netcheck.db, "
           "then start Toner again.")

_lock = threading.RLock()
# shortcut: the keys are immutable bytes, so close() drops them but can't zero the memory; upgrade if Python gains a wipeable buffer.
_key = None
_box = None       # the signed-in account's (or the recovery key's) private box key
_name = None      # the signed-in account's stored spelling; None for the recovery key
_keys = None      # the signed-in account's security keys, {"list": [...], "wraps": [...]}, as its record's keys blob holds them
_k2 = None        # ... and the secret each key's value unwraps, which with the password key seals its data key
_seen = None      # its record's "keys" (an AD or LDAP account's: its "sealed") as this process last read or wrote it: a key write refuses once the file holds another
_started = {}     # slot id -> a started directory account's box private, held until an approval seals it (roles.approve)
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


class KeyNeeded(Exception):
    """The account has security keys and the caller gave no way to ask one."""


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


# ---------------------------------------------------------------- security keys
# A keyed local record has no "key": "keys" (sealed under the password key) lists the keys and holds, per key, K2 sealed under that
# key's value; "sealed_k" is the usual payload under the password key and K2 together. "keys_n" is a hint for the sign-in window.
def _enc(key, data, aad=None):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def _dec(key, raw, aad=None):
    return AESGCM(key).decrypt(raw[:12], raw[12:], aad)


def _hkdf(material, info):
    return HKDF(hashes.SHA256(), 32, None, info).derive(material)


def _keys_of(kek, rec, name):
    """The record's keys blob opened with the password key (InvalidTag: the password is wrong)."""
    return json.loads(_dec(kek, _unb64(rec["keys"]), KEYS_AAD + name.encode("utf-8")))


def _keyed(rec, kek, payload, keys, k2, name):
    """Make `rec` a keyed record holding `keys`; its kdf, box_pub and everything else stay."""
    rec.pop("key", None)
    rec["keys_n"] = len(keys["list"])
    rec["keys"] = _b64(_enc(kek, json.dumps(keys).encode("utf-8"), KEYS_AAD + name.encode("utf-8")))
    rec["sealed_k"] = _b64(_enc(_hkdf(kek + k2, KEYED_INFO), payload, _aad(name)))


def _creds(keys):
    from core import fidokey
    return [fidokey.Cred(_unb64(k["id"]), _unb64(k["salt"]), _unb64(k["pub"])) for k in keys["list"]]


def _k2_of(keys, key):
    """K2, unwrapped with the value `key(creds) -> (credential id, value)` gives. It asks the key (a touch, minutes), so never
    under a lock."""
    from core import fidokey
    if key is None:
        raise KeyNeeded()
    cid, value = key(_creds(keys))
    i = next((i for i, k in enumerate(keys["list"]) if _unb64(k["id"]) == cid), None)
    if i is None:
        raise fidokey.NotRegistered()
    try:
        return _dec(_hkdf(value, KEY_INFO), _unb64(keys["wraps"][i]))
    except InvalidTag:
        raise fidokey.NotRegistered() from None


def _session_keys(name):
    """The signed-in session's keys when `name`, as the caller asked it and matched as _find matches names, is its account; else
    None. Never from the file: an unlock of a session signed in with keys always needs one of them, whatever the file says."""
    if _name is None or _clean(name).casefold() != _name.casefold():
        return None
    held = _keys
    return held if (held or {}).get("list") else None


def _present(keys, present):
    """`present(creds) -> credential id` (a touch, the value is not read) answers for one of `keys`; never under a lock."""
    from core import fidokey
    if present is None:
        raise KeyNeeded()
    creds = _creds(keys)
    if not creds or present(creds) not in [c.id for c in creds]:
        raise fidokey.NotRegistered()


def _with_key(got, stored, key):
    """(the payload, K2) of a keyed record whose password _attempt proved."""
    kek, keys, sealed, _ = got
    k2 = _k2_of(keys, key)
    return _dec(_hkdf(kek + k2, KEYED_INFO), sealed, _aad(stored)), k2


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


def _gate(doc, counter, now):
    """Before a try, under the lock: cap a wait the clock going back stretched, then raise Throttled while one runs."""
    if counter.get("until", 0) - now > MAX_WAIT:
        counter["until"] = now + MAX_WAIT
        _write(doc)
    if now < counter.get("until", 0):
        raise Throttled(math.ceil(counter["until"] - now))


def _failed(doc, counter, now, free=FREE_TRIES):
    """After a wrong try, under the lock: count it and write; raises Throttled once past the `free` tries (a PIN on the
    security chip has fewer, so Toner's wait comes before Windows' lockout)."""
    counter["fails"] = counter.get("fails", 0) + 1
    over = counter["fails"] - free
    if over > 0:
        counter["until"] = now + _wait(over)
    _write(doc)
    if over > 0:
        raise Throttled(_wait(over))


def _attempt(name, secret):
    """(the payload of `name`'s seal (None: the recovery seal), the stored name, the failed tries counted before it). For a keyed
    record the "payload" is (the password key, its keys blob, its sealed_k, its "keys" as stored), for _with_key once the locks
    are let go. A Part 1 seal gains its box key in the same write that clears the count. Every password try, for any name, real
    or not, counts against one shared counter (per-name counts would show which names exist); the recovery key has its own. The
    count is read, changed and written under the file lock, so two Toner processes can't race it. Raises Throttled while a wait
    runs (without checking), else WrongPassword."""
    with _lock, _FileLock():
        doc = _read()
        counter = doc["recovery"] if name is None else doc.setdefault("throttle", {"fails": 0, "until": 0})
        now = time.time()
        _gate(doc, counter, now)
        key = None
        stored = None if name is None else _find(doc, name)
        if stored is not None and doc["accounts"][stored].get("kind") == "directory":
            stored = None                                     # no password here: as an unknown name
        rec = doc["recovery"] if name is None else doc["accounts"].get(stored)
        upgrade = rec is not None and "box_pub" not in rec
        try:
            if name is None:
                key = _unseal(secret, rec, RECOVERY_AAD)
            elif stored is None:
                _kek(secret, _DUMMY_SALT, PASSWORD_KDF)       # an unknown name costs what a real check costs
            elif "keys" in rec:
                kek = _kek(secret, _unb64(rec["kdf"]["salt"]), rec["kdf"])
                key = kek, _keys_of(kek, rec, stored), _unb64(rec["sealed_k"]), rec["keys"]
            else:
                key = _unseal(secret, rec, _aad(stored))
        except InvalidTag:
            pass
        if key is None:
            _failed(doc, counter, now)
            raise WrongPassword(WRONG_RECOVERY if name is None else WRONG)
        fails = counter.get("fails", 0)
        if fails or counter.get("until") or upgrade:
            counter["fails"], counter["until"] = 0, 0
            _write(doc)
        return key, stored, fails


def _open(payload, name, keys=None, k2=None, seen=None):
    global _key, _box, _name, _keys, _k2, _seen
    sqldb.set_key(payload[:32])
    _key, _box, _name, _keys, _k2, _seen = payload[:32], payload[32:], name, keys, k2, seen


def _change(fn, accounts=False, signed_in=True):
    """Read, change and write the file under its lock, with the key open. `accounts`: fn changes the accounts or a box key, so
    the roles hook sees the file before and after. `signed_in=False`: a directory sign-in's own write before the key is open,
    which only touches what the rules don't sign. A change that leaves the file as it was writes nothing."""
    with _lock, _FileLock():
        try:
            if signed_in and _key is None:
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
        try:
            if done is not None:
                done()                              # (rules_key) first: if it fails, nothing of this change was kept
            if written is not None:
                written(True)                       # the file has landed: keep what it signed
        except BaseException:
            try:
                if doc != before:
                    _write(before)                  # not kept: the old file goes back, still under the lock, so they agree
            finally:
                if written is not None:
                    written(False)
            raise
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


def open_with_password(name, password, key=None):
    """Opens the key; returns how many password tries failed (for any name) since the last one that worked. An account with
    security keys also needs `key(creds) -> (credential id, value)` (fidokey.value), asked once the password is right; KeyNeeded
    without it. A key failure (fidokey.Failed) leaves nothing open and is not counted as a wrong password."""
    return open_proof(prove_password(name, password, key=key), name)


class Proof:
    """An account's password or PIN (and key) proven, not yet open: open_proof opens it once, as that account only. It holds the
    data key, so it is never shown (repr) and its holder drops it at the end of the call."""
    __slots__ = ("_args", "fails")

    def __init__(self, args, fails):
        self._args, self.fails = args, fails

    def __repr__(self):
        return "<datakey.Proof>"


def prove_password(name, password, key=None):
    """open_with_password's checks (counted as it counts them) and its key, without opening: a Proof. The key's touch may take
    minutes, so dirsignin's approvals ask it here, before session's lock."""
    got, stored, fails = _attempt(_clean(name), password or "")
    if isinstance(got, tuple):
        payload, k2 = _with_key(got, stored, key)
        return Proof((payload, stored, got[1], k2, got[3]), fails)
    return Proof((got, stored), fails)


def open_proof(proof, name):
    """Opens the key with a Proof made for account `name` (ValueError for another account's, or one used already); returns the
    failed tries counted before it."""
    args, proof._args = proof._args, None
    try:
        if args is None or args[1] is None or args[1].casefold() != _clean(name).casefold():
            raise ValueError("that proof doesn't open this account")
        try:
            _open(*args)
        except BaseException as e:
            raise e.with_traceback(None) from None      # _open's frame holds the data key: not kept in the traceback
    finally:
        del args
    return proof.fails


def open_with_recovery(recovery):
    """Opens the key; returns how many recovery-key tries failed since the last one that worked."""
    key, _, fails = _attempt(None, (recovery or "").upper().replace(" ", "").replace("-", ""))
    _open(key, None)
    return fails


def open_with_keys(data_key):
    """For an approval by the helper service only (core/dirsignin.py): the data key it released, open with no account's box key
    or name. The approval closes it again."""
    global _key, _box, _name
    if not isinstance(data_key, bytes) or len(data_key) != 32:
        raise ValueError("not a data key")
    with _lock:
        sqldb.set_key(data_key)
        _key, _box, _name = data_key, None, None
        _drop_keys()


def check_password(name, password, present=None):
    """True when the password is right (for unlocking). Raises Throttled the same way opening does. An account with security keys
    also needs `present(creds) -> credential id` (fidokey.present: a touch, the value is not read); KeyNeeded without it. A
    session signed in with keys always needs one of them, whatever the file says by then."""
    held = _session_keys(name)
    try:
        got, _, _ = _attempt(_clean(name), password or "")
    except WrongPassword:
        return False
    if held is not None:
        _present(held, present)                         # unlock trusts the session, not the file (which the password can re-make)
    elif isinstance(got, tuple):
        _present(got[1], present)
    return True


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
    global _box, _seen
    def reseal(doc):
        stored = _stored(doc, name)
        old = doc["accounts"][stored]
        if old.get("kind") == "directory":
            raise WrongPassword(WRONG)                  # its directory keeps its password
        _check(password, stored)
        doc["accounts"][stored], private = _account(stored, password, _key, old.get("created"), old.get("role", "Admin"))
        if stored == _name:
            if old.get("keys") != _seen:
                raise Locked("Sign in first.")          # another process changed your keys: re-sealing what this one holds would undo it
            if "keys" in old:
                # your own keys stay, with no touch: the keys blob and sealed_k go under the new password with the K2 held
                rec = doc["accounts"][stored]
                _keyed(rec, _kek(password, _unb64(rec["kdf"]["salt"]), rec["kdf"]), _key + private, _keys, _k2, stored)
        doc["throttle"] = {"fails": 0, "until": 0}
        return stored, private, doc["accounts"][stored].get("keys")
    stored, private, seen = _change(reseal, accounts=True)
    if stored == _name:                 # your own password: hold the new box key (only once the write has landed)
        _box, _seen = private, seen


def _mine(doc, secret):
    """(the signed-in account's stored name, record, password key, keys blob, payload) once `secret` is its password; the blob is
    empty for an account without keys. A wrong password counts on the shared counter, and a running wait is honoured, as
    check_password's are (an open session is no uncounted way to guess it): WrongPassword or Throttled. Locked when the record's
    keys are not what this process last saw: another process changed them, and writing what this one holds would undo that."""
    counter = doc.setdefault("throttle", {"fails": 0, "until": 0})
    now = time.time()
    _gate(doc, counter, now)
    stored = _find(doc, _name) if _name is not None else None
    rec = doc["accounts"].get(stored)
    if rec is None or rec.get("kind") != "local" or rec.get("keys") != _seen:
        raise Locked("Sign in first.")                 # (also the recovery key or a directory account: no local record of yours)
    kek = _kek(secret or "", _unb64(rec["kdf"]["salt"]), rec["kdf"])
    try:
        keys = _keys_of(kek, rec, stored) if "keys" in rec else {"list": [], "wraps": []}
        payload = _dec(kek, _unb64(rec["key"]), _aad(stored)) if "keys" not in rec else None
    except InvalidTag:
        _failed(doc, counter, now)
        raise WrongPassword(WRONG) from None
    counter["fails"], counter["until"] = 0, 0
    if payload is None:
        payload = _dec(_hkdf(kek + _k2, KEYED_INFO), _unb64(rec["sealed_k"]), _aad(stored))
    return stored, rec, kek, keys, payload


def _sso(doc, rec):
    return any(isinstance(d, dict) and d.get("id") == rec.get("directory") and d.get("kind") == "oidc" for d in doc.get("directories") or [])


def _dir_mine():
    """(stored name, record) when the signed-in account is an AD or LDAP account, else None; ValueError for an SSO one."""
    doc = read()
    stored = _find(doc, _name) if _name is not None else None
    rec = doc["accounts"].get(stored)
    if rec is None or rec.get("kind") != "directory":
        return None
    if _sso(doc, rec):
        raise ValueError()                              # SSO accounts never have keys (the refusal people see is the window's)
    return stored, rec


def _dir_keyed(keys, k2, name, payload):
    """What a keyed directory account's slot seals: K1, then its keys and today's payload sealed under K2."""
    sealed_k = _enc(_hkdf(k2, DIR_KEYED_INFO + name.encode("utf-8")), payload)
    return b"K1" + json.dumps({**keys, "sealed_k": _b64(sealed_k)}).encode("utf-8")


def _dir_blob(payload):
    """The keys blob a keyed directory seal holds, or None for today's payload (whose random data key may begin with K1 too)."""
    if payload[:2] != b"K1":
        return None
    try:
        blob = json.loads(payload[2:])
    except ValueError:
        return None
    return blob if isinstance(blob, dict) and {"list", "wraps", "sealed_k"} <= set(blob) else None


def _dir_reseal(mine, pin, keys, k2):
    """Re-seal the signed-in directory account to hold `keys` (none: today's payload) once `pin` opens its slot, counted and
    waited as check_pin's are. Returns the new seal. A chip or store slot is replaced by a fresh one under the same PIN and the old
    one dropped once the write lands, so no earlier seal put back opens again. Locked when the seal is not the one this process
    last saw: another process changed it, and writing what this one holds would undo that."""
    from core import pinslot
    stored, rec = mine
    if rec.get("sealed") != _seen or rec.get("slot_gone"):
        raise Locked("Sign in first.")
    payload = seal_payload(stored, _box)
    secret = _dir_keyed(keys, k2, stored, payload) if keys["list"] else payload
    kind, new = rec["slot"]["kind"], None
    if kind == "pin":
        # shortcut: a PIN-alone slot has nothing on this computer to replace, so an earlier seal put back still opens with the PIN; upgrade if it gains one
        sealed = pinslot.reseal(rec["slot"], rec["slot_id"], pin or "", rec["sealed"], secret)
    else:
        pinslot.open(rec["slot"], rec["slot_id"], pin or "", rec["sealed"])
        new = pinslot.new(kind, new_slot_id(), pin or "")
        sealed = new.seal(secret)

    def write(doc):
        r = doc["accounts"].get(stored)
        if r is None or r.get("sealed") != _seen or r.get("slot_id") != rec["slot_id"] or r.get("slot_gone"):
            raise Locked("Sign in first.")
        if new is not None:
            _fresh_slot(doc, new)
            r["slot"], r["slot_id"] = new.rec, new.slot_id
        r["sealed"] = sealed
        if keys["list"]:
            r["keyed"], r["keys_n"] = True, len(keys["list"])
        else:
            r.pop("keyed", None)
            r.pop("keys_n", None)
    try:
        _change(write)
    except BaseException:
        if new is not None:
            drop_slot({"kind": "directory", "slot": new.rec, "slot_id": new.slot_id})    # never written: the old slot stays
        raise
    if new is not None:
        drop_slot(rec)                                  # (the record as read: its old slot)
    return sealed


def add_key(secret, cred, value, label):
    """Add a key (fidokey.register's credential and value) to the signed-in account. The first one takes the password-only seal
    (for an AD or LDAP account, `secret` is its Toner PIN: the PIN-only seal) away in the same write. The box key and the payload
    stay, so the roles hook has nothing to see."""
    global _keys, _k2, _seen
    entry = {"id": _b64(cred.id), "salt": _b64(cred.salt), "pub": _b64(cred.public), "name": label,
             "added": datetime.now(timezone.utc).isoformat(timespec="seconds")}

    def added(keys, k2):
        k2 = k2 if keys["list"] else os.urandom(32)
        keys["list"].append(entry)
        keys["wraps"].append(_b64(_enc(_hkdf(value, KEY_INFO), k2)))
        return keys, k2

    def add(doc):
        stored, rec, kek, keys, payload = _mine(doc, secret)
        keys, k2 = added(keys, _k2)
        _keyed(rec, kek, payload, keys, k2, stored)
        return keys, k2, rec["keys"]
    mine = _dir_mine()
    from core import dirsignin                          # (dirsignin imports this module)
    if mine is not None and not dirsignin.keys_allowed(_name):
        raise ValueError(KEYS_HELPER_ON)
    if mine is None:
        _keys, _k2, _seen = _change(add)
    else:
        keys, k2 = added(copy.deepcopy(_keys or {"list": [], "wraps": []}), _k2)
        _seen = _dir_reseal(mine, secret, keys, k2)
        _keys, _k2 = keys, k2
    audit.log("security key added", label)


def prove_mine(secret):
    """The signed-in account's password (an AD or LDAP account's: its Toner PIN) checked as add_key and remove_key check it, with
    the same counting, waits and errors, and no touch: the keys dialog asks it before the key, so a typo is caught first."""
    mine = _dir_mine()
    if mine is None:
        _change(lambda doc: _mine(doc, secret)[0])
        return
    from core import pinslot
    _, rec = mine
    if rec.get("sealed") != _seen or rec.get("slot_gone"):
        raise Locked("Sign in first.")
    pinslot.open(rec["slot"], rec["slot_id"], secret or "", rec["sealed"])


def remove_key(secret, index):
    """Remove the signed-in account's key at `index` (of my_keys()). Removing the last stores the account as one without keys."""
    global _keys, _k2, _seen
    mine = _dir_mine()
    if mine is not None:
        keys = copy.deepcopy(_keys or {"list": [], "wraps": []})
        label = keys["list"].pop(index)["name"]
        keys["wraps"].pop(index)
        _seen = _dir_reseal(mine, secret, keys, _k2)
        _keys, _k2 = (keys, _k2) if keys["list"] else (None, None)
        audit.log("security key removed", label)
        return

    def drop(doc):
        stored, rec, kek, keys, payload = _mine(doc, secret)
        label = keys["list"].pop(index)["name"]
        keys["wraps"].pop(index)
        if keys["list"]:
            _keyed(rec, kek, payload, keys, _k2, stored)
            return label, keys, _k2, rec["keys"]
        plain = {}                                      # the fields in the order an account without keys has them
        for k, v in rec.items():
            if k not in ("keys_n", "keys", "sealed_k"):
                plain[k] = v
            if k == "kdf":
                plain["key"] = _b64(_enc(kek, payload, _aad(stored)))
        doc["accounts"][stored] = plain
        return label, None, None, None
    label, _keys, _k2, _seen = _change(drop)
    audit.log("security key removed", label)


def my_keys():
    """The signed-in account's keys, [{"name", "added"}], from memory."""
    return [{"name": k["name"], "added": k["added"]} for k in (_keys or {}).get("list", [])]


def has_keys(name):
    """The record's keys_n: a hint for the sign-in window, never proof."""
    doc = read()
    stored = _find(doc, _clean(name))
    return bool(stored and doc["accounts"][stored].get("keys_n"))


def remove(name):
    def drop(doc):
        stored = _stored(doc, name)
        if len(doc["accounts"]) == 1:
            raise LastAccount("Toner needs at least one account.")
        return doc["accounts"].pop(stored)
    drop_slot(_change(drop, accounts=True))


def clear_keys(name):
    """An admin, for an AD or LDAP account whose key is lost: its slot goes from this computer and its key fields from its record,
    and the record is marked (slot_gone) so its next PIN finds no slot whatever its kind (the seal stays): it sets a new PIN through
    the new-PIN approval, which seals with no keys.
    ValueError for a local or SSO account."""
    def clear(doc):
        stored = _stored(doc, name)
        rec = doc["accounts"][stored]
        if rec.get("kind") != "directory" or _sso(doc, rec):
            raise ValueError()
        rec.pop("keyed", None)
        rec.pop("keys_n", None)
        rec["slot_gone"] = True                         # unsigned: deleting it only brings back the keyed seal, which needs the key
        return stored, copy.deepcopy(rec)
    stored, rec = _change(clear, accounts=True)
    drop_slot(rec)
    audit.log("security keys removed", f"{stored}, by {_name or audit.actor()}")


def accounts():
    """Each account for the Accounts page. A directory account also has its directory's kind ("ad", "ldap"; None when the
    directory is gone) and its PIN slot's kind ("chip", "store", "pin")."""
    with _lock, _FileLock():  # (a writer's os.replace fails on Windows while this file is open)
        doc = _read()
    kinds = {d.get("id"): d.get("kind") for d in doc.get("directories") or [] if isinstance(d, dict)}
    return sorted(({"name": n, "kind": a["kind"], "created": a["created"],
                    "keys": a.get("keys_n", 0), "role": (a.get("groups_role") or "Tech") if a["kind"] == "directory" else a.get("role", "Admin"),
                    **({"directory_kind": kinds.get(a.get("directory")), "slot_kind": a.get("slot_kind")} if a["kind"] == "directory" else {})}
                   for n, a in doc["accounts"].items()), key=lambda a: a["name"].casefold())


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


# ---------------------------------------------------------------- directory accounts
# The account's key in "accounts" is its User.name. Its PIN slot's id ("slot_id") is random (new_slot_id), never reused, so two
# accounts or two copies of Toner on one computer never share a TPM key or pepper. Its seal ("sealed", made by roles.approve)
# holds the data key, its box private and its name (seal_payload) under the slot. online_at (the last good check, by the sign-in or
# the background check), full_at (the last password and Duo, which starts the session) and groups_role are written before the key
# is open, so the rules don't sign them; approved_role, the attested box key and the directories are signed.
def new_slot_id():
    """The id for a new PIN slot: pinslot.new(kind, new_slot_id(), pin)."""
    return secrets.token_hex(16)


def _is_slot_id(sid):
    return isinstance(sid, str) and len(sid) == 32 and all(c in "0123456789abcdef" for c in sid)


def _fresh_slot(doc, slot):
    """Refuse a slot whose id isn't a new_slot_id() or is already some account's."""
    if not _is_slot_id(slot.slot_id) or any(a.get("slot_id") == slot.slot_id for a in doc["accounts"].values()):
        raise ValueError("a PIN slot needs a new id of its own")


def seal_payload(name, private):
    """What a directory account's slot seals: the data key, its box private, and its name (so a seal copied into another
    account's record opens nothing there)."""
    return _key + private + name.encode("utf-8")


def directory_account(name):
    """The directory account's record (a copy), or None. An online_at or full_at later than now reads as 0 (expired): a clock
    put back can't stretch the offline hour or the session."""
    doc = read()
    stored = _find(doc, _clean(name))
    rec = doc["accounts"][stored] if stored else None
    if rec is None or rec.get("kind") != "directory":
        return None
    for field in ("online_at", "full_at"):
        at = rec.get(field) or 0
        rec[field] = 0 if at > time.time() else at
    return rec


def start_directory_account(user, directory_id, slot, role=None):
    """Write an unapproved record for `user` (a directory.User) with a new box key, whose private half is held until approval.
    `role`: its groups' role when the sign-in already has it (the helper's answer carries no groups); else read from user.groups.
    Refused (ValueError) when the name belongs to a local account, another directory or another person, or is approved."""
    from core import directory
    private, public = envelope.new_box_key()

    def start(doc):
        cfg = next((d for d in doc.get("directories") or [] if d.get("id") == directory_id), None)
        if cfg is None:
            raise ValueError("no such directory")
        _fresh_slot(doc, slot)
        stored, old = _find(doc, _clean(user.name)), None
        if stored is not None:
            old = doc["accounts"].pop(stored)
            if (old.get("kind") != "directory" or old.get("directory") != directory_id or old.get("guid") != user.guid
                    or old.get("sealed") or old.get("approved_role")):
                raise NameTaken("That username is already taken.")
        doc["accounts"][user.name] = {
            "kind": "directory", "directory": directory_id, "guid": user.guid, "display": user.display,
            "slot_kind": slot.rec["kind"], "slot": slot.rec, "slot_id": slot.slot_id, "sealed": None, "box_pub": _b64(public),
            "approved_role": None, "online_at": time.time(), "full_at": time.time(),     # (only after password and Duo)
            "groups_role": role if role is not None else directory.role_for(cfg, user.groups, user.dn),
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        return old
    replaced = _change(start, signed_in=False)
    _started[slot.slot_id] = private
    drop_slot(replaced)                                 # the unapproved record's own slot, if this replaced one


def _pin_refused(pin):
    """A PIN try that can't open anything (no such account, no usable slot, or another account's seal): it waits, costs and
    counts as a wrong PIN does, so the answers don't show which names exist. `pin` None: the cost was already paid."""
    from core import pinslot
    with _lock, _FileLock():
        doc = _read()
        counter = doc.setdefault("throttle", {"fails": 0, "until": 0})
        now = time.time()
        try:
            _gate(doc, counter, now)
            if pin is not None:
                _kek(pin, _DUMMY_SALT, pinslot.KDF["pin"])
            _failed(doc, counter, now)
        except Throttled as e:
            raise pinslot.PinLocked(e.seconds) from None
    raise pinslot.WrongPin()


def _pin(name, pin, key=None, present=None, unlock=False):
    """(the data key and box private (None after `present`), the stored name, the failed tries counted before it, its keys blob
    or None, K2 or None, its seal as read); WrongPin, PinLocked or SlotMissing. A keyed seal (known from what the slot holds,
    never from the record's keyed field) also needs `key` (fidokey.value) or, to unlock, `present` (fidokey.present), asked once
    the PIN is right and the locks are let go: KeyNeeded without one. `unlock`: a session signed in with keys always needs one of
    them, whatever the seal holds by then."""
    from core import pinslot
    pin = pin or ""
    held = _session_keys(name) if unlock else None
    with _lock:
        doc = read()
        stored = _find(doc, _clean(name))
        rec = doc["accounts"][stored] if stored else None
        if rec is None or rec.get("kind") != "directory" or not rec.get("sealed") or not _is_slot_id(rec.get("slot_id")):
            _pin_refused(pin)
        fails = (doc.get("throttle") or {}).get("fails", 0)
        if rec.get("slot_gone"):                        # an admin cleared its keys: a new PIN, as for a slot not on this computer
            with _FileLock():
                d = _read()
                try:
                    _gate(d, d.setdefault("throttle", {"fails": 0, "until": 0}), time.time())
                except Throttled as e:
                    raise pinslot.PinLocked(e.seconds) from None
            raise pinslot.SlotMissing()
        payload = pinslot.open(rec["slot"], rec["slot_id"], pin, rec["sealed"])
    if held is not None:
        _present(held, present)                         # unlock trusts the session, not the file (a chip slot's seal needs no PIN to make)
        return None, stored, fails, None, None, rec["sealed"]
    keys = k2 = None
    if (blob := _dir_blob(payload)) is not None:
        keys = {"list": blob["list"], "wraps": blob["wraps"]}
        if present is not None:
            # the name can't be read without K2: only keys this session opened its own seal with answer (a copied seal's don't)
            held = [k["id"] for k in (_keys or {}).get("list", [])] if stored == _name else []
            _present({"list": [k for k in keys["list"] if k["id"] in held]}, present)
            return None, stored, fails, keys, None, rec["sealed"]
        k2 = _k2_of(keys, key)
        try:
            payload = _dec(_hkdf(k2, DIR_KEYED_INFO + stored.encode("utf-8")), _unb64(blob["sealed_k"]))
        except InvalidTag:
            payload = b""                               # sealed for another name: refused below
    if payload[64:] != stored.encode("utf-8"):
        _pin_refused(None)                              # another account's seal copied into this record
    return payload[:64], stored, fails, keys, k2, rec["sealed"]


def open_with_pin(name, pin, key=None):
    """Opens the key; returns how many tries failed (for any name) since the last one that worked. An account with security
    keys also needs `key(creds) -> (credential id, value)` (fidokey.value), asked once the PIN is right; KeyNeeded without it.
    A key failure (fidokey.Failed) leaves nothing open and is not counted as a wrong PIN."""
    return open_proof(prove_pin(name, pin, key=key), name)


def prove_pin(name, pin, key=None):
    """open_with_pin's checks (counted as it counts them) and its key, without opening: a Proof for open_proof."""
    payload, stored, fails, keys, k2, sealed = _pin(name, pin, key=key)
    return Proof((payload, stored, keys, k2, sealed), fails)


def check_pin(name, pin, present=None):
    """True when the PIN is right (for unlocking). Raises PinLocked the same way opening does. An account with security keys
    also needs `present(creds) -> credential id` (fidokey.present: a touch, the value is not read); KeyNeeded without it."""
    from core import pinslot
    try:
        _pin(name, pin, present=present, unlock=True)
        return True
    except pinslot.WrongPin:
        return False
    except (pinslot.SlotMissing, InvalidTag):
        if _session_keys(name) is None:
            raise
        return False                                    # a keyed session whose slot the file no longer opens: it stays locked


def _set_directory_field(name, field, value):
    def go(doc):
        stored = _stored(doc, name)
        if doc["accounts"][stored].get("kind") != "directory":
            raise ValueError("There's no account with that username.")
        doc["accounts"][stored][field] = value
    _change(go, signed_in=False)


def set_online(name, at):
    _set_directory_field(name, "online_at", min(at, time.time()))


def set_full(name, at):
    """The last full check (password and Duo), which starts the session. Only a sign-in writes it, never the background check."""
    _set_directory_field(name, "full_at", min(at, time.time()))


def set_groups_role(name, role):
    if role is not None and role not in ROLES:
        raise ValueError("unknown role")
    _set_directory_field(name, "groups_role", role)


def drop_slot(rec):
    """After a directory account's record (or its slot) is gone: delete that PIN slot's TPM key or pepper from this computer."""
    if not rec or rec.get("kind") != "directory" or not _is_slot_id(rec.get("slot_id")):
        return
    _started.pop(rec["slot_id"], None)
    from core import pinslot
    try:
        pinslot.remove(rec["slot"], rec["slot_id"])
    except Exception:                                   # the record is already gone; a key left behind opens nothing
        quiet.ignored()


def _drop_keys():
    global _keys, _k2, _seen
    _keys = _k2 = _seen = None


def close():
    global _key, _box, _name
    with _lock:
        _key = _box = _name = None
        _drop_keys()
        sqldb.set_key(None)

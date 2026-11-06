"""PIN slots: one directory account's copy of a secret (its data key seal) on one computer, unlocked with a PIN.

    "chip"   Windows' security chip: a TPM RSA key named Toner-<slot id>, protected by a 6-digit PIN; the chip limits guesses.
    "store"  a random pepper in the OS protected store, mixed with a PIN of 8 or more characters.
    "pin"    that PIN alone (scrypt, n=2**16).

The record (Slot.rec) is stored; it never holds the PIN, the pepper or a key. A copy taken to another computer, or a portable
copy, has no TPM key or pepper there: open raises SlotMissing, and the person sets a new PIN with an admin's approval.

Wrong PINs count on the same counter in netcheck.keys as passwords (core/datakey.py), so a PIN can't be guessed faster than a
password: five are free, then 30 seconds, doubling up to 15 minutes. The chip counts too, and its own lockout is PinLocked.
"""
import base64
import functools
import os
import sys
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from core import datakey, osstore, passvault, tpm_windows

KDF = {"store": {"n": 2 ** 15, "r": 8, "p": 1}, "pin": {"n": 2 ** 16, "r": 8, "p": 1}}
WRONG = "That PIN isn't right."
SIMPLE = "Avoid simple PINs like 123456."
SIX = "Use 6 digits."
EIGHT = "Use at least 8 characters."
_OAEP = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)


class WrongPin(ValueError):
    def __init__(self):
        super().__init__(WRONG)


class PinLocked(Exception):
    def __init__(self, seconds):
        self.seconds = int(seconds)
        super().__init__(f"Too many wrong PINs. Wait {self.seconds} seconds, then try again.")


class SlotMissing(Exception):
    """The slot's TPM key or pepper isn't on this computer."""


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _unb64(s):
    return base64.b64decode(s.encode("ascii"))


def _aad(slot_id):
    return b"toner-pinslot:" + slot_id.encode("utf-8")


def _box(kek, secret, slot_id):
    nonce = os.urandom(12)
    return _b64(nonce + AESGCM(kek).encrypt(nonce, secret, _aad(slot_id)))


def _unbox(kek, box, slot_id):
    raw = _unb64(box)
    return AESGCM(kek).decrypt(raw[:12], raw[12:], _aad(slot_id))


def _tpm_name(slot_id):
    return "Toner-" + slot_id


def _pepper_name(slot_id):
    return "pin:" + slot_id


def _kek(rec, pin, pepper=None):
    k = Scrypt(salt=_unb64(rec["salt"]), length=32, n=rec["n"], r=rec["r"], p=rec["p"]).derive(pin.encode("utf-8"))
    if pepper is None:
        return k
    return HKDF(hashes.SHA256(), 32, salt=None, info=b"toner-pinslot:store").derive(k + pepper)


@functools.cache
def best_kind():
    """The strongest kind this computer offers (asked once a process: the chip's test makes a key)."""
    if sys.platform == "win32" and tpm_windows.available():
        return "chip"
    return "store" if osstore.available() else "pin"


def problem(kind, pin):
    """The approved sentence for a PIN that won't do, or None."""
    pin = pin or ""
    if kind == "chip":
        if len(pin) != 6 or not (pin.isascii() and pin.isdigit()):
            return SIX
        if len(set(pin)) == 1 or pin in "0123456789" or pin in "9876543210":
            return SIMPLE
        return None
    return EIGHT if len(pin) < 8 else None


class Slot:
    """`rec` is stored. For "store" and "pin" the KEK made by new() is held here, in memory only, so seal needs no PIN."""

    def __init__(self, rec, slot_id, kek=None):
        self.rec, self._slot_id, self._kek = rec, slot_id, kek

    def seal(self, secret):
        if self.rec["kind"] == "chip":
            kek = os.urandom(32)
            pub = serialization.load_der_public_key(_unb64(self.rec["pub"]))
            return {"wrapped": _b64(pub.encrypt(kek, _OAEP)), "box": _box(kek, secret, self._slot_id)}
        return {"box": _box(self._kek, secret, self._slot_id)}


def new(kind, slot_id, pin):
    p = problem(kind, pin)
    if p is not None:
        raise ValueError(p)
    if kind == "chip":
        try:
            der = tpm_windows.create(_tpm_name(slot_id), pin)
        except tpm_windows.LockedOut as e:               # Windows refuses even a new key while the chip is locked out
            raise PinLocked(e.seconds) from None
        return Slot({"kind": "chip", "pub": _b64(der)}, slot_id)
    if kind not in KDF:
        raise ValueError("unknown PIN slot kind")
    rec = {"kind": kind, "salt": _b64(os.urandom(16)), **KDF[kind]}
    pepper = None
    if kind == "store":
        pepper = os.urandom(32)
        osstore.put(_pepper_name(slot_id), pepper)
    return Slot(rec, slot_id, _kek(rec, pin, pepper))


def _try(rec, slot_id, pin, sealed):
    """The secret; WrongPin, PinLocked (the chip's lockout) or SlotMissing."""
    kind = rec["kind"]
    if kind == "chip":
        try:
            kek = tpm_windows.decrypt(_tpm_name(slot_id), pin, _unb64(sealed["wrapped"]))
        except FileNotFoundError:
            raise SlotMissing() from None
        except PermissionError:
            raise WrongPin() from None
        except tpm_windows.LockedOut as e:
            raise PinLocked(e.seconds) from None
        return _unbox(kek, sealed["box"], slot_id)        # (a damaged box: InvalidTag, not a wrong PIN)
    if any(int(rec.get(f, 0)) < KDF[kind][f] for f in ("n", "r", "p")):
        raise SlotMissing()                               # a record made cheaper to guess was tampered with
    pepper = None
    if kind == "store":
        try:
            pepper = osstore.get(_pepper_name(slot_id))
        except (OSError, passvault.NoKeyring):            # DPAPI from another user or computer, or no keyring now
            pepper = None
        if pepper is None:
            raise SlotMissing()
    try:
        return _unbox(_kek(rec, pin, pepper), sealed["box"], slot_id)
    except InvalidTag:
        raise WrongPin() from None


def open(rec, slot_id, pin, sealed):
    """The sealed secret. Every wrong PIN counts on netcheck.keys' shared counter, read and written under its lock; raises
    FileNotFoundError when there is no keys file.

    On the chip, Windows locks a user out of every TPM PIN once they have its threshold of failures (4) in 8 hours, so Toner
    lets one fewer reach the chip: the (threshold - 1)th wrong PIN starts Toner's wait, and the next try waits before the chip
    sees it."""
    free = max(tpm_windows.lockout_threshold() - 2, 0) if rec["kind"] == "chip" else datakey.FREE_TRIES
    with datakey._lock, datakey._FileLock():
        doc = datakey._read()
        counter = doc.setdefault("throttle", {"fails": 0, "until": 0})
        now = time.time()
        try:
            datakey._gate(doc, counter, now)
            try:
                secret = _try(rec, slot_id, pin or "", sealed)
            except WrongPin:
                datakey._failed(doc, counter, now, free)
                raise
        except datakey.Throttled as e:
            raise PinLocked(e.seconds) from None
        if counter.get("fails") or counter.get("until"):
            counter["fails"], counter["until"] = 0, 0
            datakey._write(doc)
        return secret


def remove(rec, slot_id):
    """Deletes the slot's TPM key or pepper from this computer, if it's here."""
    if rec["kind"] == "chip":
        tpm_windows.delete(_tpm_name(slot_id))
    elif rec["kind"] == "store":
        try:
            osstore.delete(_pepper_name(slot_id))
        except passvault.NoKeyring:
            pass

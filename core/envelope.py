"""Envelope crypto for role keys: X25519 wraps a secret to one account's public key, Ed25519 signs the role rules.

A wrap is base64 of the ephemeral public key (32 bytes), the nonce (12) and the AES-GCM ciphertext. The AES key is HKDF-SHA256 over
the X25519 shared secret. `aad` binds a wrap to where it belongs, so a wrap can't be moved to another slot.
"""
import base64
import hashlib
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
_RAW_PRIV = dict(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw,
                 encryption_algorithm=serialization.NoEncryption())


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _pair(key):
    return key.private_bytes(**_RAW_PRIV), key.public_key().public_bytes(**_RAW)


def _aes(private, public):
    shared = private.exchange(public)
    return AESGCM(HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"toner-envelope").derive(shared))


def new_box_key():
    return _pair(X25519PrivateKey.generate())


def wrap(public, secret, aad):
    eph = X25519PrivateKey.generate()
    nonce = os.urandom(12)
    ct = _aes(eph, X25519PublicKey.from_public_bytes(public)).encrypt(nonce, secret, aad)
    return _b64(eph.public_key().public_bytes(**_RAW) + nonce + ct)


def unwrap(private, blob, aad):
    """The secret; InvalidTag when the key, the aad or the blob is wrong, ValueError when the blob is too short."""
    raw = base64.b64decode(blob.encode("ascii"))
    if len(raw) < 32 + 12:
        raise ValueError("that wrapped key is too short to hold its header")
    key = _aes(X25519PrivateKey.from_private_bytes(private), X25519PublicKey.from_public_bytes(raw[:32]))
    return key.decrypt(raw[32:44], raw[44:], aad)


def new_signing_key():
    return _pair(Ed25519PrivateKey.generate())


def sign(private, data):
    return _b64(Ed25519PrivateKey.from_private_bytes(private).sign(data))


def verify(public, data, sig):
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(sig.encode("ascii"), validate=True), data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def fingerprint(public):
    return hashlib.sha256(public).hexdigest()

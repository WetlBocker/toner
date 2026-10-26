"""Saved passwords in an encrypted file, so a portable copy (or a new computer) can have them.

Toner keeps passwords, API tokens and community strings in its vault (core/passvault.py), which a copy of the data folder carries
along. Export still writes every password Toner knows about into a separate file protected by a password of your choosing (scrypt
to make the key, AES-256-GCM to seal it), to hand them to another Toner with a vault of its own; Import puts them into this one.
The file is useless without that password, and Toner never stores it.
"""
import json
import os

import keyring
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from core import db, notify, profiles, sessions

MAGIC = b"TONERVAULT1"
EXTENSION = ".tonervault"
MIN_PASSWORD = 8
SERVICE_NAMES = ("service:proxy", "service:proxy-otp", "service:ssh-tunnel", "service:ssh-tunnel-otp", "service:sftp-server", "service:ftp-server",
                 "service:agent-enroll", "service:ansible-server",
                 "service:ai-claude", "service:ai-openai", "service:ai-gemini")      # the Assistant's API keys (Settings > AI)


def known_names():
    """Every credential name Toner could have stored for what is in its databases: Global's and every organization's."""
    names = set(SERVICE_NAMES)
    for org in [db.GLOBAL] + [r["id"] for r in db.org_rows()]:
        with db.within(org):
            names |= _names_here()
            names.add(db.qualify("service:agent-enroll"))       # each organization has its own agent sign-up key
            names.add(db.qualify("firmware-source"))            # ...and its own Firmware Transfer image server login
    return sorted(names)


def _names_here():
    names = set()
    with db.connect() as c:
        devices = [r[0] for r in c.execute("SELECT name FROM devices")]
    for d in devices:
        names.update(db.secret_name(d, k) for k in db.SECRET_KINDS)
    for p in profiles._profiles_here():
        names.update(db.secret_name(f"profile:{p['name']}", k) for k in db.SECRET_KINDS)
    for s in sessions._sessions_here():
        names.add(sessions.secret_name(s["id"]))
    for ch in notify.channels():
        for key, _label, kind, _extra in notify.CHANNEL_TYPES.get(ch.get("type"), {"fields": []})["fields"]:
            if kind == "secret":
                names.add(notify._secret_name(ch["id"], key))
    return names


def collect():
    """{name: password} for the ones that are stored."""
    out = {}
    for name in known_names():
        try:
            value = keyring.get_password(db.SERVICE, name)
        except Exception:
            value = None
        if value:
            out[name] = value
    return out


def _key(password, salt):
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(password.encode())


def export_bytes(password, secrets=None):
    """The encrypted file's contents. Returns (bytes, number of passwords)."""
    if len(password or "") < MIN_PASSWORD:
        raise ValueError(f"choose a password of at least {MIN_PASSWORD} characters for the file")
    secrets = collect() if secrets is None else secrets
    salt, nonce = os.urandom(16), os.urandom(12)
    body = json.dumps({"v": 1, "secrets": secrets}).encode()
    return MAGIC + salt + nonce + AESGCM(_key(password, salt)).encrypt(nonce, body, MAGIC), len(secrets)


def read_bytes(data, password):
    """The {name: password} inside a file made by export_bytes."""
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 16 + 12 + 16:
        raise ValueError("this is not a Toner password file")
    salt, nonce, sealed = data[len(MAGIC):len(MAGIC) + 16], data[len(MAGIC) + 16:len(MAGIC) + 28], data[len(MAGIC) + 28:]
    try:
        body = AESGCM(_key(password or "", salt)).decrypt(nonce, sealed, MAGIC)
        secrets = json.loads(body)["secrets"]
    except (InvalidTag, ValueError, KeyError):
        raise ValueError("wrong password, or the file is damaged") from None
    return {str(k): str(v) for k, v in secrets.items() if k and v}


def import_bytes(data, password, replace=True):
    """Store every password in the file. With replace=False a password already on this computer is kept. Returns (stored, skipped)."""
    secrets = read_bytes(data, password)
    stored = skipped = 0
    for name, value in secrets.items():
        if not replace and keyring.get_password(db.SERVICE, name):
            skipped += 1
            continue
        keyring.set_password(db.SERVICE, name, value)
        stored += 1
    return stored, skipped

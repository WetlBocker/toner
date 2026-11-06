"""The directories list as this computer last saw it verified, kept as a fingerprint in the OS protected store.

A directory sign-in reads the list from netcheck.keys before anything can check its signature, so a hand-edited list could send a
domain password to someone else's server. A login that matches a directory therefore needs the list to match the fingerprint
remembered here: after a sign-in whose rules check out, and after an Admin changes the directories. The store's name comes from
the keys file's own path, so two copies on one computer keep their own, and editing the file can't rename it. No protected store:
no guard (the owner's call)."""
import functools
import hashlib
import json
import sys

from core import datakey, osstore, passvault, quiet


def fingerprint(dirs):
    """SHA-256 over the list's canonical JSON, then each CA file's contents (a CA file can't be read: a fixed marker)."""
    h = hashlib.sha256(json.dumps(dirs, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    for d in dirs:
        if d.get("ca_file"):
            try:
                with open(d["ca_file"], "rb") as f:
                    h.update(hashlib.sha256(f.read()).digest())
            except OSError:
                h.update(b"unreadable")
    return h.hexdigest()


@functools.cache
def _store():
    """Asked once a process: a Secret Service nobody can unlock takes 3 seconds to say no, and every sign-in remembers."""
    return osstore.available()


def store_name():
    p = str(datakey.path().resolve())
    if sys.platform == "win32":
        p = p.casefold()
    return "dirs:" + hashlib.sha256(p.encode("utf-8")).hexdigest()


def remember():
    """Remember the list as it is now. Never raises: a store error never blocks a sign-in."""
    try:
        if _store():
            osstore.put(store_name(), fingerprint(datakey.read().get("directories") or []).encode("ascii"))
    except Exception:
        quiet.ignored()


def changed(dirs):
    """True when this computer remembers a different list. Nothing remembered yet: remember this one (first use)."""
    try:
        if not _store():
            return False
        stored = osstore.get(store_name())
        now = fingerprint(dirs).encode("ascii")
        if stored is None:
            osstore.put(store_name(), now)
            return False
    except passvault.NoKeyring:
        return False
    return stored != now

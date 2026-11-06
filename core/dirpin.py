"""The directories list as this computer last saw it verified, kept as a fingerprint in the OS protected store.

A directory sign-in reads the list from netcheck.keys before anything can check its signature, so a hand-edited list could send a
domain password to someone else's server. A login that matches a directory therefore needs the list to match the fingerprint
remembered here: after a sign-in whose rules check out, and after an Admin changes the directories. The store's name comes from
the keys file's own path, so two copies on one computer keep their own, and editing the file can't rename it. On Windows it is kept
in %APPDATA%\\Toner\\dirpins.json, outside the data folder (%APPDATA%\\NetCheck, a portable copy's, or NETCHECK_DB's), so whoever
can write that folder can't delete it; elsewhere the Keychain or Secret Service is already outside it. No protected store: no guard (the owner's call)."""
import hashlib
import json
import sys
import threading

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


_avail = None          # osstore.available(), asked once: a Secret Service nobody can unlock takes 3 seconds to say no
_looking = threading.Lock()


def _store():
    global _avail
    if _avail is None:
        _avail = osstore.available()
    return _avail


def pins_file():
    """Windows: the per-user file outside the data folder (under %APPDATA%, which each test points at its own folder).
    Elsewhere None (the Keychain or Secret Service)."""
    if sys.platform != "win32":
        return None
    from core.platforms import user_data_root
    return user_data_root() / "Toner" / "dirpins.json"


def store_name():
    p = str(datakey.path().resolve())
    if sys.platform == "win32":
        p = p.casefold()
    return "dirs:" + hashlib.sha256(p.encode("utf-8")).hexdigest()


def remember():
    """Remember the list as it is now. Never raises: a store error never blocks a sign-in. With no store when first asked, look
    again off this thread (a keyring unlocked since), so a later put isn't skipped for a stale answer."""
    try:
        name, value = store_name(), fingerprint(datakey.read().get("directories") or []).encode("ascii")
        if _store():
            osstore.put(name, value, pins_file())
        elif _looking.acquire(blocking=False):
            threading.Thread(target=_look_again, args=(name, value), daemon=True).start()
    except Exception:
        quiet.ignored()


def _look_again(name, value):
    global _avail
    try:
        if osstore.available():
            osstore.put(name, value, pins_file())
            _avail = True
    except Exception:
        quiet.ignored()
    finally:
        _looking.release()


def changed(dirs):
    """True when this computer remembers a different list. Nothing remembered yet: remember this one (first use)."""
    try:
        if not _store():
            return False
        stored = osstore.get(store_name(), pins_file())
        now = fingerprint(dirs).encode("ascii")
        if stored is None:
            osstore.put(store_name(), now, pins_file())
            return False
    except passvault.NoKeyring:
        return False
    return stored != now

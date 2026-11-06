"""The directories list as this computer last saw it verified, kept as a fingerprint in the OS protected store.

A directory sign-in reads the list from netcheck.keys before anything can check its signature, so a hand-edited list could send a
domain password to someone else's server. A login that matches a directory therefore needs the list to match the fingerprint
remembered here: after a sign-in whose rules check out, and after an Admin changes the directories (each passes the doc it verified
or wrote, never a fresh read). A CA file is covered by the SHA-256 signed into the list (core/directory.py checks it at connect), so
nothing here opens a file the list names. The store's name comes from the keys file's folder and name (not where a symlink points),
so two copies on one computer keep their own, and editing or relinking the file can't rename it. On Windows it is kept
in %APPDATA%\\Toner\\dirpins.json, outside the data folder (%APPDATA%\\NetCheck, a portable copy's, or NETCHECK_DB's), so whoever
can write that folder can't delete it; elsewhere the Keychain or Secret Service is already outside it. No protected store: no guard (the owner's call)."""
import hashlib
import json
import sys
import threading

from core import datakey, osstore, passvault, quiet


def fingerprint(dirs):
    """SHA-256 over the list's canonical JSON. Opens no files."""
    return hashlib.sha256(json.dumps(dirs, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


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
    k = datakey.path()
    p = str(k.parent.resolve() / k.name)
    if sys.platform == "win32":
        p = p.casefold()
    return "dirs:" + hashlib.sha256(p.encode("utf-8")).hexdigest()


def remember(doc):
    """Remember the list in `doc`, the keys doc whose rules were just verified or written. Never raises: a store error never
    blocks a sign-in. With no store when first asked, look again off this thread (a keyring unlocked since), so a later put
    isn't skipped for a stale answer."""
    try:
        name, value = store_name(), fingerprint(doc.get("directories") or []).encode("ascii")
        if _store():
            _put(name, value)
        elif _looking.acquire(blocking=False):
            threading.Thread(target=_look_again, args=(name, value), daemon=True).start()
    except Exception:
        quiet.ignored()


def _put(name, value):
    f = pins_file()
    try:
        osstore.put(name, value, f)
    except Exception:
        if f is None:
            raise
        f.unlink(missing_ok=True)              # a corrupt pins file: start a fresh one (its entries couldn't be read anyway)
        osstore.put(name, value, f)


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
    """True when this computer remembers a different list. Nothing remembered yet: remember this one (first use).
    A pins file that can't be read is a mismatch until an ok sign-in writes a fresh one; a keyring error is no store."""
    if not _store():
        return False
    f = pins_file()
    try:
        stored = osstore.get(store_name(), f)
    except passvault.NoKeyring:
        return False
    except Exception:
        quiet.ignored()
        return f is not None
    now = fingerprint(dirs).encode("ascii")
    if stored is None:
        try:
            osstore.put(store_name(), now, f)
        except Exception:
            quiet.ignored()
        return False
    return stored != now


def forget(name):
    """Factory reset: this copy's remembered list (`name`, from store_name() while the keys file is still there) goes; on
    Windows the pins file goes too once no other copy's entry is left in it (a corrupt one holds nothing anyone can read)."""
    f = pins_file()
    if f is None:
        osstore.delete(name)
        return
    try:
        data = json.loads(f.read_text("utf-8"))
    except FileNotFoundError:
        return
    except ValueError:
        data = {}
    data.pop(name, None)
    if data:
        osstore._save(data, f)
    else:
        f.unlink(missing_ok=True)

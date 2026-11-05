"""The operating system's protected store, usable before anyone signs in (Duo's secret key lives here).
Windows: DPAPI blobs in netcheck.store beside netcheck.keys. Elsewhere: the Keychain / Secret Service that passvault keeps."""
import base64
import json
import os
import sys
import threading

from core import db, passvault


def _file():
    from core import datakey
    return datakey.path().with_name("netcheck.store")


def _backend():
    b = passvault._old_backend
    if b is None:
        import keyring
        b = keyring.get_keyring()
        if b.__class__.__name__ == "VaultKeyring":
            return None
    return None if "fail" in b.__class__.__module__ else b     # keyring.backends.fail: no Secret Service


def available():
    if sys.platform == "win32":
        return True
    b = _backend()
    if b is None:
        return False
    # A Secret Service with no one to unlock it can block forever, so probe with a read and give up after 3 seconds.
    ok = []

    def probe():
        try:
            b.get_password(db.SERVICE, "probe")
            ok.append(1)
        except Exception:
            pass
    t = threading.Thread(target=probe, daemon=True)
    t.start()
    t.join(3)
    return bool(ok)


def _load():
    try:
        return json.loads(_file().read_text("utf-8"))
    except FileNotFoundError:
        return {}


def _save(data):
    p = _file()
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(data), "utf-8")
    os.replace(tmp, p)


def put(name, secret):
    if sys.platform == "win32":
        data = _load()
        data[name] = base64.b64encode(passvault.dpapi_protect(secret)).decode()
        return _save(data)
    b = _backend()
    if b is None:
        raise passvault.NoKeyring("no keyring")
    b.set_password(db.SERVICE, name, base64.b64encode(secret).decode())


def get(name):
    if sys.platform == "win32":
        blob = _load().get(name)
        return passvault.dpapi_unprotect(base64.b64decode(blob)) if blob else None
    b = _backend()
    if b is None:
        raise passvault.NoKeyring("no keyring")
    v = b.get_password(db.SERVICE, name)
    return base64.b64decode(v) if v else None


def delete(name):
    if sys.platform == "win32":
        data = _load()
        if data.pop(name, None) is not None:
            _save(data)
        return
    b = _backend()
    if b is None:
        raise passvault.NoKeyring("no keyring")
    try:
        b.delete_password(db.SERVICE, name)
    except Exception:                       # already gone
        pass

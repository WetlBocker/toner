"""Who is signed in, and whether Toner is open, locked or signed out. Locking keeps the data key open (scheduled work and
worker threads still need the database); it only hides the window until the password is entered again."""
import threading

from core import audit, datakey, db, passvault, quiet

_lock = threading.RLock()
_state, _user, _callbacks = "signed_out", None, []


def state():
    return _state


def user():
    """The account name as stored (not as typed); None when signed out or signed in with the recovery key."""
    return _user


def on_change(fn):
    _callbacks.append(fn)


def _set(new, who=None):
    """Change state under the lock, then tell the listeners outside it so they can call back in."""
    global _state, _user
    with _lock:
        _state, _user = new, who
    for fn in list(_callbacks):
        try:
            fn(new)
        except Exception:
            quiet.ignored()


def _after_open():
    """Seam for the vault: Task 6 opens it here with the data key."""


def _opened(action, who):
    _after_open()
    with _lock:
        global _state, _user
        _state, _user = "open", who          # before the audit row, so it names the Toner user
    audit.log(action)
    _set("open", who)


def _stored_name(name):
    return next((a["name"] for a in datakey.accounts() if a["name"].casefold() == name.strip().casefold()), None)


def sign_in(name, password):
    with _lock:
        if _state != "signed_out":
            raise RuntimeError("Already signed in.")
        datakey.open_with_password(name, password)
        _opened("signed in", _stored_name(name))


def sign_in_recovery(recovery):
    with _lock:
        if _state != "signed_out":
            raise RuntimeError("Already signed in.")
        datakey.open_with_recovery(recovery)
        _opened("signed in with the recovery key", None)


def lock():
    with _lock:
        if _state != "open":
            raise RuntimeError("Toner isn't open.")
        if _user is None:
            raise RuntimeError("Signed in with the recovery key: there is no password to unlock with.")
        audit.log("locked")
        _set("locked", _user)


def unlock(password):
    with _lock:
        if _state != "locked":
            raise RuntimeError("Toner isn't locked.")
        try:
            right = datakey.check_password(_user, password)
        except datakey.Throttled:
            audit.log("unlock failed", "too many tries")
            raise
        if not right:
            audit.log("unlock failed")
            raise datakey.WrongPassword(datakey.WRONG)
        audit.log("unlocked")
        _set("open", _user)


def sign_out():
    with _lock:
        if _state != "signed_out":
            audit.log("signed out")          # while the key is still open: the audit table is encrypted
        passvault.lock()
        db.release()
        datakey.close()
        _set("signed_out")

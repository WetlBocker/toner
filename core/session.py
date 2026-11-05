"""Who is signed in, and whether Toner is open, locked or signed out. Locking keeps the data key open (scheduled work and
worker threads still need the database); it only hides the window until the password is entered again."""
import threading

from core import audit, datakey, db, passvault, quiet, sqldb

_lock = threading.RLock()
_state, _user, _callbacks = "signed_out", None, []


def state():
    return _state


def user():
    """The account name as stored (not as typed); None when signed out or signed in with the recovery key."""
    return _user


def on_change(fn):
    _callbacks.append(fn)


def _notify(new):
    """Tell the listeners after the lock is released, so one that waits on another thread calling into session can't deadlock."""
    for fn in list(_callbacks):
        try:
            fn(new)
        except Exception:
            quiet.ignored()


def _after_open():
    passvault.open_with(sqldb.current_key())


def _opened(opener, action, who):
    """Open the key, then the rest; if any step fails, close what opened so the state and the key agree."""
    global _state, _user
    with _lock:
        if _state != "signed_out":
            raise RuntimeError("Already signed in.")
        try:
            fails = opener()
            _after_open()
            who = who() if callable(who) else who
            _state, _user = "open", who          # before the audit row, so it names the Toner user
        except BaseException:
            _close()
            raise
        audit.log(action)
        if fails:                                # counted in netcheck.keys; the audit table opens only now
            audit.log(f"{fails} failed sign-in attempts since the last sign-in")
    _notify("open")


def _close():
    try:
        passvault.lock()
    finally:
        try:
            db.release()
        finally:
            datakey.close()                  # always, even when a step before it failed


def _stored_name(name):
    return next((a["name"] for a in datakey.accounts() if a["name"].casefold() == name.strip().casefold()), None)


def sign_in(name, password):
    _opened(lambda: datakey.open_with_password(name, password), "signed in", lambda: _stored_name(name))


def sign_in_recovery(recovery):
    _opened(lambda: datakey.open_with_recovery(recovery), "signed in with the recovery key", None)


def lock():
    global _state
    with _lock:
        if _state != "open":
            raise RuntimeError("Toner isn't open.")
        if _user is None:
            raise RuntimeError("Signed in with the recovery key: there is no password to unlock with.")
        audit.log("locked")
        _state = "locked"
    _notify("locked")


def unlock(password):
    global _state
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
        _state = "open"
    _notify("open")


def sign_out():
    global _state, _user
    was = _state
    try:
        with _lock:
            was = _state
            try:
                if was != "signed_out":
                    audit.log("signed out")  # while the key is still open: the audit table is encrypted
            finally:
                try:
                    _close()                 # also when "signed_out": datakey.create leaves the key open
                finally:
                    _state, _user = "signed_out", None
    finally:
        if was != "signed_out":
            _notify("signed_out")

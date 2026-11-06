"""Who is signed in, and whether Toner is open, locked or signed out. Locking keeps the data key open (scheduled work and
worker threads still need the database); it only hides the window until the password is entered again."""
import threading
import time

from core import audit, datakey, db, dirpin, passvault, pinslot, quiet, roles, sqldb

WORKDAY = 12 * 3600
REFUSED = "Your account can't sign in to Toner any more. Ask an admin."

_lock = threading.RLock()
_state, _user, _callbacks = "signed_out", None, []
_kind = None          # "local", "directory" or "recovery" while signed in
_full_at = None       # a directory account's last full check (directory and Duo): its online_at
_refused = False      # lock(reason="refused"): no unlock until a new sign-in
# shortcut: kept in memory, so rows waiting here are lost if Toner exits first; upgrade by counting them in netcheck.keys.
_soon = []            # audit rows from while the key was closed (the audit table is encrypted), written at the next sign-in
SOON_MAX = 100


class Refused(RuntimeError):
    pass


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


def _opened(opener, action, who, kind="local", detail=""):
    """Open the key, then the rest; if any step fails, close what opened so the state and the key agree."""
    global _state, _user, _kind, _full_at, _refused
    with _lock:
        if _state != "signed_out":
            raise RuntimeError("Already signed in.")
        try:
            fails = opener()
            _after_open()
            roles.unlock()                       # inside the rollback: anything it raises closes what opened
            who = who() if callable(who) else who
            detail = detail() if callable(detail) else detail
            _state, _user, _kind, _refused = "open", who, kind, False     # before the audit row, so it names the Toner user
            _full_at = datakey.directory_account(who)["online_at"] if kind == "directory" else None
        except BaseException:
            _close()
            raise
        audit.log(action, detail)
        if fails:                                # counted in netcheck.keys; the audit table opens only now
            audit.log(f"{fails} failed sign-in attempts since the last sign-in")
        while _soon:
            audit.log(*_soon.pop(0))
        if roles.state() == "ok":                # the rules (and so the directories) verified: remember them here
            dirpin.remember()
    _notify("open")


def _close():
    try:
        passvault.lock()
    finally:
        try:
            db.release()
        finally:
            try:
                roles.close()
            finally:
                datakey.close()              # always, even when a step before it failed


def _stored_name(name):
    return next((a["name"] for a in datakey.accounts() if a["name"].casefold() == name.strip().casefold()), None)


def sign_in(name, password):
    _opened(lambda: datakey.open_with_password(name, password), "signed in", lambda: _stored_name(name))


def sign_in_recovery(recovery):
    _opened(lambda: datakey.open_with_recovery(recovery), "signed in with the recovery key", None, "recovery")


def _directory_name(name):
    doc = datakey.read()
    rec = doc["accounts"][datakey._find(doc, name)]
    return next((d.get("name", "") for d in doc.get("directories") or [] if d.get("id") == rec.get("directory")), "")


def sign_in_pin(name, pin):
    """A directory account's sign-in with its PIN (core/dirsignin.py checks the directory and Duo first)."""
    _opened(lambda: datakey.open_with_pin(name, pin), "signed in", lambda: _stored_name(name), "directory",
            lambda: f"directory {_directory_name(name)}")


def kind():
    """"local", "directory" or "recovery"; None when signed out."""
    return _kind


def workday_over():
    """True once a directory account's last full check (directory and Duo) is more than 12 hours old (or the clock went back
    past it): an offline PIN sign-in doesn't start a new workday."""
    return _full_at is not None and not 0 <= time.time() - _full_at <= WORKDAY


def refused():
    return _refused


def audit_soon(action, detail="", who=None):
    """Audit now while the key is open, else at the next sign-in in this process."""
    with _lock:
        if datakey.is_open():
            audit.log(action, detail, who)
        elif len(_soon) < SOON_MAX:
            _soon.append((action, detail, who))


def lock(reason=None):
    """reason "refused" (the directory refused the account): unlocking is refused until a new sign-in, also when already locked."""
    global _state, _refused
    with _lock:
        if _state != "open" and not (reason == "refused" and _state == "locked"):
            raise RuntimeError("Toner isn't open.")
        if _user is None:
            raise RuntimeError("Signed in with the recovery key: there is no password to unlock with.")
        if _state == "open":
            audit.log("locked")
        _state, _refused = "locked", _refused or reason == "refused"
    _notify("locked")


def unlock(password):
    global _state
    with _lock:
        if _state != "locked":
            raise RuntimeError("Toner isn't locked.")
        if _refused:
            raise Refused(REFUSED)
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


def unlock_pin(pin):
    global _state
    with _lock:
        if _state != "locked":
            raise RuntimeError("Toner isn't locked.")
        if _refused:
            raise Refused(REFUSED)
        try:
            right = datakey.check_pin(_user, pin)
        except pinslot.PinLocked:
            audit.log("unlock failed", "too many tries")
            raise
        if not right:
            audit.log("unlock failed")
            raise pinslot.WrongPin()
        audit.log("unlocked")
        _state = "open"
    _notify("open")


def sign_out():
    global _state, _user, _kind, _full_at
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
                    _state, _user, _kind, _full_at = "signed_out", None, None, None
    finally:
        if was != "signed_out":
            _notify("signed_out")

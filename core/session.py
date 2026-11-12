"""Who is signed in, and whether Toner is open, locked or signed out. Locking keeps the data key open (scheduled work and
worker threads still need the database); it only hides the window until the password is entered again."""
import threading
import time

from core import audit, datakey, db, dirpin, passvault, pinslot, quiet, roles, sqldb

SESSION_HOURS = 12      # the default; Settings > Accounts changes it (signin_session_hours)
REFUSED = "Your account can't sign in to Toner any more. Ask an admin."

_lock = threading.RLock()
_state, _user, _callbacks = "signed_out", None, []
_kind = None          # "local", "directory" or "recovery" while signed in
_full_at = None       # a directory account's last full check (password and Duo): its full_at
_refused = False      # lock(reason="refused"): no unlock until a new sign-in
_opening = False      # a sign-in's opener is running (it may wait on a security key's touch, without the lock)
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


def off_change(fn):
    """Stop telling `fn` (a window that goes at Sign out: Toner stays open and builds the next one)."""
    if fn in _callbacks:
        _callbacks.remove(fn)


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
    """Open the key, then the rest; if any step fails, close what opened so the state and the key agree. The opener may wait
    minutes on a security key's touch, so it runs without the lock (_opening keeps a second sign-in out meanwhile)."""
    global _state, _user, _kind, _full_at, _refused, _opening
    with _lock:
        if _state != "signed_out" or _opening:
            raise RuntimeError("Already signed in.")
        _opening = True
    try:
        try:
            fails = opener()
        except BaseException:
            with _lock:
                _close()
            raise
        with _lock:
            try:
                _after_open()
                roles.unlock()                       # inside the rollback: anything it raises closes what opened
                who = who() if callable(who) else who
                detail = detail() if callable(detail) else detail
                _state, _user, _kind, _refused = "open", who, kind, False     # before the audit row, so it names the Toner user
                _full_at = datakey.directory_account(who)["full_at"] if kind == "directory" else None
            except BaseException:
                _close()
                raise
            finally:
                _opening = False
            audit.log(action, detail)
            if fails:                                # counted in netcheck.keys; the audit table opens only now
                audit.log(f"{fails} failed sign-in attempts since the last sign-in")
            while _soon:
                audit.log(*_soon.pop(0))
            doc = roles.verified()
            if doc is not None:                      # the rules (and so the directories) verified: remember that doc here
                dirpin.remember(doc)
    finally:
        _opening = False
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


def sign_in(name, password, key=None):
    """`key`: fidokey.value, asked when the account has security keys (KeyNeeded without it)."""
    _opened(lambda: datakey.open_with_password(name, password, key=key), "signed in", lambda: _stored_name(name))


def sign_in_recovery(recovery):
    _opened(lambda: datakey.open_with_recovery(recovery), "signed in with the recovery key", None, "recovery")


def _directory_name(name):
    doc = datakey.read()
    rec = doc["accounts"][datakey._find(doc, name)]
    return next((d.get("name", "") for d in doc.get("directories") or [] if d.get("id") == rec.get("directory")), "")


def sign_in_pin(name, pin, key=None, opened=None):
    """A directory account's sign-in with its PIN (core/dirsignin.py checks the directory and Duo first). `key`: fidokey.value,
    asked when the seal holds security keys. `opened()`: run once the seal is open, before anything is signed in, audited or told;
    what it raises closes it all again (dirsignin's check that a sign-in that skipped Duo opened a keyed seal)."""
    def opener():
        fails = datakey.open_with_pin(name, pin, key=key)
        if opened is not None:
            opened()
        return fails
    _opened(opener, "signed in", lambda: _stored_name(name), "directory",
            lambda: f"directory {_directory_name(name)}")


def kind():
    """"local", "directory" or "recovery"; None when signed out."""
    return _kind


def session_hours():
    """The session length setting, 1 to 72 hours; the default when it can't be read."""
    try:
        return min(72, max(1, int(db.get_setting("signin_session_hours"))))
    except Exception:
        return SESSION_HOURS


def session_over():
    """True once a directory account's last full check (directory and Duo) is more than session_hours() old (or the clock went
    back past it): an offline PIN sign-in doesn't start a new session."""
    return _full_at is not None and not 0 <= time.time() - _full_at <= session_hours() * 3600


def refused():
    return _refused


def audit_soon(action, detail="", who=None):
    """Audit now while the key is open, else at the next sign-in in this process."""
    with _lock:
        if datakey.is_open() and not _opening:     # (a sign-in still opening may yet be closed again)
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


def _unlock(check, locked_out, wrong):
    """check(user) -> right or not; it may wait minutes on a security key's touch, so it runs without the lock, and the state is
    looked at again once it is back: signed out or refused meanwhile, nothing opens. A key failure raises, still locked."""
    global _state
    with _lock:
        if _state != "locked":
            raise RuntimeError("Toner isn't locked.")
        if _refused:
            raise Refused(REFUSED)
        who = _user
    err = right = None
    try:
        right = check(who)
    except locked_out as e:
        err = e
    with _lock:
        if _state != "locked" or _user != who:
            raise RuntimeError("Toner isn't locked.")
        if _refused:
            raise Refused(REFUSED)
        if err is not None:
            audit.log("unlock failed", "too many tries")
            raise err
        if not right:
            audit.log("unlock failed")
            raise wrong()
        audit.log("unlocked")
        _state = "open"
    _notify("open")


def unlock(password, present=None):
    """`present`: fidokey.present, a touch, when the account has security keys (KeyNeeded without it)."""
    _unlock(lambda who: datakey.check_password(who, password, present=present), datakey.Throttled,
            lambda: datakey.WrongPassword(datakey.WRONG))


def unlock_pin(pin, present=None):
    """`present`: fidokey.present, a touch, when the seal holds security keys (KeyNeeded without it)."""
    _unlock(lambda who: datakey.check_pin(who, pin, present=present), pinslot.PinLocked, pinslot.WrongPin)


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

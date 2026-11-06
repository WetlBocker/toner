"""A directory account's sign-in, one step at a time, for the sign-in window, the lock screen and the command line to drive:

    begin           the password, bound at the directory (offline within the hour of the last good check: straight to the PIN)
    after_password  Duo's preauth, when the directory has Duo on
    duo_push/code   Duo's second step
    choose_pin      a new PIN slot: a first sign-in, "Forgot your PIN?" (restart_pin), or a computer without the slot's key
    approve         an Admin, or the recovery key, approves at this computer
    finish          the PIN signs in

Wrong directory passwords count on netcheck.keys' shared counter, as local passwords do. No password, PIN or Duo code is kept on
an Attempt, logged or put in a message."""
import time

from core import audit, datakey, db, directory, duo, perms, pinslot, roles, session

OFFLINE_SECONDS = 3600
UNREACHABLE = "Toner can't reach the directory. Connect to the network, then try again."
DUO_DOWN = "Toner can't reach Duo, so you can't sign in right now. Try again in a minute."
DUO_DENIED = "Duo didn't approve the sign-in."
WRONG_CODE = "That code isn't right."
NOT_IN_GROUP = "Your account isn't in a Toner group. Ask an admin."
CANNOT_APPROVE = "That account can't approve sign-ins."
FIRST = "This is your first sign-in to this copy of Toner. Ask an admin to sign in here to approve it."
CHANGED = "Your access changed. Ask an admin to sign in here to approve it."


class NotInGroup(Exception):
    pass


class CannotApprove(Exception):
    pass


class Attempt:
    """One sign-in. stage: "password" (checked, call after_password), "duo", "choose-pin", "approve", "pin" or "done"."""

    def __init__(self, cfg, login):
        self.cfg, self.login = cfg, login
        self.user = None            # the directory's User; None offline
        self.name = None            # the account's name in netcheck.keys
        self.stage = "password"
        self.offline = False
        self.fresh = False          # the password (and Duo, when on) checked online in this attempt
        self.message = None         # the approval page's text
        self.slot = None            # a new PIN slot waiting for its approval
        self.reset = False          # "Forgot your PIN?"


def _directories():
    try:
        return datakey.read().get("directories") or []
    except FileNotFoundError:
        return []


def classify(login):
    """("directory", cfg, login) for DOMAIN\\user with a directory's NetBIOS name or user@suffix with a suffix a directory lists;
    else ("local", login). Read from netcheck.keys without the data key."""
    login = (login or "").strip()
    cfg = None
    if "\\" in login:
        dom = login.split("\\", 1)[0].casefold()
        cfg = next((d for d in _directories() if dom and str(d.get("netbios") or "").casefold() == dom), None)
    elif "@" in login:
        suffix = login.split("@", 1)[1].casefold()
        cfg = next((d for d in _directories() if suffix in [str(s).casefold() for s in d.get("suffixes") or []]), None)
    return ("directory", cfg, login) if cfg else ("local", login)


def _expect(a, stage):
    if a.stage != stage:
        raise RuntimeError(f"this sign-in is at {a.stage}, not {stage}")


def _tries(failed=False):
    """netcheck.keys' shared password counter: Throttled while a wait runs; `failed` counts one (Throttled past the free ones)."""
    with datakey._lock, datakey._FileLock():
        doc = datakey._read()
        counter = doc.setdefault("throttle", {"fails": 0, "until": 0})
        now = time.time()
        datakey._gate(doc, counter, now)
        if failed:
            datakey._failed(doc, counter, now)


def _mine(a):
    """The account's record when it is this person's (this directory, this guid), else None."""
    rec = datakey.directory_account(a.name)
    return rec if rec and rec.get("directory") == a.cfg["id"] and rec.get("guid") == a.user.guid else None


def _offline(a):
    """The directory can't be reached: the PIN alone, within the hour of the last good check of a sealed account."""
    who, short = directory._split_login(a.cfg, a.login)
    if a.cfg["kind"] == "ad":
        name = who.lower()                                  # the UPN the directory would have named the account by
    else:
        first = (a.cfg.get("suffixes") or [""])[0]
        name = f"{short.lower()}@{first}" if first else short.lower()
    rec = datakey.directory_account(name)
    if not (rec and rec.get("directory") == a.cfg["id"] and rec.get("sealed")
            and time.time() - rec["online_at"] <= OFFLINE_SECONDS):
        raise directory.Unreachable(UNREACHABLE)
    a.name, a.offline, a.stage = name, True, "pin"
    return a


def begin(login, password):
    kind = classify(login)
    if kind[0] != "directory":
        raise ValueError("not a directory account")
    a = Attempt(kind[1], kind[2])
    _tries()
    try:
        user = directory.sign_in(a.cfg, a.login, password)
    except directory.Unreachable:
        return _offline(a)
    except directory.BadCredentials:
        user = None
    if user is None or not user.enabled:
        _tries(failed=True)
        raise datakey.WrongPassword(datakey.WRONG)
    role = directory.role_for(a.cfg, user.groups)
    if role is None:
        _tries(failed=True)
        raise NotInGroup(NOT_IN_GROUP)
    a.user, a.name = user, user.name
    if _mine(a):
        datakey.set_groups_role(a.name, role)
    return a


def _onward(a):
    """The password, and Duo when on, passed online: a new offline hour starts (not before Duo, or the password alone would
    open the way to an offline PIN sign-in)."""
    a.fresh = True
    rec = _mine(a)
    if rec:
        datakey.set_online(a.name, time.time())
    if rec and rec.get("sealed"):
        a.stage = "pin"
    else:
        a.stage, a.message = "choose-pin", FIRST


def _denied(a):
    session.audit_soon("Duo denied a sign-in", a.user.name, who=a.user.name)


def after_password(a):
    _expect(a, "password")
    if not (a.cfg.get("duo") or {}).get("on"):
        return _onward(a)
    try:
        r = duo.preauth(a.cfg, a.user.name)
    except duo.Unavailable:
        raise duo.Unavailable(DUO_DOWN) from None
    if r in ("deny", "enroll"):
        _denied(a)
        raise duo.Denied(DUO_DENIED)
    if r == "allow":                                        # Duo's bypass, set by its admin
        return _onward(a)
    a.stage = "duo"


def duo_push(a, cancel):
    _expect(a, "duo")
    try:
        duo.push(a.cfg, a.user.name, cancel)
    except duo.Unavailable:
        raise duo.Unavailable(DUO_DOWN) from None
    except duo.Denied:
        if not cancel.is_set():                             # (cancelled: the person chose a code instead)
            _denied(a)
        raise duo.Denied(DUO_DENIED) from None
    _onward(a)


def duo_code(a, code):
    _expect(a, "duo")
    try:
        duo.passcode(a.cfg, a.user.name, code)
    except duo.Unavailable:
        raise duo.Unavailable(DUO_DOWN) from None
    except duo.Denied:
        _denied(a)
        raise duo.Denied(WRONG_CODE) from None
    _onward(a)


def choose_pin(a, pin):
    """A new slot. A first sign-in writes the unapproved account with it; an approved account keeps its old slot until the
    approval re-seals under the new one."""
    _expect(a, "choose-pin")
    slot = pinslot.new(pinslot.best_kind(), datakey.new_slot_id(), pin)
    rec = _mine(a)
    if not (rec and rec.get("sealed")):
        try:
            datakey.start_directory_account(a.user, a.cfg["id"], slot)
        except BaseException:
            pinslot.remove(slot.rec, slot.slot_id)
            raise
    a.slot, a.stage = slot, "approve"


def approve(a, admin_name, admin_password):
    _approve(a, lambda: datakey.open_with_password(admin_name, admin_password))


def approve_recovery(a, recovery):
    _approve(a, lambda: datakey.open_with_recovery(recovery))


def _approve(a, opener):
    """Open the key as the approver with no session change, approve, then put back whatever was open before (a signed-in
    session keeps its keys) or close it all."""
    _expect(a, "approve")
    with session._lock:
        held = (datakey._key + datakey._box, datakey._name) if datakey.is_open() else None
        try:
            opener()
            roles.unlock()
            try:
                roles.approve(a.name, a.slot)
            except perms.Denied:
                raise CannotApprove(CANNOT_APPROVE) from None
            except ValueError:
                if a.slot is None:
                    raise
                a.stage, a.slot = "choose-pin", None        # the started box key isn't held any more: choose the PIN again
                return
            if a.slot is not None:
                audit.log("PIN reset" if a.reset else "PIN set", a.name, who=a.name)
        finally:
            roles.close()
            if held:
                datakey._open(*held)
                roles.unlock()
            else:
                db.release()
                datakey.close()
    a.slot, a.stage = None, "pin"


def finish(a, pin):
    _expect(a, "pin")
    if roles.needs_approval(a.name) == "changed":
        a.stage, a.message = "approve", CHANGED
        return
    try:
        session.sign_in_pin(a.name, pin)
    except pinslot.SlotMissing:
        if not a.fresh:                                     # a new PIN needs the password checked online
            raise directory.Unreachable(UNREACHABLE) from None
        a.stage, a.message = "choose-pin", CHANGED
        return
    a.stage = "done"


def restart_pin(a):
    """"Forgot your PIN?": only after the password (and Duo) were checked online in this attempt. The old slot stays until the
    approval of the new one lands (roles.approve removes it)."""
    _expect(a, "pin")
    if not a.fresh:
        raise RuntimeError("a new PIN needs the password checked online first")
    a.reset, a.stage, a.message = True, "choose-pin", CHANGED

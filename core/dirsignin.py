"""A directory account's sign-in, one step at a time, for the sign-in window, the lock screen and the command line to drive:

    begin           the password, bound at the directory (offline within the hour of the last good check: straight to the PIN)
    after_password  Duo's preauth, when the directory has Duo on
    duo_push/code   Duo's second step
    choose_pin      a new PIN slot: a first sign-in, "Forgot your PIN?" (restart_pin), or a computer without the slot's key
    approve         an Admin, or the recovery key, approves at this computer
    finish          the PIN signs in

An SSO connection (kind "oidc") has sso_start and sso_wait (the browser) in place of begin and the Duo steps.

Wrong directory passwords count on netcheck.keys' shared counter, as local passwords do. No password, PIN or Duo code is kept on
an Attempt, logged or put in a message; an SSO attempt's tokens stay on it, and only the refresh token is kept (in the vault)."""
import getpass
import threading
import time
import webbrowser

from core import audit, datakey, db, directory, dirpin, duo, oidc, passvault, perms, pinslot, quiet, roles, session

OFFLINE_SECONDS = 3600
UNREACHABLE = "Toner can't reach the directory. Connect to the network, then try again."
DUO_DOWN = "Toner can't reach Duo, so you can't sign in right now. Try again in a minute."
DUO_DENIED = "Duo didn't approve the sign-in."
WRONG_CODE = "That code isn't right."
NOT_IN_GROUP = "Your account isn't in a Toner group. Ask an admin."
CANNOT_APPROVE = "That account can't approve sign-ins."
FIRST = "This is your first sign-in to this copy of Toner. Ask an admin to sign in here to approve it."
CHANGED = "Your access changed. Ask an admin to sign in here to approve it."
PAUSED = "Directory sign-in is paused on this computer. An admin needs to sign in first."
CA_CHANGED = "The directory's CA file changed. An admin needs to save the directory again."
NAME_TAKEN = "That name already belongs to another account on this copy. Ask an admin."     # Choose a PIN only
TEST_OK = "Signed in as {name}. Role: {role}. Signed out."                                  # Test login only
TEST_NOT_MAPPED = "{name} isn't in an OU or group that Toner maps to a role."
SSO_CANCELLED = "The sign-in didn't finish in the browser."                                 # {provider}: the connection's name
SSO_NOT_FRESH = "{provider} didn't confirm a fresh sign-in. Try again."
SSO_BAD_ANSWER = "{provider}'s answer couldn't be checked, so the sign-in was refused."
SSO_UNREACHABLE = "{provider} can't be reached, and this account hasn't been checked online in the last hour."


def _windows_user():
    try:
        return getpass.getuser()
    except Exception:                                   # no user name in the environment or the system
        return ""


RECOVERY_APPROVER = f"recovery key ({_windows_user()})"   # {admin} in "sign-in approved" for the recovery key

_steps = threading.Lock()       # a push finishing on a worker thread vs. the person moving on (a code, Forgot your PIN?)


class NotInGroup(Exception):
    pass


class CannotApprove(Exception):
    pass


class Paused(Exception):
    """The directories list isn't the one this computer last saw verified (core/dirpin.py)."""


class CaChanged(Exception):
    """The directory's CA file isn't the one signed into the list: an admin needs to save the directory again."""


class Attempt:
    """One sign-in. stage: "password" (checked, call after_password), "browser" (SSO: call sso_wait), "duo", "choose-pin",
    "approve", "pin" or "done"."""

    def __init__(self, cfg, login):
        self.cfg, self.login = cfg, login
        self.user = None            # the directory's User; None offline
        self.role = None            # the role its groups give now; None offline
        self.name = None            # the account's name in netcheck.keys
        self.stage = "password"
        self.offline = False
        self.fresh = False          # the password (and Duo, when on) checked online in this attempt
        self.message = None         # the approval page's text
        self.slot = None            # a new PIN slot waiting for its approval
        self.reset = False          # "Forgot your PIN?"
        self.kind = None            # the PIN slot kind once the chip refused a new key (pin_kind)
        self.browser = None         # SSO: the oidc.BrowserSignIn
        self.tokens = None          # SSO: the oidc.Tokens once the browser sign-in is checked


def _keys_doc():
    try:
        return datakey.read()
    except FileNotFoundError:
        return {}


def classify(login):
    """("directory", cfg, login) for DOMAIN\\user with a directory's NetBIOS name or user@suffix with a suffix a directory lists;
    else ("local", login). Read from netcheck.keys without the data key, so a match needs the list this computer remembers
    (Paused otherwise). A local account with exactly that name (in any case, as datakey matches names) stays local."""
    login = (login or "").strip()
    doc, cfg = _keys_doc(), None
    accounts = doc.get("accounts") or {}
    local = datakey._find(doc, login) if login and accounts else None
    if local is not None and accounts[local].get("kind") != "directory":
        return "local", login
    dirs = doc.get("directories") or []
    if "\\" in login:
        dom = login.split("\\", 1)[0].casefold()
        cfg = next((d for d in dirs if dom and str(d.get("netbios") or "").casefold() == dom), None)
    elif "@" in login:
        suffix = login.split("@", 1)[1].casefold()
        cfg = next((d for d in dirs if suffix in [str(s).casefold() for s in d.get("suffixes") or []]), None)
    if cfg is None:
        return "local", login
    if dirpin.changed(dirs):
        raise Paused(PAUSED)
    return "directory", cfg, login


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


def _clear_tries():
    """After a full online check: the shared counter back to 0. Returns the count it had."""
    with datakey._lock, datakey._FileLock():
        doc = datakey._read()
        counter = doc.setdefault("throttle", {"fails": 0, "until": 0})
        fails = counter.get("fails", 0)
        if fails or counter.get("until"):
            counter["fails"], counter["until"] = 0, 0
            datakey._write(doc)
        return fails


def _mine(a):
    """The account's record when it is this person's (this directory, this guid), else None."""
    rec = datakey.directory_account(a.name)
    return rec if rec and rec.get("directory") == a.cfg["id"] and rec.get("guid") == a.user.guid else None


def _offline(a):
    """The directory can't be reached: the PIN alone, within the hour of the last good check of a sealed account."""
    who, short = directory._split_login(a.cfg, a.login)
    if a.cfg["kind"] in ("ad", "oidc") and "@" in who:
        name = who.lower()                                  # the UPN the directory would have named the account by
    else:                                                   # (DOMAIN\user: its UPN prefix taken to be the user name)
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
    except directory.CaChanged:
        raise CaChanged(CA_CHANGED) from None
    except directory.BadCredentials:
        user = None
    if user is None or not user.enabled:
        _tries(failed=True)
        raise datakey.WrongPassword(datakey.WRONG)
    role = directory.role_for(a.cfg, user.groups, user.dn)
    if role is None:
        _tries(failed=True)
        raise NotInGroup(NOT_IN_GROUP)
    a.user, a.name, a.role = user, user.name, role
    return a


def _onward(a, stage):
    """The password, and Duo when on, passed online: the full check. Only now are the offline hour, the groups' role and the
    shared counter written (the password alone must not open the way to an offline PIN sign-in). Does nothing when the attempt
    has moved on from that stage meanwhile (a push that ends after a code was entered)."""
    with _steps:
        if a.stage != stage:
            return
        a.fresh = True
        rec = _mine(a)
        if rec:
            now = time.time()
            datakey.set_online(a.name, now)
            datakey.set_full(a.name, now)
            datakey.set_groups_role(a.name, a.role)
        fails = _clear_tries()
        if fails:                                           # as a local sign-in audits them (the row waits for the key)
            session.audit_soon(f"{fails} failed sign-in attempts since the last sign-in", who=a.user.name)
        if rec and rec.get("sealed"):
            a.stage = "pin"
        else:
            a.stage, a.message = "choose-pin", FIRST


def _denied(a):
    session.audit_soon("Duo denied a sign-in", a.user.name, who=a.user.name)


def after_password(a):
    _expect(a, "password")
    if not (a.cfg.get("duo") or {}).get("on"):
        return _onward(a, "password")
    try:
        r = duo.preauth(a.cfg, a.user.name)
    except duo.Unavailable:
        raise duo.Unavailable(DUO_DOWN) from None
    if r in ("deny", "enroll"):
        _denied(a)
        raise duo.Denied(DUO_DENIED)
    if r == "allow":                                        # Duo's bypass, set by its admin
        return _onward(a, "password")
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
    _onward(a, "duo")


def duo_code(a, code):
    _expect(a, "duo")
    try:
        duo.passcode(a.cfg, a.user.name, code)
    except duo.Unavailable:
        raise duo.Unavailable(DUO_DOWN) from None
    except duo.Denied:
        _denied(a)
        raise duo.Denied(WRONG_CODE) from None
    _onward(a, "duo")


def _discover_now(cfg):
    """The provider's discovery read now, not from the hour's cache, so a provider that went down is seen as down."""
    with oidc._lock:
        oidc._meta_cache.pop(cfg["issuer"], None)
    return oidc.discover(cfg["issuer"])


def reachable(cfg):
    """True when the directory (or the SSO provider) answers now. Sends no credential."""
    if cfg.get("kind") != "oidc":
        return directory.reachable(cfg)
    try:
        _discover_now(cfg)
    except oidc.OidcError:
        return False
    return True


def sso_start(cfg, login, open_url=webbrowser.open, nonce=None):
    """An SSO sign-in: the provider's page opens in the browser (stage "browser"; sso_wait next). A provider that can't be
    reached takes the offline hour, as begin does."""
    a = Attempt(cfg, login)
    _tries()
    try:
        _discover_now(cfg)
        a.browser = oidc.BrowserSignIn(cfg, nonce=nonce, open_url=open_url, login_hint=login)
    except oidc.Unreachable:
        return _offline(a)
    try:
        a.browser.open()
    except BaseException:
        a.browser.close()                                   # the loopback port goes with it
        raise
    a.stage = "browser"
    return a


def sso_wait(a, cancel):
    """Waits for the browser (`cancel` set: Cancelled within a second), then checks the answer and the groups' role. The
    oidc errors keep their internal text (the provider's host): callers show the SSO_* sentences instead."""
    _expect(a, "browser")
    try:
        tokens = a.browser.run(cancel)
        user = oidc.user_from(a.cfg, tokens.claims, oidc.groups(a.cfg, tokens.claims, tokens.access_token))
    except oidc.Unreachable:
        return _offline(a)
    except (oidc.Refused, oidc.BadAnswer, oidc.NotFresh, oidc.Cancelled, KeyError) as e:
        _tries(failed=True)
        if isinstance(e, KeyError):                         # the ID token names no one (no sub, or no id_claim)
            raise oidc.BadAnswer(f"{oidc.host_of(a.cfg['issuer'])}'s answer names no one") from None
        raise
    role = directory.role_for(a.cfg, user.groups)
    if role is None:
        _tries(failed=True)
        raise NotInGroup(NOT_IN_GROUP)
    a.user, a.name, a.role, a.tokens = user, user.name, role, tokens
    _onward(a, "browser")


class TestLogin:
    """Test login: an Admin checks one directory user's password and Duo. begin's and the Duo steps' checks, with nothing kept:
    no data key, PIN slot, account record or session, no write to the account, and a pass never clears the shared counter.
    cfg comes from roles.verified(). stage: "password", "duo" or "done"; result is the sentence shown once done. Each finished
    test writes one "test login" audit row; a push cancelled for a code writes none."""

    def __init__(self, cfg):
        self.cfg, self.stage, self.result = cfg, "password", None
        self.name = self.role = None

    def check_password(self, login, password):
        failed = user = None
        try:
            _expect(self, "password")
            if not perms.is_admin():
                raise perms.Denied()
            _tries()                                        # a wait running: Throttled, before any bind
            try:
                user = directory.sign_in(self.cfg, login, password)
            except (directory.BadCredentials, directory.Unreachable, directory.CaChanged) as e:
                failed = type(e)                            # raised below, outside this block: nothing chains to sign_in's frame
        finally:
            del password
        if failed is directory.Unreachable:                 # no offline path: a test needs the directory
            self._fail("password", login, directory.Unreachable(UNREACHABLE))
        if failed is directory.CaChanged:
            self._fail("password", login, CaChanged(CA_CHANGED))
        if user is None or not user.enabled:
            self._fail("password", login, datakey.WrongPassword(datakey.WRONG), count=True)
        role = directory.role_for(self.cfg, user.groups, user.dn)
        if role is None:                                    # counted, as begin counts it
            self._fail("password", user.name, NotInGroup(TEST_NOT_MAPPED.format(name=user.name)), count=True)
        self.name, self.role = user.name, role
        if not (self.cfg.get("duo") or {}).get("on"):
            return self._passed("password")
        try:
            r = duo.preauth(self.cfg, self.name)
        except duo.Unavailable:
            self._fail("password", self.name, duo.Unavailable(DUO_DOWN))
        if r in ("deny", "enroll"):
            self._fail("password", self.name, duo.Denied(DUO_DENIED))
        if r == "allow":                                    # Duo's bypass, set by its admin
            return self._passed("password")
        self.stage = "duo"

    def duo_push(self, cancel):
        _expect(self, "duo")
        try:
            duo.push(self.cfg, self.name, cancel)
        except duo.Unavailable:
            if cancel.is_set():                             # the Admin chose a code instead: the test goes on
                raise duo.Unavailable(DUO_DOWN) from None
            self._fail("duo", self.name, duo.Unavailable(DUO_DOWN))
        except duo.Denied:
            if cancel.is_set():
                raise duo.Denied(DUO_DENIED) from None
            self._fail("duo", self.name, duo.Denied(DUO_DENIED))
        self._passed("duo")

    def duo_code(self, code):
        _expect(self, "duo")
        try:
            duo.passcode(self.cfg, self.name, code)
        except duo.Unavailable:
            self._fail("duo", self.name, duo.Unavailable(DUO_DOWN))
        except duo.Denied:
            self._fail("duo", self.name, duo.Denied(WRONG_CODE))
        self._passed("duo")

    def _passed(self, stage):
        self._end(stage, self.name, TEST_OK.format(name=self.name, role=self.role))

    def _fail(self, stage, name, exc, count=False):
        """Ends the test from `stage` with exc's sentence, then raises exc (also when the test had already ended)."""
        if count:
            try:
                _tries(failed=True)
            except datakey.Throttled as e:                  # past the free tries the wait is what the window shows
                exc = e
        self._end(stage, name, str(exc))
        raise exc from None

    def _end(self, stage, name, sentence):
        """Done, audited once; nothing when the test already ended meanwhile (a push that ends after a code)."""
        with _steps:
            if self.stage != stage:
                return
            self.stage, self.result = "done", sentence
        name = "".join(ch for ch in str(name) if ch >= " " and ch != chr(127))[:256]    # a typed login: one plain line
        audit.log("test login", f"{name}, {sentence}")


def pin_kind(a):
    """The kind of PIN choose_pin makes, so the page asks for the right one: the strongest here, except the chip when it
    refused a new key or when one more wrong PIN could lock it (Windows' lockout lasts hours); then the store or the PIN alone."""
    if a.kind is not None:
        return a.kind
    kind = pinslot.best_kind()
    return pinslot.fallback_kind() if kind == "chip" and pinslot.chip_wait() else kind


def choose_pin(a, pin):
    """A new slot. A first sign-in writes the unapproved account with it; an approved account keeps its old slot until the
    approval re-seals under the new one."""
    _expect(a, "choose-pin")
    kind = pin_kind(a)
    try:
        slot = pinslot.new(kind, datakey.new_slot_id(), pin)
    except pinslot.PinLocked:
        if kind != "chip":
            raise
        a.kind = pinslot.fallback_kind()                    # the chip is locked out: its 6-digit PIN won't do for the next kind
        slot = pinslot.new(a.kind, datakey.new_slot_id(), pin)
    rec = _mine(a)
    if not (rec and rec.get("sealed")):
        try:
            datakey.start_directory_account(a.user, a.cfg["id"], slot)
        except BaseException:
            _drop(slot)
            raise
    a.slot, a.stage = slot, "approve"


def _drop(slot):
    """A slot that will never be sealed: its TPM key or pepper goes from this computer."""
    try:
        pinslot.remove(slot.rec, slot.slot_id)
    except Exception:
        quiet.ignored()


def approve(a, admin_name, admin_password):
    _approve(a, lambda: datakey.open_with_password(admin_name, admin_password))


def approve_recovery(a, recovery):
    _approve(a, lambda: datakey.open_with_recovery(recovery))


def _approve(a, opener):
    """Open the key as the approver with no session change, approve, then put back whatever was open before (a signed-in
    session keeps its keys) or close it all. A cleanup failure never hides the approval's own error."""
    _expect(a, "approve")
    with session._lock:
        held = (datakey._key + datakey._box, datakey._name) if datakey.is_open() else None
        try:
            _approve_as(a, opener)
        except BaseException:
            try:
                _put_back(held)
            except Exception:
                quiet.ignored()
            raise
        _put_back(held)


def _approve_as(a, opener):
    fails = opener()
    by = datakey.signed_in_name() or RECOVERY_APPROVER
    roles.unlock()
    if fails:                                               # counted in netcheck.keys; audited while the key is open
        audit.log(f"{fails} failed sign-in attempts since the last sign-in", who=by)
    try:
        roles.approve(a.name, a.slot, approved_by=by)
    except perms.Denied:
        raise CannotApprove(CANNOT_APPROVE) from None
    except roles.NotHeld:                                   # Toner restarted since the PIN was chosen: choose it again
        _drop(a.slot)
        a.stage, a.slot = "choose-pin", None
        return
    if a.slot is not None:
        audit.log("PIN reset" if a.reset else "PIN set", a.name, who=a.name)
    a.slot, a.stage = None, "pin"


def _put_back(held):
    try:
        roles.close()
    finally:
        if held:
            datakey._open(*held)
            roles.unlock()
        else:
            try:
                db.release()
            finally:
                datakey.close()


def finish(a, pin):
    _expect(a, "pin")
    try:
        if not a.offline and roles.needs_approval(a.name) == "changed":
            if not datakey.check_pin(a.name, pin):          # the PIN first (counted), so a wrong one never reaches approval
                raise pinslot.WrongPin()
            a.stage, a.message = "approve", CHANGED
            return
        session.sign_in_pin(a.name, pin)                    # offline, "changed" signs in with the keys it already has
    except pinslot.SlotMissing:
        if not a.fresh:                                     # a new PIN needs the password checked online
            raise directory.Unreachable(UNREACHABLE) from None
        a.stage, a.message = "choose-pin", CHANGED
        return
    if a.tokens and a.tokens.refresh_token:                 # SSO: the background re-check's refresh token, once the vault is open
        passvault.put(f"sso-refresh:{a.name}", a.tokens.refresh_token)
    a.stage = "done"


def restart_pin(a):
    """"Forgot your PIN?": only after the password (and Duo) were checked online in this attempt. The old slot stays until the
    approval of the new one lands (roles.approve removes it)."""
    _expect(a, "pin")
    if not a.fresh:
        raise RuntimeError("a new PIN needs the password checked online first")
    a.reset, a.stage, a.message = True, "choose-pin", CHANGED

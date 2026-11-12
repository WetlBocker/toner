"""A directory account's sign-in, one step at a time, for the sign-in window, the lock screen and the command line to drive:

    begin           the password, bound at the directory (offline within the hour of the last good check: straight to the PIN)
    after_password  Duo's preauth, when the directory has Duo on
    duo_push/code   Duo's second step
    choose_pin      a new PIN slot: a first sign-in, "Forgot your PIN?" (restart_pin), or a computer without the slot's key
    approve         an Admin, or the recovery key, approves at this computer (approve_with_account: a directory or SSO Admin)
    finish          the PIN signs in

An SSO connection (kind "oidc") has sso_start and sso_wait (the browser) in place of begin and the Duo steps.

With "Let group members sign in without approval" on (helper_ready), the helper service checks the sign-in itself (the password
and Duo, or the SSO answer with a nonce it issued) and gives a ticket; where an approval would come next, approve_by_helper has
it release the data key for that one approval, credited to HELPER_APPROVER, and the helper signs it (an Admin's ticket releases the
rules key instead). Any helper failure is today's flow.

Wrong directory passwords count on netcheck.keys' shared counter, as local passwords do. No password, PIN or Duo code is kept on
an Attempt, logged or put in a message; an SSO attempt's tokens stay on it, and only the refresh token is kept (in the vault)."""
import base64
import getpass
import threading
import time
import webbrowser

from core import audit, datakey, db, directory, dirpin, duo, helperclient, oidc, passvault, perms, pinslot, quiet, roles, session

OFFLINE_SECONDS = 3600
UNREACHABLE = "Toner can't reach the directory. Connect to the network, then try again."
DUO_DOWN = "Toner can't reach Duo, so you can't sign in right now. Try again in a minute."
DUO_DENIED = "Duo didn't approve the sign-in."
WRONG_CODE = "That code isn't right."
NOT_IN_GROUP = "Your account isn't in a Toner group. Ask an admin."
CANNOT_APPROVE = "That account can't approve sign-ins."
NOT_HERE_BEFORE = "That account hasn't signed in on this computer before, so it can't approve here."
FIRST = "This is your first sign-in to this copy of Toner. Ask an admin to sign in here to approve it."
CHANGED = "Your access changed. Ask an admin to sign in here to approve it."
HELPER_DOWN = "Toner's helper service isn't running, so an admin has to approve this one."     # after FIRST or CHANGED
PAUSED = "Directory sign-in is paused on this computer. An admin needs to sign in first."
CA_CHANGED = "The directory's CA file changed. An admin needs to save the directory again."
NAME_TAKEN = "That name already belongs to another account on this copy. Ask an admin."     # Choose a PIN only
TEST_OK = "Signed in as {name}. Role: {role}. Signed out."                                  # Test login only
TEST_NOT_MAPPED = "{name} isn't in an OU or group that Toner maps to a role."
SSO_TEXT = "Sign in on the {provider} page that opened in your browser. Toner carries on when you're done."   # {provider}: the
SSO_CANCELLED = "The sign-in didn't finish in the browser."                                 # connection's name
SSO_DECLINED = "{provider} refused the sign-in."                                            # the person said no at the provider
SSO_NOT_FRESH = "{provider} didn't confirm a fresh sign-in. Try again."
SSO_BAD_ANSWER = "{provider}'s answer couldn't be checked, so the sign-in was refused."
SSO_UNREACHABLE = "{provider} can't be reached, and this account hasn't been checked online in the last hour."
SSO_REFUSED = "{provider} no longer allows this account. Sign in again."                  # the re-check's lock screen
HELPER_APPROVER = "group membership"                                                        # {admin} in "sign-in approved"


def sso_said(cfg, e):
    """The approved sentence for an oidc error (its own text names the provider's host and is never shown)."""
    text = (SSO_CANCELLED if isinstance(e, oidc.Cancelled) else SSO_NOT_FRESH if isinstance(e, oidc.NotFresh) else
            SSO_DECLINED if isinstance(e, oidc.Refused) else SSO_BAD_ANSWER)
    return text.format(provider=cfg["name"])


def refused_text():
    """The lock screen's sentence for a refused account: SSO_REFUSED for an SSO connection's account, else session.REFUSED."""
    last, name = roles.last_signed() or {}, session.user()
    acct = (last.get("accounts") or {}).get(name) or {}
    cfg = next((d for d in last.get("directories") or [] if isinstance(d, dict) and d.get("id") == acct.get("directory")), None)
    return SSO_REFUSED.format(provider=cfg["name"]) if cfg and cfg.get("kind") == "oidc" else session.REFUSED


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
        self.helper = False         # helper_ready() when the attempt began
        self.pending = None         # the helper's pending Duo check (its id)
        self.ticket = None          # the helper's ticket for this sign-in, used up by approve_by_helper
        self.duo_skipped = False    # Duo skipped for the record's key hint: finish proves the seal is keyed, else Duo after all


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
    """The directory can't be reached: the PIN alone, within the hour of the last good check of a sealed account (looked up by
    the attempt's account name when it has one, else by the name the directory would give the typed login)."""
    who, short = directory._split_login(a.cfg, a.login)
    if a.name:
        name = a.name
    elif a.cfg["kind"] in ("ad", "oidc") and "@" in who:
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
    a.helper = helper_ready()
    if a.helper and _check_directory(a, password):
        return a
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


HELPER_OFF = ("off", "portable")     # helperclient.state: this copy is positively not enrolled ("absent": see helper_may_be_on)


def helper_may_be_on():
    """For keys (keys_allowed, roles.set_require_keys): sign-in without approval counts as on unless helperclient.state says
    this copy isn't enrolled ("off", "portable"), or "absent" with the service positively not installed (not_installed).
    Not running (it may be enrolled and come back), other_user (it may be this keys file under another OS user), outdated,
    rules_changed (its spare copy may not be forgotten yet), or unreadable: on. helper_ready is the sign-in's other question."""
    try:
        st = helperclient.state(datakey.path())
        return not helperclient.not_installed() if st == "absent" else st not in HELPER_OFF
    except Exception:
        quiet.ignored()
        return True


def keys_allowed(name):
    """Whether account `name` may have security keys: never an SSO account, nor an AD or LDAP account while sign-in without
    approval may be on (the helper is a way round a key)."""
    rec = datakey.directory_account(name)
    if rec is None:                                     # a local account
        return True
    return not datakey._sso(datakey.read(), rec) and not helper_may_be_on()


class _Unkeyed(Exception):
    """A sign-in that skipped Duo opened a seal without keys."""


def helper_ready():
    """Sign-in without approval is on for this copy: the helper service answers, enrolled by it."""
    try:
        return helperclient.state(datakey.path(), ask_service=False) == "on"
    except Exception:                                   # never in the way of a sign-in
        quiet.ignored()
        return False


def _ask(req, timeout=10, cancel=None):
    """The helper's answer to req for this copy; {} when it can't be asked (NotRunning)."""
    try:
        return helperclient.call({**req, "keys_path": str(datakey.path())}, timeout=timeout, cancel=cancel)
    except helperclient.NotRunning:
        return {}


def _check_directory(a, password):
    """begin's check by the helper: True once it has decided (a.user, a.name, a.role and the ticket, or Duo pending at the
    helper). False when it can't decide: Toner then binds itself with the same password, in this same call, asking nothing new.
    A refused password or no group is the helper's answer, counted as begin counts it (a second bind would count twice at the
    directory); a Duo deny at preauth is too, uncounted and audited as after_password does it. Its answer names no password."""
    ans = _ask({"op": "check_directory", "connection": a.cfg["id"], "login": a.login, "password": password}, timeout=60)
    err = None if ans.get("ok") else ans.get("error")
    if err == "duo_denied":                             # the right password, Duo said no at preauth: as after_password does
        name = str(ans.get("name") or a.login)
        session.audit_soon("Duo denied a sign-in", name, who=name)
        raise duo.Denied(DUO_DENIED)
    if err in ("refused", "not_in_group"):
        _tries(failed=True)
        if err == "refused":
            raise datakey.WrongPassword(datakey.WRONG)
        raise NotInGroup(NOT_IN_GROUP)
    if err is not None or not all(isinstance(ans.get(k), str) for k in ("name", "guid", "display")) \
            or ans.get("role") not in datakey.ROLES or not isinstance(ans.get("ticket") or ans.get("pending"), str):
        return False                                    # not running, no answer, or one it can't stand behind
    a.user = directory.User(guid=ans["guid"], name=ans["name"], display=ans["display"], groups=(), enabled=True)
    a.name, a.role, a.ticket, a.pending = ans["name"], ans["role"], ans.get("ticket"), ans.get("pending")
    return True


def _helper_duo(a, req, cancel, refused):
    """The helper's Duo step for its pending check: its ticket, then onward. False when it can't be asked or answers neither
    yes nor no: the caller takes Duo itself, with no ticket."""
    ans = _ask(req, timeout=duo.PUSH_SECONDS + 3 * duo.REQUEST_TIMEOUT, cancel=cancel)
    if cancel is not None and cancel.is_set():          # the person chose a code instead: the pending check stays for it
        raise duo.Denied(DUO_DENIED)
    err = None if ans.get("ok") else ans.get("error")
    if err == "refused":
        _denied(a)
        raise duo.Denied(refused)
    if err == "unreachable":
        raise duo.Unavailable(DUO_DOWN)
    a.pending = None
    if err is not None or not isinstance(ans.get("ticket"), str):
        return False
    a.ticket = ans["ticket"]
    _onward(a, "duo")
    return True


def _onward(a, stage):
    """The password, and Duo when on, passed online: the full check. Only now are the groups' role and the shared counter
    written, and the offline hour and full_at too, except for an attempt that skipped Duo for a key: finish writes those once
    the key has opened a keyed seal (the password alone must not open the way to an offline PIN sign-in). Does nothing when the
    attempt has moved on from that stage meanwhile (a push that ends after a code was entered)."""
    with _steps:
        if a.stage != stage:
            return
        a.fresh = True
        rec = _mine(a)
        if rec:
            now = time.time()
            if not a.duo_skipped:                           # skipped for a key: written once finish has opened a keyed seal
                datakey.set_online(a.name, now)
                datakey.set_full(a.name, now)
            datakey.set_groups_role(a.name, a.role)
        fails = _clear_tries()
        if fails:                                           # as a local sign-in audits them (the row waits for the key)
            session.audit_soon(f"{fails} failed sign-in attempts since the last sign-in", who=a.user.name)
        if rec and rec.get("sealed") and a.message != CHANGED:
            a.stage = "pin"
        else:                                               # (CHANGED: a new PIN was asked for before Duo, _duo_first)
            a.stage, a.message = "choose-pin", a.message or FIRST


def _denied(a):
    session.audit_soon("Duo denied a sign-in", a.user.name, who=a.user.name)


def after_password(a):
    _expect(a, "password")
    if a.pending:                                       # the helper's Duo check
        a.stage = "duo"
        return
    if a.ticket or not (a.cfg.get("duo") or {}).get("on"):     # a ticket: the helper checked Duo (or it was bypassed)
        return _onward(a, "password")
    rec = _mine(a)
    if a.cfg.get("kind") != "oidc" and rec and rec.get("sealed") and datakey.has_keys(a.name):
        a.duo_skipped = True                                # the key is the second step (a hint only: finish proves it)
        return _onward(a, "password")
    _duo(a)


def _duo(a):
    """Duo's preauth for an attempt at "password": stage "duo", or onward on Duo's bypass."""
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


def _duo_first(a, reset=False, message=None):
    """A skipped Duo is good only for the key proving itself at the PIN: any other way on (a new PIN, an approval) takes Duo
    first, from "pin", and after it arrives where it was going (message CHANGED: choose a PIN; None: the PIN again). Duo refusing
    or down: back at "pin" as it was, still skipped."""
    was = a.reset, a.message
    a.duo_skipped, a.stage, a.reset, a.message = False, "password", reset, message
    try:
        _duo(a)
    except BaseException:
        a.duo_skipped, a.stage, (a.reset, a.message) = True, "pin", was
        raise


def duo_push(a, cancel):
    _expect(a, "duo")
    if a.pending and _helper_duo(a, {"op": "duo_push", "pending": a.pending}, cancel, DUO_DENIED):
        return
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
    if a.pending and _helper_duo(a, {"op": "duo_code", "pending": a.pending, "code": code}, None, WRONG_CODE):
        return
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
    a.helper = nonce is None and helper_ready()
    if a.helper:                                        # the helper checks only a sign-in with a nonce it issued
        ans = _ask({"op": "nonce", "connection": cfg["id"]})
        nonce = ans.get("nonce") if ans.get("ok") and isinstance(ans.get("nonce"), str) else None
        a.helper = nonce is not None
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
    if a.helper:
        _check_sso(a)
    _onward(a, "browser")


def _check_sso(a):
    """The helper checks the same sign-in: a ticket only when its answer is the same person (by guid, never by the editable
    name alone) with the same role as Toner's own check. Anything else: no ticket, and an admin approves as today."""
    ans = _ask({"op": "check_sso", "connection": a.cfg["id"], "id_token": a.tokens.id_token,
                "access_token": a.tokens.access_token or ""}, timeout=30)
    if ans.get("ok") and isinstance(ans.get("ticket"), str) and \
            (ans.get("name"), ans.get("guid"), ans.get("role")) == (a.name, a.user.guid, a.role):
        a.ticket = ans["ticket"]


class TestLogin:
    """Test login: an Admin checks one directory user's password and Duo. begin's and the Duo steps' checks, with nothing kept:
    no data key, PIN slot, account record or session, no write to the account, and a pass never clears the shared counter.
    cfg comes from roles.verified(); an SSO connection's test is check_sso (the browser) in place of check_password and Duo.
    stage: "password", "duo" or "done"; result is the sentence shown once done. Each finished
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

    def check_sso(self, open_url, cancel):
        """An SSO connection's test, in place of check_password: one browser sign-in, its groups and their role. The tokens go with
        this call. `cancel` set (the dialog closed): no audit row and nothing counted. The oidc errors carry the SSO_* sentences."""
        _expect(self, "password")
        if not perms.is_admin():
            raise perms.Denied()
        _tries()
        provider, user, browser = self.cfg["name"], None, None
        try:
            _discover_now(self.cfg)                         # a provider that went down is seen as down, not waited on
            browser = oidc.BrowserSignIn(self.cfg, open_url=open_url, scopes="openid profile email")     # no refresh token asked for
            browser.open()
            tokens = browser.run(cancel)
            user = oidc.user_from(self.cfg, tokens.claims, oidc.groups(self.cfg, tokens.claims, tokens.access_token))
        except oidc.Unreachable:
            failed = directory.Unreachable(UNREACHABLE)
        except oidc.Cancelled:
            if cancel.is_set():
                raise
            failed = oidc.Cancelled(SSO_CANCELLED)
        except oidc.NotFresh:
            failed = oidc.NotFresh(SSO_NOT_FRESH.format(provider=provider))
        except oidc.Refused:
            failed = oidc.Refused(SSO_DECLINED.format(provider=provider))
        except (oidc.OidcError, KeyError):                  # KeyError: the ID token names no one
            failed = oidc.BadAnswer(SSO_BAD_ANSWER.format(provider=provider))
        finally:
            if browser is not None:
                browser.close()
        if user is None:
            self._fail("password", provider, failed, count=not isinstance(failed, directory.Unreachable))
        role = directory.role_for(self.cfg, user.groups)
        if role is None:
            self._fail("password", user.name, NotInGroup(TEST_NOT_MAPPED.format(name=user.name)), count=True)
        self.name, self.role = user.name, role
        self._passed("password")

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
            datakey.start_directory_account(a.user, a.cfg["id"], slot, a.role)
        except BaseException:
            _drop(slot)
            raise
    a.slot, a.stage = slot, "approve"
    if a.ticket:
        approve_by_helper(a)
    _why_admin(a)


def _why_admin(a):
    """On the approval page: HELPER_DOWN after its text when sign-in without approval would have done it but the helper
    service doesn't answer (installed, not running)."""
    if a.stage != "approve" or HELPER_DOWN in (a.message or ""):
        return
    try:
        down = helperclient.state(datakey.path()) == "not_running"
    except Exception:                                   # never in the way of a sign-in
        quiet.ignored()
        return
    if down:
        a.message = f"{a.message} {HELPER_DOWN}"


def _drop(slot):
    """A slot that will never be sealed: its TPM key or pepper goes from this computer."""
    try:
        pinslot.remove(slot.rec, slot.slot_id)
    except Exception:
        quiet.ignored()


def approve(a, admin_name, admin_password, key=None):
    """`key`: fidokey.value, asked when the admin's account has security keys (before session's lock is taken)."""
    _approve(a, lambda proof: datakey.open_proof(proof, admin_name),
             prove=lambda: datakey.prove_password(admin_name, admin_password, key=key))


def approve_recovery(a, recovery):
    _approve(a, lambda: datakey.open_with_recovery(recovery))


def approve_with_account(a, approver, pin, key=None):
    """A directory or SSO Admin approves with their own sign-in (an Attempt at its PIN, checked online just now) and their Toner
    PIN on this computer (and `key`, fidokey.value, when their seal holds security keys). Their session is never opened; the
    audit credits them by name. An approver whose sign-in skipped Duo for a key their seal turns out not to hold can't approve.
    The PIN and the key are asked before session's lock is taken; these checks are made again under it."""
    name = approver.name

    def ready():
        if approver.name != name or str(name or "").casefold() == str(a.name or "").casefold():
            raise CannotApprove(CANNOT_APPROVE)
        rec = datakey.directory_account(name) if name else None
        if not (rec and rec.get("sealed")):
            raise CannotApprove(NOT_HERE_BEFORE)
        if approver.stage != "pin" or not approver.fresh or approver.role != "Admin":     # the role from this sign-in's groups
            raise CannotApprove(CANNOT_APPROVE)
    ready()

    def prove():
        try:
            return datakey.prove_pin(name, pin, key=key)
        except pinslot.SlotMissing:                         # no PIN slot on this computer: they'd need a new PIN here first
            raise CannotApprove(NOT_HERE_BEFORE) from None

    def opener(proof):
        ready()
        fails = datakey.open_proof(proof, name)
        if approver.duo_skipped and not datakey.my_keys():
            raise CannotApprove(CANNOT_APPROVE)
        return fails
    _approve(a, opener, prove=prove)


def approve_by_helper(a):
    """At the approval (stage "approve"): the helper releases the data key for the attempt's ticket, and Toner approves as
    HELPER_APPROVER. For an Admin's ticket it releases the rules key too; for anyone else's it signs that one approval itself
    (sign_approval), so the rules key never reaches this process. The keys live only inside this approval; _put_back lets go of
    them. Any helper error, or a ticket for another role than this sign-in's: no keys, and the approval page stays, as today."""
    ticket, a.ticket = a.ticket, None
    ans = _ask({"op": "release", "ticket": ticket, "name": a.name})
    if not ans.get("ok") or ans.get("role") != a.role:
        return
    admin = a.role == "Admin"

    def opener():
        datakey.open_with_keys(base64.b64decode(str(ans.get("data_key")), validate=True))
        db._forget_settings()
        db.get_setting("rules_key")                     # one read: a data key that isn't this copy's fails here, before any write
        roles.close()                                   # nothing of a session open before: only the helper's rules key, if any
        if admin:
            roles.hold("rules", base64.b64decode(str(ans.get("rules_private")), validate=True))
        return 0

    def signer(payload):
        got = _ask({"op": "sign_approval", "ticket": ticket, "name": a.name, "signed": payload.decode("utf-8")})
        if not got.get("ok"):
            raise ValueError("the helper didn't sign the approval")
        return got.get("rules_sig")
    try:
        _approve(a, opener, by=HELPER_APPROVER, signer=None if admin else signer)
    except Exception:                                   # (its message names no key) an admin approves instead
        quiet.ignored()


def _session_now():
    return session.state(), session.user(), datakey._key


def _approve(a, opener, by=None, signer=None, prove=None):
    """Open the key as the approver with no session change, approve, then put back whatever was open before (a signed-in
    session keeps its keys) or close it all. A cleanup failure never hides the approval's own error. `by`: the approver's
    name when no account opens the key (the helper's opener holds its own role key). `prove()`: the approver's password or PIN
    and key (a touch may take minutes), asked before session's lock is taken; `opener(proof)` opens it under the lock, once the
    attempt and the session are found as they were (a sign-in, lock or sign-out meanwhile: RuntimeError, no approval)."""
    _expect(a, "approve")
    slot, name, before = a.slot, a.name, _session_now()
    proof = prove() if prove is not None else None
    try:
        with session._lock:
            _expect(a, "approve")
            if a.slot is not slot or a.name != name:
                raise RuntimeError("this sign-in changed while the approver was asked")
            if session._opening or _session_now() != before:
                raise RuntimeError("the session changed while the approver was asked")
            held = (datakey._key + datakey._box, datakey._name, datakey._keys, datakey._k2, datakey._seen) if datakey.is_open() else None
            try:
                _approve_as(a, opener if prove is None else lambda: opener(proof), by, signer)
            except BaseException:
                try:
                    _put_back(held)
                except Exception:
                    quiet.ignored()
                raise
            _put_back(held)
    finally:
        proof = None                                    # (it holds the data key: not past this call)


def _approve_as(a, opener, by=None, signer=None):
    fails = opener()
    if by is None:
        by = datakey.signed_in_name() or RECOVERY_APPROVER
        roles.unlock()
    if fails:                                               # counted in netcheck.keys; audited while the key is open
        audit.log(f"{fails} failed sign-in attempts since the last sign-in", who=by)
    try:
        roles.approve(a.name, a.slot, approved_by=by, signer=signer)
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


def finish(a, pin, key=None):
    """`key`: fidokey.value, asked when the seal holds security keys. An attempt that skipped Duo for the record's key hint signs
    in only when the seal it opens is keyed (and only then is its full check written); else nothing is signed in, audited or told,
    and it goes to Duo after all. Its other ways on (an approval for a changed role, a new PIN for a missing slot) take Duo first."""
    _expect(a, "pin")

    def keyed():
        if not a.duo_skipped:
            return
        if not datakey.my_keys():
            raise _Unkeyed()
        now = time.time()                                   # the password and the key: the full check
        datakey.set_online(a.name, now)
        datakey.set_full(a.name, now)
    try:
        if not a.offline and roles.needs_approval(a.name) == "changed":
            try:                                            # the PIN first (counted), so a wrong one never reaches approval
                if not datakey.check_pin(a.name, pin):
                    raise pinslot.WrongPin()
            except datakey.KeyNeeded:                       # the PIN is right and the seal is keyed
                pass
            if a.duo_skipped:                               # an approval is no key proving itself: Duo, then the PIN again
                return _duo_first(a)
            a.stage, a.message = "approve", CHANGED
            if a.ticket:
                approve_by_helper(a)                        # approved: on with the PIN just checked
            if a.stage != "pin":
                _why_admin(a)
                return
        session.sign_in_pin(a.name, pin, key=key, opened=keyed)     # offline, "changed" signs in with the keys it already has
    except _Unkeyed:
        return _duo_first(a)
    except pinslot.SlotMissing:
        if not a.fresh:                                     # a new PIN needs the password checked online
            raise directory.Unreachable(UNREACHABLE) from None
        if a.duo_skipped:
            return _duo_first(a, message=CHANGED)
        a.stage, a.message = "choose-pin", CHANGED
        return
    if a.tokens and a.tokens.refresh_token:                 # SSO: the background re-check's refresh token, once the vault is open
        try:
            passvault.put(f"sso-refresh:{a.name}", a.tokens.refresh_token)
        except Exception:                                   # signed in already: the re-check then skips until the next sign-in
            quiet.ignored()
    a.stage = "done"


def restart_pin(a):
    """"Forgot your PIN?": only after the password (and Duo) were checked online in this attempt. The old slot stays until the
    approval of the new one lands (roles.approve removes it). An attempt that skipped Duo for a key takes Duo first (stage "duo",
    then "choose-pin"); Duo refusing or down raises today's errors, back at "pin"."""
    _expect(a, "pin")
    if not a.fresh:
        raise RuntimeError("a new PIN needs the password checked online first")
    if a.duo_skipped:
        return _duo_first(a, reset=True, message=CHANGED)
    a.reset, a.stage, a.message = True, "choose-pin", CHANGED

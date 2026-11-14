# Run directly (python tests/test_sso_signin.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# SSO sign-in steps (core/dirsignin.py sso_start/sso_wait) against a fake local provider (tests/fake_oidc.py) and a fake security
# chip: the first sign-in with an admin's approval and the refresh token kept in the vault, the PIN after it, no group, the
# offline hour, a cancelled browser, and no token in the audit or the log.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\ssosignin%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import json, logging, threading
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from core import audit, datakey, db, directory, dirpin, oidc, osstore, passvault, pinslot, roles, session, tpm_windows
from core import dirsignin as S
from fake_oidc import FakeProvider, leaks

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def raises(fn, exc):
    try:
        fn()
    except exc as e:
        return e
    except Exception as e:
        print("   (raised", type(e).__name__, ")")
    return None


# ---------------------------------------------------------------- fakes: the protected store, the chip, the provider, the log
PEPPERS, PINS = {}, {}
def _box(file): return PEPPERS if file is None else PINS
osstore.available = lambda: True
osstore.put = lambda n, v, file=None: _box(file).__setitem__(n, v)
osstore.get = lambda n, file=None: _box(file).get(n)
osstore.delete = lambda n: PEPPERS.pop(n, None)


class FakeTpm:
    LockedOut = tpm_windows.LockedOut
    keys, locked = {}, 0

    @classmethod
    def lockout_threshold(cls): return 4
    @classmethod
    def lockout_window(cls): return 28800

    @classmethod
    def available(cls): return True

    @classmethod
    def create(cls, name, pin):
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.keys[name] = (k, pin)
        return k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    @classmethod
    def decrypt(cls, name, pin, data):
        if name not in cls.keys:
            raise FileNotFoundError(name)
        k, right = cls.keys[name]
        if pin != right:
            raise PermissionError("wrong PIN")
        return k.decrypt(data, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

    @classmethod
    def delete(cls, name): cls.keys.pop(name, None)


pinslot.tpm_windows = FakeTpm
pinslot.best_kind = lambda: "chip"

oidc._TEST_ALLOW_HTTP = True
P = FakeProvider()
ISS = P.start()

LOG = []
class Keep(logging.Handler):
    def emit(self, record): LOG.append(self.format(record))
logging.getLogger().addHandler(Keep())
logging.getLogger().setLevel(logging.DEBUG)

def browse(url):
    """The person's browser: follows the provider's redirect back to Toner's loopback port."""
    def go():
        try:
            requests.get(url, timeout=10, **oidc._DIRECT)
        except requests.RequestException:
            pass
    threading.Thread(target=go, daemon=True).start()

SSO = {"id": "s1", "name": "Contoso", "kind": "oidc", "provider": "other", "issuer": ISS, "client_id": "toner-app",
       "groups_claim": "groups", "id_claim": "sub", "suffixes": ["example.com"], "groups": {"Tech": ["g1"]},
       "group_names": {"g1": "Techs"}, "everyone": None}
PW, PIN = "correct horse battery 42", "246813"
ANN = "ann@example.com"

def fails():
    return json.loads(datakey.path().read_text(encoding="utf-8"))["throttle"]["fails"]

def sso(open_url=browse, cancel=None):
    a = S.sso_start(SSO, ANN, open_url=open_url)
    if a.stage == "browser":
        S.sso_wait(a, cancel or threading.Event())
    return a


# ---------------------------------------------------------------- set up: an Admin, the SSO connection
datakey.create("Admin1", PW)
db.init()
datakey.close()
session.sign_in("Admin1", PW)
roles.set_directories([SSO])
session.sign_out()
check("classify: an email in the connection's domain is the SSO connection's", S.classify(ANN)[1]["kind"] == "oidc")

# ---------------------------------------------------------------- the first sign-in: browser, choose a PIN, approval, PIN
opened = []
a = S.sso_start(SSO, ANN, open_url=lambda u: (opened.append(u), browse(u)))
check("sso_start: the browser step, the page opened once", a.stage == "browser" and opened == [a.browser.url]
      and a.browser is not None and a.tokens is None)
S.sso_wait(a, threading.Event())
check("sso_wait: a first sign-in chooses a PIN, with the first-sign-in text", a.stage == "choose-pin" and a.message == S.FIRST
      and a.fresh and a.name == ANN and a.role == "Tech" and a.user.guid == "sub-1", vars(a))
check("...the provider saw the hint", P.authorize_seen[-1].get("login_hint") == ANN)
check("...and the tokens are on the attempt", a.tokens.refresh_token == "rt-1" and a.tokens.access_token == "at-1")
TOKENS = [a.tokens.id_token, "at-1", "rt-1"]
S.choose_pin(a, PIN)
check("choose_pin: an admin approves next, with FIRST", a.stage == "approve" and a.message == S.FIRST)
rec = datakey.directory_account(ANN)
check("...an unapproved record for the SSO connection", rec["directory"] == "s1" and rec["guid"] == "sub-1"
      and rec["groups_role"] == "Tech" and rec["sealed"] is None, rec)
S.approve(a, "Admin1", PW)
check("approved: the PIN comes next, nobody signed in", a.stage == "pin" and session.state() == "signed_out")
S.finish(a, PIN)
check("the PIN signs Ann in", a.stage == "done" and session.state() == "open" and session.user() == ANN
      and session.kind() == "directory")
check("the refresh token is kept in the vault", passvault.get("sso-refresh:" + ANN) == "rt-1")
check("audited: signed in with the connection", [r for r in audit.recent(500) if r["action"] == "signed in"][0]["detail"]
      == "directory Contoso")
session.sign_out()

# ---------------------------------------------------------------- the next sign-in: straight to the PIN
datakey.set_online(ANN, time.time() - 5000)
a = sso()
check("the next sign-in goes straight to the PIN", a.stage == "pin" and a.fresh
      and time.time() - datakey.directory_account(ANN)["online_at"] < 60)
S.finish(a, PIN)
check("...and opens", a.stage == "done" and session.user() == ANN)
session.sign_out()
real_put = passvault.put
def no_vault(*a, **k): raise passvault.Locked("the vault can't be written")
passvault.put = no_vault
a = sso()
S.finish(a, PIN)
passvault.put = real_put
check("the refresh token can't be kept: signed in all the same (the re-check skips)", a.stage == "done" and session.user() == ANN)
session.sign_out()

# ---------------------------------------------------------------- not in a mapped group
P.id_claims = {"groups": ["other"]}
before = fails()
e = raises(sso, S.NotInGroup)
check("not in a mapped group: NotInGroup, with the approved sentence, counted", e is not None and str(e) == S.NOT_IN_GROUP
      and fails() == before + 1)
P.id_claims = {"preferred_username": "ann@evil.example"}
before = fails()
check("an account outside the connection's email domains: BadAnswer, counted", raises(sso, oidc.BadAnswer) is not None
      and fails() == before + 1)
P.id_claims = {"preferred_username": "ANN@EXAMPLE.COM"}
check("...the domain is compared in any case", sso().stage == "pin")
P.id_claims = {}

# ---------------------------------------------------------------- refused answers count on the shared counter
before = fails()
stop = threading.Event(); stop.set()
e = raises(lambda: sso(open_url=lambda u: None, cancel=stop), oidc.Cancelled)
check("a cancelled browser sign-in: Cancelled, counted once", e is not None and fails() == before + 1, fails() - before)
P.id_claims = {"auth_time": int(time.time()) - 3600}
before = fails()
check("an old sign-in at the provider: NotFresh, counted", raises(sso, oidc.NotFresh) is not None and fails() == before + 1)
P.id_claims = {}
P.mode = "denied"
before = fails()
check("the provider refuses: Refused, counted", raises(sso, oidc.Refused) is not None and fails() == before + 1)
P.mode = "ok"
S._clear_tries()

# ---------------------------------------------------------------- the provider down: the offline hour, then refused
real_token = P.routes["/token"]
P.routes["/token"] = lambda prov, h: h.send_json({}, 503)      # down after the browser came back
datakey.set_online(ANN, time.time() - 30 * 60)
a = sso()
check("down mid-sign-in, checked 30 minutes ago: the PIN alone", a.offline and a.stage == "pin" and a.user is None
      and a.tokens is None and not a.fresh and a.name == ANN)
P.routes["/token"] = real_token
P.force = 503                                                    # down from the start (discovery is not taken from the cache)
a = sso()
check("down from the start, 30 minutes ago: the PIN alone", a.offline and a.stage == "pin")
S.finish(a, PIN)
check("...and the PIN opens", a.stage == "done" and session.user() == ANN)
session.sign_out()
datakey.set_online(ANN, time.time() - 2 * 3600)
check("down, checked 2 hours ago: Unreachable", raises(sso, directory.Unreachable) is not None)
check("reachable: False while the provider is down", S.reachable(SSO) is False)
P.force = None
check("reachable: True when it answers", S.reachable(SSO) is True)

# ---------------------------------------------------------------- no token anywhere
session.sign_in("Admin1", PW)
rows = json.dumps(audit.recent(5000))
check("the audit holds no token", not any(t in rows for t in TOKENS))
check("the log holds no token", not leaks(LOG, TOKENS), leaks(LOG, TOKENS))
session.sign_out()

P.stop()
print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

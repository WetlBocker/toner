# Run directly (python tests/test_sso_recheck.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The background re-check of an SSO account (core/dircheck.py) through its refresh token, against a fake local provider.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\ssorecheck%d.db").replace("\\", os.sep) % int(time.time())
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
from fake_oidc import FakeProvider

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
       "groups_claim": "groups", "id_claim": "sub", "suffixes": ["example.com"], "groups": {"Tech": ["g1"], "Engineer": ["g2"]},
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

from core import dircheck
ROW = "locked: the directory refused the account"
def rows(action): return [r for r in audit.recent(5000) if r["action"] == action]

datakey.create("Admin1", PW)
db.init()
datakey.close()
session.sign_in("Admin1", PW)
roles.set_directories([SSO])
session.sign_out()

def reopen():
    """A fresh Ann session with the first refresh token back in the vault."""
    session.sign_out()
    P.revoked.clear(); P.id_claims = {}; P.force = None
    a = sso(); S.finish(a, PIN)
    passvault.put("sso-refresh:" + ANN, "rt-1")

a = sso(); S.choose_pin(a, PIN); S.approve(a, "Admin1", PW); S.finish(a, PIN)
check("set-up: Ann signed in with SSO", session.user() == ANN and session.kind() == "directory")

# ---------------------------------------------------------------- ok, and the refresh token rotates
datakey.set_online(ANN, 1000.0)
check("ok", dircheck.run_once() == "ok" and session.state() == "open")
check("...online_at updated, the refresh token rotated", time.time() - datakey.directory_account(ANN)["online_at"] < 60
      and passvault.get("sso-refresh:" + ANN) == "rt-2")
check("...the provider was asked with the stored token", P.token_requests[-1].get("refresh_token") == "rt-1")

# ---------------------------------------------------------------- a group change to Engineer
passvault.put("sso-refresh:" + ANN, "rt-1")
told = []
roles.on_change(lambda: told.append(1))
P.id_claims = {"groups": ["g2"]}
check("group change: ok, role Engineer, the window is told", dircheck.run_once() == "ok" and told == [1]
      and datakey.directory_account(ANN)["groups_role"] == "Engineer")
passvault.put("sso-refresh:" + ANN, "rt-1")
check("the same role again tells nobody", dircheck.run_once() == "ok" and told == [1])

# ---------------------------------------------------------------- no new ID token: the last role stays
passvault.put("sso-refresh:" + ANN, "rt-1")
real_refresh = oidc.refresh
oidc.refresh = lambda cfg, rt: oidc.Tokens("", "at", None, {})
check("no ID token: ok, role unchanged", dircheck.run_once() == "ok" and datakey.directory_account(ANN)["groups_role"] == "Engineer")
oidc.refresh = real_refresh

# ---------------------------------------------------------------- groups map to no role
passvault.put("sso-refresh:" + ANN, "rt-1")
P.id_claims = {"groups": ["other"]}
check("no role: refused, locked, audited", dircheck.run_once() == "refused" and session.state() == "locked" and session.refused()
      and len(rows(ROW)) == 1)
check("...the lock screen text is SSO_REFUSED with the connection's name", S.refused_text() == "Contoso no longer allows this account. Sign in again.")

# ---------------------------------------------------------------- a revoked refresh token
reopen()
P.revoked.add("rt-1")
check("revoked: refused, locked, audited", dircheck.run_once() == "refused" and session.state() == "locked" and session.refused()
      and len(rows(ROW)) == 2)

# ---------------------------------------------------------------- a provider answering for someone else
reopen()
P.id_claims = {"sub": "sub-other"}
check("another sub: refused and locked", dircheck.run_once() == "refused" and session.refused())
check("...and its refresh token was not kept", passvault.get("sso-refresh:" + ANN) == "rt-1")
reopen()
oidc.refresh = lambda cfg, rt: oidc.Tokens("x", "at", "rt-x", {"sub": "sub-1", "iss": "https://evil.example"})
check("another issuer: refused and locked", dircheck.run_once() == "refused" and session.refused())
oidc.refresh = real_refresh

# ---------------------------------------------------------------- a provider that is down
reopen()
P.force = 503
check("provider down: offline, still open", dircheck.run_once() == "offline" and session.state() == "open" and not session.refused())
P.force = None

# ---------------------------------------------------------------- no stored refresh token
passvault.remove("sso-refresh:" + ANN)
check("no refresh token: skipped", dircheck.run_once() == "skipped" and session.state() == "open")

# ---------------------------------------------------------------- no secret anywhere
check("no token in the log or the audit", not any(t in x for x in LOG + [str(r) for r in audit.recent(5000)] for t in ("rt-1", "rt-2", "at-1", "at-2")))

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

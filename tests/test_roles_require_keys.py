# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# "Require a security key" (core/roles.py): kept in the signed rules only while on, so a copy that never used it signs as before
# and the helper verifies it either way; an admin's switch, refused while sign-in without approval is on; who must add a key.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\reqkeys%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import base64, json, pathlib, subprocess, types
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakekey
from core import audit, datakey, db, directory, envelope, helperclient, osstore, pinslot, roles, session, updates
from core.helper import protocol, server

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)


def raised(exc, fn):
    """The exception when fn raises exc, else None."""
    try:
        fn()
    except exc as e:
        return e
    except Exception as e:
        print("   (raised", type(e).__name__, e, ")")
    return None


PEPPERS = {}
osstore.available = lambda: True
osstore.put = PEPPERS.__setitem__
osstore.get = PEPPERS.get
osstore.delete = lambda n: PEPPERS.pop(n, None)

# the helper switch, as helperclient.state reads it (tests/test_helper_client.py fakes the transport the same way)
HELPER_ON = [False]


class FakeConn:
    ans = None
    def send_bytes(self, b):
        req = protocol.decode(b)
        self.ans = protocol.encode({"protocol": protocol.PROTOCOL, "owner": True, "enrolled": True} if req["op"] == "status" else {})
    def poll(self, timeout): return True
    def recv_bytes(self, n): return self.ans
    def close(self): pass


def fake_connect():
    if not HELPER_ON[0]:
        raise helperclient.NotRunning()
    return FakeConn()


helperclient._connect = fake_connect
helperclient.installed = lambda: False
REAL_NOT_INSTALLED, helperclient.not_installed = helperclient.not_installed, lambda: True    # (whatever is installed here)
updates.installed_kind = lambda: "installed"

PW, PW2, PIN = "correct horse battery 42", "techs have long passwords 7", "a long pin-only pin 3"
SSO = {"id": "s1", "name": "Contoso", "kind": "oidc", "provider": "other", "issuer": "https://login.example.com", "client_id": "toner-app",
       "groups_claim": "groups", "id_claim": "sub", "suffixes": ["example.com"], "groups": {"Tech": ["g1"]},
       "group_names": {"g1": "Techs"}, "everyone": None}
SSO_USER = directory.User("sub-sso-user", "sso-user", "SSO User", ("g1",), True)

recovery = datakey.create("Admin1", PW)
db.init()
datakey.close()
session.sign_in("Admin1", PW)
datakey.add_local("Tech1", PW2, role="Tech")
roles.set_directories([SSO])
session.sign_out()
slot = pinslot.new("pin", datakey.new_slot_id(), PIN)
datakey.start_directory_account(SSO_USER, "s1", slot)
session.sign_in("Admin1", PW)
roles.approve("sso-user", slot)
fake = fakekey.install()
cred, val = fake.register("Blue", os.urandom(32))
datakey.add_key(PW, cred, val, "Blue")
session.sign_out()
session.sign_in("Admin1", PW, key=fake.value)
d = datakey.read()
read = lambda p: pathlib.Path(p).read_bytes()


def helper_verifies():
    return server._verified(str(datakey.path()), datakey.read()["rules_pub"], read) is not None


check("off by default, and the signed body is what it was", not roles.require_keys() and "require_keys" not in roles._signed(d).decode()
      and envelope.verify(base64.b64decode(d["rules_pub"]), roles._signed(d), d["rules_sig"]))
helper_verifies_rules = helper_verifies()
roles.set_require_keys(True)
check("on: signed, verified, and in the signed body", roles.require_keys() and roles.verified() is not None
      and json.loads(roles._signed(datakey.read()))["require_keys"] is True)
check("the helper verifies the rules with the switch on, with the same body", helper_verifies())
row = audit.recent(1)[0]
check("turning it on is audited, by whom", (row["action"], row["detail"]) == ("security keys required turned on", "by Admin1"), row)


def must_add_for(name, pw=None, pin=None, key=None):
    session.sign_out()
    if pin is None:
        session.sign_in(name, pw, key=key)
    else:
        session.sign_in_pin(name, pin)
    return roles.must_add_key()


must = {"Tech1": must_add_for("Tech1", PW2), "Admin1": must_add_for("Admin1", PW, key=fake.value),
        "sso-user": must_add_for("sso-user", pin=PIN)}
check("an account without a key must add one; one with a key need not; an SSO account is not asked", must == {"Tech1": True, "Admin1": False, "sso-user": False}, must)
session.sign_out()
session.sign_in_recovery(recovery)
check("nor is the recovery key", roles.must_add_key() is False)
must_add_for("Tech1", PW2)                                         # (signed in as Tech1)
check("a Tech cannot turn it off", raised(datakey.Locked, lambda: roles.set_require_keys(False)) is not None and roles.require_keys())
session.sign_out()
session.sign_in("Admin1", PW, key=fake.value)
roles.set_require_keys(False)
row = audit.recent(1)[0]
check("off: gone from the signed body, still verified, audited", not roles.require_keys() and roles.verified() is not None
      and "require_keys" not in roles._signed(datakey.read()).decode()
      and (row["action"], row["detail"]) == ("security keys required turned off", "by Admin1"), row)
check("the helper verifies the rules with the switch off, as before", helper_verifies_rules and helper_verifies())
check("off, no account is sent to add a key", must_add_for("Tech1", PW2) is False)
session.sign_out()
session.sign_in("Admin1", PW, key=fake.value)
HELPER_ON[0] = True
e = raised(ValueError, lambda: roles.set_require_keys(True))
check("it cannot go on while the helper switch is on", e is not None and e.args[0] == 'Turn off "Let group members sign in without approval" '
      'first. It can\'t be on while security keys are required.' and not roles.require_keys())
HELPER_ON[0] = False
STATES = ("portable", "absent: no such service", "absent: installed but disabled", "absent: timeout", "absent: error",
          "not_running", "outdated", "other_user", "rules_changed", "off", "on", "raises")
# this copy positively not enrolled: off, portable, or no helper service at all (another OS has none)
ALLOWED = {"off", "portable", "absent: no such service"} | (set() if sys.platform in ("win32", "linux") else
                                                             {s for s in STATES if s.startswith("absent")})
REAL_RUN = subprocess.run


def state_is(st):
    def state(*a, **k):
        if st == "raises":
            raise OSError("the helper's state can't be read")
        return st.split(":")[0]
    return state


def service_manager(st):
    """sc.exe or systemctl as helperclient.not_installed asks them, for the "absent" cases."""
    def run(cmd, **kw):
        if st == "absent: timeout":
            raise subprocess.TimeoutExpired(cmd, 10)
        if st == "absent: error":
            raise OSError("no service manager")
        missing = st == "absent: no such service"
        if cmd[0] == "sc.exe":
            return subprocess.CompletedProcess(cmd, 1060 if missing else 0, b"", b"")
        return subprocess.CompletedProcess(cmd, 0, b"not-found\n" if missing else b"loaded\n", b"")
    return run


real_state, went_on = helperclient.state, {}
helperclient.not_installed = REAL_NOT_INSTALLED          # (asking the faked service manager)
for st in STATES:
    helperclient.state, subprocess.run = state_is(st), service_manager(st)
    e = raised(ValueError, lambda: roles.set_require_keys(True)) if st not in ALLOWED else None
    went_on[st] = roles.require_keys()
    if st in ALLOWED:
        roles.set_require_keys(True)
        went_on[st] = roles.require_keys()
        roles.set_require_keys(False)
    elif e is None or e.args[0] != roles.REQUIRE_HELPER_ON:
        went_on[st] = "not refused in the approved words"
helperclient.state, subprocess.run, helperclient.not_installed = real_state, REAL_RUN, lambda: True
check("it goes on only when the helper's state says this copy isn't enrolled (fail closed, an unreadable state too)",
      went_on == {st: st in ALLOWED for st in STATES}, went_on)

# Linux: where systemd isn't the running init there is no helper; where it is, a disabled unit still counts as on
real_sys, real_dir = helperclient.sys, helperclient.SYSTEMD_DIR
helperclient.sys, helperclient.state, helperclient.not_installed = types.SimpleNamespace(platform="linux"), state_is("absent"), REAL_NOT_INSTALLED
helperclient.SYSTEMD_DIR = pathlib.Path(_tmp.mkdtemp(prefix="netcheck_run_")) / "systemd" / "system"     # (not there)
subprocess.run = service_manager("absent: installed but disabled")
roles.set_require_keys(True)
no_systemd = roles.require_keys()
roles.set_require_keys(False)
helperclient.SYSTEMD_DIR.mkdir(parents=True)
e = raised(ValueError, lambda: roles.set_require_keys(True))
check("Linux: on without systemd running; refused with it running and the unit disabled", no_systemd and e is not None
      and e.args[0] == roles.REQUIRE_HELPER_ON and not roles.require_keys())
helperclient.sys, helperclient.SYSTEMD_DIR, helperclient.state = real_sys, real_dir, real_state
subprocess.run, helperclient.not_installed = REAL_RUN, lambda: True
session.sign_out()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

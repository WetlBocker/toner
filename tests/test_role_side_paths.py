# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# What a Tech's role closes stays closed on the side paths: a show command that writes a file, a custom SSH check, and the
# Assistant's tools (core/cmdrun.py read_only, core/custom.py validate and test_check, core/assistant/tools.py offered and run).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, json
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "sidepaths%d.db" % int(time.time()))
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import cmdrun, custom, datakey, db, perms, roles, session
from core.assistant import tools as T

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def denied(fn):
    try:
        fn()
    except perms.Denied as e:
        return str(e)
    except Exception as e:                                  # anything else is not the refusal
        print("   (raised", type(e).__name__, ")")
    return None

PW, PW2 = "correct horse battery 42", "amber kettle meadow 77"
DEV = dict(name="sw1", vendor="cisco", host="127.0.0.1", port=1, platform="cisco_ios", username="admin", site="default")
WRITERS = ("show running-config | redirect flash:config.text", "show running-config | tee tftp://192.0.2.9/sw1.cfg",
           "show clock | append flash:vlan.dat", "show running-config > bootflash:x.cfg", "show configuration | save /var/tmp/c")

# ---------------------------------------------------------------- the read-only guard
for c in WRITERS:
    check(f"writes a file, so it is not read-only: {c}", not cmdrun.read_only(c))
check("a plain show and a filtered show still read only", cmdrun.read_only("show version") and cmdrun.read_only("show running-config | include hostname"))

datakey.create("Admin1", PW); db.init()
datakey.add_local("Tech1", PW2, role="Tech")
session.sign_out(); session.sign_in("Admin1", PW)
roles.set_permissions("Tech", {"tool:command-runner": False, "tool:sessions": False})
db.set_setting("ai_run_commands", True)
names = lambda: {t.name for t in T.offered()}
check("an Admin is offered the command and session-log tools", {"run_commands", "list_session_logs", "read_session_log"} <= names(), names())
session.sign_out(); session.sign_in("Tech1", PW2)
check("signed in as a Tech without push", not perms.allowed("push") and not perms.allowed("tool:command-runner"))

# ---------------------------------------------------------------- the push gate
msg = denied(lambda: cmdrun.need_push([DEV], [WRITERS[0]]))
check("the Command Runner refuses a Tech a show that writes a file", msg is not None and WRITERS[0] in msg, msg)

# ---------------------------------------------------------------- custom SSH checks
CHK = dict(name="tidy", kind="ssh", target="delete /force flash:c2960x.bin", mode="match", parse="x", enabled=1)
msg = denied(lambda: custom.validate(CHK))
check("a Tech can't save a custom SSH check that could change a device", msg is not None and "delete /force flash:c2960x.bin" in msg, msg)
sent = []
custom.run_ssh = lambda *a, **k: sent.append(a) or []
check("or test one", denied(lambda: custom.test_check(CHK, DEV)) is not None and not sent, sent)
check("a custom SSH check that only reads is still accepted", denied(lambda: custom.validate(dict(CHK, target="show version"))) is None)

# ---------------------------------------------------------------- the Assistant's tools
check("a Tech is not offered tools for pages the role can't open", not {"run_commands", "list_session_logs", "read_session_log"} & names(), names())
ran = []
cmdrun.run_on_device = lambda *a, **k: ran.append(a) or {"ok": True, "output": {}}
for tool, args in (("run_commands", {"device": "sw1", "commands": ["show version"]}), ("list_session_logs", {}), ("read_session_log", {"session_id": 1})):
    out = json.loads(T.run(tool, args))
    check(f"a call to {tool} is refused with the role's reason", out == {"error": perms.REASON}, out)
check("nothing was sent to a device", not ran, ran)
session.sign_out()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

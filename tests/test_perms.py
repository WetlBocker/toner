# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The permission catalogue (core/perms.py): the switchable permissions, their labels and each role defaults.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\perms%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import backup, db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
app = __import__("PySide6.QtWidgets", fromlist=["QApplication"]).QApplication([])
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
from core import perms as P
from ui.settings import GROUPS
D = P.DEFAULTS; keys = {k for k, _ in P.PERMISSIONS}
t, e = D["Tech"], D["Engineer"]
check("tech: push and unmasked off", t["push"] is False and t["unmasked"] is False)
check("tech: Appearance and Terminal on", t["settings:Appearance"] and t["settings:Terminal"])
check("tech: other settings pages off", all(v is False for k, v in t.items() if k.startswith("settings:") and k not in ("settings:Appearance", "settings:Terminal")))
check("tech: every tool and ai on", t["ai"] is True and all(v is True for k, v in t.items() if k.startswith("tool:")))
check("engineer: all on", all(v is True for v in e.values()))
check("defaults cover exactly PERMISSIONS", set(t) == keys and set(e) == keys)
check("no duplicate keys", len(keys) == len(P.PERMISSIONS))
check("21 settings pages", len(P.SETTINGS_PAGES) == 21)
titles = {n for _, ns in GROUPS for n in ns}
check("each page title is in GROUPS", all(p in titles for p in P.SETTINGS_PAGES) and "Accounts" not in P.SETTINGS_PAGES)
check("28 tools", len(P.TOOLS) == 28, len(P.TOOLS))
check("labels", dict(P.PERMISSIONS)["push"] == "Push changes to devices" and dict(P.PERMISSIONS)["tool:ping"] == "Ping / Traceroute / DNS")
check("denied default message", str(P.Denied()) == P.REASON == "Your role doesn't allow this. Ask an admin." and issubclass(P.Denied, PermissionError))
print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Small adjustments batch: overview cards, clear button, OUI download, gauge needles, user menu, failed pulse.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "adjbatch%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingadjbatch%d" % int(time.time()))
from core import db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
from PySide6.QtWidgets import QApplication, QLabel, QLineEdit, QToolButton, QWidget
app = QApplication([])
import app as A
A.apply_look(app)
from ui import motion

print("== 1. Overview has no Last runs / Recent activity cards")
from ui.dashboard import DashboardTab
dash = DashboardTab(); dash.resize(1200, 760); dash.show(); app.processEvents()
titles = {l.text() for l in dash.findChildren(QLabel)}
check("no card titled Last runs", "Last runs" not in titles, sorted(titles)[:40])
check("no card titled Recent activity", "Recent activity" not in titles)
check("the Health and Availability cards are still there", {"Health", "Availability"} <= titles)

print("== 2. The clear button is centred in a search box")
boxes = [("a bare box", QLineEdit())]
for name, e in boxes:
    e.setClearButtonEnabled(True); e.setText("abc"); e.resize(240, e.sizeHint().height()); e.show()
app.processEvents()
for name, e in boxes:
    b = e.findChild(QToolButton)
    c = b.geometry().center().y(); mid = e.contentsRect().center().y()
    check(f"{name}: the clear button's middle is within 1 px of the box's middle", b is not None and abs(c - mid) <= 1 and b.geometry().top() >= 0 and b.geometry().bottom() <= e.height(), (b.geometry(), e.rect()))

print("== 5. OUI download sends a browser User-Agent")
import requests
from core import oui
seen = {}
class Resp:
    text = "AABBCC     (base 16)\t\tAcme Corp\n"
    def raise_for_status(self): pass
real_get = requests.get
def fake_get(url, **kw):
    seen.update(kw); seen["url"] = url
    return Resp()
requests.get = fake_get
try:
    oui.cache_path = lambda: __import__("pathlib").Path(SP) / "oui_test.txt"
    oui.update_from_ieee()
finally:
    requests.get = real_get
ua = (seen.get("headers") or {}).get("User-Agent", "")
check("a User-Agent is sent, and it is not python-requests'", ua and "python-requests" not in ua.lower() and ua.startswith("Mozilla/"), seen.get("headers"))
check("the timeout is kept", seen.get("timeout") == 30)

print("== 7. Gauge needles turn about the arc's centre")
from ui import chartspec as cs
g = cs.gauge(cs.palette(), 50, warn=70, fail=90)["series"][0]
check("pointer and anchor sit at the centre", g["pointer"]["offsetCenter"] == [0, 0] and g["anchor"]["offsetCenter"] == [0, 0], (g["pointer"]["offsetCenter"], g["anchor"]["offsetCenter"]))
angle = g["startAngle"] + (g["endAngle"] - g["startAngle"]) * (50 - g["min"]) / (g["max"] - g["min"])
check("50 of 100 points at the arc's midpoint (straight up)", g["startAngle"] == 200 and g["endAngle"] == -20 and angle == 90, angle)
check("the value text is still below the hub", float(g["detail"]["offsetCenter"][1].rstrip("%")) > 0)

print("== 9. The user menu sits above Settings")
from ui.nav import NavStack
nav = NavStack("Toner")
for label in ("Overview", "Inventory", "Tools"):
    nav.addTab(QWidget(), label, None, "Network")
st = QWidget(); nav.addTab(st, "Settings", "settings", NavStack.BOTTOM); nav.addTab(QWidget(), "About", "about", NavStack.BOTTOM)
from PySide6.QtWidgets import QMenu
nav.set_user("alice", QMenu())
nav.resize(900, 600); nav.show(); app.processEvents()
urow = next((r for r in range(nav.list.count()) if nav.list.itemWidget(nav.list.item(r)) is nav.user), None)
check("the user button is a row of the sidebar list", urow is not None)
check("...above Settings and About", urow is not None and urow < nav.row_of(nav.stack.indexOf(st)) and urow > nav._spacer)

print("== 11. A FAIL icon pulses")
from ui.glance import GlanceMap
m = GlanceMap(); m.resize(400, 200); m.show(); app.processEvents()
m.status = {"sw1": "FAIL"}; m.down = set(); m.checking = set()
motion.force("Subtle"); m._pulsing()
check("a FAIL status icon has a running pulse with motion on", m._anim is not None and m._anim.state() == m._anim.State.Running)
motion.force("Off"); m._pulsing()
check("...and none with motion off", m._anim is None)
motion.force(None)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

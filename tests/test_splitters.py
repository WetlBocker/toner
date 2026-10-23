# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Pages use the whole window on a 1920 screen, and a splitter dragged on a page keeps its sizes across restarts.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "split%d.db" % int(time.time())); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import db
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QSplitter
app = QApplication.instance() or QApplication([])
import app as A
from ui import nav
A.apply_look(app)


def wait(ms):
    end = time.time() + ms / 1000
    while time.time() < end:
        app.processEvents(); time.sleep(0.02)


def history_split(w):
    return next(s for s in w.history.findChildren(QSplitter) if s.orientation() == Qt.Orientation.Horizontal)


print("== a 1920-wide window")
w = A.Main(); w.resize(1920, 1000); w.show(); wait(100)
w.go("History"); wait(50)
check("the content width cap lets a 1920 screen use the whole window", nav.CONTENT_WIDTH >= 1920 and w.history.width() >= 1800, w.history.width())
check("'splitters' is a per-computer Global setting, left out of exports", "splitters" in db.NOT_PORTABLE and "splitters" in db.GLOBAL_ONLY)

print("== dragging History's divider")
split = history_split(w)
before = split.sizes()
split.setSizes([500, 1300]); split.splitterMoved.emit(500, 1); wait(50)
check("nothing is written while the drag is still going", not db.get_setting("splitters"))
wait(500)
saved = db.get_setting("splitters").get("history")
check("the sizes are kept once the drag settles", saved == split.sizes() and saved != before, (saved, before))
w.go("Tools"); w.tools.show_tool(w.tools.apitest); wait(50)          # a splitter only has real sizes once its page is laid out
api = w.tools.apitest.split
api.setSizes([600, 1100]); api.splitterMoved.emit(600, 1); wait(500)
check("each page's splitter has its own entry", set(db.get_setting("splitters")) == {"history", "api_tester"}, db.get_setting("splitters"))
w.close()

print("== the next start")
w2 = A.Main(); w2.resize(1920, 1000); w2.show(); wait(100)
w2.go("History"); wait(50)
check("History opens with the dragged sizes", abs(history_split(w2).sizes()[0] - saved[0]) <= 2, (history_split(w2).sizes(), saved))
w2.go("Tools"); w2.tools.show_tool(w2.tools.apitest); wait(50)
check("and so does the API Tester", abs(w2.tools.apitest.split.sizes()[0] - 600) <= 2, w2.tools.apitest.split.sizes())
w2.close()

print("== a saved entry that no longer fits the page")
db.set_setting("splitters", {"history": [1, 2, 3]})
w3 = A.Main(); w3.resize(1920, 1000); w3.show(); wait(100)
w3.go("History"); wait(50)
check("is ignored and the page uses its usual sizes", all(s > 100 for s in history_split(w3).sizes()), history_split(w3).sizes())
w3.close()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

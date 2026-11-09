# Run directly (python tests/test_assistant_motion.py). The Assistant panel's slide: the page narrows with it frame by frame (no
# fade, no ghost picture of the page), about 220 ms, nothing at all with motion off, and a quick open then close ends closed
# with no picture of the panel left behind.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "am%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import db
db.init()
from core import assistant as AI
from PySide6.QtCore import QCoreApplication, QEvent, QObject
from PySide6.QtWidgets import QApplication, QLabel, QWidget
app = QApplication([])
import app as A
A.apply_look(app)
from ui import motion

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def spin(ms):
    end = time.time() + ms / 1000
    while time.time() < end: QCoreApplication.processEvents(); time.sleep(0.005)

db.set_home(db.GLOBAL)
w = A.Main(); w.resize(1900, 820); w.show(); spin(100)
AI.set_state(True, "Connected: Claude Opus 5.5.", "Claude Opus 5.5"); spin(60)

class Count(QObject):
    n = 0
    def eventFilter(self, o, e):
        if e.type() == QEvent.Type.LayoutRequest: self.n += 1
        return False
counter = Count(); w.tabs.installEventFilter(counter)
calls = []
real_set = w.body.setSizes
w.body.setSizes = lambda s: (calls.append(list(s)), real_set(s))[1]
def overlays(): return [c for c in w.findChildren(QLabel) if c.objectName() == "assistantSlide"]
def run(on, wait_ms):
    calls.clear(); counter.n = 0
    w.show_assistant(on); started = time.time(); spin(wait_ms)
    return time.time() - started

print("== motion on")
motion.force("Lively")
w.show_assistant(True); spin(500); w.show_assistant(False); spin(500)          # warm up (first show lays out lazily)
from PySide6.QtCore import QPoint
def page_edge(): return w.tabs.mapTo(w, QPoint(w.tabs.contentsRect().right() + 1, 0)).x()
def page_w(): return w.tabs.contentsRect().width()
def ghosts(): return [c for c in w.findChildren(QWidget) if c.objectName() == "assistantPage"]
total = sum(w.body.sizes())
run(True, 40)
first = page_w()
check("opening: the panel's picture slides in and the real page's right edge meets it, mid-way",
      len(overlays()) == 1 and total - overlays()[0].width() < first < total and abs(page_edge() - overlays()[0].x()) <= 2,
      (len(overlays()), first, page_edge(), overlays() and overlays()[0].x()))
check("...no fade and no second picture of the page (the ghost)", not ghosts() and all(o.graphicsEffect() is None for o in overlays()))
spin(60)
check("...the page narrows frame by frame, as beside the sidebar", page_w() < first, (first, page_w()))
spin(500)
check("opening: ends open, the picture gone, the page sized by the splitter again", w.assistant.isVisible() and not overlays() and w.body.sizes()[1] > 100
      and w.tabs.contentsMargins().right() == 0 and sum(w.body.sizes()) >= total - 2, (calls, w.body.sizes(), w.tabs.contentsMargins().right()))
w.show_assistant(False); spin(60)
check("closing: the page widens after the panel's picture as it leaves", len(overlays()) == 1 and abs(page_edge() - overlays()[0].x()) <= 2
      and page_w() < total, (page_edge(), overlays() and overlays()[0].x()))
spin(500)
check("closing: ends closed, no picture left, the page full width", not w.assistant.isVisible() and not overlays() and page_w() >= total and w.tabs.contentsMargins().right() == 0, page_w())
w.show_assistant(True); spin(40)
w.ai_button.click(); spin(600)
check("the button pressed mid-way through opening closes it", not w.assistant.isVisible() and not overlays() and not w.assistant_open())
check("the slide lasts 180 to 260 ms", 180 <= A.Main.PANEL_MS <= 260, A.Main.PANEL_MS)
w.show_assistant(True); spin(40); w.show_assistant(False); spin(600)
check("open then quickly close: closed, no picture left, no error", not w.assistant.isVisible() and not overlays() and not w.ai_button.isChecked())
w.show_assistant(True); spin(40); w.show_assistant(False); spin(40); w.show_assistant(True); spin(600)
check("open, close, open: open", w.assistant.isVisible() and not overlays() and w.ai_button.isChecked())
w.show_assistant(False); spin(600)

print("== a remembered width wider than the window")
kept = db.get_setting("splitters")
db.set_setting("splitters", {**(kept or {}), "assistant_panel": [100, 5000]})
total = sum(w.body.sizes())
w.show_assistant(True); spin(60)
check("the picture leaves the page at least 300 px", len(overlays()) == 1 and overlays()[0].width() <= total - 300, ([c.width() for c in overlays()], total))
spin(500)
check("...and so does the panel when the slide ends", w.assistant.isVisible() and w.body.sizes()[0] >= 300, w.body.sizes())
w.show_assistant(False); spin(600)
db.set_setting("splitters", kept)

print("== motion off")
motion.force("Off")
t = run(True, 0)
check("instant: open at once, no picture, sizes set once", w.assistant.isVisible() and not overlays() and len(calls) == 1 and w.body.sizes()[1] > 100, calls)
run(False, 0)
check("instant: closed at once", not w.assistant.isVisible() and not overlays() and len(calls) == 1)
motion.force(None)

print(f"\n{ok} passed, {bad} failed"); raise SystemExit(1 if bad else 0)

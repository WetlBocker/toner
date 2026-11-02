# Run directly (python tests/test_x.py) or all together (python tests/run_all.py).
# The chart widget with its browser engine (QtWebEngine): the page loads, draws an option, exports a picture, and reports a
# click through the web channel. Skipped (as passed) where QtWebEngine cannot start, which the other tests never need.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_os.environ.pop("TONER_NO_WEBCHARTS", None)                       # this file wants the real thing
if hasattr(_os, "geteuid") and _os.geteuid() == 0:                 # Chromium will not sandbox as root (a container)
    _os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--no-sandbox --disable-gpu")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "webchart%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingwebchart%d" % int(time.time()))
from core import db
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication
from ui import chartspec, webchart
webchart.prepare_application()
app = QApplication([])

def pump(cond, ms=8000):
    t0 = time.time()
    while time.time() - t0 < ms / 1000:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return cond()

print("== QtWebEngine")
if not webchart.available():
    print("  (QtWebEngine is not available here: the widget shows its note instead; nothing more to test)")
    v = webchart.ChartView()
    check("without the engine the widget is a note, and drawing on it does nothing", v.note.text().startswith("Charts need") and v.draw(lambda p: {}) is None)
else:
    v = webchart.ChartView()
    v.resize(640, 400); v.show()
    v.draw(lambda p: chartspec.donut(p, {"OK": 3, "FAIL": 1}, title="t"))
    check("the page loads", pump(lambda: v._loaded, 15000))
    out = os.path.join(SP, "chart.png"); got = []
    QTimer.singleShot(1200, lambda: v.to_png(out, got.append))
    check("the chart is drawn and exports as a picture", pump(lambda: bool(got), 15000) and got[0] is True and os.path.getsize(out) > 2000)
    seen = []
    v.clicked.connect(seen.append)
    v._view.page().runJavaScript('toner.emitClick({name: "FAIL", value: 1})')
    check("a click on the page comes back to Python as a dict", pump(lambda: bool(seen)) and seen[0].get("name") == "FAIL", seen)
    v.restyle()
    check("restyling keeps the chart", pump(lambda: v._builder is not None) and v._loaded)

print()
print(f"{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

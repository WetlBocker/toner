# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Graphs drawn with pyqtgraph: what they share (the theme's colours, none of pyqtgraph's own menus or buttons), the live ping
# graph, the iperf3 throughput graph, and how pyqtgraph and numpy come with Toner.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import math, os, sys, time, types
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "graphs%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
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
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)
import pyqtgraph as pg
from ui import plots, theme, tools2, tools3
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

print("== what every graph shares")
w = plots.plot_widget()
check("pyqtgraph's own menu is off (its words are not Toner's)", not w.getViewBox().menuEnabled())
check("and so is its auto-range button", w.getPlotItem().buttonsHidden)
surface, border, muted = plots.restyle(w)
check("it is painted in the theme's colours", surface.name() == theme.current()["surface"] and muted.name() == theme.current()["muted"])
check("the accent is the Toner theme's", plots.colours()[4].name() == theme.current()["accent"])

print("== the live ping graph")
g = tools2.LatencyGraph(); g.resize(700, 240); g.show(); app.processEvents()
check("before Start it says how to begin", g.empty.isVisible() and g.empty.text() == "Press Start" and not g.plot.isVisible())
for i in range(20):
    g.add(None if i in (5, 6) else 4.0 + i)
app.processEvents()
xs, ys = g.line.getData()
check("each reply is a point, the newest at the right", len(ys) == 20 and xs[-1] == g.samples.maxlen - 1 and ys[-1] == 23.0, (len(ys), xs[-1], ys[-1]))
check("a lost reply breaks the line", math.isnan(ys[5]) and math.isnan(ys[6]))
lx, ly = g.lost.getData()
check("and is marked on the floor", list(lx) == [xs[5], xs[6]] and list(ly) == [0, 0], (list(lx), list(ly)))
ticks = g.plot.getAxis("left")._tickLevels[0]
check("the scale reads in ms, with room above the highest reply", [t[1] for t in ticks][-1].endswith(" ms") and ticks[-1][0] >= 23 * 1.2 - 0.01, ticks)
check("it doesn't zoom while it runs", g.plot.getViewBox().state["mouseEnabled"] == [False, False])
check("the graph shows once there are replies", g.plot.isVisible() and not g.empty.isVisible())
for _ in range(400):
    g.add(5.0)
check("it keeps the last 300", len(g.samples) == 300 and len(g.line.getData()[1]) == 300)
g.clear(); app.processEvents()
check("Reset clears it", not g.samples and g.empty.isVisible())

print("== the iperf3 throughput graph")
t = tools3.ThroughputGraph(); t.resize(700, 200); t.show(); app.processEvents()
check("before a test it says what will appear", t.empty.isVisible() and t.empty.text() == "The speed appears here during a test")
t.set_points([(1, 90.0), (2, 94.0), (3, 88.0)]); app.processEvents()
check("a test draws each interval", list(t.curve.getData()[1]) == [90.0, 94.0, 88.0] and t.plot.isVisible())
check("with now, peak and average above it", t.summary.text() == "now 88.0   peak 94.0   average 90.7 Mbit/s", t.summary.text())
check("the time axis reads in seconds", t.plot.getAxis("bottom").tickStrings([2, 4], 1, 2) == ["2 s", "4 s"])
check("the speed axis says Mbit/s", t.plot.getAxis("left").labelText == "Mbit/s")
t.plot.setXRange(1.5, 2.5, padding=0)
t.plot.scene().sigMouseClicked.emit(types.SimpleNamespace(double=lambda: True))
lo, hi = t.plot.getViewBox().viewRange()[0]
check("drag to zoom in on part of a test; double-click to see it all", lo <= 1 and hi >= 3, (lo, hi))
t.set_points([]); check("and clears", t.points == [] and t.empty.isVisible())

print("== how pyqtgraph and numpy come with Toner")
from ui import about
names = dict(about.LIBRARIES)
check("About lists them, in the agreed words", names.get("pyqtgraph") == "graphs" and names.get("numpy") == "the numbers behind the graphs")
check("with their versions", about._version_of("pyqtgraph") == pg.__version__ and about._version_of("numpy"))
lock = open(os.path.join(root, "requirements.lock"), encoding="utf-8").read().split()
check("the lock pins them, and colorama, which pyqtgraph needs", {"pyqtgraph==0.14.0", "numpy==2.5.3", "colorama==0.4.6"} <= set(lock))
check("requirements.txt asks for pyqtgraph", "pyqtgraph>=0.14" in open(os.path.join(root, "requirements.txt"), encoding="utf-8").read())
for script in ("build.ps1", "build_linux.sh"):
    # pyqtgraph's own PyInstaller hook (in pyinstaller-hooks-contrib) brings its data and templates and leaves out its examples;
    # --collect-all imported the examples too, which open a Qt window and crashed the Linux build (no display there)
    check(f"{script} leaves pyqtgraph to its own hook", "pyqtgraph" not in open(os.path.join(root, "packaging", script), encoding="utf-8").read())
import importlib.util
hook = os.path.join(os.path.dirname(importlib.util.find_spec("_pyinstaller_hooks_contrib").origin), "stdhooks", "hook-pyqtgraph.py")
check("that hook is there, and leaves out the examples", os.path.exists(hook) and "examples" in open(hook, encoding="utf-8").read())

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

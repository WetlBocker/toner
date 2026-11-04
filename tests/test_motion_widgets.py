# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The moving parts of the Overview and the status strip: with motion off they land on their final state at once; with it on they move
# and end in the same place. Getting started is one line; the count tiles pop; raised panels paint a shadow.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "motion%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingmotion%d" % int(time.time()))
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
from drivers.base import Result
from PySide6.QtWidgets import QApplication, QMessageBox, QPushButton
app = QApplication([])
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
import app as A
A.apply_look(app)
from ui import motion, theme
from ui.dashboard import BarList, Card, DashboardTab
from ui.panels import Panel, ProgressLine, ShimmerBar
from ui.statusstrip import StatusStrip

def spin(ms):
    t0 = time.time()
    while time.time() - t0 < ms / 1000:
        app.processEvents(); time.sleep(0.01)

print("== motion off: everything lands at once")
check("no screen means no motion", motion.level() == "Off")
bars = BarList(); bars.resize(300, 100); bars.show()
bars.set_rows([("a", 100.0, ""), ("b", 50.0, "")])
check("the availability bars are full-length at once", bars.grown == 1.0)
line = ProgressLine(); line.show()
line.set_progress(2, 4); app.processEvents()
check("the progress line shows and is at its value at once", line.isVisibleTo(line) and abs(line.shown - 0.5) < 1e-6 and not line.sweep.isActive())
line.set_progress(4, 4)
check("...and goes when the run ends", not line.isVisibleTo(line) and line.shown == 0.0)
card = Card("Failing", "FAIL"); card.show(); app.processEvents()
card.set(1); base = card.value.font().pointSizeF(); card.set(3); app.processEvents()
check("a tile's number changes without a pop", abs(card.value.font().pointSizeF() - base) < 1e-6 and card._pop is None)
card.enterEvent(None)
check("and no lift under the mouse", card.lay.contentsMargins().top() == 12)

print("== motion on: they move, and end in the same place")
motion.force("Lively")
bars.set_rows([("a", 100.0, ""), ("b", 50.0, ""), ("c", 10.0, "")])
check("the bars start from nothing", bars.grown < 0.5 and bars._grow is not None)
spin(1100)
check("...and grow to full", abs(bars.grown - 1.0) < 1e-6, bars.grown)
line.set_progress(1, 4); app.processEvents()
check("the progress line sweeps while it runs", line.sweep.isActive())
spin(450)
check("...and reaches its value", abs(line.shown - 0.25) < 0.02, line.shown)
line.set_progress(4, 4)
check("...then stops", not line.sweep.isActive())
card.set(7); app.processEvents()
check("a changed number pops", card._pop is not None)
spin(500)
check("...and settles back to its size", abs(card.value.font().pointSizeF() - base) < 0.05, (card.value.font().pointSizeF(), base))
card.enterEvent(None)
check("the tile lifts under the mouse", card.lay.contentsMargins().top() == 10)
card.leaveEvent(None)
check("...and settles when it leaves", card.lay.contentsMargins().top() == 12)
bar = ShimmerBar(); bar.setMaximum(4); bar.setValue(2); bar.resize(160, 12); bar.show(); app.processEvents()
check("the strip's bar sweeps while shown", bar.sweep.isActive() and (bar.grab() or True))
bar.hide()
check("...and stops when hidden", not bar.sweep.isActive())
motion.force(None)

print("== the status strip while checks run")
import types
s = StatusStrip(types.SimpleNamespace()); s.show(); app.processEvents()
s.on_progress(1, 3); app.processEvents()
check("a dot and the bar show while running", s.live.isVisibleTo(s) and s.progress.isVisibleTo(s) and s.progress.value() == 1 and "1 of 3" in s.run.text())
s.on_progress(3, 3); app.processEvents()
check("...and go when it ends", not s.live.isVisibleTo(s) and not s.progress.isVisibleTo(s))

print("== Getting started, on one line")
d = DashboardTab(); d.resize(1200, 760); d.show(); app.processEvents()
check("a new installation: three steps left, the first named, every button offered", d.start_title.text() == "Getting started: 3 steps left" and d.start_next.text().startswith("Add the devices")
      and [b.text() for bs in d.step_buttons.values() for b in bs if b.isVisibleTo(d)] == ["Add a device", "Scan the network", "Run checks", "Set up notifications"], d.start_title.text())
db.save_device(dict(name="sw1", vendor="cisco", host="10.0.0.1", port=0, platform="cisco_ios", username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))
db.save_run([Result("sw1", "cpu", "OK", "5%")])
d.refresh(); app.processEvents()
check("done steps drop their buttons and the count falls", d.start_title.text() == "Getting started: 1 step left" and d.start_next.text().startswith("Choose how to be told")
      and [b.text() for bs in d.step_buttons.values() for b in bs if b.isVisibleTo(d)] == ["Set up notifications"], d.start_title.text())
check("the marks still say which are done", d.steps["devices"][0].text() == "✓" and d.steps["run"][0].text() == "✓" and d.steps["alerts"][0].text() == "•")
check("the row of actions sits on each problem row, not under the list", d.attention.columnCount() == 5 and d.attention.horizontalHeaderItem(4).text() == "Actions" and not hasattr(d, "act_open"))

print("== raised panels")
p = Panel(); p.resize(200, 100); p.show(); app.processEvents()
flat = p.grab().toImage()
check("Bordered: the card fills its panel edge to edge", p.card.geometry().left() == 0 and p.card.width() == p.width())
db.set_setting("panels", "Raised"); A.apply_look(app); p.restyle(); app.processEvents()
check("Raised keeps a margin round the card and paints a shadow there (the picture changes)", theme.current()["raised"] and p.card.geometry().left() == 6 and p.grab().toImage() != flat)
db.set_setting("panels", "Bordered"); A.apply_look(app)

print("== a progress line fed again after its fill finished (a real run: a tick every few seconds)")
motion.force("Subtle")
line = ProgressLine(); line.resize(300, 4); line.show(); line.set_progress(1, 6); spin(600)
try:
    line.set_progress(2, 6); line.set_progress(3, 6); crashed = False
except RuntimeError as e:
    crashed = str(e)
check("...does not raise (the finished animation had deleted itself)", crashed is False and line.isVisible(), crashed)
line.set_progress(6, 6)

print("== rows fly up and fade in when a list comes into view")
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QTreeWidget, QTreeWidgetItem, QWidget
tbl = QTableWidget(4, 2); tbl.resize(300, 200); tbl.show(); app.processEvents()
for i in range(4): tbl.setItem(i, 0, QTableWidgetItem(f"row {i}"))
tree = QTreeWidget(); tree.resize(300, 200); tree.show()
top = QTreeWidgetItem(tree, ["parent"]); QTreeWidgetItem(top, ["child"]); top.setExpanded(True); app.processEvents()
motion.force("Off")
check("with motion off, reveal does nothing", motion.reveal(tbl) is None and tbl.viewport().graphicsEffect() is None)
motion.force("Subtle")
bands = motion.row_bands(tbl)
check("the rows of a table are its bands, top to bottom", len(bands) == 4 and all(h > 0 for _t, h in bands) and bands[1][0] == bands[0][0] + bands[0][1], bands)
check("an open child in a tree counts as a row", len(motion.row_bands(tree)) == 2, motion.row_bands(tree))
check("under Subtle, nothing flies in (it is decoration: Lively's)", motion.reveal(tbl) is None and tbl.viewport().graphicsEffect() is None)
motion.force("Lively")
eff = motion.reveal(tbl); app.processEvents()
check("reveal puts its effect on the viewport and keeps a reference to it", eff is not None and tbl.viewport().graphicsEffect() is eff and tbl.viewport()._reveal is eff)
spin(120)
check("the first row leads, the last follows", 0 < eff.progress(0) and eff.progress(0) >= eff.progress(3), (eff.progress(0), eff.progress(3)))
spin(1300)
check("...and it takes itself off when every row has landed", tbl.viewport().graphicsEffect() is None and tbl.viewport()._reveal is None)
bars = BarList(); bars.resize(300, 120); bars.show(); bars.set_rows([("a", 100.0, ""), ("b", 50.0, "")]); spin(1000)
bars.replay(); app.processEvents()
check("Availability fills again on replay, its rows fading in", bars.grown < 1.0 and bars.graphicsEffect() is not None and bars.bands() == [(6, 26), (36, 26)], bars.grown)
spin(1300); bars.replay(); bars.replay(); spin(1300)
check("...replaying again after it finished is safe, and the bars end full", bars.grown == 1.0 and bars.graphicsEffect() is None, bars.grown)
from ui.nav import NavStack
nav = NavStack("Toner"); a, b = QWidget(), QWidget(); hits = []
b.entered = lambda: hits.append("b")
nav.addTab(a, "A", None, "Watch"); nav.addTab(b, "B", None, "Watch"); nav.resize(1000, 600); nav.show(); app.processEvents()
nav.setCurrentWidget(b); app.processEvents()
check("the sidebar tells a section it came into view", hits == ["b"], hits)
nav.setCurrentWidget(a); nav.setCurrentWidget(b); app.processEvents()
check("...each time", hits == ["b", "b"], hits)
d2 = DashboardTab(); d2.resize(1200, 760); d2.show(); app.processEvents(); d2.entered(); app.processEvents()
check("the Overview's entrance: the problems fly in and the bars fill", d2.attention.viewport().graphicsEffect() is not None and d2.bars.grown < 1.0)
spin(1500)
motion.force(None)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

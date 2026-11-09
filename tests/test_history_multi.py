# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, types
pass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\hm%d.db").replace("\\", os.sep) % int(time.time())
from core import db
db.init()
from drivers.base import Result
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
db.save_device(dict(name="sw1", vendor="cisco", host="10.0.0.1", port=0, platform="", username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))
for i in range(8):
    db.save_run([Result("sw1", "cpu", "OK", f"{20+i*5}%", numeric=20.0+i*5), Result("sw1", "memory", "OK", f"{50+i}%", numeric=50.0+i),
                 Result("sw1", "uptime", "OK", "x", numeric=100.0*(i+1)), Result("sw1", "bgp", "OK", "2/2", numeric=2.0)])
    time.sleep(1.05)
import ui.history as H
w = H.HistoryTab(); w.resize(1100, 600)
def lines():
    """Over time's line panels (each drawn) as their chart stacks: one per scale."""
    for p in w.panels.panels:
        p.drawn or p.draw()
    return [p.stack for p in w.panels.panels if hasattr(p, "stack")]
names = lambda: [[c for c, _ in st_.series] for st_ in lines()]
check("device listed, first check ticked by default", w.dev.currentText() == "sw1" and len(w.chk.selected()) == 1, w.chk.selected())
check("one series drawn", [len(st_.series[0][1]) for st_ in lines()] == [8], names())
first = w.chk.selected()[0]
check("all of the device's checks are offered", set(w.check_keys) == {"CPU", "Memory", "Uptime", "BGP"}, list(w.check_keys))
w.chk.set_selected(["CPU", "Memory"]); w.chk._toggled()
check("two checks drawn together", names() == [["cpu", "memory"]], names())
check("thresholds only for a single check", lines()[0].th is None)
check("button text lists the ticked checks", w.chk.text() == "CPU, Memory", w.chk.text())
w.chk.set_selected(["CPU", "Memory", "Uptime", "BGP"]); w.chk._toggled()
check("button text lists four short names", w.chk.text() == "BGP, CPU, Memory, Uptime", w.chk.text())
check("a panel per check, lines of one scale together, uptime as its table", names() == [["bgp"], ["cpu", "memory"]]
      and [p.kind for p in w.panels.panels] == ["line", "line", "uptime"], ([p.kind for p in w.panels.panels], names()))
w.chk.set_selected(["CPU"]); w.chk._toggled()
check("back to one check keeps its thresholds", names() == [["cpu"]] and lines()[0].th is not None and lines()[0].th["warn"] == 70, lines()[0].th)
w.chk.clear()
check("nothing ticked -> no panels", w.panels.panels == [])
w.chk.set_selected(["Memory", "BGP"]); w.fill_checks("sw1")
check("ticks survive a refresh of the list", sorted(w.chk.selected()) == ["BGP", "Memory"], w.chk.selected())
w.refresh()
check("ticks survive a full history refresh", sorted(w.chk.selected()) == ["BGP", "Memory"], w.chk.selected())
cs = H.ChartStack(); cs.resize(1100, 600)                  # the chart stack itself, as the line panels use it
cs.set_data([("2026-01-01 10:00:00", 5.0), ("2026-01-02 10:00:00", 9.0)], "uptime", None)
check("old single-check API still works", len(cs.series) == 1 and cs.grab() is not None)
# a check that exists only for some runs is aligned on the shared time axis
cs.set_series([("cpu", [("a", 10.0), ("b", 20.0), ("c", 30.0)]), ("memory", [("b", 50.0), ("c", 60.0)])]); cs.grab()
check("series with different run counts draw", len(cs.series) == 2)
print("== separate charts per scale, and hover values")
from PySide6.QtCore import QPointF, Qt, QEvent
from PySide6.QtGui import QMouseEvent, QPointingDevice
cs.resize(1100, 900); cs.show()
TH = db.get_thresholds()
put = lambda *checks, th=None: (cs.set_series([(c, db.series("sw1", c)) for c in checks], th), QApplication.processEvents())
put("cpu", "memory", "uptime", "bgp")
titles = [c.title for c in cs.charts]
check("percentages share a chart; other scales get their own", titles[:2] == ["Percent", "Values up to 10"] and len(titles) == 3 and titles[2].startswith("Up for"), titles)       # uptime: its own chart, captioned
check("each check is in the chart that fits it", sorted(sorted(s[0] for s in c.series) for c in cs.charts) == [["bgp"], ["cpu", "memory"], ["uptime"]], [[s[0] for s in c.series] for c in cs.charts])
col = {s[0]: s[2].name() for c in cs.charts for s in c.series}
check("every check has its own colour", len(set(col.values())) == 4, col)
put("cpu", "memory")
check("only percentages -> one chart, no scale title", len(cs.charts) == 1 and cs.charts[0].title == "")
put("uptime")
check("a single check -> one chart (uptime says how long it has been up)", len(cs.charts) == 1 and cs.charts[0].title.startswith("Up for"))
put()
check("nothing ticked -> one empty chart with the prompt", len(cs.charts) == 1 and cs.charts[0].series == [] and cs.requested == 0)

put("cpu", "memory")
ch = cs.charts[0]; ch.grab()
n = len(ch.stamps)
at = lambda i, y=50: ch.vb.mapViewToScene(QPointF(i, y))                  # a point over run i, as the mouse would be
ch._moved(at(2))
check("hovering picks the nearest run", ch.hover == 2, ch.hover)
rows = ch.hover_rows()
check("the readout lists each measured value", [(a, b) for a, b, _ in rows] == [("CPU", "30%"), ("Memory", "52%")], rows)
check("with a guide line and the readout showing", ch.guide.isVisible() and ch.readout.isVisible() and "CPU  30%" in ch.readout.toPlainText())
ch._moved(at(-0.4)); check("left edge = first run", ch.hover == 0 and ch.hover_rows()[0][1] == "20%")
ch._moved(at(n - 1 + 0.2)); check("right edge = last run", ch.hover == n - 1 and ch.hover_rows()[0][1] == "55%")
ch._moved(QPointF(-5000, -5000)); check("pointer far outside the plot clears it", ch.hover is None and ch.hover_rows() == [] and not ch.readout.isVisible())
ch._moved(at(3)); ch.grab().save(SP + (r"\history_hover.png").replace("\\", os.sep))
ch.leaveEvent(None); check("leaving the chart clears it", ch.hover is None)

print("== zooming, the legend and the hint")
check("pyqtgraph's own menu and button are switched off (their words are not Toner's)", not ch.vb.menuEnabled() and not ch.plot.plotItem.buttonsHidden is False)
check("only time zooms; the scale stays put", ch.vb.state["mouseEnabled"] == [True, False] and ch.vb.state["mouseMode"] == ch.vb.RectMode)
ch.vb.setXRange(1, 3, padding=0)                                          # what dragging across runs 1 to 3 does
check("dragging zooms in on a stretch of time", abs(ch.vb.viewRange()[0][0] - 1) < 0.01 and abs(ch.vb.viewRange()[0][1] - 3) < 0.01, ch.vb.viewRange()[0])
ch._clicked(types.SimpleNamespace(double=lambda: True))
check("double-clicking shows the whole stretch again", ch.vb.viewRange()[0][0] < 0 and ch.vb.viewRange()[0][1] > n - 1.5, ch.vb.viewRange()[0])
names = [ch.legend_lay.itemAt(i).widget() for i in range(ch.legend_lay.count())]
check("each check has a name above the chart", [b.text() for b in names] == ["CPU", "Memory"], [b.text() for b in names])
names[1].click()
check("clicking a name hides that check, and the readout leaves it out", not ch.curves["memory"].isVisible()
      and (ch._moved(at(2)) or True) and [a for a, _b, _c in ch.hover_rows()] == ["CPU"])
names[1].click()
check("clicking it again shows it", ch.curves["memory"].isVisible())
check("the hint says how, in the agreed words", cs.hint is not None and cs.hint.text()
      == "Drag across a graph to zoom in. Double-click to zoom back out. Click a name in the legend to hide it.")
put("cpu", th=TH["cpu"])
one = cs.charts[0]
lines = sorted(round(i.value()) for i in one.plot.items() if isinstance(i, H.pg.InfiniteLine) and i.angle == 0)
check("one percentage check shows its WARN and FAIL lines", lines == sorted([one.th["warn"], one.th["fail"]]), (lines, one.th))
put()
check("nothing ticked: no hint", cs.hint is None)
check("value formats", H.fmt_value("cpu", 85.0) == "85%" and H.fmt_value("memory", 85.46) == "85.5%" and H.fmt_value("temperature", 72.0) == "72 °C"
      and H.fmt_value("uptime", 100.0) == "4:04:00:00" and H.fmt_value("bgp", 2.0) == "2" and H.fmt_value("port errors", 10234.0) == "10,234" and H.fmt_value("channel util (ng)", 41.5) == "41.5%",
      [H.fmt_value("cpu", 85.0), H.fmt_value("temperature", 72.0), H.fmt_value("uptime", 100.0), H.fmt_value("bgp", 2.0), H.fmt_value("port errors", 10234.0)])
w.chk.set_selected(["CPU", "Memory", "Uptime", "BGP"]); w.chk._toggled(); QApplication.processEvents()
w.grab().save(SP + (r"\history_stack.png").replace("\\", os.sep))


print("== The picker lists shown names")
db.save_device(dict(name="pk", vendor="fortinet", host="10.0.0.2", port=0, platform="", username="u", site="default", verify_ssl=0, ha_expected=0,
                    enabled=1, location="", details="", folder_id=None))
db.save_run([Result("pk", c, "OK", "", numeric=n) for c, n in (("resources", 3.0), ("certificate", 30.0), ("certificate :443", 20.0),
                                                                 ("certificates", 10.0), ("ha", 1.0), ("ha sync", 1.0), ("cpu", 12.0))])
w.refresh(); w.dev.setCurrentIndex(w.dev.findData("pk"))
check("one Certificates, one HA, no Resources", sorted(w.check_keys) == ["CPU", "Certificates", "HA"], list(w.check_keys))
w.chk.set_selected(["Certificates", "HA"]); w.chk._toggled()
panels = {p.kind: sorted(p.checks) for p in w.panels.panels}
check("ticking them draws every certificate source and both HA checks", panels == {"certs": ["certificate", "certificate :443", "certificates"],
      "ha": ["ha", "ha sync"]}, panels)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

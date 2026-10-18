# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
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
check("device listed, first check ticked by default", w.dev.currentText() == "sw1" and len(w.chk.selected()) == 1, w.chk.selected())
check("one series drawn", len(w.chart.series) == 1 and len(w.chart.series[0][1]) == 8, [len(s[1]) for s in w.chart.series])
first = w.chk.selected()[0]
check("all of the device's checks are offered", set(w.check_keys) == {"CPU", "Memory", "Uptime", "BGP"}, list(w.check_keys))
w.chk.set_selected(["CPU", "Memory"]); w.chk._toggled()
check("two checks drawn together", [c for c, _ in w.chart.series] == ["cpu", "memory"], [c for c, _ in w.chart.series])
check("thresholds only for a single check", w.chart.th is None)
check("button text lists the ticked checks", w.chk.text() == "CPU, Memory", w.chk.text())
w.chk.set_selected(["CPU", "Memory", "Uptime", "BGP"]); w.chk._toggled()
check("button text lists four short names", w.chk.text() == "BGP, CPU, Memory, Uptime", w.chk.text())
check("mixed units draw (relative scale)", len(w.chart.series) == 4)
w.chart.grab().save(SP + (r"\history_multi.png").replace("\\", os.sep))
w.chk.set_selected(["Uptime", "BGP"]); w.chk._toggled(); w.chart.grab()
check("two non-percent checks share an axis", len(w.chart.series) == 2)
w.chk.set_selected(["CPU"]); w.chk._toggled()
check("back to one check keeps its thresholds", len(w.chart.series) == 1 and w.chart.th is not None and w.chart.th["warn"] == 70, w.chart.th)
w.chart.grab().save(SP + (r"\history_single.png").replace("\\", os.sep))
w.chk.clear()
check("nothing ticked -> prompt, no series", w.chart.series == [] and w.chart.requested == 0)
w.chart.grab()
w.chk.set_selected(["Memory", "BGP"]); w.fill_checks("sw1")
check("ticks survive a refresh of the list", sorted(w.chk.selected()) == ["BGP", "Memory"], w.chk.selected())
w.refresh()
check("ticks survive a full history refresh", sorted(w.chk.selected()) == ["BGP", "Memory"], w.chk.selected())
w.chart.set_data([("2026-01-01 10:00:00", 5.0), ("2026-01-02 10:00:00", 9.0)], "uptime", None)
check("old single-check API still works", len(w.chart.series) == 1 and w.chart.grab() is not None)
# a check that exists only for some runs is aligned on the shared time axis
w.chart.set_series([("cpu", [("a", 10.0), ("b", 20.0), ("c", 30.0)]), ("memory", [("b", 50.0), ("c", 60.0)])]); w.chart.grab()
check("series with different run counts draw", len(w.chart.series) == 2)
print("== separate charts per scale, and hover values")
from PySide6.QtCore import QPointF, Qt, QEvent
from PySide6.QtGui import QMouseEvent, QPointingDevice
w.resize(1100, 900); w.show()
w.chk.set_selected(["CPU", "Memory", "Uptime", "BGP"]); w.chk._toggled(); QApplication.processEvents()
titles = [c.title for c in w.chart.charts]
check("percentages share a chart; other scales get their own", titles[:2] == ["Percent", "Values up to 10"] and len(titles) == 3 and titles[2].startswith("Up for"), titles)       # uptime: its own chart, captioned
check("each check is in the chart that fits it", sorted(sorted(s[0] for s in c.series) for c in w.chart.charts) == [["bgp"], ["cpu", "memory"], ["uptime"]], [[s[0] for s in c.series] for c in w.chart.charts])
col = {s[0]: s[2].name() for c in w.chart.charts for s in c.series}
check("every check has its own colour", len(set(col.values())) == 4, col)
w.chk.set_selected(["CPU", "Memory"]); w.chk._toggled()
check("only percentages -> one chart, no scale title", len(w.chart.charts) == 1 and w.chart.charts[0].title == "")
w.chk.set_selected(["Uptime"]); w.chk._toggled()
check("a single check -> one chart (uptime says how long it has been up)", len(w.chart.charts) == 1 and w.chart.charts[0].title.startswith("Up for"))
w.chk.set_selected([]); w.chk._toggled()
check("nothing ticked -> one empty chart with the prompt", len(w.chart.charts) == 1 and w.chart.charts[0].series == [] and w.chart.requested == 0)

w.chk.set_selected(["CPU", "Memory"]); w.chk._toggled(); QApplication.processEvents()
ch = w.chart.charts[0]; ch.grab()
r = ch._geom["rect"]; n = len(ch._geom["stamps"])
dev = QPointingDevice.primaryPointingDevice()
def move(x, y):
    ev = QMouseEvent(QEvent.Type.MouseMove, QPointF(x, y), QPointF(x, y), Qt.MouseButton.NoButton, Qt.MouseButton.NoButton, Qt.KeyboardModifier.NoModifier, dev)
    ch.mouseMoveEvent(ev)
move(ch._geom["x"](ch._geom["stamps"][2]), r.center().y())
check("hovering picks the nearest run", ch.hover == 2, ch.hover)
rows = ch.hover_rows()
check("tooltip lists each measured value", [(a, b) for a, b, _ in rows] == [("CPU", "30%"), ("Memory", "52%")], rows)
move(r.left() + 1, r.center().y()); check("left edge = first run", ch.hover == 0 and ch.hover_rows()[0][1] == "20%")
move(r.right() + 5, r.center().y()); check("right edge = last run", ch.hover == n - 1 and ch.hover_rows()[0][1] == "55%")
move(r.center().x(), r.bottom() + 200); check("pointer far outside the plot clears it", ch.hover is None and ch.hover_rows() == [])
move(r.center().x(), r.center().y()); ch.grab().save(SP + (r"\history_hover.png").replace("\\", os.sep))
ch.leaveEvent(None); check("leaving the chart clears it", ch.hover is None)
check("value formats", H.fmt_value("cpu", 85.0) == "85%" and H.fmt_value("memory", 85.46) == "85.5%" and H.fmt_value("temperature", 72.0) == "72 °C"
      and H.fmt_value("uptime", 100.0) == "4:04:00:00" and H.fmt_value("bgp", 2.0) == "2" and H.fmt_value("port errors", 10234.0) == "10,234" and H.fmt_value("channel util (ng)", 41.5) == "41.5%",
      [H.fmt_value("cpu", 85.0), H.fmt_value("temperature", 72.0), H.fmt_value("uptime", 100.0), H.fmt_value("bgp", 2.0), H.fmt_value("port errors", 10234.0)])
w.chk.set_selected(["CPU", "Memory", "Uptime", "BGP"]); w.chk._toggled(); QApplication.processEvents()
w.grab().save(SP + (r"\history_stack.png").replace("\\", os.sep))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

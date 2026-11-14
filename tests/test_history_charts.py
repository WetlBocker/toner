# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). History: the chart follows the kind of data.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\hc%d.db").replace("\\", os.sep) % int(time.time())
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
import ui.history as H
from core.chartkinds import chart_kind
from ui import chartspec, webchart

row = lambda **k: {"numeric": None, "value": "", "status": "OK", **k}
check("numbers over several times -> line", chart_kind([row(numeric=1.0, t="a"), row(numeric=2.0, t="b")]) == "line")
check("numbers at one time -> bar", chart_kind([row(numeric=1.0), row(numeric=2.0)]) == "bar")
check("plain-word values with statuses -> status", chart_kind([row(value="connected"), row(value="", status="FAIL")]) == "status")
check("text values -> table", chart_kind([row(value="7.1.2"), row(value="Catalyst 9300")]) == "table")
check("a firmware check with a WARN is still a table", chart_kind([row(value="7.1.2"), row(value="6.0", status="WARN")]) == "table")
check("model names are text -> table", chart_kind([row(value="Catalyst"), row(value="Nexus")]) == "table")
check("licence words are text -> table", chart_kind([row(value="Valid"), row(value="Expired")]) == "table")
check("up/down without numbers -> status", chart_kind([row(value="up"), row(value="down")]) == "status")
check("Enabled -> status", chart_kind([row(value="Enabled")]) == "status")
check("no rows -> table", chart_kind([]) == "table")

for i in range(3):
    db.save_device(dict(name=f"sw{i}", vendor="cisco", host=f"10.0.0.{i}", port=0, platform="", username="u", site="default", verify_ssl=0,
                        ha_expected=0, enabled=1, location="", details="", folder_id=None))
db.save_run([Result(f"sw{i}", "cpu", "OK", f"{20+i*5}%", numeric=20.0 + i * 5) for i in range(3)]
            + [Result(f"sw{i}", "link", "OK" if i < 2 else "FAIL", "connected" if i < 2 else "down") for i in range(3)]
            + [Result(f"sw{i}", "firmware", "OK", f"7.{i}.2") for i in range(3)])
w = H.HistoryTab(); w.resize(1100, 600)
p = webchart.palette()

def pick(label):
    w.compare_check.setCurrentIndex(w.compare_check.findText(label))
    w.draw_compare()

labels = [w.compare_check.itemText(i) for i in range(w.compare_check.count())]
check("every stored check is offered, text ones too", {"CPU", "Link", "Firmware"} <= set(labels), labels)
pick("CPU")
check("a number per device -> a gauge each", sorted(g.builder(p)["series"][0]["data"][0]["value"] for g in w.compare_gauges) == [20.0, 25.0, 30.0]
      and w.compare_table is None)
pick("Link")
t = w.compare_table
check("statuses only -> the health table", not w.compare_gauges and t is not None and t.model().rowCount() == 3
      and sorted(r["status"] for r in t.rows) == ["FAIL", "OK", "OK"])
pick("Firmware")
t = w.compare_table
check("a firmware version -> a table, no chart", not w.compare_gauges and t is not None)
check("table: Device, Version", [t.model().headerData(i, H.Qt.Orientation.Horizontal) for i in range(2)] == ["Device", "Version"])
check("table: a row per device with its version", sorted(r["version"] for r in t.rows) == ["7.0.2", "7.1.2", "7.2.2"])
pick("CPU")
check("back to gauges", len(w.compare_gauges) == 3)

print("== Over time")
for v, st in (("7.0.2", "OK"), ("7.0.2", "OK"), ("7.1.0", "WARN")):
    db.save_run([Result("sw0", "firmware", st, v), Result("sw0", "link", st, "connected" if st == "OK" else "down"), Result("sw0", "cpu", "OK", "5%", numeric=5.0)])
    time.sleep(1.05)
w.refresh(); w.dev.setCurrentIndex(w.dev.findData("sw0"))
def panels():
    """Over time's panels, each drawn."""
    for pn in w.panels.panels:
        pn.drawn or pn.draw()
    return w.panels.panels
w.chk.set_selected(["Link"]); w.chk._toggled()
pn = panels()
opt = pn[0].chart._builder(p) if len(pn) == 1 and hasattr(pn[0], "chart") else {}
check("Over time: a status check -> a status heatmap, a square taking its worst status", pn[0].kind == "heatmap"
      and opt.get("series", [{}])[0].get("type") == "heatmap" and [d["name"] for d in opt["series"][0]["data"]] == ["WARN"], opt.get("series"))
w.chk.set_selected(["Firmware"]); w.chk._toggled()
pn = panels()
t = getattr(pn[0], "table", None)
check("Over time: a text check -> the change table, no chart", t is not None and not hasattr(pn[0], "chart"))
rows_ = [t.model().index(i, 2).data() for i in range(t.model().rowCount())]
check("two versions over time -> two change rows, newest first", rows_ == ["7.1.0", "7.0.2"], rows_)
w.chk.set_selected(["Firmware", "Link"]); w.chk._toggled()
check("Over time: text and status ticked -> a panel each, in the picker's order", [pn.kind for pn in panels()] == ["table", "heatmap"],
      [pn.kind for pn in panels()])
w.chk.set_selected(["CPU"]); w.chk._toggled()
pn = panels()
check("Over time: a number -> the line chart as before", [pn_.kind for pn_ in pn] == ["line"] and len(pn[0].stack.series) == 1)
check("the check picker's tooltip", w.compare_check.toolTip() == "The check to chart", w.compare_check.toolTip())

print("== Failures: a cell or a bar lists the rows it counts")
from datetime import datetime as _dt
w.draw_failures()
now = _dt.now()
w.fail_when.clicked.emit({"kind": "series", "value": [now.hour, 0, 1]})
dlg = getattr(w, "_fail_list", None)
cells = lambda t: [[t.item(i, j).text() for j in range(t.columnCount())] for i in range(t.rowCount())] if t else []
day = f"{now:%a} {now.day} {now:%b}"
check("a heatmap cell opens its FAIL and ERROR rows, titled by the day and hour", dlg is not None and dlg.windowTitle() == f"Failures: {day} {now.hour:02d}:00"
      and [dlg.table.horizontalHeaderItem(j).text() for j in range(5)] == ["Time", "Device", "Check", "Status", "Message"]
      and any(r[1] == "sw2" and r[3] == "FAIL" for r in cells(dlg.table)) and all(r[3] in ("FAIL", "ERROR") for r in cells(dlg.table)),
      dlg and (dlg.windowTitle(), cells(dlg.table)))
w.fail_where.clicked.emit({"kind": "series", "dataIndex": 0})
dlg = getattr(w, "_fail_list", None)
check("a device's bar opens that device's rows, titled by its name", dlg is not None and dlg.windowTitle() == "Failures: sw2"
      and cells(dlg.table) and all(r[1] == "sw2" for r in cells(dlg.table)), dlg and (dlg.windowTitle(), cells(dlg.table)))
w.fail_when.clicked.emit({"kind": "series", "value": [(now.hour + 12) % 24, 0, 0]})
check("...an empty cell opens nothing new", dlg is not None and getattr(w, "_fail_list", None) is dlg)
w.fail_period.setCurrentIndex(next(i for i in range(w.fail_period.count()) if w.fail_period.itemData(i) > 30))     # a grid of weeks
check("a long period is a grid of weeks", not w._fail_grid.hourly)
w.fail_when.clicked.emit({"kind": "series", "value": [now.weekday(), 0, 1]})
dlg = getattr(w, "_fail_list", None)
check("a week grid's square is titled by its own date, not the week and the weekday", dlg is not None and dlg.windowTitle() == f"Failures: {day}",
      dlg and dlg.windowTitle())
print("== Failures follows the search box")
w.find.setText("")
w.chart_tabs.setCurrentIndex(2)
app.processEvents()
check("(every device's failures to start with)", "sw2" in {r["device"] for _t, r in w._fail_rows}, {r["device"] for _t, r in w._fail_rows})
w.find.setText("sw0")
app.processEvents()
check("a search narrows the Failures tab while it is shown", "sw2" not in {r["device"] for _t, r in w._fail_rows}, {r["device"] for _t, r in w._fail_rows})
w.find.setText("")
app.processEvents()
check("...and clearing it brings them back", "sw2" in {r["device"] for _t, r in w._fail_rows})

print("== the Value column sorts by the number, not its text")
from PySide6.QtCore import Qt as _Qt
db.save_device(dict(name="sv1", vendor="cisco", host="10.9.9.9", port=0, platform="cisco_ios", username="u", site="default", verify_ssl=0, ha_expected=0,
                    enabled=1, location="", details="", folder_id=None))
db.save_run([Result("sv1", "cpu", "OK", "9%", numeric=9.0), Result("sv1", "memory", "FAIL", "100%", numeric=100.0), Result("sv1", "sessions", "OK", "20%", numeric=20.0)])
w.show()                                                 # (a hidden page reads its rows when it is shown)
w.refresh()
app.processEvents()
w.model.sort(4, _Qt.SortOrder.AscendingOrder)
order = [c["label"] for d in w.model.devs if d["label"] == "sv1" for c in d["checks"]]
check("9% before 20% before 100%", order == ["CPU", "Sessions", "Memory"], order)

print("== a table left empty by the search or the time range says why")
w.find.setText("zz-no-such-device")
app.processEvents()
check("a search that matches nothing: Inventory's words", not w.empty.isHidden() and w.empty.head.text() == "Nothing matches"
      and w.empty.sub.text() == "Clear the search box or the filter to see every device", (w.empty.isHidden(), w.empty.head.text()))
w.find.setText("")
app.processEvents()
check("...and it goes when rows are back", w.empty.isHidden())
from datetime import date as _date
w.range.set_dates(_date(2001, 1, 1), _date(2001, 1, 2))
check("a range with no results says so", not w.empty.isHidden() and w.empty.head.text() == "No results in this time range"
      and w.empty.sub.text() == "Choose a longer range to see older results", (w.empty.isHidden(), w.empty.head.text(), w.range.describe()))
w.range.set_hours(8)
check("...and back in range the hint goes", w.empty.isHidden())
w.range.set_hours(1)
check("one hour is 'Last 1 hour', in the box and in the reports", w.range.describe() == "Last 1 hour" and w.range.hours.text() == "Last 1 hour",
      (w.range.describe(), w.range.hours.text()))
w.range.set_hours(8)
check("...and eight are 'Last 8 hours'", w.range.describe() == "Last 8 hours" and w.range.hours.text() == "Last 8 hours")

print("== Over time keeps its panels while only the search box changes")
w.chart_tabs.setCurrentIndex(0)
w.dev.setCurrentIndex(w.dev.findData("sw0"))
w.chk.set_selected(["CPU"]); w.chk._toggled()
kept = list(w.panels.panels)
w.find.setText("sw")
app.processEvents()
check("the same device and checks: the panels are not rebuilt", w.panels.panels == kept and kept)
w.find.setText("")
app.processEvents()
w.refresh()
check("a refresh with nothing new stored keeps them too (an Inventory change, a playbook)", w.panels.panels == kept)

print("== Over time after a run: drawn again, with what the person had zoomed, hidden, selected and scrolled to")
from datetime import datetime as _dt, timedelta as _td
def run_at(minutes_ago, n):
    rid = db.save_run([Result("sv1", "cpu", "OK", f"{10 + n}%", numeric=10.0 + n), Result("sv1", "memory", "OK", f"{40 + n}%", numeric=40.0 + n),
                       Result("sv1", "services", "FAIL" if n == 2 else "OK", "1 stopped" if n == 2 else "all running"),
                       ])
    with db.connect() as c:
        c.execute("UPDATE runs SET started_at=? WHERE id=?", ((_dt.now() - _td(minutes=minutes_ago)).strftime("%Y-%m-%d %H:%M:%S"), rid))
for n, m in enumerate((50, 40, 30, 20, 10)):
    run_at(m, n)
w.refresh(); app.processEvents()
w.dev.setCurrentIndex(w.dev.findData("sv1"))
w.chk.set_selected(["CPU", "Memory", "Services"]); w.chk._toggled(); app.processEvents()
P = w.panels
for p_ in P.panels:
    if not p_.drawn: p_.draw()
app.processEvents()
lines = next(p_ for p_ in P.panels if p_.kind == "line")
heat = next(p_ for p_ in P.panels if p_.kind == "heatmap")
chart = lines.stack.charts[0]
check("(the test's panels: CPU and Memory on one graph, then a heatmap)", len(chart.stamps) >= 5 and set(chart.curves) == {"cpu", "memory"}
      and [p_.kind for p_ in P.panels] == ["line", "heatmap"], ([p_.kind for p_ in P.panels], chart.stamps))
chart.plot.setXRange(1, 3, padding=0); app.processEvents()
a, b = chart.stamps[1], chart.stamps[3]
next(chart.legend_lay.itemAt(i).widget() for i in range(chart.legend_lay.count()) if chart.legend_lay.itemAt(i).widget().text() == "Memory").setChecked(False)
failed = next(t for t, r in heat.rows if r["status"] == "FAIL")
x, y = heat.grid.cell(failed)
P._square(heat, {"kind": "series", "value": [x, y, 2]})
check("(a square is selected: its readings are listed)", not heat.detail.isHidden() and heat.detail.model().rowCount() >= 1)
bar = P.verticalScrollBar()
bar.setValue(bar.maximum()); app.processEvents()
top = bar.value()
before = list(P.panels)
run_at(1, 7)
w.refresh(); app.processEvents()
check("new readings: the panels are drawn again", P.panels != before and len(P.panels) == 2)
lines2 = next(p_ for p_ in P.panels if p_.kind == "line")
heat2 = next(p_ for p_ in P.panels if p_.kind == "heatmap")
check("...those drawn before are drawn at once, and the page stays where it was scrolled to", all(p_.drawn for p_ in P.panels)
      and top > 0 and bar.value() == top, (top, bar.value(), bar.maximum()))
chart2 = lines2.stack.charts[0]
(x0, x1), _yr = chart2.vb.viewRange()
check("...a graph that was zoomed in shows the same stretch of time", chart2 is not chart and len(chart2.stamps) == len(chart.stamps) + 1
      and chart2.stamps[round(x0)] == a and chart2.stamps[round(x1)] == b, (chart2.stamps, x0, x1, a, b))
check("...a name hidden in the legend stays hidden", not chart2.curves["memory"].isVisible() and chart2.curves["cpu"].isVisible())
check("...and the selected square still lists its readings", not heat2.detail.isHidden() and heat2.detail.model().rowCount() >= 1 and heat2.text.isHidden())
w.dev.setCurrentIndex(w.dev.findData("sw0")); app.processEvents()
w.dev.setCurrentIndex(w.dev.findData("sv1")); app.processEvents()
for p_ in P.panels:
    if not p_.drawn: p_.draw()
(x0, x1), _yr = next(p_ for p_ in P.panels if p_.kind == "line").stack.charts[0].vb.viewRange()
check("another device and back starts afresh: the whole stretch of time", x0 < 0 and x1 > len(chart2.stamps) - 1.5, (x0, x1))

print("== Failures at 30 days: every date has a row tall enough to read, and the page scrolls")
from PySide6.QtWidgets import QScrollArea as _QScrollArea
w.chart_tabs.setCurrentIndex(2)
w.fail_period.setCurrentIndex(w.fail_period.findData(30)); app.processEvents()
rows30 = len(w._fail_grid.rows)
check("the heatmap is as tall as its dates need (16 px a row)", rows30 >= 30 and w.fail_when.minimumHeight() >= 16 * rows30, (rows30, w.fail_when.minimumHeight()))
check("...inside a scrolling page, so the window is not pushed taller", isinstance(w.chart_tabs.widget(2), _QScrollArea)
      and w.chart_tabs.minimumSizeHint().height() < 500, w.chart_tabs.minimumSizeHint().height())
w.fail_period.setCurrentIndex(w.fail_period.findData(7)); app.processEvents()
check("7 days: short again", w.fail_when.minimumHeight() < 16 * rows30, w.fail_when.minimumHeight())
scale = w.fail_when._builder(p)["visualMap"]
check("the colour scale says what its ends mean: the most in one square, and none", scale.get("text") == [str(scale["max"]), "0"], scale.get("text"))

print("== a long device name on a dial or a ring is cut in the middle to fit its tile, whole on hover")
from PySide6.QtGui import QFont as _QFont, QFontMetrics as _QFontMetrics
LONGNAME = "edge-switch-building-7-floor-3-rack-12.corp.example.com"
db.save_device(dict(name=LONGNAME, vendor="cisco", host="10.0.9.9", port=0, platform="", username="u", site="default", verify_ssl=0,
                    ha_expected=0, enabled=1, location="", details="", folder_id=None))
db.save_run([Result(LONGNAME, "cpu", "OK", "33%", numeric=33.0), Result(LONGNAME, "interfaces", "WARN", "40/48")])
w.refresh(); app.processEvents()
def px(text, size, bold=False):
    f = _QFont(app.font()); f.setPixelSize(size); f.setBold(bold)
    return _QFontMetrics(f).horizontalAdvance(text)
w.chart_tabs.setCurrentIndex(1)
pick("CPU")
g = next(g for g in w.compare_gauges if g.name.startswith(LONGNAME))
opt = g.builder(p)
short_opt = next(g for g in w.compare_gauges if g.name.startswith("sw0")).builder(p)
shown = opt["series"][0]["data"][0]["name"]
check("the dial's name fits its 210 px tile, keeping both ends", shown != LONGNAME and shown.startswith("edge-") and shown.endswith(".com")
      and px(shown, 12) <= 210, (shown, px(shown, 12)))
check("...and hovering the dial says the whole name", opt.get(chartspec.TIP) == LONGNAME and chartspec.TIP not in short_opt, opt.get(chartspec.TIP))
short = short_opt
check("a name that fits is left alone", short["series"][0]["data"][0]["name"] == "sw0")
from PySide6.QtCore import Qt as _Qt2
_label = "nas-01 (Acme Corporation of North America) / tank/backups"            # as Global names another organization's dataset
_cut = webchart.fit_text(_label, px(_label, 12) * 2 // 3)
check("a dial named 'device (organization) / item' keeps the device's start and the item's end when cut",
      _cut != _label and _cut.startswith("nas-01 (") and _cut.endswith("tank/backups") and px(_cut, 12) <= px(_label, 12) * 2 // 3, _cut)
pick("Interfaces")
r_ = next(r_ for r_ in w.compare_rings if r_.name == LONGNAME)
opt = r_.builder(p)
check("the ring's title fits its 240 px tile", opt["title"]["text"] != LONGNAME and opt["title"]["text"].endswith(".com")
      and px(opt["title"]["text"], 13, True) <= 240, (opt["title"]["text"], px(opt["title"]["text"], 13, True)))
check("...and hovering a segment names the device too", LONGNAME in opt["tooltip"]["formatter"] and "{b}" in opt["tooltip"]["formatter"], opt["tooltip"])

print("== WAN usage is a percentage")
check("is_percent", H.is_percent("wan usage") and H.is_percent("wan usage (Gi1)"))
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

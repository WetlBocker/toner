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
from ui import chartspec, webchart

row = lambda **k: {"numeric": None, "value": "", "status": "OK", **k}
check("numbers over several times -> line", H.chart_kind([row(numeric=1.0, t="a"), row(numeric=2.0, t="b")]) == "line")
check("numbers at one time -> bar", H.chart_kind([row(numeric=1.0), row(numeric=2.0)]) == "bar")
check("plain-word values with statuses -> status", H.chart_kind([row(value="connected"), row(value="", status="FAIL")]) == "status")
check("text values -> table", H.chart_kind([row(value="7.1.2"), row(value="Catalyst 9300")]) == "table")
check("a firmware check with a WARN is still a table", H.chart_kind([row(value="7.1.2"), row(value="6.0", status="WARN")]) == "table")
check("model names are text -> table", H.chart_kind([row(value="Catalyst"), row(value="Nexus")]) == "table")
check("licence words are text -> table", H.chart_kind([row(value="Valid"), row(value="Expired")]) == "table")
check("up/down without numbers -> status", H.chart_kind([row(value="up"), row(value="down")]) == "status")
check("Enabled -> status", H.chart_kind([row(value="Enabled")]) == "status")
check("no rows -> table", H.chart_kind([]) == "table")

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
    return w.compare_chart._builder(p) if w.compare_stack.currentWidget() is w.compare_chart else None

labels = [w.compare_check.itemText(i) for i in range(w.compare_check.count())]
check("every check of the run is offered, text ones too", {"CPU", "Link", "Firmware"} <= set(labels), labels)
opt = pick("CPU")
check("a number per device -> bar chart", opt and opt["series"][0]["type"] == "bar" and "stack" not in opt["series"][0]
      and sorted(d["value"] for d in opt["series"][0]["data"]) == [20.0, 25.0, 30.0], opt)
opt = pick("Link")
check("statuses only -> stacked bars of status counts", opt and all(s.get("stack") for s in opt["series"])
      and {s["name"] for s in opt["series"]} == {"OK", "FAIL"}, opt)
opt = pick("Firmware")
check("a firmware version -> a table, no chart", opt is None and w.compare_stack.currentWidget() is w.compare_table)
t = w.compare_table
check("table: Device, Value, Checked", [t.horizontalHeaderItem(i).text() for i in range(3)] == ["Device", "Value", "Checked"])
check("table: a row per device with its value", t.rowCount() == 3 and sorted(t.item(i, 1).text() for i in range(3)) == ["7.0.2", "7.1.2", "7.2.2"])
check("table: the Checked column holds the run time", t.item(0, 2).text() == db.list_runs()[0]["started_at"])
pick("CPU")
check("back to a chart", w.compare_stack.currentWidget() is w.compare_chart)

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
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

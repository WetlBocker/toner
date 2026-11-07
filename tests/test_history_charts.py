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
check("no rows -> table", H.chart_kind([]) == "table")

for i in range(3):
    db.save_device(dict(name=f"sw{i}", vendor="cisco", host=f"10.0.0.{i}", port=0, platform="", username="u", site="default", verify_ssl=0,
                        ha_expected=0, enabled=1, location="", details="", folder_id=None))
db.save_run([Result(f"sw{i}", "cpu", "OK", f"{20+i*5}%", numeric=20.0 + i * 5) for i in range(3)]
            + [Result(f"sw{i}", "link", "OK" if i < 2 else "FAIL", "connected" if i < 2 else "down") for i in range(3)]
            + [Result(f"sw{i}", "firmware", "OK", f"7.{i}.2") for i in range(3)])
w = H.HistoryTab(); w.resize(1100, 600)
w.runs.selectRow(0); w.show_run()
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
check("table: the Checked column holds the run time", t.item(0, 2).text() == w.runs.item(0, 0).text())
pick("CPU")
check("back to a chart", w.compare_stack.currentWidget() is w.compare_chart)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

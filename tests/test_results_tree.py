# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
pass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\rt%d.db").replace("\\", os.sep) % int(time.time())
from core import db
db.init()
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QCoreApplication
app = QApplication([])
import ui.results as R
from drivers.base import Result

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

for n, v in (("core-sw1", "cisco"), ("edge-fw", "fortinet"), ("udm", "unifi"), ("quiet", "cisco"), ("dead", "cisco")):
    db.save_device(dict(name=n, vendor=v, host="10.0.0.1", port=0, platform="", username="u", site="default", verify_ssl=0,
                        ha_expected=0, enabled=1, location="", details="", folder_id=None))

RES = [Result("core-sw1", "cpu", "OK", "12%"), Result("core-sw1", "memory", "WARN", "85%", "high"), Result("core-sw1", "uptime", "OK", "3d"),
       Result("edge-fw", "wan links", "FAIL", "1/2 up", "down: wan2"), Result("edge-fw", "cpu", "OK", "5%"),
       Result("udm / ap-1", "uptime", "OK", "9d"), Result("udm / ap-1", "temperature", "WARN", "72C"), Result("udm / usw", "cpu", "OK", "3%"),
       Result("quiet", "cpu", "OK", "1%"), Result("quiet", "memory", "OK", "20%"),
       Result("dead", "connection", "ERROR", "", "TimeoutError")]

def fake_run_all(devices, thresholds, on_results=None, workers=10, opts=None):
    for r in RES:
        if on_results: on_results([r])
    return RES
R.run_all = fake_run_all

w = R.ResultsTab(); w.resize(1000, 500)
T = w.table
tops = lambda: [T.topLevelItem(i) for i in range(T.topLevelItemCount())]
w.start()
w.worker.wait(5000); QCoreApplication.processEvents()
for _ in range(50):
    QCoreApplication.processEvents(); time.sleep(0.02)
    if w.run_btn.isEnabled(): break

names = [t.text(0) for t in tops()]
check("one row per device (UniFi sub-devices folded into the controller)", sorted(names) == ["core-sw1", "dead", "edge-fw", "quiet", "udm"], names)
check("worst problems first", names[0] == "dead" and names[1] == "edge-fw" and names[-1] == "quiet", names)
check("what needs a look opens by itself, healthy devices stay collapsed", all(t.isExpanded() == (t.text(0) != "quiet") for t in tops()), [(t.text(0), t.isExpanded()) for t in tops()])
d = {t.text(0): t for t in tops()}
check("device row shows worst status and counts", d["core-sw1"].text(2) == "WARN" and d["core-sw1"].text(1) == "3 checks" and d["core-sw1"].text(4) == "memory: high" and d["core-sw1"].toolTip(4) == "1 WARN", [d["core-sw1"].text(i) for i in range(5)])
check("all-OK device says so", d["quiet"].text(2) == "OK" and d["quiet"].text(4) == "all OK")
check("error device", d["dead"].text(2) == "ERROR" and d["dead"].text(1) == "connection" and d["dead"].text(4) == "TimeoutError" and d["dead"].childCount() == 0 and d["dead"].toolTip(4) == "1 ERROR", d["dead"].text(4))
check("checks are the children, worst first", [d["core-sw1"].child(i).text(1) for i in range(3)] == ["memory", "cpu", "uptime"] and d["core-sw1"].child(0).text(0) == "" and d["core-sw1"].child(0).text(3) == "85%" and d["core-sw1"].child(0).text(4) == "high")
check("UniFi children name their sub-device", sorted(d["udm"].child(i).text(1) for i in range(3)) == ["ap-1: temperature", "ap-1: uptime", "usw: cpu"], [d["udm"].child(i).text(1) for i in range(3)])
check("results still stored flat for reports/notifications", len(w.results) == len(RES) and w.results[0].status == "ERROR")
check("chips count checks, summary counts devices", w.chips.counts == {"OK": 7, "WARN": 2, "FAIL": 1, "ERROR": 1} and w.summary.text() == "5 devices, 11 checks", (w.chips.counts, w.summary.text()))
check("history saved", db.get_setting("retention_days") is not None)

d["quiet"].setExpanded(True)
check("expanding is remembered", "quiet" in w.expanded)
w.repopulate()
d = {t.text(0): t for t in tops()}
check("open device stays open across a rebuild", d["quiet"].isExpanded() and d["edge-fw"].isExpanded())
w.table.expandAll(); check("expand all", all(t.isExpanded() for t in tops()))
w.table.collapseAll(); check("collapse all", not any(t.isExpanded() for t in tops()) and not w.expanded)

w.show_filter("problems")
d = {t.text(0): t for t in tops()}
check("problems only: all-OK device hidden", "quiet" not in d and set(d) == {"core-sw1", "dead", "edge-fw", "udm"}, list(d))
check("problems only: only the problem checks inside", [d["core-sw1"].child(i).text(1) for i in range(d["core-sw1"].childCount())] == ["memory"]
      and d["udm"].childCount() == 1)
w.show_filter("all")

# live updates: arrival order, placeholders for devices still running, open rows stay open
RES2 = list(RES)
class Hold:
    pass
w.last_ran = ["a-dev", "b-dev"]; w.results = []; w._active = True; w.repopulate()
check("while running, devices without results show Running...", [(t.text(0), t.text(2)) for t in tops()] == [("a-dev", "Running..."), ("b-dev", "Running...")])
w.add([Result("b-dev", "cpu", "OK", "1%")])
check("results appear as they arrive, in arrival order", [t.text(0) for t in tops()] == ["a-dev", "b-dev"] and tops()[1].text(2) == "OK" and tops()[0].text(2) == "Running...")
w._active = False; w.repopulate()
check("a device that returned nothing says so after the run", tops()[-1].text(0) == "a-dev" and tops()[-1].text(2) == "No results", [(t.text(0), t.text(2)) for t in tops()])

# real colors in the screenshot
w.last_ran = ["core-sw1", "edge-fw", "udm", "quiet", "dead"]; w.results = list(RES); w._active = False
w.expanded = {"core-sw1", "edge-fw"}; w.repopulate(); w.show()
w.grab().save(SP + (r"\results_tree.png").replace("\\", os.sep))

print("== N/A rows (a check that does not apply)")
NA_RES = [Result("quiet", "bgp", "N/A", "not configured", "BGP is not configured on this device"), Result("quiet", "cpu", "OK", "1%"),
          Result("quiet", "environment", "N/A", "no sensors", "this device reports no fans, power supplies or temperature")]
w.last_ran = ["quiet", "edge-fw"]; w.results = NA_RES + [r for r in RES if r.device == "edge-fw"]; w._active = False
w.show_filter("all"); w.repopulate()
q = next(t for t in tops() if t.text(0) == "quiet")
check("a device with OK and N/A rows is OK, says 'all OK', and lists the N/A rows after the OK one",
      q.text(2) == "OK" and q.text(4) == "all OK" and [q.child(i).text(2) for i in range(q.childCount())] == ["OK", "N/A", "N/A"],
      (q.text(2), q.text(4), [q.child(i).text(2) for i in range(q.childCount())]))
w.show_filter("healthy"); w.repopulate()
check("it counts as healthy", "quiet" in [t.text(0) for t in tops()], [t.text(0) for t in tops()])
w.show_filter("problems"); w.repopulate()
check("and not as a problem", [t.text(0) for t in tops()] == ["edge-fw"], [t.text(0) for t in tops()])
w.show_filter("all")
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

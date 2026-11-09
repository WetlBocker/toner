# Run directly (python tests/test_overtime.py). Over time: a panel per ticked check, each drawn as its own kind, drawn as it scrolls into view.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_os.environ.setdefault("TONER_NO_WEBCHARTS", "1")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "ot%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from datetime import datetime, timedelta
from core import backup, db, display
db.init()
from drivers.base import Result
from PySide6.QtCore import QPoint, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)
from ui import chartspec
from ui.webchart import ChartView
import ui.overtime as O

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

P = chartspec.palette()
drawn = []                                                   # every ChartView.draw, with the option its builder gave
real_draw = ChartView.draw
def counting(self, builder):
    self.opt = builder(P)
    drawn.append(self)
    real_draw(self, builder)
ChartView.draw = counting

dev = lambda name, vendor: db.save_device(dict(name=name, vendor=vendor, host="10.0.0.1", port=0, platform="", username="u", site="default", verify_ssl=0,
                                               ha_expected=0, enabled=1, location="", details="", folder_id=None))
dev("w1", "windows"); dev("w2", "windows"); dev("nas", "truenas")
item = lambda name, numeric=None, status=None, text="", **data: {"name": name, "numeric": numeric, "status": status, "text": text, "data": data}
GB = 1024 ** 3
pending = [item("Cumulative update", text="KB1", severity="Critical", searched="2026-11-08T10:00:00Z"), item("Defender", text="KB2", severity="Critical"),
           item("Office", text="KB3", severity="Important"), item("Driver", text="KB4", severity="")]
runs = [
    [Result("w1", "cpu", "OK", "10%", numeric=10.0), Result("w1", "memory", "OK", "50%", numeric=50.0), Result("w1", "disk health", "OK", "0", numeric=0.0),
     Result("w1", "disks", "OK", "40%", numeric=40.0), Result("w1", "uptime", "OK", "100 h", numeric=100.0), Result("w1", "ha", "OK", "active"),
     Result("w1", "ha sync", "OK", "synced"), Result("w1", "resources", "ERROR", "", "could not read"), Result("w1", "reachability", "OK", "5 ms", numeric=5.0),
     Result("w1", "certificate :443", "OK", "200 days", numeric=200.0, items=[item("w1.example", 200.0, expires="2027-05-27", where="port 443")]),
     Result("w1", "certificates", "OK", "30 days", numeric=30.0, items=[item("CN=w1", 30.0, expires="2026-12-08", where="store")]),
     Result("w1", "interface errors", "OK", "0", numeric=0.0, items=[item("Gi1", 0.0), item("Gi2", 0.0)]),
     Result("w1", "config backup", "OK", "saved"),
     Result("w2", "disks", "OK", "33%", numeric=33.0), Result("w2", "patches", "OK", "3 days", numeric=3.0),
     Result("nas", "disks", "OK", "41 °C", numeric=41.0, items=[item("ada0", 41.0, "OK"), item("ada1", 38.0, "OK")])],
    [Result("w1", "cpu", "OK", "20%", numeric=20.0), Result("w1", "memory", "OK", "55%", numeric=55.0),
     Result("w1", "disk health", "FAIL", "1", "disk 1: Unhealthy", numeric=1.0),
     Result("w1", "disks", "OK", "70%", numeric=70.0, items=[item("C:", 50.0, used=250 * GB, total=500 * GB), item("D:", 70.0, used=70 * GB, total=100 * GB)]),
     Result("w1", "uptime", "OK", "101 h", numeric=101.0), Result("w1", "ha", "OK", "active"), Result("w1", "ha sync", "WARN", "out of sync"),
     Result("w1", "reachability", "FAIL", "no answer", "port 443 did not answer"),
     Result("w1", "interface errors", "WARN", "5", numeric=5.0, items=[item("Gi1", 0.0), item("Gi2", 5.0)]),
     Result("w1", "patches", "OK", "2 days", numeric=2.0, items=pending),
     Result("nas", "disks", "FAIL", "44 °C", numeric=44.0, items=[item("ada0", 44.0, "OK"), item("ada1", 40.0, "FAIL")])],
    [Result("w1", "cpu", "OK", "30%", numeric=30.0), Result("w1", "memory", "OK", "60%", numeric=60.0), Result("w1", "uptime", "OK", "0.5 h", numeric=0.5),
     Result("w1", "ha", "OK", "standby"), Result("w1", "reachability", "OK", "6 ms", numeric=6.0)],
]
for r in runs:
    db.save_run(r)
    time.sleep(1.05)
backup.store("w1", "hostname w1\nvlan 10\n"); time.sleep(1.05); backup.store("w1", "hostname w1\nvlan 10\nvlan 20\n")
time.sleep(1.05)
ALL = ["certificate :443", "certificates", "config backup", "cpu", "memory", "disk health", "disks", "ha", "ha sync", "interface errors", "patches",
       "reachability", "resources", "uptime"]                 # the picker's order
assert sorted(ALL) == sorted(db.device_all_checks()["w1"]), db.device_all_checks()["w1"]
START, END = datetime.now() - timedelta(hours=1), datetime.now() + timedelta(minutes=1)
th = db.get_thresholds()

cp = O.CheckPanels()
cp.resize(900, 400)
cp.setVisible(True)
QApplication.processEvents()
drawn.clear()
cp.show("w1", "windows", ALL, START, END, th)
QApplication.processEvents()
by = {O.shown_name(p.checks[0]): p for p in cp.panels}
print("== a panel per shown check")
check("one panel per shown check, cpu and memory sharing a scale", list(by) == ["certificates", "config backup", "cpu", "disk health", "disks", "ha",
      "interface errors", "patches", "reachability", "uptime"] and by["cpu"].checks == ["cpu", "memory"], [p.checks for p in cp.panels])
check("resources has no panel", all("resources" not in p.checks for p in cp.panels))
check("certificate and certificates share one panel", by["certificates"].checks == ["certificate :443", "certificates"], by["certificates"].checks)
check("Trends gets the measurements only", [c for c, _pts in cp.line_series()] == ["cpu", "memory", "disks", "interface errors", "reachability"],
      [c for c, _pts in cp.line_series()])

print("== drawn as they scroll into view")
check("the lower panels wait", not by["patches"].drawn and not by["uptime"].drawn and by["certificates"].drawn, [p.drawn for p in cp.panels])
before = len(drawn)
check("no chart below the view has been drawn", by["patches"] not in [v.parent() for v in drawn] and before == sum(
      len(p.findChildren(ChartView)) for p in cp.panels if p.drawn), before)
bar = cp.verticalScrollBar()
while bar.value() < bar.maximum():                            # scroll down, a step at a time, as a person would
    bar.setValue(bar.value() + 150)
    QApplication.processEvents()
check("scrolled down, every panel is drawn", all(p.drawn for p in cp.panels), [p.drawn for p in cp.panels])
check("and only then are their charts drawn", len(drawn) > before, (before, len(drawn)))

print("== heatmap: a square lists what happened in it")
hp = by["disk health"]
opt = hp.chart.opt
check("statuses as numbers, so ECharts draws the squares", all(isinstance(d["value"][2], int) for d in opt["series"][0]["data"]), opt["series"][0]["data"])
check("the hint shows before a selection", hp.text.text() == O.HINT and not hp.detail.isVisibleTo(hp))
fail_t = next(t for t, r in hp.rows if r["status"] == "FAIL")
x, y = hp.grid.cell(fail_t)
check("the FAIL square is red", any(d["value"][:2] == [x, y] and d["itemStyle"]["color"] == chartspec.status_color(P, "FAIL") for d in opt["series"][0]["data"]))
hp.chart.clicked.emit({"kind": "series", "value": [x, y, 2]})
m = hp.detail.model()
cells = [[m.index(i, j).data() for j in range(m.columnCount())] for i in range(m.rowCount())]
check("the detail list has the agreed columns", [m.headerData(j, Qt.Orientation.Horizontal) for j in range(m.columnCount())] == ["Time", "Device", "Status", "Value", "Message"])
check("selecting the FAIL square lists its row, naming the disk", any("disk 1" in row[4] for row in cells) and hp.detail.isVisibleTo(hp) and not hp.text.isVisibleTo(hp), cells)

print("== gauges")
check("a gauge per disk", len(by["disks"].gauges) == 2 and by["disks"].gauges[0].opt["series"][0]["data"][0]["value"] == 50.0, len(by["disks"].gauges))
check("with used and total under it", "250.0 GB of 500.0 GB" in by["disks"].gauges[0].opt["series"][0]["data"][0]["name"], by["disks"].gauges[0].opt["series"][0]["data"][0]["name"])

print("== the patches wheel")
ring = by["patches"].chart.opt
names = [d["name"] for d in ring["series"][0]["data"]]
check("the centre is the pending count", ring["graphic"][0]["style"]["text"] == "4", ring["graphic"][0]["style"]["text"])
check("segments by Microsoft severity, with Unrated for none", names == list(O.SEVERITIES) and ring["series"][0]["data"][4]["value"] == 1, ring["series"][0]["data"])
check("the date Windows last searched", by["patches"].text.text().startswith("Windows last searched for updates on ") and "2026" in by["patches"].text.text(), by["patches"].text.text())
by["patches"].chart.clicked.emit({"kind": "series", "name": "Critical"})
pm = by["patches"].detail.model()
check("a segment lists its updates", pm.rowCount() == 2 and [pm.headerData(j, Qt.Orientation.Horizontal) for j in range(3)] == ["Update", "KB", "Severity"]
      and {pm.index(i, 1).data() for i in range(2)} == {"KB1", "KB2"})

print("== tables")
ut = by["uptime"].table.model()
check("uptime: the current uptime on top, then a row per restart", ut.rowCount() == 2 and ut.index(0, 1).data() == display.uptime_words(0.5)
      and ut.index(1, 1).data() == display.uptime_words(101.0), [[ut.index(i, j).data() for j in range(2)] for i in range(ut.rowCount())])
check("uptime columns", [ut.headerData(j, Qt.Orientation.Horizontal) for j in range(2)] == ["Restarted (about)", "Had been up for"])
ha = by["ha"].table.model()
check("ha: the approved columns, a row each time either changed", [ha.headerData(j, Qt.Orientation.Horizontal) for j in range(3)] == ["Checked", "HA", "HA sync"]
      and ha.rowCount() == 3 and ha.index(0, 1).data() == "Standby", [[ha.index(i, j).data() for j in range(3)] for i in range(ha.rowCount())])
ct = by["certificates"].table.model()
check("certificates: both checks' certificates and where each was found", sorted(ct.index(i, 3).data() for i in range(ct.rowCount())) == ["Certificate store", "Port 443"]
      and [ct.headerData(j, Qt.Orientation.Horizontal) for j in range(4)] == ["Certificate", "Expires", "Days left", "Found in"])
cfg = by["config backup"]
check("config backup: a row per saved version, the newest shown as its changes", cfg.table.model().rowCount() == 2 and "+vlan 20" in cfg.config.toPlainText(),
      cfg.config.toPlainText())
cfg.switch.setCurrentIndex(1)
check("or as the full configuration", cfg.config.toPlainText().startswith("hostname w1") and "vlan 20" in cfg.config.toPlainText())
check("reachability: the check with no answer is a red mark", len(by["reachability"].stack.charts[0].marks) == 1)
ie = by["interface errors"]
check("interface errors: a line per interface, the picker starting with those that had errors", ie.picker.selected() == ["Gi2"] and
      [c for c, _p in ie.lines.series] == ["Gi2"], ie.picker.selected())
ie.picker.set_selected(["Gi1", "Gi2"]); ie.picker._toggled()
check("ticking another interface draws it too", [c for c, _p in ie.lines.series] == ["Gi1", "Gi2"])

print("== every table sorts by a click on its header")
for p in cp.panels:
    t = getattr(p, "table", None)
    if t is None:
        continue
    head = t.horizontalHeader()
    QTest.mouseClick(head.viewport(), Qt.MouseButton.LeftButton, pos=QPoint(head.sectionViewportPosition(1) + 5, head.height() // 2))
    check(f"{p.checks[0]}: sorted by its second column", t.isSortingEnabled() and head.sortIndicatorSection() == 1, head.sortIndicatorSection())
ut = by["uptime"].table
ut.sortByColumn(1, Qt.SortOrder.DescendingOrder)
check("durations sort as durations, not as text", ut.model().index(0, 1).data() == display.uptime_words(101.0), ut.model().index(0, 1).data())

print("== the other devices")
cp.show("w2", "windows", db.device_all_checks()["w2"], START, END, th)
for p in cp.panels:
    p.drawn or p.draw()
by2 = {O.shown_name(p.checks[0]): p for p in cp.panels}
check("an older agent: the wheel says so instead of a ring", by2["patches"].text.text() == O.OLD_AGENT and not hasattr(by2["patches"], "chart"))
check("a disk row with no drives: one gauge from its number", len(by2["disks"].gauges) == 1 and by2["disks"].gauges[0].opt["series"][0]["data"][0]["value"] == 33.0)
cp.show("nas", "truenas", ["disks"], START, END, th)
for p in cp.panels:
    p.drawn or p.draw()
nas = cp.panels[0]
check("TrueNAS disks: SMART squares and a temperature line per drive", nas.kind == "heatmap" and hasattr(nas, "chart") and
      sorted(c for c, _p in nas.lines.series) == ["ada0", "ada1"], nas.kind)

print("== an empty range")
cp.show("w1", "windows", ALL, datetime(2001, 1, 1), datetime(2001, 1, 2), th)
for p in cp.panels:
    p.drawn or p.draw()
texts = {p.checks[0]: p.text.text() if p.text else None for p in cp.panels}
check("every panel says there were no readings", all(t == O.EMPTY for t in texts.values()), texts)

print("== uptime words")
check("days and hours, or hours and minutes under a day", display.uptime_words(12 * 24 + 4.2) == "12 days 4 hours" and display.uptime_words(5 + 20 / 60) == "5 hours 20 minutes"
      and display.uptime_words(25) == "1 day 1 hour", [display.uptime_words(12 * 24 + 4.2), display.uptime_words(5 + 20 / 60), display.uptime_words(25)])
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

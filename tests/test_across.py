# Run directly (python tests/test_across.py). History > Across devices: each device's latest reading (or its average), drawn as the check's kind.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_os.environ.setdefault("TONER_NO_WEBCHARTS", "1")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "ac%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from datetime import datetime, timedelta
from core import db, orgs
from core.firmware import human_size
db.init()
from drivers.base import Result
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)
from ui import chartspec
from ui.webchart import ChartView
import ui.history as H

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

P = chartspec.palette()
real_draw = ChartView.draw
def capturing(self, builder):
    self.opt = builder(P)
    real_draw(self, builder)
ChartView.draw = capturing

now = datetime.now()
acme = orgs.create("Acme", "acme")
def dev(name, vendor, org=db.GLOBAL, platform=""):
    with db.within(org):
        db.save_device(dict(name=name, vendor=vendor, host="10.0.0.1", port=0, platform=platform, username="u", site="default", verify_ssl=0,
                            ha_expected=0, enabled=1, location="", details="", folder_id=None))
def save(org, rows, ago):
    """One run in that file, backdated."""
    with db.within(org):
        db.save_run(rows)
        with db.connect() as c:
            c.execute("UPDATE runs SET started_at=? WHERE id=(SELECT MAX(id) FROM runs)", ((now - ago).strftime("%Y-%m-%d %H:%M:%S"),))
item = lambda name, numeric=None, status=None, text="", **data: {"name": name, "numeric": numeric, "status": status, "text": text, "data": data}
GB = 1024 ** 3

for n, v in (("w1", "windows"), ("w2", "windows"), ("nas", "truenas"), ("sw1", "cisco"), ("sw2", "cisco")):
    dev(n, v)
dev("asa", "cisco", platform="asa")
dev("b", "windows", org=acme)
asa = next(d for d in db.list_devices() if d["name"] == "asa")
db.set_software(asa, {"version": "9.12(4)67"})

save(db.GLOBAL, [Result("w1", "cpu", "OK", "10%", numeric=10.0)], timedelta(days=20))          # outside 7 days, inside 30
save(db.GLOBAL, [Result("w1", "cpu", "OK", "20%", numeric=20.0), Result("w2", "cpu", "OK", "40%", numeric=40.0),
                 Result("nas", "disks", "OK", "40 °C", numeric=40.0, items=[item("ada0", 39.0, "OK"), item("ada1", 40.0, "OK")]),
                 Result("nas", "datasets", "OK", "60%", numeric=60.0, items=[item("tank/a", 30.0), item("tank/b", 60.0)])], timedelta(days=2))
save(db.GLOBAL, [
    Result("w1", "cpu", "OK", "30%", numeric=30.0), Result("w2", "cpu", "FAIL", "95%", numeric=95.0), Result("asa", "cpu", "OK", "5%", numeric=5.0),
    Result("w1", "antivirus", "OK", "Defender, up to date"), Result("w2", "antivirus", "WARN", "Defender, 9 days old"),
    Result("w1", "resources", "ERROR", "", "could not read"),
    Result("w1", "certificate :443", "OK", "200 days", numeric=200.0, items=[item("w1.example", 200.0, expires="2027-05-27", where="port 443")]),
    Result("w1", "certificates", "OK", "30 days", numeric=30.0, items=[item("CN=w1", 30.0, expires="2026-12-08", where="store"),
                                                                       item("CN=w1-old", 5.0, expires="2026-11-14", where="store")]),
    Result("w1", "disks", "OK", "70%", numeric=70.0), Result("w2", "disks", "OK", "33%", numeric=33.0),
    Result("nas", "disks", "FAIL", "44 °C", "ada1: SMART failed", numeric=44.0, items=[item("ada0", 41.0, "OK"), item("ada1", 44.0, "FAIL")]),
    Result("nas", "datasets", "OK", "80%", numeric=80.0, items=[item("tank/a", 50.0, used=50 * GB, total=100 * GB), item("tank/b", 80.0)]),
    Result("sw1", "temperature", "OK", "45 °C", numeric=45.0),
    Result("sw1", "interfaces", "FAIL", "2/4 up", numeric=2.0, items=[item("Gi1", status="OK", text="up"), item("Gi2", status="WARN", text="errdisabled"),
                                                                      item("Gi3", status="FAIL", text="down"), item("Gi4", status="OK", text="up")]),
    Result("sw1", "environment", "FAIL", "1 of 2 not ok", numeric=1.0, items=[item("Fan 1", status="OK", text="ok"), item("PSU 2", status="FAIL", text="failed")]),
    Result("sw1", "firmware", "OK", "17.3.1"),
    Result("sw1", "link", "FAIL", "down", "uplink lost"), Result("w1", "link", "OK", "connected"),
    Result("w1", "reachability", "OK", "5 ms", numeric=5.0),
    Result("sw2", "interfaces", "FAIL", "3/4 up", "down: Gi9", numeric=3.0), Result("sw2", "environment", "OK", "3 ok", numeric=0.0),    # stored before items
], timedelta(hours=1))
save(acme, [Result("b", "cpu", "OK", "60%", numeric=60.0),
            Result("b", "certificates", "WARN", "20 days", numeric=20.0, items=[item("CN=b", 20.0, expires="2026-11-29", where="store")])],
     timedelta(hours=2))
old = orgs.create("Old", "old")
dev("o1", "windows", org=old)
save(old, [Result("o1", "cpu", "OK", "12%", numeric=12.0)], timedelta(hours=1))
orgs.set_archived(old, True)
db.set_home(db.GLOBAL)
bk = db.dkey("b", acme)
check("the organization's device is keyed for Global", bk != "b" and "@@" in bk, bk)

w = H.HistoryTab()
w.resize(1100, 700)
w.chart_tabs.setCurrentIndex(1)
w.show()
QApplication.processEvents()

labels = {w.compare_check.itemData(i): w.compare_check.itemText(i) for i in range(w.compare_check.count())}
print("== the check list")
check("checks come from stored history, not the time range", {"cpu", "antivirus", "certificates", "environment", "firmware", "interfaces", "link",
                                                              "disks", "datasets", "temperature"} <= set(labels), labels)
check("certificate checks are listed once, as certificates", "certificate :443" not in labels and list(labels).count("certificates") == 1, labels)
check("hidden checks (resources) are left out", "resources" not in labels, labels)

def pick(shown, mode=0):
    w.compare_switch.setCurrentIndex(mode)
    w.compare_check.setCurrentIndex(w.compare_check.findData(shown))
    w.draw_compare()
    QApplication.processEvents()

def gauges():
    return [(g.view.opt["series"][0]["data"][0]["name"], g.view.opt["series"][0]["data"][0]["value"]) for g in w.compare_gauges]

calls = []                                                    # every per-device items read: Across devices must not make them
real_latest_items = db.latest_items
db.latest_items = lambda *a: calls.append(a) or real_latest_items(*a)

print("== gauges")
pick("cpu")
got = gauges()
check("cpu: one gauge per device, worst first, Global keys labelled with their organization",
      got[0] == ("w2", 95.0) and sorted(got[1:]) == sorted([("w1", 30.0), ("asa", 5.0), ("b (Acme)", 60.0)]) and len(got) == 4, got)
check("the switch has the approved labels", [w.compare_switch.itemText(i) for i in range(w.compare_switch.count())]
      == ["Latest", "7-day average", "30-day average", "90-day average"] and w.compare_switch.isVisibleTo(w))
check("gauges sit in a wrapping grid", all(isinstance(g.parentWidget().layout(), H.FlowLayout) for g in w.compare_gauges))
check("a gauge carries the device's warn and fail marks", w.compare_gauges[0].view.opt["series"][0]["axisLine"]["lineStyle"]["color"][0][0] == 0.7,
      w.compare_gauges[0].view.opt["series"][0]["axisLine"])
pick("cpu", 1)
avg = db.average_per_device(["cpu"], 7)
got = dict(gauges())
check("7-day average: the averages average_per_device gives", got == {"w1": round(avg["w1"], 1), "w2": round(avg["w2"], 1), "asa": 5.0, "b (Acme)": 60.0}
      and got["w1"] == 25.0, (got, avg))
pick("cpu", 2)
check("30-day average reaches the older row", dict(gauges())["w1"] == 20.0, gauges())
pick("temperature")
got = gauges()
check("temperature: a device's gauge and one per TrueNAS drive, labelled device / drive",
      {n for n, _v in got} == {"sw1", "nas / ada0", "nas / ada1"} and dict(got)["nas / ada1"] == 44.0, got)
g = next(g for g in w.compare_gauges if g.view.opt["series"][0]["data"][0]["name"] == "sw1").view
check("a temperature gauge is in °C with a maximum past its fail mark", g.opt["series"][0]["detail"]["formatter"] == "{value} °C"
      and g.opt["series"][0]["max"] >= 85 * 1.1 - 1e-9, g.opt["series"][0])
pick("temperature", 1)
avg = db.average_items_per_device(["disks"], 7)
check("...7-day averages: the device's and each drive's own", dict(gauges()) == {"sw1": 45.0, "nas / ada0": 40.0, "nas / ada1": 42.0}
      and avg[("nas", "ada1")] == 42.0, (gauges(), avg))
pick("datasets")
got = gauges()
check("datasets: one gauge per dataset, labelled device / dataset, used and total under it",
      [n.split("\n")[0] for n, _v in got] == ["nas / tank/b", "nas / tank/a"] and got[1] == (f"nas / tank/a\n{human_size(50 * GB)} of {human_size(100 * GB)}", 50.0), got)
SIZE = f"\n{human_size(50 * GB)} of {human_size(100 * GB)}"
pick("datasets", 1)
check("...7-day averages of each dataset, under the latest names and sizes, with the switch shown",
      gauges() == [("nas / tank/b", 70.0), ("nas / tank/a" + SIZE, 40.0)] and w.compare_switch.isVisibleTo(w), gauges())
pick("reachability")
check("a measurement keeps its own unit", w.compare_gauges[0].view.opt["series"][0]["detail"]["formatter"] == "{value} ms",
      w.compare_gauges[0].view.opt["series"][0]["detail"])
pick("disks")
check("disks: Windows disks as gauges, never the TrueNAS drives", sorted(n for n, _v in gauges()) == ["w1", "w2"], gauges())
rows = w.compare_table.rows if w.compare_table else []
check("...TrueNAS disks (SMART health) in the health table", [r["device"] for r in rows] == ["nas"] and rows[0]["status"] == "FAIL", rows)

def headers(t):
    return [t.model().headerData(i, H.Qt.Orientation.Horizontal) for i in range(t.model().columnCount())]

print("== tables")
pick("antivirus")
t = w.compare_table
check("antivirus: a table, Device, Value, Checked", t is not None and headers(t) == ["Device", "Value", "Checked"] and not w.compare_gauges
      and sorted(r["value"] for r in t.rows) == ["Defender, 9 days old", "Defender, up to date"] and not w.compare_switch.isVisibleTo(w), t and headers(t))
pick("certificates")
t = w.compare_table
check("certificates: a row per certificate, across certificate and certificates, both organizations",
      headers(t) == ["Device", "Certificate", "Expires", "Days left", "Found in"]
      and sorted((r["device"], r["name"], r["where"]) for r in t.rows) == [("b (Acme)", "CN=b", "Certificate store"), ("w1", "CN=w1", "Certificate store"),
                                                                           ("w1", "CN=w1-old", "Certificate store"), ("w1", "w1.example", "Port 443")],
      t and (headers(t), t.rows))
pick("environment")
t = w.compare_table
check("environment: a row per component, Device, Component, State", headers(t) == ["Device", "Component", "State"]
      and sorted((r["device"], r["component"], r["state"]) for r in t.rows) == [("sw1", "Fan 1", "ok"), ("sw1", "PSU 2", "failed"),
                                                                              ("sw2", "Environment", "3 ok")], t and t.rows)
pick("firmware")
t = w.compare_table
check("firmware: Device, Version, with the ASA from software_of", headers(t) == ["Device", "Version"]
      and sorted((r["device"], r["version"]) for r in t.rows) == [("asa", "9.12(4)67"), ("sw1", "17.3.1")], t and t.rows)
pick("link")
t = w.compare_table
check("an unlisted status check: the health table", t is not None and headers(t) == ["Device", "Status", "Value", "Message", "Checked"]
      and sorted((r["device"], r["status"], r["message"]) for r in t.rows) == [("sw1", "FAIL", "uplink lost"), ("w1", "OK", "")], t and t.rows)

print("== interfaces")
pick("interfaces")
check("interfaces: a ring per device", sorted(r.name for r in w.compare_rings) == ["sw1", "sw2"])
old_ring = next(r for r in w.compare_rings if r.name == "sw2").view
segs = {d["name"]: d["value"] for d in old_ring.opt["series"][0]["data"]}
check("a row stored before items: its ring from the row's own 3/4 up", segs == {"Up": 3, "Err-disabled": 0, "Down": 1}
      and old_ring.opt["graphic"][0]["style"]["text"] == "4", segs)
ring = next(r for r in w.compare_rings if r.name == "sw1").view
segs = {d["name"]: d["value"] for d in ring.opt["series"][0]["data"]}
check("up, err-disabled and down counts, the total in the middle", segs == {"Up": 2, "Err-disabled": 1, "Down": 1}
      and ring.opt["graphic"][0]["style"]["text"] == "4" and ring.opt["title"]["text"] == "sw1", (segs, ring.opt.get("graphic"), ring.opt.get("title")))
check("the detail list waits for a selection", not w.compare_detail.isVisibleTo(w))
ring.clicked.emit({"kind": "series", "name": "Up"})
QApplication.processEvents()
d = w.compare_detail
check("selecting a segment lists those interfaces", d.isVisibleTo(w) and headers(d) == ["Time", "Device", "Status", "Value", "Message"]
      and sorted(r["value"] for r in d.rows) == ["Gi1", "Gi4"] and all(r["device"] == "sw1" and r["status"] == "OK" for r in d.rows), d.rows)
ring.clicked.emit({"kind": "series", "name": "Down"})
check("...another segment, its interfaces", [r["value"] for r in w.compare_detail.rows] == ["Gi3"], w.compare_detail.rows)

print("== the time range does not touch it")
w.range.changed.emit()
QApplication.processEvents()
check("a range change leaves the list and the chart", w.compare_check.currentData() == "interfaces" and len(w.compare_rings) == 2)
check("no per-device items reads: one batched read per file", calls == [], calls[:5])

print("== charts are drawn as they scroll into view")
w.compare_area.setFixedHeight(120)
pick("cpu")
drawn = [g.view is not None for g in w.compare_gauges]
check("gauges below the view wait", any(drawn) and not all(drawn), drawn)
bar = w.compare_area.verticalScrollBar()
while bar.value() < bar.maximum():
    bar.setValue(bar.value() + 100)
    QApplication.processEvents()
check("scrolled down, every gauge is drawn", all(g.view is not None for g in w.compare_gauges), [g.view is not None for g in w.compare_gauges])
w.compare_area.setMinimumHeight(0)
w.compare_area.setMaximumHeight(16777215)

print("== archived organizations, when the funnel picks them")
w.funnel.set("org", {old})
QApplication.processEvents()
pick("cpu")
check("their devices' gauges show too", gauges() == [("o1 (Old)", 12.0)], gauges())
w.funnel.clear()
QApplication.processEvents()
print("== the search box narrows the devices")
w.find.setText("w2")
QApplication.processEvents()
pick("cpu")
check("only the devices the search leaves", gauges() == [("w2", 95.0)], gauges())
check("...and only their checks are listed", w.compare_check.findData("datasets") < 0)
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

# Run directly (python tests/test_device_page.py). The device page: the dials that matter (CPU, memory, a disk each, a WAN link each),
# an Uptime fact under Status, facts that wrap instead of clipping, every check ticked, Trends with measurements only, a time range on
# History and Trends, and the Vulnerabilities tab.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_os.environ.setdefault("TONER_NO_WEBCHARTS", "1")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "dp%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from datetime import datetime, timedelta
from core import advisories, db, display
from core.chartkinds import is_measurement
db.init()
from drivers.base import Result
from PySide6.QtCore import QCoreApplication, Qt
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)
from ui import chartspec
from ui.webchart import ChartView

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def spin(ms):
    end = time.time() + ms / 1000
    while time.time() < end: QCoreApplication.processEvents(); time.sleep(0.005)

P = chartspec.palette()
real_draw = ChartView.draw
def capturing(self, builder):
    self.opt = builder(P)
    real_draw(self, builder)
ChartView.draw = capturing

ASA = "9.12(4)67 (asa9-12-4-67-smp-k8.bin), read 8 Nov 2026 at 23:31, with the long note the owner saw losing its last line on the page"
assert len(ASA) >= 120
dev = lambda name, vendor, **k: db.save_device(dict(name=name, vendor=vendor, host="10.0.0.1", port=0, platform="", username="u", site="default", verify_ssl=0,
                                                    ha_expected=0, enabled=1, location="", details=k.get("details", ""), folder_id=None))
dev("fw", "fortinet", details=ASA); dev("nas", "truenas"); dev("rtr", "cisco"); dev("sw2", "juniper")
item = lambda name, numeric=None, status=None, text="", **data: {"name": name, "numeric": numeric, "status": status, "text": text, "data": data}
GB = 1024 ** 3
db.save_run([Result("fw", "cpu", "OK", "12%", numeric=12.0), Result("fw", "memory", "OK", "40%", numeric=40.0),
             Result("fw", "temperature", "OK", "45 °C", numeric=45.0), Result("fw", "sessions", "OK", "30%", numeric=30.0),
             Result("fw", "disk", "OK", "60%", numeric=60.0, items=[item("internal", 60.0, used=60 * GB, total=100 * GB)]),
             Result("fw", "wan usage", "OK", "35%", numeric=35.0, items=[item("wan1", 35.0, in_bps=1e6, out_bps=2e6, available_bps=1e8),
                                                                         item("wan2", 5.0, in_bps=1e5, out_bps=2e5, available_bps=1e8)]),
             Result("fw", "uptime", "OK", "100 h", numeric=100.5), Result("fw", "firmware", "OK", "7.2.5"),
             Result("fw", "disk health", "OK", "0", numeric=0.0),
             Result("nas", "cpu", "OK", "5%", numeric=5.0), Result("nas", "memory", "OK", "20%", numeric=20.0),
             Result("nas", "disks", "OK", "41 °C", numeric=41.0, items=[item("ada0", 41.0, "OK")]),
             Result("nas", "datasets", "OK", "2 dataset(s)", numeric=70.0, items=[item("tank/a", 70.0, used=7.0, total=10.0)])]
            + [Result(f"nas / {p}", "pool space", "OK", f"{v:.0f}%", numeric=v, items=[item(p, v, used=v * GB, total=100 * GB)]) for p, v in (("tank", 55.0), ("backup", 25.0))])
time.sleep(1.05)

import ui.device_view as DV
V = DV.DeviceView(db.find_device("fw")); V.resize(900, 640); V.show(); spin(80)

print("== Overview dials")
names = lambda view: [g.accessibleName() for g in view._gauges]
check("exactly CPU, Memory, a dial per disk and a dial per WAN link; no temperature or sessions",
      names(V) == ["CPU dial", "Memory dial", "Disk: internal dial", "WAN Usage: wan1 dial", "WAN Usage: wan2 dial"], names(V))
disk = V._gauges[2].opt["series"][0]
check("a disk dial shows its percentage, with used and total under it", disk["data"][0]["value"] == 60.0 and "60.0 GB of 100.0 GB" in str(disk), disk)
wan = V._gauges[3].opt["series"][0]
check("a WAN dial is its link's percentage, out of 100", wan["data"][0]["value"] == 35.0 and wan["max"] == 100, wan)
N = DV.DeviceView(db.find_device("nas")); N.show(); spin(50)
check("TrueNAS: one dial per pool from its '<device> / <pool>' rows; not SMART disks, not datasets",
      names(N) == ["CPU dial", "Memory dial", "Pool Space: backup dial", "Pool Space: tank dial"], names(N))

print("== Facts")
def facts(form):
    out = []
    for i in range(form.rowCount()):
        lab, val = form.itemAt(i, form.ItemRole.LabelRole), form.itemAt(i, form.ItemRole.FieldRole)
        out.append((lab.widget().text().replace("<span style='color:gray'>", "").replace("</span>", ""), val.widget()))
    return out
f = facts(V.info)
keys = [k for k, _w in f]
check("Uptime comes right after Status", keys[:2] == ["Status", "Uptime"], keys)
check("written by uptime_words", dict(f)["Uptime"].text() == display.uptime_words(100.5), dict(f)["Uptime"].text())
check("a device with no uptime reading has no Uptime line", "Uptime" not in [k for k, _w in facts(N.info)])
from ui.inventory import DetailsPane
pane = DetailsPane(); pane.resize(400, 900); pane.show(); pane.set_device(db.find_device("fw")); spin(80)
pf = facts(pane.summary.info)
check("the pane's 'checked ...' line wraps, so it never widens the pane past its width", pane.checked.wordWrap())
check("the Inventory details pane shows Uptime too", "Uptime" in [k for k, _w in pf] and dict(pf)["Uptime"].text() == display.uptime_words(100.5), [k for k, _w in pf])
def fits(label):
    return label.height() >= label.heightForWidth(label.width()) and label.heightForWidth(label.width()) > label.fontMetrics().height() * 2
V.tabs.setCurrentIndex(0); spin(50)
check("a 120-character fact wraps onto every line it needs on the device page", fits(dict(f)["Notes"]), (dict(f)["Notes"].height(), dict(f)["Notes"].heightForWidth(dict(f)["Notes"].width())))
for width in (300, 360, 400):                                # the pane is 300 to 460 wide
    pane.resize(width, 900); spin(80)
    notes = dict(facts(pane.summary.info))["Notes"]
    check(f"and in the Inventory pane at {width} px", pane.width() == width and fits(notes), (pane.width(), notes.height(), notes.heightForWidth(notes.width()), notes.width()))

print("== Picker, Trends and the time range")
allk = list(V.keys)
check("the picker starts with every check ticked, text checks too", sorted(V.pick.selected()) == sorted(allk) and {"CPU", "Disk Health", "Uptime", "WAN Usage", "Firmware"} <= set(allk), (V.pick.selected(), allk))
shown = lambda: [c for p in V.panels.panels for c in p.checks]
before = shown()
V.pick.set_selected([k for k in allk if k != "CPU"]); V.pick.changed.emit()
check("unticking a check redraws without it", "cpu" in before and "cpu" not in shown(), (before, shown()))
V.pick.set_selected(allk); V.pick.changed.emit()
trend_series = lambda view: [s for t in view.trends for s in t.opt.get("series", [])]
lines = [s["name"] for s in trend_series(V)]
measured = {display.check_name(c) for c in V.keys.values() if is_measurement(c, "fortinet")}
check("Trends draws only the measurements", set(lines) <= measured and "CPU" in lines and not {"Disk Health", "Uptime", "Firmware"} & set(lines), lines)
check("History and Trends start on the last 8 hours", V.range.describe() == "Last 8 hours" and abs((V.panels.start - (datetime.now() - timedelta(hours=8))).total_seconds()) < 60)
V.tabs.setCurrentIndex(2); spin(30)
check("the range is on the Trends tab too", V.range.isVisibleTo(V.tabs.widget(2)))
V.tabs.setCurrentIndex(1); spin(30)
check("and on the History tab", V.range.isVisibleTo(V.tabs.widget(1)))
old = datetime.now() - timedelta(days=40)
V.range.set_dates(old, old + timedelta(days=1)); spin(30)
check("History follows the range", V.panels.start == datetime.combine(old.date(), datetime.min.time()), V.panels.start)
check("and Trends: nothing in that range", not any(s.get("data") for s in trend_series(V)), [t.opt for t in V.trends])
V.range.set_hours(8); spin(30)
check("back to recent: Trends draws again", any(s["name"] == "CPU" for s in trend_series(V)))

print("== Trends: a chart per scale")
dev("tr", "fortinet")
for i in range(3):
    db.save_run([Result("tr", "cpu", "OK", "", numeric=10.0 + i), Result("tr", "memory", "OK", "", numeric=40.0 + i),
                 Result("tr", "reachability", "OK", "", numeric=12.0 + i), Result("tr", "events", "OK", "", numeric=3.0 + i)])
    time.sleep(1.05)
T = DV.DeviceView(db.find_device("tr")); T.resize(900, 640); T.show(); spin(50)
T.pick.set_selected(["CPU", "Memory", "Reachability", "Events"]); T.pick.changed.emit(); spin(30)
groups = [[s["name"] for s in t.opt["series"] if s.get("type") == "line"] for t in T.trends]
check("cpu, memory, reachability and events: three charts (percent, ms, count), not one",
      sorted(groups) == [["CPU", "Memory"], ["Events"], ["Reachability"]], groups)
marks = lambda: [str(t.opt).count("markLine") for t in T.trends]
check("two checks on a chart: no limits", marks() == [0, 0, 0], marks())
T.pick.set_selected(["CPU", "Reachability", "Events"]); T.pick.changed.emit(); spin(30)
check("CPU alone on its chart has its limits; the charts without limits have none", marks() == [1, 0, 0], marks())

print("== The picker lists shown names")
dev("pk", "fortinet")
db.save_run([Result("pk", c, "OK", "", numeric=n) for c, n in (("resources", 3.0), ("certificate", 30.0), ("certificate :443", 20.0),
                                                                 ("certificates", 10.0), ("ha", 1.0), ("ha sync", 1.0), ("cpu", 12.0))])
K = DV.DeviceView(db.find_device("pk")); K.show(); spin(50)
check("one Certificates, one HA, no Resources", sorted(K.keys) == ["CPU", "Certificates", "HA"], list(K.keys))
K.pick.set_selected(["Certificates", "HA"]); K.pick.changed.emit(); spin(30)
panels = {p.kind: sorted(p.checks) for p in K.panels.panels}
check("ticking them draws every certificate source and both HA checks", panels == {"certs": ["certificate", "certificate :443", "certificates"],
      "ha": ["ha", "ha sync"]}, panels)

print("== Vulnerabilities")
tabs = [V.tabs.tabText(i) for i in range(V.tabs.count())]
check("the tab sits between Trends and Configuration", tabs == ["Overview", "History", "Trends", "Vulnerabilities", "Configuration"], tabs)
check("cvss_of reads a row's score", advisories.cvss_of("CVSS 7.5, EPSS 3%") == 7.5 and advisories.cvss_of("CVSS 10") == 10.0 and advisories.cvss_of("") is None)
check("the severity bands", advisories.SEVERITY_BANDS == (("Low", 0, 4), ("Medium", 4, 7), ("High", 7, 9), ("Critical", 9, 10.01)))
vt = V.vuln
check("no scan yet says so and points to Scanning", vt.empty.isVisibleTo(vt) and vt.empty.text() == "No scan yet. Scan this device on the Scanning page to see its advisories.", vt.empty.text())
db.save_scan([Result("fw", advisories.SOFTWARE, "FAIL", "7.2.5", "FortiOS 7.2.5, 3 advisories"),
              Result("fw", "CVE-2024-0001", "FAIL", "CVSS 9.8", "Heap overflow in sslvpnd Fixed in 7.2.7."),
              Result("fw", "CVE-2024-0002", "FAIL", "CVSS 7.5, EPSS 12%", "Path traversal in the GUI Fixed in 7.2.6."),
              Result("fw", "CVE-2024-0003", "OK", "CVSS 5", "Information disclosure"),
              Result("fw", advisories.KEV, "FAIL", "", "CVE-2024-0002, CVE-2024-00011 on CISA's known exploited list"),
              Result("fw", "Hardening: admin over HTTP", "FAIL", "", "HTTP administration is on"),
              Result("nas", advisories.SOFTWARE, "N/A", "", advisories.NO_SOURCE),
              Result("sw2", advisories.SOFTWARE, "OK", "21.4R3", "Junos 21.4R3"), Result("sw2", advisories.ADVISORIES, "OK", "", advisories.NONE_FOUND),
              Result("sw2", advisories.KEV, "OK", "", advisories.NONE_KEV),
              Result("rtr", advisories.SOFTWARE, "FAIL", "17.9.4", "IOS XE 17.9.4, 3 advisories"),
              Result("rtr", "cisco-sa-listed", "FAIL", "CVSS 8.1", "On the list"), Result("rtr", "cisco-sa-high", "WARN", "CVSS 8.1", "Not on the list"),
              Result("rtr", "cisco-sa-critical", "FAIL", "CVSS 9.8", "Critical either way"),
              Result("rtr", advisories.KEV, "FAIL", "", "CVE-2023-20198 on CISA's known exploited list")])
V.reload(); spin(30)
pie = vt.chart.opt["series"][0]["data"]
check("a slice per severity: Critical 1, High 1, Medium 1, Low 0; hardening rules not counted",
      [(d["name"], d["value"]) for d in pie] == [("Low", 0), ("Medium", 1), ("High", 1), ("Critical", 1)] and not vt.empty.isVisibleTo(vt), pie)
vt.chart.clicked.emit({"kind": "series", "name": "High"})
m = vt.detail.model()
heads = [m.headerData(j, Qt.Orientation.Horizontal) for j in range(m.columnCount())]
row = [m.index(0, j).data() for j in range(m.columnCount())]
check("the list's columns", heads == ["Advisory", "Title", "CVSS", "Exploited", "Link"], heads)
check("High lists the 7.5 advisory: id, title, score, exploited, link", m.rowCount() == 1 and row == ["CVE-2024-0002", "Path traversal in the GUI", 7.5, "Yes",
      advisories.advisory_url("CVE-2024-0002", "fortinet")] and vt.detail.isVisibleTo(vt), row)
vt.chart.clicked.emit({"kind": "series", "name": "Critical"})
check("a CVE is matched whole: CVE-2024-0001 is not exploited because CVE-2024-00011 is", [m.index(0, j).data() for j in range(m.columnCount())][3] == "No")
from ui.vulntab import VulnTab
other = VulnTab()
other.show_device(db.find_device("rtr"))
said = {r["id"]: r["exploited"] for r in other.rows}
check("a Cisco advisory: FAIL under 9 is exploited, WARN is not, FAIL at 9.8 cannot be told", said == {"cisco-sa-listed": "Yes", "cisco-sa-high": "No", "cisco-sa-critical": ""}, said)
N.reload(); spin(30)
check("nothing looked up: the version row says why", N.vuln.empty.isVisibleTo(N.vuln) and N.vuln.empty.text() == advisories.NO_SOURCE, N.vuln.empty.text())
other.show_device(db.find_device("sw2"))
check("looked up and nothing found: no advisories for this version", other.empty.isVisibleTo(other) and other.empty.text() == "No advisories for this version"
      and not other.chart.isVisibleTo(other), other.empty.text())

print("== the Scanning page's pie uses the same bands")
import ui.scanning as S
tab = S.ScanningTab(); tab.charts_btn.setChecked(True); tab.resize(1280, 700); tab.show(); spin(50); tab.repopulate(); tab.draw_charts()
sp = tab.cvss_chart.opt["series"][0]["data"]
check("named Low, Medium, High, Critical, counting the same rows (fw's and rtr's)", [(d["name"], d["value"]) for d in sp] == [("Low", 0), ("Medium", 1), ("High", 3), ("Critical", 2)], sp)

print("== a device in an organization's view")
from core import orgs
acme = orgs.create("Acme", "ACME")
with db.within(acme):
    dev("acme-fw", "fortinet")
    db.save_scan([Result("acme-fw", advisories.SOFTWARE, "FAIL", "7.2.5", "FortiOS 7.2.5, 1 advisory"),
                  Result("acme-fw", "CVE-2024-0009", "FAIL", "CVSS 9.1", "Something bad")])
db.set_home(acme)
other.show_device(db.find_device("acme-fw"))
check("seen from its organization, its scan rows are found", [r["id"] for r in other.rows] == ["CVE-2024-0009"], other.rows)
db.set_home(db.GLOBAL)
other.show_device(db.find_device(db.qualified("acme-fw", acme)))
check("and from Global", [r["id"] for r in other.rows] == ["CVE-2024-0009"], other.rows)
other.show_device(db.find_device("fw"))
check("Global's own device still finds only its own", sorted(r["id"] for r in other.rows) == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"], other.rows)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

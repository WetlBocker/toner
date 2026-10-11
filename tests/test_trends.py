# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import csv, os, sys, time
from datetime import datetime, timedelta
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\tr%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import db, service, trends
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def dev(name, vendor="cisco", platform="cisco_ios"):
    d = dict(name=name, vendor=vendor, host=name, port=0, platform=platform, username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None)
    db.save_device(d)
NOW = datetime(2026, 6, 15, 12, 0, 0)
def run_at(when, rows):
    with db.connect() as c:
        rid = c.execute("INSERT INTO runs(started_at, ok, warn, fail, error) VALUES(?,?,?,?,?)", (when.strftime(trends.FMT), 0, 0, 0, 0)).lastrowid
        for device, check_, status, value, msg in rows:
            c.execute("INSERT INTO results(run_id, device, check_name, status, value, message) VALUES(?,?,?,?,?,?)", (rid, device, check_, status, value, msg))
    return rid

for n in ("core1", "edge1", "edge2"): dev(n)
dev("web1", "windows", "agent")
# the week before (days 8 to 14 ago): everything fine
for d in range(8, 14): run_at(NOW - timedelta(days=d), [("core1", "cpu", "OK", "5%", ""), ("edge1", "cpu", "OK", "5%", ""), ("edge2", "cpu", "OK", "5%", ""), ("web1", "cpu", "OK", "5%", "")])
# this week: 6 runs. edge1 fails in 3 of them, edge2 is unreachable in 1, core1 and web1 are fine
for i, d in enumerate(range(1, 7)):
    rows = [("core1", "cpu", "OK", "5%", ""), ("web1", "cpu", "OK", "5%", ""),
            ("edge1", "bgp", "FAIL" if i % 2 == 0 else "OK", "", "peer down" if i % 2 == 0 else ""),
            ("edge2", "connection", "ERROR", "", "timeout") if i == 3 else ("edge2", "cpu", "OK", "5%", "")]
    run_at(NOW - timedelta(days=d), rows)
db.connect().execute("DELETE FROM alert_state").connection.commit()
with db.connect() as c:
    c.execute("INSERT INTO alert_state(device, check_name, status, since) VALUES('edge1','bgp','FAIL','2026-06-13 08:00:00')")
    for i in range(10):
        c.execute("INSERT INTO agent_metrics(device, at, cpu, memory, disk, uptime_h) VALUES('web1',?,?,?,?,?)", ((NOW - timedelta(days=6, hours=-i * 12)).strftime(trends.FMT), 20.0 + i * 5, 50, 60.0 + i * 0.5, 100))

print("== the numbers")
d = trends.compute(7, NOW)
check("runs and devices in the period", d["runs"] == 6 and d["devices"] == 4, (d["runs"], d["devices"]))
check("overall healthy share: 22 of 24 device-runs were healthy (edge1 failed 3, edge2 errored 1... )", abs(d["healthy"] - (24 - 4) / 24 * 100) < 0.01, d["healthy"])
check("overall reachable share: only the one timeout counts", abs(d["reachable"] - 23 / 24 * 100) < 0.01, d["reachable"])
check("the week before was perfect, so the change is down by the gap", d["previous"] == 100.0 and abs(d["delta"] - (d["healthy"] - 100)) < 0.01 and d["delta"] < 0)
check("the worst offenders come worst first, perfect devices left out", [w[0] for w in d["worst"]] == ["edge1", "edge2"] and d["worst"][0][1] == 50.0 and abs(d["worst"][1][2] - 5 / 6 * 100) < 0.01 and d["worst"][0][4] == 100.0)
check("what keeps failing counts occurrences and devices", d["failing"][0] == ("bgp", 3, 1) and ("connection", 1, 1) in d["failing"])
check("still wrong now comes from the open alerts, oldest first", d["still"] == [("edge1", "bgp", "FAIL", "2026-06-13 08:00:00")])
check("Windows agent numbers: busiest CPU and disks that grew", d["busiest"][0][0] == "web1" and d["busiest"][0][2] == 65.0 and d["disk_growth"] and d["disk_growth"][0][0] == "web1" and abs(d["disk_growth"][0][3] - 4.5) < 0.01, (d["busiest"], d["disk_growth"]))
check("devices that were deleted since are not counted", (lambda: (db.delete_device([x for x in db.list_devices() if x["name"] == "edge2"][0]["id"]), "edge2" not in [w[0] for w in trends.compute(7, NOW)["worst"]])[1])())
check("a period with no runs says so, without dividing by zero", trends.compute(7, NOW - timedelta(days=400))["healthy"] is None and trends.compute(7, NOW - timedelta(days=400))["runs"] == 0)

print("== the report")
html = trends.to_html(d)
check("the HTML has the headline, the trend, the offenders and what is open", "7-day trend" in html and "Healthy 83.3%" in html and "down" in html and "edge1" in html and "peer down" not in html and "Still wrong now" in html and "What keeps failing" in html)
check("the Windows part appears when there are Windows computers", "Windows computers (1)" in html and "Busiest by CPU" in html and "Disks filling up" in html)
db.set_setting("report_org", "<Acme & Sons>")
check("text from your data is escaped", "&lt;Acme &amp; Sons&gt;" in trends.to_html(d) and "<Acme" not in trends.to_html(d))
perfect = trends.compute(7, NOW - timedelta(days=9)); perfect["worst"] = []; perfect["still"] = []
check("a perfect period says so", "Every device was healthy in every run" in trends.to_html(perfect) and "Nothing is open" in trends.to_html(perfect))
p = os.path.join(SP, "trend.csv"); trends.to_csv(d, p)
rows = list(csv.reader(open(p, encoding="utf-8")))
check("the CSV has the headline numbers and a row per imperfect device", rows[1][0] == "Healthy %" and any(r and r[0] == "edge1" and r[1] == "50.0" for r in rows))
h = os.path.join(SP, "trend.html"); trends.save_html(d, h)
check("HTML is saved as a file", "<html>" in open(h, encoding="utf-8").read())

print("== on a schedule")
check("off by default: never due", db.get_setting("trend_schedule") == "" and not trends.due(NOW))
db.set_setting("trend_schedule", "weekly")
check("weekly and never made: due", trends.due(NOW))
db.set_setting("trend_last", (NOW - timedelta(days=3)).strftime(trends.FMT)); check("made 3 days ago: not due", not trends.due(NOW))
db.set_setting("trend_last", (NOW - timedelta(days=7, minutes=1)).strftime(trends.FMT)); check("made a week ago: due", trends.due(NOW))
db.set_setting("trend_schedule", "monthly"); check("monthly waits four weeks", not trends.due(NOW) and trends.due(NOW + timedelta(days=21)))
db.set_setting("trend_last", "garbage"); check("a garbled date means due", trends.due(NOW))
db.set_setting("report_folder", "")
check("with no reports folder nothing is made", trends.generate_scheduled(NOW) == "")
folder = os.path.join(SP, "reports"); os.makedirs(folder); db.set_setting("report_folder", folder); db.set_setting("trend_schedule", "weekly"); db.set_setting("trend_last", "")
now_real = datetime.now()
run_at(now_real - timedelta(hours=1), [("core1", "cpu", "OK", "5%", "")])
path = trends.generate_scheduled(now_real)
check("without a Qt application (the background service) it makes HTML in the folder, and remembers when", path.endswith(".html") and os.path.dirname(path) == folder and "7-day" in open(path, encoding="utf-8").read()
      and db.get_setting("trend_last") == now_real.strftime(trends.FMT) and not trends.due(now_real))
db.set_setting("trend_last", "")
daemon = service.Daemon(log=lambda m: None)
did = daemon.tick(now_real)
check("the service makes it when it is due, on its own", ("trend report", os.path.join(folder, f"Toner-trend-{now_real:%Y-%m-%d}.html")) in did, did)
check("and not again straight away", not any(x[0] == "trend report" for x in daemon.tick(now_real)))

print("== in the program")
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
db.set_setting("trend_last", "")
pdf = trends.generate_scheduled(now_real)
check("with a window system it makes a PDF", pdf.endswith(".pdf") and open(pdf, "rb").read(5) == b"%PDF-" and os.path.getsize(pdf) > 1500, pdf)
infos = []; QMessageBox.information = staticmethod(lambda *a, **k: infos.append(a[2]))
from ui.reports_tab import ReportsTab
import ui.settings as S
tab = ReportsTab(lambda: [])
check("the Reports tab has a Trend report button with the three periods", tab.trend_btn.text() == "Trend report" and [tab.trend_period.itemData(i) for i in range(3)] == [7, 30, 90])
out = os.path.join(SP, "ui-trend.pdf"); QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (out, ""))
import ui.reports_tab as RT
RT.QDesktopServices.openUrl = staticmethod(lambda u: True)
tab.export_trend()
check("it saves the chosen format (PDF here)", os.path.exists(out) and open(out, "rb").read(5) == b"%PDF-")
out2 = os.path.join(SP, "ui-trend.csv"); QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (out2, "")); tab.export_trend()
check("or CSV", "Healthy %" in open(out2, encoding="utf-8").read())
with db.connect() as c: c.execute("DELETE FROM runs"); c.execute("DELETE FROM results")
tab.export_trend()
check("with no runs yet it says so and writes nothing new", infos and "no runs" in infos[-1])
page = S.ReportsPage(); page.load()
check("Settings > Reports offers Off, every week, every month", [page.trend.itemData(i) for i in range(page.trend.count())] == ["", "weekly", "monthly"] and page.trend.currentData() == "weekly")
page.folder.setText(""); page.trend.setCurrentIndex(page.trend.findData("monthly"))
check("a schedule needs a folder to save into", page.validate() and "folder" in page.validate()[0])
page.folder.setText(folder); check("with one it is fine", page.validate() == [])
page.save(); check("and is saved", db.get_setting("trend_schedule") == "monthly")

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

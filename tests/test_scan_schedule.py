# Run directly (python tests/test_scan_schedule.py). Scheduled scans (Settings > Scanning > Scan automatically): the shared period table,
# which devices a scan covers, that a failing source cannot make it repeat, the service's tick, the window's hook and the settings page.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, types
from datetime import datetime, timedelta
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "ss%d.db" % int(time.time())); os.environ["APPDATA"] = SP
from core import db, periods, service, trends
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
from drivers.base import Result
from core import advisories, scansched

NOW = datetime(2026, 6, 15, 12, 0, 0)
F = periods.FMT
print("== the period table")
check("the periods and their labels", periods.DAYS == {"daily": 1, "weekly": 7, "biweekly": 14, "monthly": 28, "quarterly": 91}
      and periods.LABELS == {"": "Off", "daily": "Daily", "weekly": "Weekly", "biweekly": "Bi-Weekly", "monthly": "Monthly", "quarterly": "Quarterly"})
for kind, days in periods.DAYS.items():
    short = (NOW - timedelta(days=days) + timedelta(minutes=1)).strftime(F); exact = (NOW - timedelta(days=days)).strftime(F)
    check(f"{kind}: a minute short is not due, exactly on is", not periods.is_due(kind, short, NOW) and periods.is_due(kind, exact, NOW))
check("off or unknown is never due, even never run", not periods.is_due("", "", NOW) and not periods.is_due("yearly", "", NOW))
check("never run, or an unreadable date, is due", periods.is_due("daily", "", NOW) and periods.is_due("daily", "garbage", NOW) and periods.is_due("daily", None, NOW))
db.set_setting("trend_schedule", "weekly"); db.set_setting("trend_last", (NOW - timedelta(days=7)).strftime(F))
check("the trend report answers as before: weekly", trends.due(NOW) and not trends.due(NOW - timedelta(minutes=1)))
db.set_setting("trend_schedule", "monthly")
check("...monthly stays 28 days", trends.due(NOW + timedelta(days=21)) and not trends.due(NOW + timedelta(days=20)))
db.set_setting("trend_schedule", "")

print("== which devices, and what is kept")
def dev(name, vendor, enabled=1, location=""):
    db.save_device(dict(name=name, vendor=vendor, host=name, port=0, platform="cisco_ios", username="", site="default", verify_ssl=0, ha_expected=0, enabled=enabled, location=location, details="", folder_id=None))
dev("c1", "cisco"); dev("c2", "cisco", enabled=0); dev("f1", "fortinet"); dev("c3", "cisco")
seen = []
def fake_scan(d):
    seen.append(d["name"])
    if d["name"] == "c3":
        raise RuntimeError("source down")
    return [Result(d["name"], advisories.SOFTWARE, "OK", "1.0", "m")]
advisories.scan = fake_scan
cisco = [g for g in db.group_labels() if "isco" in g]
check("the Cisco group exists", len(cisco) == 1, db.group_labels())
check("off: not due", not scansched.scan_due(NOW))
db.set_setting("scan_schedule", "daily"); db.set_setting("scan_groups", cisco)
check("on and never run: due", scansched.scan_due(NOW))
rows = scansched.run_scheduled_scan(NOW)
check("it scans only the enabled devices of the chosen groups", sorted(seen) == ["c1", "c3"], seen)
check("a device whose scan raises gives an ERROR row and the others still count", sorted(r.device for r in rows) == ["c1", "c3"] and {r.device: r.status for r in rows}["c3"] == "ERROR", [(r.device, r.status) for r in rows])
saved = db.latest_scan_results()[0]
check("the rows are saved as the Scanning page saves them (its Latest scan shows them)", sorted(r["device"] for r in saved) == ["c1", "c3"], saved)
check("scan_last is stored and a second tick a minute later does not scan again", db.get_setting("scan_last") == NOW.strftime(F)
      and not scansched.scan_due(NOW + timedelta(minutes=1)) and scansched.scan_due(NOW + timedelta(days=1)))
a = db.connect().execute("SELECT actor, action, detail FROM audit ORDER BY id DESC LIMIT 1").fetchone()
check("one audit line, in the config backup style", (a["action"], a["detail"]) == ("scan", "2 device(s) (service)"), tuple(a))
seen.clear(); db.set_setting("scan_last", ""); db.set_setting("scan_groups", ["Vendor: Gone"])
check("groups that have all gone scan nothing, and it still does not repeat", scansched.run_scheduled_scan(NOW) == [] and not seen and not scansched.scan_due(NOW + timedelta(minutes=1)))
db.set_setting("scan_groups", [])
seen.clear(); db.set_setting("scan_last", ""); scansched.run_scheduled_scan(NOW)
check("no group chosen means every enabled device", sorted(seen) == ["c1", "c3", "f1"], seen)

print("== the service's tick")
db.set_setting("scan_groups", cisco); db.set_setting("scan_last", ""); seen.clear()
d = service.Daemon(log=lambda m: None)
did = d.tick(NOW)
check("the owning process runs it in its loop", ("scan", 2) in did and sorted(seen) == ["c1", "c3"], (did, seen))
d.tick(NOW + timedelta(minutes=1))
check("and not again a minute later", sorted(seen) == ["c1", "c3"], seen)
orig = service.owns_schedule; service.owns_schedule = lambda: False
db.set_setting("scan_last", ""); seen.clear(); did = d.tick(NOW + timedelta(days=2))
service.owns_schedule = orig
check("a process that does not own the schedule does not scan", not seen and not any(k == "scan" for k, _ in did), (did, seen))

print("== the window")
from PySide6.QtWidgets import QApplication, QLabel
app = QApplication([])
import app as A
started = []
tab = types.SimpleNamespace(busy=False, running=lambda: tab.busy, start_scheduled=lambda groups: started.append(groups))
win = types.SimpleNamespace(scanning=tab)
db.set_setting("scan_last", ""); A.Main.do_housekeeping(win)
check("the one-minute hook starts it on the Scanning page's worker with the chosen groups", started == [cisco], started)
A.Main.do_housekeeping(win)
check("a minute later it does not start again", len(started) == 1)
db.set_setting("scan_last", ""); tab.busy = True; A.Main.do_housekeeping(win)
check("not while a scan is already running (it waits, nothing is marked)", len(started) == 1 and db.get_setting("scan_last") == "")
tab.busy = False; service.owns_schedule = lambda: False; A.Main.do_housekeeping(win); service.owns_schedule = orig
check("not when the service owns the schedule", len(started) == 1)

print("== Settings > Scanning")
from ui.settings_pages.scanning import ScanningPage
import ui.settings as ST
db.set_setting("scan_schedule", "weekly"); db.set_setting("scan_groups", cisco)
pg = ScanningPage(); pg.load()
labels = [l.text() for l in pg.findChildren(QLabel)]
check("the rows are 'Scan automatically' and 'Devices'", "Scan automatically" in labels and "Devices" in labels, labels)
check("the options are Off, Daily, Weekly, Bi-Weekly, Monthly", [pg.schedule.itemText(i) for i in range(pg.schedule.count())] == ["Off", "Daily", "Weekly", "Bi-Weekly", "Monthly"])
check("it loads the stored schedule and groups", pg.schedule.currentData() == "weekly" and pg.groups.selected() == cisco)
pg.schedule.setCurrentIndex(pg.schedule.findData("biweekly")); pg.groups.set_selected(["Vendor: Fortinet"]); pg.save()
check("it saves both", db.get_setting("scan_schedule") == "biweekly" and db.get_setting("scan_groups") == ["Vendor: Fortinet"])
S = ST.SettingsTab(); S.resize(1200, 800); S.show(); app.processEvents()
S.select_page("Scanning"); app.processEvents(); time.sleep(0.2); app.processEvents(); S.check_dirty()
sp = S.pages[S.stack.currentIndex()]; i = S.stack.currentIndex()
check("opened, the page is not dirty", not S._dirty.get(i))
sp.schedule.setCurrentIndex(sp.schedule.findData("daily")); S.check_dirty()
check("a changed schedule is tracked as an unsaved edit", S._dirty.get(i), dict(S._dirty))
sp.load(); S.check_dirty(); sp.groups.set_selected(cisco); S.check_dirty()
check("a changed group choice is tracked too", S._dirty.get(i), dict(S._dirty))
check("the labels of the two settings", ST.KEY_LABELS["scan_schedule"] == "Scan automatically" and ST.KEY_LABELS["scan_groups"] == "Devices")
note_text = "Scans the chosen devices for vulnerabilities and hardening while Toner or its background service is running. The results are on the Scanning page."
check("the approved note is on the page", any(l.text() == note_text for l in pg.findChildren(QLabel)))
print(f"\n{ok} passed, {bad} failed")

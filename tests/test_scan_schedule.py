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
    return [Result(d["name"], advisories.SOFTWARE, "OK", "1.0", "m", org=d.get("org"))]
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

print("== every organization, one clock")
from core import orgs
acme = orgs.create("Acme Charter", "ACME"); beta = orgs.create("Beta Works", "BETA"); gone = orgs.create("Gone Ltd", "GONE")
for o, names in ((acme, ("a1", "a2")), (beta, ("b1", "b2")), (gone, ("g1", "g2"))):
    with db.within(o):
        dev(names[0], "cisco"); dev(names[1], "fortinet")
orgs.set_archived(gone, True)
db.set_setting("scan_groups", cisco); db.set_setting("scan_schedule", "daily"); db.set_setting("scan_last", ""); seen.clear()
db.set_home(acme)                                   # the window shows one organization
rows = scansched.run_scheduled_scan(NOW)
check("it covers Global's and every active organization's devices in the chosen group, and skips an archived one", sorted(seen) == ["a1", "b1", "c1", "c3"], seen)
db.set_home(db.GLOBAL)
here = {}
for o in (db.GLOBAL, acme, beta, gone):
    with db.within(o):
        here[o] = sorted({r["device"] for r in db.connect().execute("SELECT device FROM scan_results")})
check("each row is saved in the file of the organization its device belongs to", here[db.GLOBAL] == ["c1", "c3", "f1"] and here[acme] == ["a1"] and here[beta] == ["b1"] and here[gone] == [], here)
check("scan_last is Global's, not the organization's", db.get_setting("scan_last") == NOW.strftime(F) and "scan_last" not in db.ORG_LOCAL)
with db.within(acme):
    check("...and an organization reads the same one", db.get_setting("scan_last") == NOW.strftime(F))
n = db.connect().execute("SELECT COUNT(*) FROM audit WHERE action='scan'").fetchone()[0]
check("one audit line for the whole scan, in Global", n >= 1 and db.connect().execute("SELECT detail FROM audit WHERE action='scan' ORDER BY id DESC LIMIT 1").fetchone()[0] == "4 device(s) (service)")
seen.clear(); db.set_setting("scan_last", ""); db.set_setting("scan_groups", ["Vendor: Gone"])
check("groups that exist nowhere scan nothing", scansched.run_scheduled_scan(NOW) == [] and not seen)
db.set_setting("scan_groups", cisco)

real_all = advisories.scan_all
def boom(devs, **k): raise RuntimeError("everything down")
advisories.scan_all = boom; db.set_setting("scan_last", "")
try: scansched.run_scheduled_scan(NOW); raised = False
except RuntimeError: raised = True
advisories.scan_all = real_all
check("a scan that fails outright has stored scan_last and does not start again a minute later", raised and db.get_setting("scan_last") == NOW.strftime(F) and not scansched.scan_due(NOW + timedelta(minutes=1)))

print("== the service's tick")
db.set_setting("scan_groups", cisco); db.set_setting("scan_last", ""); seen.clear()
d = service.Daemon(log=lambda m: None)
did = d.tick(NOW)
check("the owning process runs it in its loop, every organization at once", ("scan", 4) in did and sorted(seen) == ["a1", "b1", "c1", "c3"], (did, seen))
d.tick(NOW + timedelta(minutes=1))
check("and not again a minute later", len(seen) == 4, seen)
orig = service.owns_schedule; service.owns_schedule = lambda: False
db.set_setting("scan_last", ""); seen.clear(); did = d.tick(NOW + timedelta(days=2))
service.owns_schedule = orig
check("a process that does not own the schedule does not scan", not seen and not any(k == "scan" for k, _ in did), (did, seen))

print("== the window")
from PySide6.QtWidgets import QApplication, QLabel
app = QApplication([])
import app as A
from ui import scheduler
import threading
def gset(k, v):
    with db.within(db.GLOBAL): db.set_setting(k, v)
def gget(k):
    with db.within(db.GLOBAL): return db.get_setting(k)
reloaded = []
tab = types.SimpleNamespace(busy=False, running=lambda: tab.busy, reload=lambda: reloaded.append(1))
gset("scan_last", ""); seen.clear(); db.set_home(acme)
held = threading.Event(); orig_run = scheduler.ScanJob.run
scheduler.ScanJob.run = lambda self: (held.wait(10), orig_run(self))[1]            # hold the thread's work so the test can look while it runs
main = threading.get_ident()
scheduler.start_scan(tab)
job = scheduler.ScanJob.current
check("the window shows Acme and starts a scan on its own thread, which is held here, so the UI thread was not used", job is not None and job.isRunning() and not seen, (job, seen))
check("scan_last is stored before the network work", gget("scan_last") != "" and not seen)
gset("scan_last", ""); scheduler.start_scan(tab)
check("not while the previous scheduled scan is still running", scheduler.ScanJob.current is job and gget("scan_last") == "")
held.set(); job.wait(15000); app.processEvents()
check("it scans every organization, from the thread", sorted(seen) == ["a1", "b1", "c1", "c3"], seen)
check("the Scanning page reloads its latest scan when it ends", reloaded == [1], reloaded)
scheduler.ScanJob.run = orig_run
gset("scan_last", ""); tab.busy = True; n0 = len(seen); scheduler.start_scan(tab)
check("not while a manual scan is running (nothing stored)", len(seen) == n0 and gget("scan_last") == "")
tab.busy = False; service.owns_schedule = lambda: False; scheduler.start_scan(tab); service.owns_schedule = orig
check("not when the service owns the schedule", len(seen) == n0 and gget("scan_last") == "")
scheduler.start_scan(tab); scheduler.ScanJob.current.wait(15000); app.processEvents(); n1 = len(seen)
scheduler.start_scan(tab)
check("a minute later nothing starts again", len(seen) == n1 and not scheduler.ScanJob.current.isRunning())
db.set_home(db.GLOBAL)
check("the housekeeping hook calls it", "scheduler.start_scan(self.scanning)" in open(A.__file__).read())

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

print("== each device is scanned against its own organization's backups")
from core import backup, hardening
BAD = "hostname sw\nenable password cisco\nip http server\nip finger\nsnmp-server community public RO\nline vty 0 4\n transport input telnet\n"
CLEAN = "hostname sw\n"
def cdev(name):
    db.save_device(dict(name=name, vendor="cisco", host=name, port=0, platform="cisco_ios", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))
cdev("gw"); backup.store("gw", BAD, mask=False)
with db.within(acme): cdev("sw"); backup.store("sw", CLEAN, mask=False)
with db.within(beta): cdev("sw"); cdev("bx"); backup.store("sw", BAD, mask=False)
advisories.scan = lambda dv: advisories.versions(dv) + hardening.scan(dv)             # the real scan: only the network lookups are off
db.set_setting("scan_enabled", False); db.set_setting("scan_groups", cisco)
for shown in (acme, beta, db.GLOBAL):
    db.set_home(shown)
    got = scansched.scan(scansched.begin(NOW))
    db.set_home(db.GLOBAL)
    def hard(name, org):
        return [r for r in got if r.device == name and r.org == org and r.check.startswith("Hardening")]
    tel = lambda name, org: next((r.status for r in hard(name, org) if r.check == "Hardening: Telnet allowed on VTY lines"), None)
    fails = lambda name, org: sum(r.status == "FAIL" for r in hard(name, org))
    where = f"(window shows {db.org_name(shown) if shown else 'Global'})"
    check(f"a Global device reads Global's backup {where}", fails("gw", 0) > 0, [(r.check, r.status) for r in hard("gw", 0)][:3])
    check(f"Acme's 'sw' reads its own backup (Telnet fine), not Beta's {where}", tel("sw", acme) == "OK", [(r.check, r.status, r.message[:30]) for r in hard("sw", acme)][:3])
    check(f"Beta's 'sw' reads its own backup (Telnet allowed) {where}", tel("sw", beta) == "FAIL")
    check(f"a device with no backup says so {where}", [r.message for r in hard("bx", beta)] == [hardening.NO_BACKUP], [r.message for r in hard("bx", beta)])


print("== the window's job: a failure, shutdown, and the real Scanning page")
import logging
from ui.scanning import ScanningTab
class Catch(logging.Handler):
    def __init__(self): super().__init__(); self.lines = []
    def emit(self, r): self.lines.append(r.getMessage())
catch = Catch(); logging.getLogger("ui.scheduler").addHandler(catch)
real_scan = scansched.scan
def gset(k, v):
    with db.within(db.GLOBAL): db.set_setting(k, v)
def locked(devs): raise RuntimeError("database is locked")
scansched.scan = locked
db.set_home(acme); gset("scan_last", ""); gset("scan_schedule", "daily")
tab2 = types.SimpleNamespace(running=lambda: False, reload=lambda: None)
scheduler.start_scan(tab2); job = scheduler.ScanJob.current; job.wait(15000)
check("a scan that raises in the job is logged, and the job ends", catch.lines == ["scheduled scan failed"] and job.isFinished(), catch.lines)
scansched.scan = real_scan
gset("scan_last", ""); scheduler.start_scan(tab2)
check("...and the next scheduled scan can run", scheduler.ScanJob.current is not job); scheduler.ScanJob.current.wait(15000)
waited = []
scheduler.ScanJob.current = types.SimpleNamespace(wait=lambda ms: waited.append(ms), isRunning=lambda: True)
scheduler.Scheduler(tab2).shutdown()
check("shutting down waits for a running scheduled scan", waited == [30000], waited)
scheduler.ScanJob.current = None
real = ScanningTab(); real.resize(900, 500); real.show(); app.processEvents()
db.set_home(acme); real.reset_view(); before = len(real.results)
gset("scan_last", "")
with db.within(acme):
    with db.connect() as c: c.execute("DELETE FROM scan_results"); c.execute("DELETE FROM scans")
real.reset_view(); empty = len(real.results)
scheduler.start_scan(real); scheduler.ScanJob.current.wait(15000)
t0 = time.time()
while not real.results and time.time() - t0 < 10: app.processEvents(); time.sleep(0.02)
check("the real Scanning page shows the new latest scan when the job ends", empty == 0 and real.stored and any(r.device.split("@@")[0] == "sw" for r in real.results), (empty, real.stored, [r.device for r in real.results][:4]))
db.set_home(db.GLOBAL)
print(f"\n{ok} passed, {bad} failed")

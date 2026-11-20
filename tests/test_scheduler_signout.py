# Run directly (python tests/test_scheduler_signout.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched, and no device is contacted: the
# workers are replaced below.
# Sign out closes the window and deletes it while Toner stays open (app.main). Nothing of the schedules may run after that: the
# health checks, the config backups, other organizations' runs, a run on start that was not yet due, and the scheduled scan.
# 2.0.0 logged "Internal C++ object (PySide6.QtWidgets.QLabel) already deleted" from Scheduler._fire after a sign-out.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "so%d.db" % int(time.time())); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import db, orgs, scansched, service
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

import shiboken6
from PySide6.QtCore import QEvent
from PySide6.QtWidgets import QApplication
import app as A
from ui import configs, results, scheduler
app = QApplication.instance() or QApplication(sys.argv)

started, raised = [], []                             # runs that began; exceptions nothing caught (what Toner writes to its log)
sys.excepthook = lambda kind, value, tb: raised.append(f"{kind.__name__}: {value}")
def no_run(what):
    def stop(*_a, **_k):
        started.append(what)
        raise AssertionError(f"{what} started")
    return stop
results.ResultsTab._worker = no_run("health checks")                    # the only places a run reaches a device
configs.BackupWorker = no_run("config backups")
service.own_devices = lambda groups=None: started.append("another organization's run") or []
service.owns_schedule = lambda: True                 # this window runs the schedule (no service does)
scansched.scan_due = lambda now=None: False          # the window's housekeeping starts no scan of its own here

def dev(name):
    db.save_device(dict(name=name, vendor="cisco", host=name, port=0, platform="cisco_ios", username="", site="default", verify_ssl=0,
                        ha_expected=0, enabled=1, location="", details="", folder_id=None))
def schedules(on_start):
    for key in ("schedule_enabled", "backup_enabled"):
        db.set_setting(key, True)
    for key in ("schedule_on_start", "backup_on_start"):
        db.set_setting(key, on_start)
dev("c1")
acme = orgs.create("Acme Charter", "ACME")
with db.within(acme):
    dev("a1")

def spin(seconds):
    end = time.time() + seconds
    while time.time() < end:
        app.processEvents(); time.sleep(0.005)
def window():
    win = A.Main(); win.show(); app.processEvents()
    return win
def sign_out(win):
    """What Sign out does: Main.sign_out closes the window, then app.main deletes it and goes back to the sign-in page."""
    win.sign_out()
    win.deleteLater(); app.sendPostedEvents(None, QEvent.Type.DeferredDelete)
def alive(obj):
    return shiboken6.isValid(obj)
def timers_of(win):
    return [t for s in (win.scheduler, win.backup_scheduler) for t in (s.timer, *s.others.values())]

print("== signed out while the schedules are armed")
schedules(on_start=False)
with db.within(acme):
    schedules(on_start=False)
win = window()
timers = timers_of(win)
check("(armed: checks and backups, here and in another organization)", len(timers) == 4 and all(t.isActive() for t in timers), len(timers))
housekeeping = win.housekeeping
sign_out(win)
check("the window has gone", not alive(win) and not alive(win.results.summary))
check("the schedules went with it", not alive(win.scheduler) and not alive(win.backup_scheduler))
check("...and so did every timer of theirs", not any(alive(t) for t in timers), [alive(t) for t in timers])
check("...and the housekeeping that starts the scheduled scan", not alive(housekeeping))
for t in timers:                                     # a timer that outlived the window comes due
    if alive(t):
        t.timeout.emit()
spin(0.2)
check("a schedule coming due afterwards runs nothing", started == [], started)
check("...and raises nothing", raised == [], raised)
started.clear(); raised.clear()

print("== signed out before the run on start was due")
scheduler.Scheduler.START_DELAY = scheduler.BackupScheduler.START_DELAY = 300      # (2 and 8 seconds in Toner; the others' run a second later)
schedules(on_start=True)
with db.within(acme):
    schedules(on_start=True)
win = window()
sign_out(win)
spin(1.7)
check("no run on start begins on the window that has gone", started == [], started)
check("...and nothing is raised", raised == [], raised)
started.clear(); raised.clear()

print("== closed, not yet deleted (a factory reset stops everything before it deletes)")
win = window()
win.scheduler.shutdown(); win.backup_scheduler.shutdown()
spin(1.7)
check("shutdown() stops the runs on start that were not yet due", started == [], started)
check("...and the schedules", not any(t.isActive() for t in timers_of(win)))
win.scheduler.apply(); win.backup_scheduler.apply()
check("apply() arms them again (a factory reset that deleted nothing)", all(t.isActive() for t in timers_of(win)) and len(timers_of(win)) == 4)
sign_out(win)
spin(0.2)
check("nothing was raised", raised == [], raised)
started.clear(); raised.clear()

print("== a scheduled scan still running at sign-out")
schedules(on_start=False)
with db.within(acme):
    schedules(on_start=False)
win = window()
scanned = []
scansched.scan_due = lambda now=None: True
scansched.begin = lambda now=None, who=None: [{"name": "c1"}]
scansched.scan = lambda devices: (time.sleep(0.4), scanned.append(len(devices)))
scheduler.start_scan(win.scanning)
scansched.scan_due = lambda now=None: False
job = scheduler.ScanJob.current
check("(the scan is running)", job is not None and job.isRunning())
sign_out(win)
check("sign-out waits for it to end", not job.isRunning() and scanned == [1], scanned)
spin(0.2)
check("...and its end tells no window that has gone", raised == [], raised)

print("== a health-check run and a scan started by hand, still going at sign-out")
from PySide6.QtCore import QThread, Signal
ended = []
class Slow(QThread):                                 # a run that takes a while and reaches no device
    batch = Signal(list); check = Signal(str, str)
    def __init__(self, what):
        super().__init__(); self.what = what
    def run(self):
        time.sleep(0.4); ended.append(self.what)
win = window()
win.results._worker = lambda devices: Slow("checks")
win.scanning._worker = lambda devices: Slow("scan")
win.results.start(); win.scanning.start(); app.processEvents()
workers = [win.results.worker, win.scanning.worker]
check("(both are running)", all(w is not None and w.isRunning() for w in workers))
sign_out(win)
check("sign-out waits for both to end (they would go on reaching devices with the data closed)",
      not any(w.isRunning() for w in workers) and sorted(ended) == ["checks", "scan"], ended)
spin(0.6)
check("...and nothing is raised", raised == [], raised)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Responsiveness on a long history: tables refill without measuring every row after each cell, the newest results come from an
# index (migration 8), the checks that have numbers are listed as results are stored, the newest results are kept per file until
# runs change, and availability is counted by SQLite.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, sqlite3
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "perf%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from datetime import datetime, timedelta
from core import db, orgs
from drivers.base import Result
db.init()

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def dev(name, **kw):
    db.save_device(dict(dict(name=name, vendor="cisco", host="10.0.0.1", port=0, platform="", username="u", site="default", verify_ssl=0,
                             ha_expected=0, enabled=1, location="", details="", folder_id=None), **kw))

def plan(sql, args=()):
    with db.connect() as c:
        return " | ".join(r[3] for r in c.execute("EXPLAIN QUERY PLAN " + sql, args))

def indexes():
    with db.connect() as c:
        return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='results'")}

# ================================================================ migration 8
print("== upgrading a database from before (migration 8)")
old = os.path.join(SP, "before8_%d.db" % int(time.time() * 1000))
saved = os.environ["NETCHECK_DB"]
os.environ["NETCHECK_DB"] = old
db._wal_set.clear(); db.forget_orgs(); db._forget_settings()
db.init()
with db.connect() as c:                                            # what 1.6.6 left: the old index, no list of numeric checks
    c.executescript("DROP INDEX IF EXISTS idx_results_latest; DROP TRIGGER IF EXISTS numeric_checks_add; DROP TABLE IF EXISTS numeric_checks;"
                    "CREATE INDEX idx_results_series ON results(device, check_name); PRAGMA user_version = 7;")
    rid = c.execute("INSERT INTO runs(started_at, ok, warn, fail, error) VALUES('2026-10-01 10:00:00', 2, 0, 0, 0)").lastrowid
    c.executemany("INSERT INTO results(run_id, device, check_name, status, value, message, numeric) VALUES(?,?,?,?,?,?,?)",
                  [(rid, "sw1", "cpu", "OK", "5%", "", 5.0), (rid, "sw1", "firmware", "OK", "17.3", "", None),
                   (rid, "ctrl / ap1", "clients", "OK", "12", "", 12.0)])
check("the old database is at version 7 with the old index", db.schema_version() == 7 and "idx_results_series" in indexes())
db.init()
check("upgrading brings it to the newest version", db.schema_version() == db.SCHEMA_VERSION >= 8)
check("the index by device, check and run replaces the one by device and check",
      "idx_results_latest" in indexes() and "idx_results_series" not in indexes(), indexes())
check("the checks that already have numbers are listed", db.device_checks() == {"sw1": ["cpu"], "ctrl / ap1": ["clients"]}, db.device_checks())
db.init()
check("opening it again doesn't bring the old index back", "idx_results_series" not in indexes())
os.environ["NETCHECK_DB"] = saved
db._wal_set.clear(); db.forget_orgs(); db._forget_settings(); db._invalidate_folders(); db.forget_history()

print("== the newest results come from the index")
SKIP = ("config backup",)
check("each device's newest run is read from the index alone", "COVERING INDEX idx_results_latest" in
      plan("SELECT device, MAX(run_id) AS rid FROM results WHERE check_name NOT IN (?) GROUP BY device", SKIP),
      plan("SELECT device, MAX(run_id) AS rid FROM results WHERE check_name NOT IN (?) GROUP BY device", SKIP))
check("a chart's points come newest first from the index", "idx_results_latest" in
      plan("SELECT runs.started_at AS t, results.numeric AS v FROM results JOIN runs ON runs.id = results.run_id "
           "WHERE results.device=? AND results.check_name=? AND results.numeric IS NOT NULL ORDER BY results.run_id DESC LIMIT ?", ("a", "b", 5)))

print("== checks that have numbers")
dev("sw1"); dev("fw1")
db.save_run([Result("sw1", "cpu", "OK", "5%", "", 5.0), Result("sw1", "firmware", "OK", "17.3", ""), Result("fw1", "memory", "WARN", "81%", "", 81.0)])
check("a result with a number lists its check, one without doesn't", db.device_checks() == {"fw1": ["memory"], "sw1": ["cpu"]}, db.device_checks())
db.save_run([Result("sw1", "cpu", "OK", "6%", "", 6.0), Result("sw1", "temperature", "OK", "41", "", 41.0)])
check("a new check with a number is added, without repeats", db.device_checks()["sw1"] == ["cpu", "temperature"], db.device_checks())
check("the chart still reads its points", [v for _t, v in db.series("sw1", "cpu")] == [5.0, 6.0], db.series("sw1", "cpu"))

print("== remembered until runs change")
health = db.device_health()
check("each device's newest state", health["sw1"]["status"] == "OK" and health["fw1"]["status"] == "WARN", health)
health["sw1"]["status"] = "changed by a caller"; health["fw1"]["problems"].append(("x", "FAIL", ""))
again = db.device_health()
check("each caller gets its own copy", again["sw1"]["status"] == "OK" and len(again["fw1"]["problems"]) == 1, again)
kept = [k for k in db._remember if k[1] == "_device_health_here"]
check("the answer is kept for the file", len(kept) == 1)
calls = []
inner = db._remember[kept[0]]
db._remember[kept[0]] = (inner[0], {"sw1": {"status": "ERROR", "at": "", "checks": 0, "problems": []}})
check("while the runs haven't changed, the kept answer is used", db.device_health()["sw1"]["status"] == "ERROR")
db.save_run([Result("sw1", "cpu", "FAIL", "99%", "busy", 99.0)])
check("a new run is read at once", db.device_health()["sw1"]["status"] == "FAIL" and "fw1" in db.device_health())
rows, _at = db.latest_results()
rows[0]["device"] = "changed"
check("the newest results are copies too", all(r["device"] != "changed" for r in db.latest_results()[0]))
with db.connect() as c:
    c.execute("DELETE FROM runs WHERE id = (SELECT MAX(id) FROM runs)")
check("removing a run is noticed", db.device_health()["sw1"]["status"] == "OK", db.device_health()["sw1"])

print("== moving a device takes its checks along, and is read afresh")
acme = orgs.create("Acme", "ACME")
db.forget_orgs()
db.device_health()
with db.within(db.GLOBAL):
    sw1 = next(d for d in db.list_devices() if d["name"] == "sw1")
orgs.move_devices([sw1], acme)
with db.within(db.GLOBAL):
    check("the organization it left no longer lists its checks or its state", "sw1" not in db.device_checks()
          and "sw1" not in db.device_health(), (db.device_checks(), list(db.device_health())))
with db.within(acme):
    check("the organization it went to lists them", db.device_checks().get("sw1") == ["cpu", "temperature"]
          and db.device_health()["sw1"]["status"] == "OK", (db.device_checks(), db.device_health()))

# ================================================================ availability
print("== availability is counted by SQLite, with the same answer")
def old_availability(days=7, start=None, end=None):
    """The way 1.6.6 counted it, row by row."""
    cutoff = start or (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    until = end or "9999-12-31 00:00:00"
    seen, stats = {}, {}
    with db.connect() as c:
        for r in c.execute("SELECT results.run_id AS rid, device, check_name, status FROM results JOIN runs ON runs.id = results.run_id "
                           "WHERE runs.started_at >= ? AND runs.started_at < ? AND check_name != 'config backup'", (cutoff, until)):
            s = seen.setdefault((r["rid"], db._base(r["device"])), {"conn": False, "bad": False})
            if r["check_name"] == "connection" and r["status"] == "ERROR":
                s["conn"] = True
            if db._SEV.get(r["status"], 0) >= 2:
                s["bad"] = True
    for (rid, d), s in seen.items():
        st = stats.setdefault(d, {"runs": 0, "reachable": 0, "healthy": 0})
        st["runs"] += 1; st["reachable"] += 0 if s["conn"] else 1; st["healthy"] += 0 if s["bad"] else 1
    return stats
with db.connect() as c:
    def run(at, rows):
        rid = c.execute("INSERT INTO runs(started_at, ok, warn, fail, error) VALUES(?, 0, 0, 0, 0)", (at,)).lastrowid
        c.executemany("INSERT INTO results(run_id, device, check_name, status, value, message) VALUES(?,?,?,?,?,?)",
                      [(rid, d, ch, s, "", "") for d, ch, s in rows])
    now = datetime.now()
    for h in range(30):
        at = (now - timedelta(hours=h * 7)).strftime("%Y-%m-%d %H:%M:%S")        # some inside the last week, some before it
        run(at, [("fw1", "cpu", "OK"), ("fw1", "memory", ["OK", "WARN", "FAIL"][h % 3]),
                 ("ctrl", "health", "OK"), ("ctrl / ap1", "clients", ["OK", "ERROR"][h % 2]), ("ctrl / ap2", "clients", "OK"),
                 ("lab", "connection", ["ERROR", "OK"][h % 2]), ("lab", "config backup", "FAIL"),
                 ("nas", "disk", "OK"), ("nas", "config backup", "FAIL")])
for args in ((7,), (2,), (30,), (7, (now - timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S"), now.strftime("%Y-%m-%d %H:%M:%S"))):
    new, was = db._availability_here(*args), old_availability(*args)
    check(f"the same counts for {args[0]} days" + (" between two times" if len(args) > 1 else ""), new == was and new, (new, was))
check("a UniFi sub-device counts for its controller", "ctrl / ap1" not in db._availability_here(30) and "ctrl" in db._availability_here(30))
nas = db._availability_here(30)["nas"]
check("a failed config backup doesn't make a run unhealthy", nas["healthy"] == nas["runs"] > 0, nas)

# ================================================================ tables
print("== tables refill without measuring every row after each cell")
from PySide6.QtWidgets import QApplication, QHeaderView, QStyledItemDelegate, QTableWidget, QTableWidgetItem
app = QApplication.instance() or QApplication([])
from ui.widgets import StatusDelegate, filling
FIT, STRETCH = QHeaderView.ResizeMode.ResizeToContents, QHeaderView.ResizeMode.Stretch

class Counting(QStyledItemDelegate):
    calls = 0
    def sizeHint(self, option, index):
        Counting.calls += 1
        return super().sizeHint(option, index)

def table():
    t = QTableWidget(0, 3)
    for i, m in enumerate((FIT, STRETCH, FIT)):
        t.horizontalHeader().setSectionResizeMode(i, m)
    t.setItemDelegate(Counting(t)); t.resize(900, 500); t.show(); app.processEvents()
    return t

def fill(t, n, helped):
    def put():
        t.setRowCount(n)
        for i in range(n):
            for j, text in enumerate((f"device-{i:03d}", "a longer explanation of what is wrong", "2 h ago")):
                t.setItem(i, j, QTableWidgetItem(text))
    if helped:
        with filling(t):
            put()
    else:
        put()
    app.processEvents()

plain, helped = table(), table()
fill(plain, 120, False); fill(helped, 120, True)
Counting.calls = 0; fill(plain, 120, False); unhelped_calls = Counting.calls
Counting.calls = 0; fill(helped, 120, True); helped_calls = Counting.calls
check("refilling 120 rows measures each cell a few times, not every row after every cell", helped_calls < 120 * 3 * 4 < unhelped_calls,
      (helped_calls, unhelped_calls))
check("the columns end up just as wide", [helped.columnWidth(i) for i in range(3)] == [plain.columnWidth(i) for i in range(3)],
      ([helped.columnWidth(i) for i in range(3)], [plain.columnWidth(i) for i in range(3)]))
check("and fit their contents again afterwards", [helped.horizontalHeader().sectionResizeMode(i) for i in range(3)] == [FIT, STRETCH, FIT])
helped.selectRow(7)
fill(helped, 120, True)
check("the selected row stays selected", helped.currentRow() == 7)

print("== the Overview's Needs attention list, refilled")
import app as A
for i in range(60):
    dev(f"bad{i:02d}")
db.save_run([Result(f"bad{i:02d}", "cpu", "FAIL", "99%", "busy", 99.0) for i in range(60)])
w = A.Main(); w.show(); app.processEvents()
dash = w.dashboard
calls = [0]
real = StatusDelegate.sizeHint
StatusDelegate.sizeHint = lambda self, option, index: (calls.__setitem__(0, calls[0] + 1), real(self, option, index))[1]
dash.refresh(); app.processEvents()
calls[0] = 0
dash.refresh(); app.processEvents()
StatusDelegate.sizeHint = real
rows = dash.attention.rowCount()
check("the list has the failing devices", rows >= 60, rows)
check("refilling it measures its status column a few times per row, not every row per cell", calls[0] < rows * 6, (calls[0], rows))
check("its columns still fit their contents", dash.attention.horizontalHeader().sectionResizeMode(0) == FIT
      and dash.attention.horizontalHeader().sectionResizeMode(2) == STRETCH)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

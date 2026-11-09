# Run directly (python tests/test_history_queries.py). History queries by time range and per device, across organizations.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, time
from datetime import datetime, timedelta
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "hq%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import db, orgs
from drivers.base import Result
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

now = datetime.now()
fmt = lambda t: t.strftime("%Y-%m-%d %H:%M:%S")
acme = orgs.create("Acme", "acme")

def save(org, rows, ago):
    """Store one run in that file, then backdate it."""
    with db.within(org):
        db.save_run(rows)
        with db.connect() as c:
            c.execute("UPDATE runs SET started_at=? WHERE id=(SELECT MAX(id) FROM runs)", (fmt(now - ago),))

# a: 250 hourly cpu rows (10 days), b (in Acme): 2 recent rows
for i in range(250):
    save(db.GLOBAL, [Result("a", "cpu", "OK", f"{i % 50}%", "load", numeric=float(i % 50))], timedelta(hours=i + 1) - timedelta(minutes=30))
save(acme, [Result("b", "cpu", "WARN", "80%", "busy", numeric=80.0)], timedelta(hours=2))
save(acme, [Result("b", "cpu", "OK", "40%", "", numeric=40.0)], timedelta(hours=30))
save(db.GLOBAL, [Result("a", "certificate", "OK", "90 days", "", numeric=90.0)], timedelta(hours=3))
save(acme, [Result("b", "certificates", "WARN", "20 days", "CN=x", numeric=20.0)], timedelta(hours=1))
db.set_home(db.GLOBAL)

print("== results_between")
r = db.results_between(now - timedelta(hours=8), now)
bk = db.dkey("b", acme)
check("only the last 8 hours (8 of a's cpu, 2 certificate rows, b's 2h cpu)", len(r) == 11 and all(x["t"] >= fmt(now - timedelta(hours=8)) for x in r), len(r))
check("newest first", [x["t"] for x in r] == sorted((x["t"] for x in r), reverse=True))
check("the organization's row is keyed with dkey", any(x["device"] == bk and x["check_name"] == "cpu" and x["message"] == "busy" for x in r))
check("rows carry the keys", set(r[0]) == {"t", "device", "check_name", "status", "value", "message", "numeric"}, r[0])

print("== check_rows and series")
rows = db.check_rows("a", "cpu", start=now - timedelta(days=90))
check("a range has no 200 limit", len(rows) == 250, len(rows))
check("rows have message", rows and "message" in rows[0] and rows[0]["message"] == "load")
check("default still limited to 200", len(db.check_rows("a", "cpu")) == 200)
check("end bounds the range", len(db.check_rows("a", "cpu", start=now - timedelta(days=90), end=now - timedelta(hours=100))) == 150)
check("series in a range has no limit", len(db.series("a", "cpu", start=now - timedelta(days=90))) == 250 and len(db.series("a", "cpu")) == 200)
check("series reads an organization's device by key", len(db.series(bk, "cpu", start=now - timedelta(days=90))) == 2)

print("== across devices")
# rows sit at (i + 1) h - 30 min, so none is on the 7-day edge whatever the clock does between seeding and the call
inside = [i for i in range(250) if i + 0.5 <= 7 * 24]
exp = sum(i % 50 for i in inside) / len(inside)
avg = db.average_per_device(["cpu"], 7)
check("average is the hand-computed mean", abs(avg["a"] - exp) < 1e-9 and avg[bk] == 60.0, (avg, exp))
check("rows without a number are left out", db.average_per_device(["nothing"], 7) == {})
lat = db.latest_per_device(["certificate", "certificates"])
check("one row per device", sorted(x["device"] for x in lat) == sorted(["a", bk]), lat)
check("the newest of its checks", {x["device"]: x["check_name"] for x in lat} == {"a": "certificate", bk: "certificates"})
check("a device with several rows of those checks still gives its newest only", len(db.latest_per_device(["cpu", "certificate", "certificates"])) == 2)
check("rows carry the keys", set(lat[0]) == {"device", "check_name", "status", "value", "message", "numeric", "t"})

print("== index")
sql = db._LATEST.format(vals="(?),(?)")
with db.connect() as c:
    plan = " ".join(str(tuple(r)) for r in c.execute("EXPLAIN QUERY PLAN " + sql, ("certificate", "certificates")))
check("latest_per_device seeks the index and never scans results", "SCAN results" not in plan and "idx_results_latest" in plan, plan)
with db.connect() as c:
    plan = " ".join(str(tuple(r)) for r in c.execute("EXPLAIN QUERY PLAN SELECT * FROM runs WHERE started_at >= ?", ("x",)))
check("runs are found by start time through an index", "idx_runs_started" in plan, plan)

print(f"\n{ok} passed, {bad} failed")
raise SystemExit(1 if bad else 0)

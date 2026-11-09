# Run directly (python tests/test_result_items.py). A Result can carry items (per disk, certificate, interface...): they are stored
# with the run, read back oldest first, work from the Global view, and go when their run is pruned.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "ri%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import db
db.init()
from drivers.base import Result, Driver

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

item = {"name": "C:", "numeric": 61.0, "status": "OK", "text": "", "data": {"used": 61e9, "total": 100e9}}
r = Result("srv", "disks", "OK", "61%", "", 61.0, items=[item])
check("copy keeps items", type(r)(**{**r.__dict__, "device": "x"}).items == [item])
check("items do not affect equality", r == Result("srv", "disks", "OK", "61%", "", 61.0))
d = Driver({"name": "srv", "host": "h", "type": "x"}, {})
check("Driver.result takes items", d.result("disks", "OK", "1", "", 1.0, items=[item]).items == [item])
check("Driver.result items default None", d.result("disks", "OK").items is None)

db.save_run([r, Result("srv", "cpu", "OK", "5%", "", 5.0)])
check("schema version", db.schema_version() == 15, db.schema_version())
t, items = db.latest_items("srv", "disks")
check("latest_items data", items[0]["data"]["total"] == 100e9, items)
check("latest_items time", bool(t))
check("items_of one entry", len(db.items_of("srv", "disks")) == 1)
check("items_of entry shape", set(db.items_of("srv", "disks")[0]) == {"t", "items"})
check("no items gives []", db.latest_items("srv", "cpu")[1] == [] and [e["items"] for e in db.items_of("srv", "cpu")] == [[]])
check("unknown check", db.latest_items("srv", "nope") == (None, []))
check("run_results unchanged", {x["check_name"] for x in db.run_results(db.list_runs()[0]["id"])} == {"disks", "cpu"})
check("end bound excludes", db.items_of("srv", "disks", end="2000-01-01 00:00:00") == [])

db.set_setting("retention_days", 0)
time.sleep(1.1)
db.save_run([Result("srv", "cpu", "OK", "5%", "", 5.0)])
with db.connect() as c:
    orphans = c.execute("SELECT COUNT(*) FROM result_items WHERE result_id NOT IN (SELECT id FROM results)").fetchone()[0]
    left = c.execute("SELECT COUNT(*) FROM result_items").fetchone()[0]
check("pruning leaves no orphan items", orphans == 0 and left == 0, (orphans, left))

print(f"\n{ok} passed, {bad} failed"); raise SystemExit(1 if bad else 0)

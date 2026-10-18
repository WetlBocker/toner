# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import os, sqlite3, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\hard%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

print("== a new database")
db.init()
with db.connect() as c:
    mode = c.execute("PRAGMA journal_mode").fetchone()[0]; busy = c.execute("PRAGMA busy_timeout").fetchone()[0]; fk = c.execute("PRAGMA foreign_keys").fetchone()[0]
check("it uses WAL, waits up to 15 s for a competing write, and enforces foreign keys", mode == "wal" and busy == 15000 and fk == 1, (mode, busy, fk))
check("it is stamped with the newest schema version", db.schema_version() == db.SCHEMA_VERSION == db.MIGRATIONS[-1][0] and db.SCHEMA_VERSION >= 2)
check("the migration numbers are 1, 2, 3... with no gaps", [n for n, _ in db.MIGRATIONS] == list(range(1, len(db.MIGRATIONS) + 1)))
with db.connect() as c:
    tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
check("the tables added by later steps exist", {"agent_metrics", "agent_seen", "agent_reports"} <= tables)
db.init(); check("running init again is harmless", db.schema_version() == db.SCHEMA_VERSION)

print("== upgrading an old database")
old = SP + (r"\old%d.db").replace("\\", os.sep) % int(time.time()); os.environ["NETCHECK_DB"] = old
raw = sqlite3.connect(old)
raw.executescript("""CREATE TABLE devices (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, vendor TEXT NOT NULL, host TEXT NOT NULL, port INTEGER DEFAULT 0,
  platform TEXT DEFAULT '', username TEXT DEFAULT '', site TEXT DEFAULT 'default', verify_ssl INTEGER DEFAULT 0, ha_expected INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1);
  INSERT INTO devices(name, vendor, host) VALUES('legacy-sw', 'cisco', '10.0.0.1');""")
raw.commit(); raw.close()
check("a database from before any numbering is at version 0", sqlite3.connect(old).execute("PRAGMA user_version").fetchone()[0] == 0)
db.init()
with db.connect() as c:
    cols = {r[1] for r in c.execute("PRAGMA table_info(devices)")}
check("every column added over the years is added, the data is kept, and it is stamped", {"location", "details", "folder_id", "tags", "fields", "profile_id", "snmp", "jump", "proxy", "winopts"} <= cols
      and db.list_devices()[0]["name"] == "legacy-sw" and db.schema_version() == db.SCHEMA_VERSION)
newer = SP + (r"\newer%d.db").replace("\\", os.sep) % int(time.time()); os.environ["NETCHECK_DB"] = newer; db.init()
with db.connect() as c: c.execute("PRAGMA user_version = 99")
db.init()
check("a database from a newer Toner is left alone (nothing is run, nothing is downgraded)", db.schema_version() == 99)

print("== settings are cached")
os.environ["NETCHECK_DB"] = SP + (r"\cache%d.db").replace("\\", os.sep) % int(time.time()); db.init()
calls = []
real_connect = db.connect
def counting():
    calls.append(1); return real_connect()
db.connect = counting
db.get_setting("workers"); n0 = len(calls)
for _ in range(50): db.get_setting("workers"); db.get_setting("theme"); db.get_setting("proxy")
check("150 reads cost no extra database connections", len(calls) == n0, len(calls) - n0)
db.set_setting("workers", 7)
check("a write is seen at once by the next read", db.get_setting("workers") == 7)
db.connect = real_connect
check("defaults are still copies nobody can modify", db.get_setting("snippets") == [] and db.get_setting("snippets") is not db.get_setting("snippets"))
other = sqlite3.connect(os.environ["NETCHECK_DB"]); other.execute("UPDATE settings SET value='9' WHERE key='workers'"); other.commit(); other.close()
check("a change made by another program is picked up within the cache time", (time.sleep(db.SETTINGS_TTL + 0.3), db.get_setting("workers"))[1] == 9)
first = db.get_setting("workers"); os.environ["NETCHECK_DB"] = SP + (r"\cache2_%d.db").replace("\\", os.sep) % int(time.time()); db.init()
check("a different database does not see the cached values of the last one", db.get_setting("workers") == db.DEFAULT_SETTINGS["workers"] and first == 9)

print("== writers do not trip over each other")
os.environ["NETCHECK_DB"] = SP + (r"\busy%d.db").replace("\\", os.sep) % int(time.time()); db.init()
errors = []
def writer(i):
    try:
        for j in range(40):
            db.set_setting(f"k{i}", j)
            with db.connect() as c: c.execute("INSERT INTO audit(at, actor, action, detail) VALUES(?,?,?,?)", ("now", "t", "x", f"{i}-{j}"))
    except Exception as e:
        errors.append(repr(e))
def reader():
    try:
        for _ in range(200): db.list_devices(); db.get_setting("workers")
    except Exception as e:
        errors.append(repr(e))
ts = [threading.Thread(target=writer, args=(i,)) for i in range(6)] + [threading.Thread(target=reader) for _ in range(3)]
t0 = time.time(); [t.start() for t in ts]; [t.join(60) for t in ts]
with db.connect() as c: n = c.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
check("six writers and three readers at once: no 'database is locked', nothing lost", not errors and n == 240, (errors[:2], n))
check("and it does not take long", time.time() - t0 < 30, time.time() - t0)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

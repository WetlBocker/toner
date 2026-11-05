# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Every database opens through core/sqldb.py (SQLCipher): plain with no key, encrypted with one, and the conversion and export helpers.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\sqldb%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
import sqlite3
from pathlib import Path
from core import db, sqldb
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1
    else: bad += 1; print("FAIL", name, extra)

PLAIN = b"SQLite format 3\x00"
head = lambda p: Path(p).read_bytes()[:16]
D = Path(SP)

sqldb.set_key(None)
p = D / "plain.db"
c = sqldb.connect(p); c.execute("CREATE TABLE t (a)"); c.execute("INSERT INTO t VALUES (1)"); c.commit(); c.close()
check("no key: plain header", head(p) == PLAIN)
check("no key: is_encrypted False", not sqldb.is_encrypted(p))
check("driver is SQLCipher 4", sqldb.sqlite3 is not sqlite3 and sqldb.connect(":memory:").execute("PRAGMA cipher_version").fetchone()[0].startswith("4"))

key = os.urandom(32)
sqldb.set_key(key)
check("current_key", sqldb.current_key() == key)
e = D / "enc.db"
c = sqldb.connect(e); c.execute("CREATE TABLE t (a)"); c.execute("INSERT INTO t VALUES (7)"); c.commit()
check("key: rows round-trip", c.execute("SELECT a FROM t").fetchall()[0][0] == 7); c.close()
check("key: header not plain", head(e) != PLAIN)
check("key: is_encrypted", sqldb.is_encrypted(e))
wrong_key = os.urandom(32); sqldb.set_key(wrong_key)
try: sqldb.connect(e); wrong = False
except sqldb.sqlite3.DatabaseError as ex: wrong = wrong_key.hex() not in str(ex) and key.hex() not in str(ex)
check("wrong key: DatabaseError at connect, no key in message", wrong)
sqldb.set_key(None)
try: sqldb.connect(e).execute("SELECT count(*) FROM sqlite_master"); raised = False
except sqldb.sqlite3.DatabaseError: raised = True
check("encrypted file without a key: DatabaseError", raised)

q = D / "conv.db"
sqldb.set_key(None)
c = sqldb.connect(q); c.execute("PRAGMA journal_mode = WAL"); c.execute("PRAGMA user_version = 5"); c.execute("CREATE TABLE t (a)")
c.executemany("INSERT INTO t VALUES (?)", [(1,), (2,), (3,)]); c.commit(); c.close()
sqldb.encrypt_file(q, key)
check("encrypt_file: encrypted", sqldb.is_encrypted(q))
check("encrypt_file: no .encrypting left", not list(D.glob("*.encrypting")))
check("encrypt_file: no -wal/-shm left", not (D / "conv.db-wal").exists() and not (D / "conv.db-shm").exists())
sqldb.set_key(key)
c = sqldb.connect(q)
check("encrypt_file: same 3 rows", [r[0] for r in c.execute("SELECT a FROM t ORDER BY a")] == [1, 2, 3])
check("encrypt_file: user_version kept", c.execute("PRAGMA user_version").fetchone()[0] == 5)

# another connection holding the file: the checkpoint can't empty the WAL, so nothing may be deleted or replaced
b = D / "busy.db"
sqldb.set_key(None)
w = sqldb.connect(b); w.execute("PRAGMA journal_mode = WAL"); w.execute("CREATE TABLE t (a)"); w.execute("INSERT INTO t VALUES (1)"); w.commit()
r = sqldb.connect(b); r.execute("BEGIN"); r.execute("SELECT * FROM t").fetchall()
w.execute("INSERT INTO t VALUES (2)"); w.commit()
try: sqldb.encrypt_file(b, key); refused = False
except sqldb.sqlite3.OperationalError as ex: refused = key.hex() not in str(ex)
check("encrypt_file: busy checkpoint refuses", refused)
check("encrypt_file: busy leaves the file, its WAL and no .encrypting", not sqldb.is_encrypted(b) and (D / "busy.db-wal").exists()
      and not (D / "busy.db.encrypting").exists())
r.rollback(); r.close(); w.close()
check("encrypt_file: busy lost nothing", [x[0] for x in sqldb.connect(b).execute("SELECT a FROM t ORDER BY a")] == [1, 2])

# a connection that is merely open (idle, nothing in the WAL for it), and one that keeps committing during the encrypt: on POSIX
# the swap would leave either writing to the old file, so encrypt_file must refuse while any other connection has it open
import threading
def rows_of(path):
    c = sqldb.connect(path)
    try: return [x[0] for x in c.execute("SELECT a FROM t ORDER BY a")]
    finally: c.close()
i = D / "idle.db"
w = sqldb.connect(i); w.execute("PRAGMA journal_mode = WAL"); w.execute("CREATE TABLE t (a)"); w.execute("INSERT INTO t VALUES (1)"); w.commit(); w.close()
idle = sqldb.connect(i); idle.execute("SELECT * FROM t").fetchall()
try: sqldb.encrypt_file(i, key); refused = False
except sqldb.sqlite3.OperationalError as ex: refused = key.hex() not in str(ex)
check("encrypt_file: an idle open connection refuses", refused and not sqldb.is_encrypted(i) and not (D / "idle.db.encrypting").exists())
idle.execute("INSERT INTO t VALUES (2)"); idle.commit()
check("encrypt_file: the idle connection still writes to the file everyone sees", rows_of(i) == [1, 2])
idle.close()
written, stop = [], threading.Event()
busy_w = sqldb.connect(i, timeout=5, check_same_thread=False); busy_w.execute("SELECT 1").fetchall()
def keep_writing():
    n = 100
    while not stop.is_set():
        try:
            busy_w.execute("INSERT INTO t VALUES (?)", (n,)); busy_w.commit(); written.append(n); n += 1
        except sqldb.sqlite3.OperationalError:
            busy_w.rollback()
t = threading.Thread(target=keep_writing); t.start()
while len(written) < 5: time.sleep(0.01)
try: sqldb.encrypt_file(i, key); refused = False
except sqldb.sqlite3.OperationalError: refused = True
stop.set(); t.join(); busy_w.close()
rows = rows_of(i)
check("encrypt_file: a connection committing during the encrypt refuses, every row intact", refused and not sqldb.is_encrypted(i)
      and rows == [1, 2] + written, f"{refused} {len(rows)} {len(written)}")
sqldb.encrypt_file(i, key)
sqldb.set_key(key)
check("encrypt_file: once no one else has it open, it encrypts with every row", sqldb.is_encrypted(i)
      and rows_of(i) == [1, 2] + written)
sqldb.set_key(None)

# a failure after the export (the swap) leaves no .encrypting behind
f = D / "swap.db"
c2 = sqldb.connect(f); c2.execute("CREATE TABLE t (a)"); c2.commit(); c2.close()
real_replace = sqldb.os.replace
def failing(*a): raise PermissionError("in use")
sqldb.os.replace = failing
try: sqldb.encrypt_file(f, key); swapped = True
except PermissionError: swapped = False
finally: sqldb.os.replace = real_replace
check("encrypt_file: a failed swap raises, leaves the file plain and no .encrypting", not swapped and not sqldb.is_encrypted(f)
      and not (D / "swap.db.encrypting").exists())
sqldb.set_key(key)
c = sqldb.connect(q)
x = D / "export.db"
sqldb.export_copy(c, x, "correct horse battery"); c.close()
sqldb.set_key(None)
n = sqldb.connect(x); n.execute("PRAGMA key = 'correct horse battery'")
check("export_copy: opens with the passphrase", n.execute("SELECT count(*) FROM t").fetchone()[0] == 3)
check("export_copy: user_version kept", n.execute("PRAGMA user_version").fetchone()[0] == 5); n.close()
try: sqldb.connect(x).execute("SELECT count(*) FROM sqlite_master"); raised = False
except sqldb.sqlite3.DatabaseError: raised = True
check("export_copy: closed without it", raised)

try: sqldb.set_key(key); e = sqldb.connect(D / "empty.db"); sqldb.export_copy(e, D / "emptyout.db", ""); refused = False
except ValueError as ex: refused = True
finally: sqldb.set_key(None)
check("export_copy: an empty passphrase is refused and writes nothing", refused and not (D / "emptyout.db").exists())
src = sqldb.connect(D / "srcfail.db"); src.execute("CREATE TABLE t(a)"); src.commit()
try: sqldb.export_copy(src, D / "nodir" / "x.db", "correct horse battery"); raised = False
except sqldb.sqlite3.Error: raised = True
check("export_copy: a failed export raises the original error", raised)
src.close()
wf = D / "wal.db"; w = sqldb.sqlite3.connect(wf); w.execute("PRAGMA journal_mode = WAL"); w.execute("CREATE TABLE t(a)"); w.commit(); w.close()
sqldb.encrypt_file(wf, key); sqldb.set_key(key)
k = sqldb.connect(wf)
check("encrypt_file: the encrypted file is in WAL mode", k.execute("PRAGMA journal_mode").fetchone()[0] == "wal")
bk = D / "walbackup.db"; sqldb.export_copy(k, bk, "correct horse battery"); k.close(); sqldb.set_key(None)
b = sqldb.connect(bk); b.execute("PRAGMA key = 'correct horse battery'")
check("export_copy: the backup stays in DELETE mode", b.execute("PRAGMA journal_mode").fetchone()[0] == "delete"); b.close()
check("export_copy: no -wal beside the backup", not Path(str(bk) + "-wal").exists())

real = sqldb.sqlite3
sqldb.sqlite3 = sqlite3                          # a build without SQLCipher: stdlib ignores PRAGMA key
sqldb.set_key(key)
try: sqldb.connect(D / "fallback.db"); refused = False
except sqlite3.DatabaseError as ex: refused = key.hex() not in str(ex)
finally: sqldb.sqlite3 = real; sqldb.set_key(None)
check("keyed connect on a driver without SQLCipher refuses", refused)

check("Error family caught", issubclass(sqldb.sqlite3.IntegrityError, sqldb.sqlite3.Error))
check("NameTaken is an IntegrityError", issubclass(db.NameTaken, sqldb.sqlite3.IntegrityError))

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

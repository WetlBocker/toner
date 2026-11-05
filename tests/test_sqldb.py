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
x = D / "export.db"
sqldb.export_copy(c, x, "correct horse battery"); c.close()
sqldb.set_key(None)
n = sqldb.connect(x); n.execute("PRAGMA key = 'correct horse battery'")
check("export_copy: opens with the passphrase", n.execute("SELECT count(*) FROM t").fetchone()[0] == 3); n.close()
try: sqldb.connect(x).execute("SELECT count(*) FROM sqlite_master"); raised = False
except sqldb.sqlite3.DatabaseError: raised = True
check("export_copy: closed without it", raised)

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

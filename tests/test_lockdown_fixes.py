# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The final review's lockdown fixes: plain database backups in the data folder are encrypted (and new ones default to Documents),
# the SFTP server's host key is encrypted PEM, pending() doesn't reopen logs it already saw sealed, and Bitwarden's data.json
# is never touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "lockfix%d" % int(time.time()), "netcheck.db"); os.environ["APPDATA"] = SP
os.makedirs(os.path.dirname(os.environ["NETCHECK_DB"]), exist_ok=True)
from core import db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from pathlib import Path
from core import datakey, fileserver, lockdown, sealedfile, sessionlog, sqldb

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def raises(exc, fn, *a):
    try: fn(*a)
    except exc: return True
    except Exception: return False
    return False

root = db.base_path().parent
def plain_db(path, rows):
    c = sqldb.sqlite3.connect(path); c.execute("CREATE TABLE t(a)"); c.executemany("INSERT INTO t VALUES(?)", [(r,) for r in rows])
    c.execute("PRAGMA user_version = 7"); c.commit(); c.close()

print("== a plain copy, as an older Toner left it")
backup, other = root / "toner-backup-2026-01-02.db", root / "notes.db"
plain_db(backup, ["dev1", "dev2"]); plain_db(other, ["x"])
db.init()
exported = root / "toner-backup-locked.db"
with db.connect() as c:
    sqldb.export_copy(c, exported, "a backup password 123")
exported_bytes = exported.read_bytes()
sftp = root / "sftp_host_key"
fp = fileserver.fingerprint(fileserver.load_host_key(str(sftp)))
check("before sign-in, the SFTP key is written plain, as always", b"ENCRYPTED" not in sftp.read_bytes())
bw = root / "bitwarden-cli" / "data.json"; bw.parent.mkdir(exist_ok=True); bw.write_text('{"plain": "as Bitwarden writes it"}')
bw_bytes = bw.read_bytes()
for i in range(40):
    (sessionlog.log_dir() / f"old-{i}.log").write_text(f"session {i}\n")

datakey.create("Admin", "correct horse battery 42")
pending = lockdown.pending()
check("pending lists the plain backup and any other plain database in the data folder", backup in pending and other in pending, pending)
check("...not a backup that already has its own password", exported not in pending)
check("...the SFTP host key", sftp in pending)
check("...never Bitwarden's data.json", bw not in pending and not any(bw.parent == p or bw.parent in p.parents for p in pending))

lockdown.run()
check("the backup is encrypted in place under the data key, rows and version intact", sqldb.is_encrypted(backup)
      and sqldb.connect(backup).execute("SELECT count(*), (SELECT user_version FROM pragma_user_version) FROM t").fetchone() == (2, 7))
check("so is the other database", sqldb.is_encrypted(other))
check("the passworded backup is untouched", exported.read_bytes() == exported_bytes)
check("the SFTP key is encrypted PEM", b"ENCRYPTED PRIVATE KEY" in sftp.read_bytes())
check("...and is the same identity (clients see the same fingerprint)", fileserver.fingerprint(fileserver.load_host_key(str(sftp))) == fp)
check("Bitwarden's data.json is as it was", bw.read_bytes() == bw_bytes)
check("nothing is pending", lockdown.pending() == [], lockdown.pending())

print("== the SFTP key with no key open")
datakey.close()
check("reading it is refused", raises(sealedfile.Locked, fileserver.load_host_key, str(sftp)))
fresh = root / "org-sftp" / "sftp_host_key"
check("making one is refused, and nothing plain is written", raises(sealedfile.Locked, fileserver.load_host_key, str(fresh)) and not fresh.exists())
datakey.open_with_password("Admin", "correct horse battery 42")
fileserver.load_host_key(str(fresh))
check("made while signed in: encrypted from the start", b"ENCRYPTED PRIVATE KEY" in fresh.read_bytes())

print("== pending() doesn't reopen logs it already saw sealed")
opened = []
real_is_sealed = sealedfile.is_sealed
sealedfile.is_sealed = lambda p: opened.append(Path(p)) or real_is_sealed(p)
lockdown.pending()
logs = [p for p in opened if p.parent == sessionlog.log_dir()]
check("the second look opens none of them", logs == [], len(logs))
changed = sessionlog.log_dir() / "old-3.log"
os.utime(changed, ns=(changed.stat().st_atime_ns, changed.stat().st_mtime_ns + 10 ** 9)); opened.clear()
lockdown.pending()
check("a file that changed since is opened again", [p for p in opened if p.parent == sessionlog.log_dir()] == [changed], opened)
plain = sessionlog.log_dir() / "old-5.log"
size, mtime = plain.stat().st_size, plain.stat().st_mtime_ns
plain.write_bytes(b"x" * size); os.utime(plain, ns=(mtime, mtime + 10 ** 6))   # same size, written a millisecond later
check("one replaced by a plain file is found", plain in lockdown.pending())
plain.unlink()
idx = [p for p in root.iterdir() if p.suffix == ".sealed"]
check("the index is a small file in the data folder", len(idx) == 1, idx)
idx[0].write_text("{not json")
opened.clear()
check("a damaged index just means a full look", lockdown.pending() == [] and len([p for p in opened if p.parent == sessionlog.log_dir()]) == 39, len(opened))
idx[0].unlink(); opened.clear()
check("so does a missing one", lockdown.pending() == [] and len([p for p in opened if p.parent == sessionlog.log_dir()]) == 39)
sealedfile.is_sealed = real_is_sealed

print("== new database backups default to Documents")
from PySide6.QtCore import QStandardPaths
from PySide6.QtWidgets import QApplication, QFileDialog
app = QApplication.instance() or QApplication([])
from core import session
session.sign_out(); session.sign_in("Admin", "correct horse battery 42")
import ui.settings_pages.security as SEC
page = SEC.DataPage(lambda: None)
page._ask_password = lambda *a: "a backup password 123"
asked = []
QFileDialog.getSaveFileName = staticmethod(lambda parent, title, default, *a: asked.append(default) or ("", ""))
page.backup()
docs = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DocumentsLocation)
check("the save dialog starts in Documents, not the data folder", asked and Path(asked[0]).parent == Path(docs)
      and Path(asked[0]).name.startswith("toner-backup-"), (asked, docs))
session.sign_out()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

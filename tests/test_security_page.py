# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Settings > Data and logs: the database backup is encrypted with a password chosen at export.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\secpage%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import backup, db
db.init()
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

import tempfile
from pathlib import Path
from PySide6.QtWidgets import QFileDialog, QMessageBox
from PySide6.QtWidgets import QApplication
app = QApplication([])
from core import sqldb, passwords
from ui.settings_pages import security as S
QMessageBox.information = staticmethod(lambda *a, **k: shown.append(a[2]))
QMessageBox.warning = staticmethod(lambda *a, **k: shown.append(a[2]))
shown = []
page = S.DataPage(lambda: None)
out = Path(tempfile.mkdtemp()) / "b.db"
QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (str(out), ""))

def run(*answers):
    seq = iter(answers); shown.clear(); out.unlink(missing_ok=True)
    page._ask_password = lambda t, l: next(seq)
    page.backup()

good = "correct horse battery"
run(good, good)
c = sqldb.sqlite3.connect(out); c.execute("PRAGMA key = '%s'" % good)
check("backup opens with the password", c.execute("SELECT count(*) FROM sqlite_master").fetchone()[0] > 0); c.close()
try: sqldb.sqlite3.connect(out).execute("SELECT count(*) FROM sqlite_master"); closed = False
except sqldb.sqlite3.DatabaseError: closed = True
check("backup is closed without it", closed)
check("success says saved passwords are not included", any("Saved passwords stay in Toner's vault and aren't included." in m for m in shown))
check("success says it is encrypted with the chosen password", any("encrypted with the password you chose." in m for m in shown))
run(good, good + "x")
check("different answers save nothing", not out.exists())
run("short", "short")
check("a weak password saves nothing and says why", not out.exists() and any("12" in m for m in shown))
run(None)
check("cancelling saves nothing", not out.exists())
print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

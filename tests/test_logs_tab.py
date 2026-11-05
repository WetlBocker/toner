# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Tools > Logs with sealed logs: every file in the logs folder is listed (session logs, and the backup, Command Runner and
# firmware logs), and "Save a readable copy..." decrypts one to a file the person picks (Documents by default).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "logstab%d" % int(time.time()), "netcheck.db"); os.environ["APPDATA"] = SP
os.makedirs(os.path.dirname(os.environ["NETCHECK_DB"]), exist_ok=True)
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from pathlib import Path
from core import backup, cmdrun, datakey, db, firmware, sealedfile, session, sessionlog

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

from PySide6.QtCore import QStandardPaths
from PySide6.QtWidgets import QApplication, QFileDialog, QPushButton
app = QApplication([])
datakey.create("Admin", "correct horse battery 42"); db.init(); session.sign_out(); session.sign_in("Admin", "correct horse battery 42")
dev = {"name": "sw1"}
log = sessionlog.SessionLog("sw1", "10.0.0.1", 22, "u"); log.write(b"sw1# show version\n"); log.close("closed")
sealedfile.save_text(backup.session_file(dev), "backup session: show running-config\n")
sealedfile.save_text(cmdrun.session_file(dev), "command runner session\n")
sealedfile.save_text(firmware.log_path(dev), "firmware session\n")
check("the logs are sealed on disk", all(sealedfile.is_sealed(p) for p in sessionlog.log_dir().iterdir()))

from ui.tools import LogsTab
tab = LogsTab()
cells = lambda r: [tab.table.item(r, c).text() if tab.table.item(r, c) else "" for c in range(tab.table.columnCount())]
rows = [cells(r) for r in range(tab.table.rowCount())]
check("every file in the logs folder is listed: the session, and the backup, Command Runner and firmware logs", len(rows) == 4, rows)
def row_of(name):
    return next(r for r in range(tab.table.rowCount()) if Path(tab.sessions[r]["log_path"]).name == name)
r = row_of(backup.session_file(dev).name)
check("...each with its device", "sw1" in cells(r), cells(r))
tab.table.selectRow(r)
check("selecting one shows it decrypted", "backup session: show running-config" in tab.view.toPlainText(), tab.view.toPlainText())
tab.table.selectRow(row_of(Path(log.path).name))
check("a session log still shows too", "show version" in tab.view.toPlainText())

save = next((b for b in tab.findChildren(QPushButton) if b.text() == "Save a readable copy..."), None)
check("there is a Save a readable copy... button", save is not None)
picked = []
out = Path(SP) / "readable.log"
QFileDialog.getSaveFileName = staticmethod(lambda parent, title, default, *a: picked.append(default) or (str(out), ""))
tab.table.selectRow(row_of(firmware.log_path(dev).name)); save.click()
docs = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DocumentsLocation)
check("it suggests the log's own name in Documents", picked and Path(picked[0]) == Path(docs) / firmware.log_path(dev).name, picked)
check("and writes the readable text there", out.read_text(encoding="utf-8") == "firmware session\n")

tab.MAX_VIEW = 10
tab.table.selectRow(row_of(backup.session_file(dev).name)); tab.show_log()
check("a long log's hint points to the readable copy", "Save a readable copy for all of it." in tab.view.toPlainText()
      and "open the file" not in tab.view.toPlainText(), tab.view.toPlainText()[:200])
session.sign_out()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

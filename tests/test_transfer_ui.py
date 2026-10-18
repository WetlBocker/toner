# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform != "win32":                       # xcopy is Windows' (Linux would use rsync: not built yet)
    print("skipped: this test is about Windows itself"); print("\n0 passed, 0 failed"); _sys.exit(0)
import logging, os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\tu%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import audit, db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtCore import QCoreApplication
app = QApplication([])
import app as A
A.apply_look(app)
import ui.tools3 as T3
import ui.tools as T
from _scp_server import ScpServer

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def pump(cond, n=500):
    for _ in range(n):
        QCoreApplication.processEvents(); time.sleep(0.02)
        if cond(): break
    QCoreApplication.processEvents()
asked = []
QMessageBox.question = staticmethod(lambda *a, **k: (asked.append(a[2]), QMessageBox.StandardButton.Yes)[1])

base = os.path.join(SP, "tu%d" % int(time.time())); share = os.path.join(base, "dev"); mine = os.path.join(base, "mine"); dl = os.path.join(base, "dl")
for d in (share, mine, dl): os.makedirs(d)
open(os.path.join(mine, "image.bin"), "wb").write(os.urandom(300000)); open(os.path.join(share, "run.cfg"), "wb").write(b"hostname sw1\n")
big = os.urandom(3_000_000); open(os.path.join(share, "big.bin"), "wb").write(big)
os.makedirs(os.path.join(mine, "tree", "sub")); open(os.path.join(mine, "tree", "a.cfg"), "wb").write(b"A"); open(os.path.join(mine, "tree", "sub", "b.cfg"), "wb").write(b"BB")
srv = ScpServer(share, slow=True)
db.save_device(dict(name="branch-sw", vendor="cisco", host="127.0.0.1", port=srv.port, platform="", username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))
STORE[("netcheck", "branch-sw")] = "pw"

print("== the tools are in the File transfer section")
tools = T.ToolsTab(); tools.resize(1200, 800); tools.show()
names = [tools.tabs.tabText(i) for i in range(tools.tabs.count())]
check("four tools, in order, after the heading", names[names.index("TFTP Server"):names.index("TFTP Server") + 4] == ["TFTP Server", "SFTP Server", "SCP", "Copy Files (xcopy)"], names)
check("the SCP page picks up devices like the other tools do", tools.scp in tools._pickers)

print("== SCP page")
sc = T3.ScpTab(); sc.resize(1100, 700); sc.show(); sc.picker.refresh()
check("starts in 'upload' mode, with the download-only option hidden", sc.direction.currentData() is True and sc.overwrite.isHidden() and not sc.file_btn.isHidden() and "From (this computer)" in sc.local_label.text())
sc.picker.setCurrentIndex(sc.picker.findText("branch-sw", Qt := __import__("PySide6.QtCore", fromlist=["Qt"]).Qt.MatchFlag.MatchStartsWith))
check("choosing a device fills in its address, port and user", sc.host.text() == "127.0.0.1" and sc.port.value() == srv.port and sc.user.text() == "u", (sc.host.text(), sc.port.value(), sc.user.text()))
check("and says the stored password will be used", "stored password" in sc.password.placeholderText())
for setup, msg in ((lambda: sc.user.setText(""), "user name"), (lambda: (sc.user.setText("u"), sc.remote.setText("")), "path on the device"),
                   (lambda: (sc.remote.setText("x"), sc.local.setText("")), "on this computer"), (lambda: sc.local.setText(os.path.join(mine, "missing")), "does not exist"),
                   (lambda: (sc.local.setText(os.path.join(mine, "image.bin")), sc.host.setText("http://x")), "Host")):
    setup(); sc.out.clear(); sc.start(); check(f"missing input explained: {msg}", msg.lower() in sc.out.toPlainText().lower() and not sc.running(), sc.out.toPlainText())
sc.host.setText("127.0.0.1")
sc.local.setText(os.path.join(mine, "image.bin")); sc.remote.setText("incoming.bin"); sc.out.clear(); sc.start()
check("while it runs, the form is locked and Stop is on", (not sc.go.isEnabled() and sc.stop.isEnabled() and not sc.host.isEnabled()) or not sc.running())
pump(lambda: sc.go.isEnabled() and not sc.running())
check("an upload with the stored password works", open(os.path.join(share, "incoming.bin"), "rb").read() == open(os.path.join(mine, "image.bin"), "rb").read() and "Done: 1 file(s)" in sc.out.toPlainText(), sc.out.toPlainText())
check("the output names the file and the command", "send " in sc.out.toPlainText() and "image.bin" in sc.out.toPlainText() and "Connecting to 127.0.0.1" in sc.out.toPlainText())
check("the progress bar ends full, the form is usable again", sc.bar.value() == sc.bar.maximum() and sc.go.isEnabled() and sc.host.isEnabled() and not sc.stop.isEnabled())
check("it is in the audit log", any(a["action"] == "scp upload" and "branch-sw" in a["detail"] for a in audit.recent()))
sc.local.setText(os.path.join(mine, "tree")); sc.recursive.setChecked(False); sc.remote.setText("."); sc.out.clear(); sc.start(); pump(lambda: not sc.running())
check("a folder without 'Include sub-folders' is explained", "sub-folders" in sc.out.toPlainText(), sc.out.toPlainText())
sc.recursive.setChecked(True); os.makedirs(os.path.join(share, "up")); sc.remote.setText("up"); sc.out.clear(); sc.start(); pump(lambda: not sc.running() and "Done" in sc.out.toPlainText())
check("with it, the whole folder is sent", open(os.path.join(share, "up", "tree", "sub", "b.cfg"), "rb").read() == b"BB" and "Done: 2 file(s)" in sc.out.toPlainText(), sc.out.toPlainText())
check("sub-folders are listed in the output", "tree/" in sc.out.toPlainText())

sc.direction.setCurrentIndex(sc.direction.findData(False))
check("download mode: labels flip, 'replace' option appears, file picker goes", "To (this computer)" in sc.local_label.text() and "From (on the device)" in sc.remote_label.text() and not sc.overwrite.isHidden() and sc.file_btn.isHidden())
sc.recursive.setChecked(False); sc.local.setText(dl); sc.remote.setText("run.cfg"); sc.out.clear(); sc.start(); pump(lambda: not sc.running() and "Done" in sc.out.toPlainText())
check("a download", open(os.path.join(dl, "run.cfg"), "rb").read() == b"hostname sw1\n" and any(a["action"] == "scp download" for a in audit.recent()))
open(os.path.join(dl, "run.cfg"), "wb").write(b"MINE"); sc.out.clear(); sc.start(); pump(lambda: not sc.running() and "Done" in sc.out.toPlainText())
check("an existing local file is kept, and the output says so", open(os.path.join(dl, "run.cfg"), "rb").read() == b"MINE" and "kept your existing file" in sc.out.toPlainText(), sc.out.toPlainText())
sc.overwrite.setChecked(True); sc.out.clear(); sc.start(); pump(lambda: not sc.running() and "Done" in sc.out.toPlainText())
check("ticking 'replace' replaces it", open(os.path.join(dl, "run.cfg"), "rb").read() == b"hostname sw1\n")
sc.remote.setText("nothing.cfg"); sc.out.clear(); sc.start(); pump(lambda: not sc.running() and "Failed" in sc.out.toPlainText())
check("a missing file shows the device's message", "No such file or directory" in sc.out.toPlainText() and sc.go.isEnabled(), sc.out.toPlainText())
check("a failure is audited as such", any(a["action"] == "scp download failed" for a in audit.recent()))
sc.remote.setText("big.bin"); sc.local.setText(os.path.join(dl, "stopme.bin")); sc.out.clear(); sc.start()
pump(lambda: sc.bar.value() > 50000 or not sc.running()); sc.halt(); pump(lambda: not sc.running())
check("Stop cancels a transfer and leaves nothing behind", "Stopped." in sc.out.toPlainText() and not os.path.exists(os.path.join(dl, "stopme.bin")) and not [f for f in os.listdir(dl) if f.endswith(".toner-part")], sc.out.toPlainText()[-200:])
sc.password.setText("wrong"); sc.remote.setText("run.cfg"); sc.out.clear(); sc.start(); pump(lambda: not sc.running() and "Login failed" in sc.out.toPlainText())
check("a wrong password is explained", "Login failed" in sc.out.toPlainText())
sc.password.clear(); sc.shutdown()
sc2 = T3.ScpTab(); sc2.picker.refresh(); sc2.picker.setCurrentIndex(0)
check("typing a host by hand works too (no device chosen)", sc2.picker.currentData() is None and sc2.stored_password() == "")

print("== xcopy page")
xc = T3.XcopyTab(); xc.resize(1100, 700); xc.show()
check("xcopy.exe is found, and the page explains what it does", xc.exe and "contents of the source folder" in xc.findChildren(__import__("PySide6.QtWidgets", fromlist=["QLabel"]).QLabel)[0].text())
check("sensible defaults: sub-folders on, replace, keep going", xc.subfolders.isChecked() and xc.existing.currentData() == "replace" and xc.keep_going.isChecked() and not xc.verify.isChecked())
xc.source.setText(""); xc.out.clear(); xc.start(True); check("no source is explained", "Choose the folder" in xc.out.toPlainText() and not xc.runner.running())
xc.source.setText(os.path.join(mine, "tree")); xc.dest.setText(""); xc.out.clear(); xc.start(True); check("no destination is explained", "where to copy" in xc.out.toPlainText().lower())
xc.dest.setText(os.path.join(base, "copied")); xc.out.clear(); xc.start(True); pump(lambda: xc.result.text() != "")
check("Preview lists files and copies nothing", "a.cfg" in xc.out.toPlainText() and not os.path.exists(os.path.join(base, "copied")) and xc.result.text() == "Preview: 2 file(s) would be copied. Nothing was copied.", xc.result.text())
check("the command line is shown", "> xcopy " in xc.out.toPlainText() and "/L" in xc.out.toPlainText())
asked.clear(); xc.out.clear(); xc.start(False); pump(lambda: xc.result.text().startswith("Done"))
check("Copy copies the tree, and says how many", open(os.path.join(base, "copied", "sub", "b.cfg"), "rb").read() == b"BB" and xc.result.text() == "Done: 2 file(s).", xc.result.text())
check("no question when the destination did not exist", not asked)
check("the buttons come back", xc.go.isEnabled() and xc.preview.isEnabled() and not xc.stop.isEnabled())
open(os.path.join(mine, "tree", "a.cfg"), "wb").write(b"A-NEW"); asked.clear(); xc.out.clear(); xc.start(False); pump(lambda: xc.result.text().startswith("Done"))
check("copying over a destination that has files asks first, and then replaces", asked and "will be replaced" in asked[0] and open(os.path.join(base, "copied", "a.cfg"), "rb").read() == b"A-NEW", asked)
xc.existing.setCurrentIndex(xc.existing.findData("newer")); asked.clear(); xc.start(False); pump(lambda: xc.result.text() != "" and not xc.runner.running())
check("'only if newer' asks nothing and copies nothing new", not asked and xc.result.text() in ("Nothing needed copying (0 files).",), xc.result.text())
xc.existing.setCurrentIndex(xc.existing.findData("replace")); xc.subfolders.setChecked(False); xc.dest.setText(os.path.join(base, "flat")); xc.start(False); pump(lambda: xc.result.text().startswith("Done"))
check("without sub-folders only the top level is copied", os.path.exists(os.path.join(base, "flat", "a.cfg")) and not os.path.exists(os.path.join(base, "flat", "sub")))
check("copies are in the audit log, previews are not", sum(1 for a in audit.recent() if a["action"] == "xcopy") == 4, [a["action"] for a in audit.recent()][:8])
xc.source.setText(os.path.join(base, "no-such-folder")); xc.out.clear(); xc.start(True); check("a source that is not there is explained", "does not exist" in xc.out.toPlainText())
xc.source.setText(os.path.join(mine, "tree")); xc.dest.setText(os.path.join(mine, "tree")); xc.out.clear(); xc.start(True); check("source and destination the same is refused", "same" in xc.out.toPlainText())
xc.shutdown()

srv.stop()
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

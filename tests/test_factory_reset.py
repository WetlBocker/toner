# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away data folder and fakes every system store, so nothing on this computer is touched: the reset here only ever
# deletes the throw-away folder made below.
# Reset Toner to factory settings (1.6.10): core/reset.py, the dialog, the button (Global only) and the window's part.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, logging
SP = os.environ["SP"]
os.environ["APPDATA"] = os.path.join(SP, "reset%d" % int(time.time()))      # the data folder is APPDATA\NetCheck...
os.environ.pop("NETCHECK_DB", None)                                        # ...with the database inside it, as in a real install
os.environ["XDG_CONFIG_HOME"] = os.path.join(SP, "config")                 # (Linux: where the autostart entry would be)
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import agents, autostart, db, orgs, passvault, paths, platforms, reset, service, sessionlog, updates
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)


def dev(name):
    return dict(name=name, vendor="cisco", host="10.0.0.1", port=0, platform="", username="u", site="default", verify_ssl=0, ha_expected=0,
                enabled=1, location="", details="", folder_id=None)


data = paths.data_dir()
check("the throw-away data folder holds the database, as a real install does", str(data) == os.path.join(os.environ["APPDATA"], "NetCheck")
      and db.base_path().parent == data)
assert str(data).startswith(SP), "never run this against a real data folder"


def fill():
    """A used install: two organizations with devices, a vault, logs, a certificate, an update, a held schedule lock, an open log."""
    db.init()
    for name in ("Acme", "Beta"):
        org = orgs.create(name, name.upper())
        with db.within(org):
            db.save_device(dev(name.lower() + "-sw1"))
    db.set_setting("report_org", "Reset Test")
    passvault.create("correct horse battery staple", remember=False)
    passvault.put("acme-sw1", "pw-not-printed")
    passvault.key_path().write_bytes(passvault.KEYRING_MARK)            # remembered through the system keyring (Linux, macOS)
    (sessionlog.log_dir() / "acme-sw1 2026-01-01.log").write_text("session", encoding="utf-8")
    (agents.cert_dir() / "agent.pem").write_text("cert", encoding="utf-8")
    (updates.updates_dir() / "Toner-Setup-1.6.9.exe").write_bytes(b"\0" * 10)
    ro = data / "oui.txt"
    ro.write_text("00-00-00 Test", encoding="utf-8")
    os.chmod(ro, 0o444)                                                 # a read-only file must go too
    check("the window's process holds the schedule lock", service.owns_schedule() and service._schedule_lock is not None)
    handler = logging.FileHandler(data / "toner.log", encoding="utf-8")
    logging.getLogger("toner").addHandler(handler)
    logging.getLogger("toner").warning("a line in the log")
    if platforms.LINUX:
        autostart.set_enabled(True)


fill()
creds = {"netcheck": "legacy", "jw@netcheck": "legacy2", "someone@other": "keep", "netcheckx": "keep"}
native = {(passvault.NATIVE_SERVICE, str(passvault.path())): "key", ("Other app", "x"): "keep"}
reset._cred_enumerate = lambda: list(creds)
reset._cred_delete = lambda t: creds.pop(t)
reset._native_delete = lambda s, u: native.pop((s, u))

print("== what counts as Toner's in Credential Manager")
check("the service name and user@service entries, nothing else", reset.legacy_targets(["netcheck", "jw@netcheck", "someone@other", "netcheckx", "Toner vault"])
      == ["netcheck", "jw@netcheck"])

if platforms.WINDOWS:
    print("== a file still held by another program (Windows refuses the rename)")
    held_path = sessionlog.log_dir() / "held.log"
    held = open(held_path, "a")
    try:
        reset.wipe()
        check("wipe refuses", False)
    except reset.ResetError as e:
        check("wipe refuses, naming the file, and says nothing was deleted", str(e) == reset.IN_USE.format(path=held_path) and not e.deleted, str(e))
    held.close()
    check("...and nothing was deleted", data.exists() and db.base_path().exists() and passvault.path().exists() and len(creds) == 4 and len(native) == 2)
    check("...the probe left no trace", not list(data.rglob("*.inuse")))

print("== the reset")
reset.wipe()
check("the data folder is gone", not data.exists())
check("...and no renamed copy of it is left behind", not [p.name for p in data.parent.iterdir() if p.name.startswith("NetCheck")], list(data.parent.iterdir()))
check("Toner's Credential Manager entries are gone, other programs' stay", creds == {"someone@other": "keep", "netcheckx": "keep"}, creds)
check("the vault key in the system keyring is gone, other programs' stay", native == {("Other app", "x"): "keep"}, native)
check("the schedule lock was let go", service._schedule_lock is None)
check("the log file was closed", not any(getattr(h, "baseFilename", "").startswith(str(data)) for h in logging.getLogger("toner").handlers))
check("the vault is locked in memory", not passvault.is_open())
if platforms.LINUX:
    check("the autostart entry is gone", not autostart.enabled())
check("nothing was written afterwards", not data.exists())

print("== a database kept outside the data folder")
os.environ["NETCHECK_DB"] = os.path.join(SP, "elsewhere.db")
try:
    reset.folder()
    check("is refused", False)
except reset.ResetError as e:
    check("is refused, saying so", str(e).startswith("Toner could not reset. Its database is not in its data folder") and str(e).endswith("Nothing was deleted."), str(e))
os.environ.pop("NETCHECK_DB")

print("== the button, the dialog and the window")
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtGui import QCloseEvent
app = QApplication.instance() or QApplication([])
fill()
native[(passvault.NATIVE_SERVICE, str(passvault.path()))] = "key"       # remembered again, in the (fake) system keyring
import app as A
A.apply_look(app)
from ui import factoryreset as FR
from ui.settings_pages.security import DataPage
acme = next(o["id"] for o in orgs.list_orgs() if o["name"] == "Acme")
pg = DataPage(lambda: None)
pg.refresh()
check("in Global the page has the button", not pg.reset_btn.isHidden() and pg.reset_btn.text() == "Reset Toner to factory settings...")
db.set_home(acme); pg.refresh()
check("inside an organization it is hidden", pg.reset_btn.isHidden())
db.set_home(0); pg.refresh()
check("...and back in Global", not pg.reset_btn.isHidden())
dlg = FR.ResetDialog()
check("the dialog's title and button", dlg.windowTitle() == "Reset Toner to factory settings" and dlg.ok.text() == "Reset and quit" and not dlg.ok.isEnabled())
body = FR.text()
check("the dialog says what goes, where, and what is not touched", body.startswith("This deletes everything Toner keeps on this computer and closes Toner:")
      and f"Data folder: {data}" in body and "Windows agents keep their tokens and Demarc keeps this Toner enrolled" in body
      and body.endswith("Back up the database and export saved passwords first if you may want them back."), body)
check("Linux names the autostart entry, Windows does not", ("the Start Toner when I sign in entry" in body) == platforms.LINUX)
dlg.confirm.setText("reset"); check("lower case does not enable it", not dlg.ok.isEnabled())
dlg.confirm.setText("RESET "); check("a stray space does not", not dlg.ok.isEnabled())
dlg.confirm.setText("RESET"); check("RESET enables it", dlg.ok.isEnabled())
dlg.confirm.setText("RESE"); check("...and deleting a letter turns it off again", not dlg.ok.isEnabled())

warned = []
QMessageBox.warning = staticmethod(lambda *a, **k: warned.append((a[1], a[2])))
w = A.Main(); w.resize(1200, 800); w.show(); app.processEvents()
calls, real_perform = [], FR.perform
FR.perform = lambda main: calls.append(main)
page = next(p for p in w.settings.pages if p.title == "Data and logs")
page.reset_btn.click()
check("the button reaches the window through Settings", calls == [w])
FR.perform = real_perform
real_exec = FR.ResetDialog.exec
FR.ResetDialog.exec = lambda self: True
w.results.running = lambda: True
check("a run still going is refused in the agreed words", FR.perform(w) is False and warned[-1] == ("Reset Toner to factory settings", "A run is still going. Wait for it to finish, then reset.")
      and data.exists(), warned[-1:])
w.results.running = lambda: False
FR.ResetDialog.exec = lambda self: False
check("Cancel does nothing", FR.perform(w) is False and data.exists() and not warned[1:])
FR.ResetDialog.exec = lambda self: True
if platforms.WINDOWS:
    held = open(sessionlog.log_dir() / "held2.log", "a")
    check("a held file: the window says so and keeps running", FR.perform(w) is False and warned[-1][1].startswith("Toner could not reset.") and data.exists()
          and not w._wiped and w.housekeeping.isActive(), warned[-1:])
    held.close()
n = len(warned)
check("RESET: the data goes and Toner quits", FR.perform(w) is True and not data.exists() and w._wiped and w._quitting and len(warned) == n, warned[n:])
ev = QCloseEvent(); w.closeEvent(ev)
check("closing afterwards writes nothing", ev.isAccepted() and not data.exists())
FR.ResetDialog.exec = real_exec

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

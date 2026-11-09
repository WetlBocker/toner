# Run directly (python tests/test_lock_quit.py). Closing Toner while the lock screen is up: with nothing to ask the lock goes with Toner
# and the app quits; with something to ask nothing closes and the lock says to unlock first; "Run in background" hides the lock with
# the window and Open brings it back; tray Quit only quits when the close was accepted; Sign out while locked still works.
# Each case runs in its own process (Main shuts the whole app down when it closes).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, subprocess, sys, time
CASES = ["close", "unsaved", "vault", "settings", "running", "firmware", "both", "bg", "tray_no", "tray_yes", "signout", "locked_tray", "update",
         "discard_unsaved", "discard_vault", "discard_settings"]
if len(sys.argv) < 2:
    ok = bad = 0
    for c in CASES:
        try:
            r = subprocess.run([sys.executable, "-u", os.path.abspath(__file__), c], capture_output=True, text=True, timeout=60)
            out = r.stdout + ("  FAIL %s: exit code %s %s" % (c, r.returncode, r.stderr[-300:]) + chr(10) if r.returncode else "")
        except subprocess.TimeoutExpired:
            out = "  FAIL %s: hung (a question box nobody can answer?)" % c + chr(10)
        print(out, end="")
        ok += out.count("  ok  "); bad += out.count("  FAIL") + (0 if "  ok  " in out or "  FAIL" in out else 1)
    print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "lq%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import datakey, db, session
PW = "correct horse battery 42"
datakey.create("Admin", PW); db.init()
session.sign_out(); session.sign_in("admin", PW)
from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
case = sys.argv[1]

def check(name, cond, extra=""):
    print("  ok  " if cond else "  FAIL", f"{case}: {name}", "" if cond else extra)
def spin(ms):
    end = time.time() + ms / 1000
    while time.time() < end: QCoreApplication.processEvents(); time.sleep(0.005)

quits = []
QApplication.quit = staticmethod(lambda: quits.append(1))
boxes = []
real_q = QMessageBox.question
QMessageBox.question = staticmethod(lambda *a, **k: boxes.append(a[2] if len(a) > 2 else "") or QMessageBox.StandardButton.No)
w = A.Main(); w.resize(1200, 760); w.show(); spin(300)
lock = w.lock_screen
if case == "bg":
    db.set_setting("run_in_background", True); w.notifier.tray_available = True
reasons = {"unsaved": ("a playbook has unsaved changes.", lambda: setattr(w.tools.playbooks, "dirty", lambda: True)),
           "vault": ("some changes haven't reached the password vault yet.", lambda: setattr(__import__("core.extstore", fromlist=["x"]), "unsent", lambda: 2)),
           "settings": ("there are unsaved settings.", lambda: setattr(w.settings, "unsaved_count", lambda: 1)),
           "running": ("a playbook is running.", lambda: setattr(w.automation, "running", lambda: True)),
           "firmware": ("a firmware transfer is still running.", lambda: setattr(w.tools.firmware, "transferring", lambda: True))}
asked = []                                                       # questions Main's closing steps would ask or act on
base = case.replace("discard_", "")
if base in reasons: reasons[base][1]()
if case == "both": reasons["running"][1](); reasons["settings"][1]()
w.tools.playbooks.leave = lambda: asked.append("leave") or True
w.settings.confirm_leave = lambda *a, **k: asked.append("settings") or True
session.lock(); spin(300)
check("lock is up", lock.locked and lock.isVisible())
if case == "close":
    w.close(); spin(300)
    check("main closed", not w.isVisible()); check("lock gone", not lock.isVisible() and not lock.locked)
    check("no visible window left", not any(x.isVisible() for x in QApplication.topLevelWidgets()))
elif case.startswith("discard_"):
    w.close(); spin(200)
    check("button shown", not lock.discard.isHidden() and lock.error.text() == "Unlock to close Toner: " + reasons[base][0])
    lock.discard.click(); spin(300)
    check("closed and quit", not any(x.isVisible() for x in QApplication.topLevelWidgets()) and not lock.locked, str(quits))
    check("nothing asked, saved or sent", not boxes and not asked, f"{boxes} {asked}")
elif case in reasons or case == "both":
    r = reasons["running" if case == "both" else case][0]
    pending = case in ("unsaved", "vault", "settings")
    check("close refused", w.close() is False); spin(200)
    check("button only for pending changes", lock.discard.isHidden() == (not pending))
    check("no question asked", not boxes, str(boxes))
    check("main still open, lock up", w.isVisible() and lock.locked and lock.isVisible())
    check("one line says why", lock.error.text() == "Unlock to close Toner: " + r, lock.error.text())
    session.unlock(PW); spin(200)
    check("unlocked clears the line and button", lock.error.text() == "" and not lock.locked and lock.discard.isHidden())
    if pending:
        w.close(); spin(200)
        check("unlocked: close asks as usual", bool(asked or boxes), str((asked, boxes)))
elif case == "bg":
    w.close(); spin(300)
    check("main hidden", not w.isVisible()); check("lock hidden too", not lock.isVisible()); check("lock still armed", lock.locked)
    w.show_window(); spin(300)
    check("lock back over Toner", w.isVisible() and lock.isVisible())
elif case.startswith("tray"):
    if case == "tray_no": w.settings.unsaved_count = lambda: 1; session.unlock(PW); spin(200)
    else: session.unlock(PW); spin(200)
    if case == "tray_no":
        w.settings.confirm_leave = lambda *a, **k: False
    w.quit_for_real(); spin(300)
    check("quit only when close accepted", bool(quits) == (case == "tray_yes"), str(quits))
elif case == "signout":
    w.settings.unsaved_count = lambda: 1
    lock.other.click(); spin(300)
    check("settings question asked, not the lock's line", "settings" in asked and "Unlock to close" not in lock.error.text(), str(asked))
    check("signed out", session.state() != "locked" and bool(quits), f"{session.state()} {quits}")
elif case == "locked_tray":
    w.settings.unsaved_count = lambda: 1
    w.hide(); lock._cover_all(); spin(200)
    w.quit_for_real(); spin(300)
    check("nothing quit", not quits and not asked, str((quits, asked)))
    check("line and button visible", lock.isVisible() and not lock.discard.isHidden() and lock.error.text() == "Unlock to close Toner: there are unsaved settings.", lock.error.text())
elif case == "update":
    w.settings.unsaved_count = lambda: 1
    w.about.quit_requested.emit(); spin(300)
    check("update path quits though the close was refused", bool(quits), str(quits))
os._exit(0)

# Run directly (python tests/test_helper_switch_ui.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched. Nothing is installed: the
# helper client's calls are replaced.
# Settings > Accounts: the "Let group members sign in without approval" switch: its wording, the warning before it turns on,
# installing the helper when needed, the audit rows, the states that disable it, Admins only, and no pending Save change.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\hswitch%d.db").replace("\\", os.sep) % int(time.time())
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import audit, datakey, db, helperclient, lockdown, session

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

# ---------------------------------------------------------------- the helper client, replaced
STATE, CALLS, FAIL = ["absent"], [], [None]
helperclient.state = lambda path: CALLS.append("state") or STATE[0]
def install_elevated(timeout=120):
    CALLS.append("install")
    if FAIL[0]:
        raise helperclient.InstallFailed(FAIL[0])
    STATE[0] = "off"
def enroll():
    CALLS.append("enroll")
    STATE[0] = "on"
def forget(keys_path=None):
    CALLS.append("forget")
    STATE[0] = "off"
helperclient.install_elevated, helperclient.enroll, helperclient.forget = install_elevated, enroll, forget

PW, PW2 = "violet staple orbit 42", "amber kettle meadow 77"
datakey.create("Admin", PW)
db.init()
lockdown.run()
datakey.close()
session.sign_in("Admin", PW)
datakey.add_local("Tech1", PW2, "Tech")

from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as APP
APP.apply_look(app)
import ui.settings as ST
from ui.settings_pages import accounts as A

BOXES, CHOICE, WARNED = [], ["Cancel"], []
def fake_exec(self):
    BOXES.append((self.windowTitle(), self.text(), [b.text() for b in self.buttons()]))
    next(b for b in self.buttons() if b.text() == CHOICE[0]).click()
    return 0
QMessageBox.exec = fake_exec
QMessageBox.warning = staticmethod(lambda parent, title, text, *a, **k: WARNED.append(text))
acts = lambda: [(r["action"], r["detail"]) for r in audit.recent()]

S = ST.SettingsTab(); S.resize(1200, 900); S.show(); S.select_page("Accounts"); app.processEvents()
page = next(p for p in S.pages if p.title == "Accounts")
page.load(); app.processEvents()
sw, note = page.helper, page.helper_note

print("== the switch")
check("its label and tip are the approved wording", sw.text() == "Let group members sign in without approval"
      and sw.toolTip() == "Anyone in a mapped group can sign in on this computer for the first time without an admin.")
check("it sits under Session length", page.form.indexOf(sw) == page.form.indexOf(page.session) + 1, (page.form.indexOf(sw), page.form.indexOf(page.session)))
check("an Admin sees it: absent, enabled, off, no note", not sw.isHidden() and sw.isEnabled() and not sw.isChecked() and note.isHidden())

print("== ticking it")
CALLS.clear(); n = len(acts())
sw.click(); app.processEvents()
WARN = ("Toner's helper service will keep a spare copy of Toner's key on this computer, so anyone in a mapped group can sign in here for "
        "the first time without an admin. Programs running as you can't reach that copy, but an administrator of this computer can. "
        "Installing the helper service needs administrator rights. Turning this off deletes the spare copy.")
LINUX = " On Linux, the spare copy is protected only by this computer's disk encryption, so use full-disk encryption."
check("ticking shows the approved warning (on Linux, with the disk encryption sentence after it)", BOXES and BOXES[-1] == (
      "Let group members sign in without approval?", WARN + (LINUX if sys.platform.startswith("linux") else ""), ["Turn on", "Cancel"]),
      BOXES[-1:])
real_platform = sys.platform
for plat, want in (("linux", WARN + LINUX), ("win32", WARN)):
    sys.platform = plat
    try:
        sw.click(); app.processEvents()
    finally:
        sys.platform = real_platform
    check(f"...the warning on {plat}, exact", BOXES[-1][1] == want and not sw.isChecked(), BOXES[-1:])
check("Cancel changes nothing", not sw.isChecked() and "install" not in CALLS and "enroll" not in CALLS and len(acts()) == n, CALLS)
check("...and leaves no pending Save change", S.pending_changes() == [], S.pending_changes())

CHOICE[0] = "Turn on"; CALLS.clear()
sw.click(); app.processEvents()
check("Turn on while absent: installs the helper, then enrolls", [c for c in CALLS if c != "state"] == ["install", "enroll"], CALLS)
check("...on", sw.isChecked() and sw.isEnabled())
check("...audited: turned on by the Admin", ("sign-in without approval turned on", "by Admin") in acts(), acts()[:3])
check("ticking leaves no pending Save change", S.pending_changes() == [], S.pending_changes())

print("== unticking it")
CALLS.clear()
sw.click(); app.processEvents()
check("unticking forgets, without a warning", [c for c in CALLS if c != "state"] == ["forget"] and not sw.isChecked(), CALLS)
check("...audited: turned off by the Admin", ("sign-in without approval turned off", "by Admin") in acts(), acts()[:3])
check("...and no pending Save change", S.pending_changes() == [], S.pending_changes())

print("== Turn on when it is off already: no install")
CALLS.clear(); BOXES.clear()
sw.click(); app.processEvents()
check("installed and running: enrolled only", [c for c in CALLS if c != "state"] == ["enroll"] and sw.isChecked() and len(BOXES) == 1, CALLS)
sw.click(); app.processEvents()

print("== the install fails")
STATE[0], FAIL[0] = "absent", "it stopped with code 1."
page.load(); CALLS.clear()
sw.click(); app.processEvents()
check("InstallFailed: the approved message with the reason", WARNED and WARNED[-1] == "Toner's helper service couldn't be installed: it stopped with code 1.", WARNED)
check("...not enrolled, left unticked", "enroll" not in CALLS and not sw.isChecked())
FAIL[0] = None

print("== the states that keep it off")
for st, text, enabled in (("portable", "A portable copy can't use this: it has no helper service.", False),
                          ("other_user", "Toner's helper service on this computer serves another user.", False),
                          ("not_running", "Toner's helper service is installed but not running.", False),
                          ("outdated", "Toner's helper service is out of date. Turn this on again to update it.", True),
                          ("rules_changed", "Sign-in without approval was turned off because Toner's rules key was replaced. Turn it on again to use it.", True)):
    STATE[0] = st
    page.load()
    check(f"{st}: {'enabled' if enabled else 'disabled'}, unticked, with its note", sw.isEnabled() == enabled and not sw.isChecked()
          and not note.isHidden() and note.text() == text, (sw.isEnabled(), note.text()))
STATE[0] = "outdated"; page.load(); CALLS.clear()
sw.click(); app.processEvents()
check("Turn on while out of date: installs again, then enrolls", [c for c in CALLS if c != "state"] == ["install", "enroll"] and sw.isChecked(), CALLS)
check("...and the note goes", note.isHidden())

print("== unticking when the helper can't be reached")
STATE[0] = "on"; page.load(); WARNED.clear()
def unreachable(keys_path=None):
    CALLS.append("forget")
    raise helperclient.NotRunning()
helperclient.forget = unreachable
sw.click(); app.processEvents()
check("the approved sentence; not audited; the switch still on, as the helper has it", WARNED == [
      "Toner's helper service couldn't be reached, so its spare copy of Toner's key is still there. Try again when it's running."]
      and sw.isChecked() and ("sign-in without approval turned off", "by Admin") not in acts()[:1], WARNED)
def broken():
    CALLS.append("enroll")
    raise RuntimeError("unexpected")
helperclient.forget, real_enroll, helperclient.enroll = forget, helperclient.enroll, broken
STATE[0] = "off"; page.load()
RAISED, real_hook = [], sys.excepthook
sys.excepthook = lambda *e: RAISED.append(e[0])         # (Qt hands a slot's exception to the hook)
sw.click(); app.processEvents()
sys.excepthook = real_hook
helperclient.enroll = real_enroll
check("an unexpected error: the switch is still put back to the helper's state", not sw.isChecked() and RAISED == [RuntimeError],
      RAISED)

print("== turned off by a new rules key: said once")
STATE[0] = "off"
db.set_setting("helper_off_notice", True)
page.load()
check("the note is shown", not note.isHidden() and note.text() == A.OFF_RULES and not sw.isChecked() and sw.isEnabled())
check("...and the flag cleared", db.get_setting("helper_off_notice") is False)
page.load()
check("...so it isn't shown again", note.isHidden())

print("== Admins only")
session.sign_out()
session.sign_in("Tech1", PW2)
page.load()
check("a Tech doesn't see it (nor its note)", sw.isHidden() and note.isHidden())
session.sign_out()
session.sign_in("Admin", PW)
page.load()
check("an Admin does again", not sw.isHidden())
check("nothing pending at the end", S.pending_changes() == [], S.pending_changes())

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

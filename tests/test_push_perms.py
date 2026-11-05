# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Pushing to devices needs the role's "push" permission: every core path raises Denied before connecting, and each button shows it.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\pushp%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import backup, db
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

from core import ansible, apitool, cmdrun, datakey, firmware as fw, perms, scp, session, sshkeys
import requests

PW, PW2, PW3 = "correct horse battery 42", "another long password 9", "a third quite long password 5"
REFUSAL = "Your role can't run commands that change a device: "
TIP = "Your role doesn't allow this. Ask an admin."
DEV = {"name": "sw1", "key": "sw1", "vendor": "cisco", "address": "10.0.0.1", "org": None}

# nothing below the check may connect
cmdrun._run_ssh = lambda dev, commands, opts, rt, out: out["outputs"].append(("ran", ""))
cmdrun._save_session = lambda dev, log: None
requests.request = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no network in tests"))
fw.connect = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no device in tests"))


def verdict(fn):
    """'denied' (with its message), or 'passed' when the check let it through (anything later may fail: nothing is connected)."""
    try:
        fn()
    except perms.Denied as e:
        return "denied", str(e)
    except Exception:
        pass
    return "passed", ""


R = {"platform": "ios", "flashes": [{"fs": "flash:"}], "key": "sw1", "dev": DEV}
CHOICE = {"name": "a.bin", "size": 10, "md5": "0" * 32}
SRC = {"proto": "http", "host": "10.0.0.9", "port": 80, "path": "", "password": ""}
cases = {
    "cmdrun.run_on_device": lambda: cmdrun.run_on_device(DEV, ["configure terminal"]),
    "cmdrun.run_many": lambda: cmdrun.run_many([DEV], ["write memory"]),
    "firmware.transfer": lambda: fw.transfer(DEV, R, CHOICE, SRC),
    "firmware.cleanup": lambda: fw.cleanup(DEV, R, {"install": False, "files": [("flash:", "a.bin", 1)]}),
    "firmware.save_and_install": lambda: fw.save_and_install(DEV, R, "a.bin"),
    "firmware.after_copy": lambda: fw.after_copy(DEV, R, "a.bin"),
    "ansible.run": lambda: ansible.run(ansible.RunSpec("nope.yml", []), lambda _l: None),
    "sshkeys.add_to_device": lambda: sshkeys.add_to_device(object(), "ssh-ed25519 AAAA x"),
    "scp.upload": lambda: scp.Scp(object()).upload(__file__, "/tmp/x"),
    "apitool.send POST": lambda: apitool.send({"method": "POST", "url": "http://127.0.0.1:9/", "verify": True, "headers": {}, "data": None, "timeout": 1}),
    "apitool.send DELETE": lambda: apitool.send({"method": "delete", "url": "http://127.0.0.1:9/", "verify": True, "headers": {}, "data": None, "timeout": 1}),
}
reads = {
    "cmdrun.run_on_device show version": lambda: cmdrun.run_on_device(DEV, ["show version"]),
    "cmdrun.run_many show version": lambda: cmdrun.run_many([DEV], ["show version"]),
    "ansible syntax check": lambda: ansible.run(ansible.RunSpec("nope.yml", [], syntax_only=True), lambda _l: None),
    "scp.download": lambda: scp.Scp(object()).download("/tmp/x", SP + os.sep + "dl"),
    "apitool.send GET": lambda: apitool.send({"method": "GET", "url": "http://127.0.0.1:9/", "verify": True, "headers": {}, "data": None, "timeout": 1}),
    "apitool.send HEAD": lambda: apitool.send({"method": "HEAD", "url": "http://127.0.0.1:9/", "verify": True, "headers": {}, "data": None, "timeout": 1}),
    "apitool.send OPTIONS": lambda: apitool.send({"method": "OPTIONS", "url": "http://127.0.0.1:9/", "verify": True, "headers": {}, "data": None, "timeout": 1}),
}


def screens():
    """Every window with a button that writes to a device, built under whoever is signed in now."""
    from ui.apitool import ApiTesterTab
    from ui.automation import PlaybooksPage
    from ui.firmware import CleanupStep, FirmwareTab
    from ui.playbookeditor import PlaybookEditorTab
    from ui.sshkeysui import DeployKey
    from ui.tools2 import CommandRunnerTab
    from ui.tools3 import ScpTab
    out = {}
    global KEEP
    KEEP = []
    pb = PlaybooksPage(); KEEP.append(pb); pb._buttons(); out["Automation Run"] = pb.go
    ed = PlaybookEditorTab(); KEEP.append(ed); ed.current = "x.yml"; ed._buttons(); out["Playbook Editor Run..."] = ed.run_btn
    dk = DeployKey(); KEEP.append(dk); out["SSH Keys Add to device"] = dk.go
    sc = ScpTab(); KEEP.append(sc); sc.direction.setCurrentIndex(0); out["SCP Start (upload)"] = sc.go
    cl = CleanupStep(); KEEP.append(cl); cl.chosen = lambda: [(R, {"install": False, "files": [("flash:", "a.bin", 1)]})]; cl._sync(); out["Firmware Delete ticked files"] = cl.delete
    fwt = FirmwareTab(); KEEP.append(fwt); fwt.stack.setCurrentIndex(4); fwt.images.ready = lambda: True; fwt._sync(); out["Firmware Transfer"] = fwt.next
    api = ApiTesterTab(); KEEP.append(api); api.method.setCurrentText("POST"); out["API Tester Send (POST)"] = api.send_btn
    return out, sc, api


def drive_ui(who, allowed):
    out, sc, api = screens()
    for name, b in out.items():
        check(f"{who}: {name} " + ("enabled" if allowed else "disabled with the tooltip"),
              (b.isEnabled() and b.toolTip() != TIP) if allowed else (not b.isEnabled() and b.toolTip() == TIP), (b.isEnabled(), b.toolTip()))
    sc.direction.setCurrentIndex(1)
    check(f"{who}: SCP download stays enabled", sc.go.isEnabled() and sc.go.toolTip() != TIP)
    for m in ("GET", "HEAD", "OPTIONS"):
        api.method.setCurrentText(m)
        check(f"{who}: API Tester {m} stays enabled", api.send_btn.isEnabled() and api.send_btn.toolTip() != TIP)
    api.method.setCurrentText("PUT")
    check(f"{who}: API Tester PUT " + ("enabled" if allowed else "disabled"), api.send_btn.isEnabled() == allowed)
    # Command Runner: read-only commands run for everyone; a changing one says why and runs nothing
    from ui.tools2 import CommandRunnerTab
    cr = CommandRunnerTab(); KEEP.append(cr)
    cr.checked_devices = lambda: [DEV]
    cr.safe.setChecked(False)
    QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.No)
    started = []
    real_run_many = cmdrun.run_many
    cmdrun.run_many = lambda *a, **k: started.append(a) or []
    cr.commands.setPlainText("configure terminal")
    cr.start()
    refused = cr.status.text() == REFUSAL + "configure terminal" and cr.worker is None
    check(f"{who}: Command Runner " + ("asks about a changing command" if allowed else "refuses a changing command"),
          (not refused and cr.worker is None) if allowed else refused, cr.status.text())
    cr.commands.setPlainText("show version")
    cr.start()
    if cr.worker is not None:
        cr.worker.wait(5000)
    check(f"{who}: Command Runner runs a read-only command", len(started) == 1 and not cr.status.text().startswith(REFUSAL), cr.status.text())
    cmdrun.run_many = real_run_many


# ---------------------------------------------------------------- sign-in off: nothing changes
db.init()
check("no keys file: sign-in off", not datakey.exists())
for n, fn in cases.items():
    check(f"off: {n} not denied", verdict(fn)[0] == "passed")
for n, fn in reads.items():
    check(f"off: {n} not denied", verdict(fn)[0] == "passed")
drive_ui("off", True)
os.environ["NETCHECK_DB"] = SP + os.sep + "pushp_keyed.db"                   # the off phase used a plain database; the keyed one starts fresh

# ---------------------------------------------------------------- a Tech
datakey.create("Admin1", PW)
db.init()
session.sign_out(); session.sign_in("Admin1", PW)
datakey.add_local("Tech1", PW2, role="Tech")
datakey.add_local("Eng1", PW3, role="Engineer")
from core import roles
roles.sync_grants()
session.sign_out(); session.sign_in("Tech1", PW2)
check("Tech: push is closed", not perms.allowed("push"), (roles.state(), datakey.signed_in_name(), roles.role_of(datakey.signed_in_name()), session.state()))
for n, fn in cases.items():
    v, msg = verdict(fn)
    check(f"Tech: {n} denied", v == "denied", msg)
check("Tech: run_on_device says which commands", verdict(cases["cmdrun.run_on_device"])[1] == REFUSAL + "configure terminal")
check("Tech: run_many says which commands", verdict(cases["cmdrun.run_many"])[1] == REFUSAL + "write memory")
check("Tech: the others say the approved reason", verdict(cases["firmware.cleanup"])[1] == TIP == verdict(cases["apitool.send POST"])[1], verdict(cases["firmware.cleanup"]))
check("Tech: a mixed list names only the changing ones",
      verdict(lambda: cmdrun.run_on_device(DEV, ["show version", "clear counters"]))[1] == REFUSAL + "clear counters")
for n, fn in reads.items():
    check(f"Tech: {n} not denied", verdict(fn)[0] == "passed")
_r = cmdrun.run_on_device(DEV, ["show version"]); check("Tech: show version really runs", _r["ok"], _r)
drive_ui("Tech", False)

# ---------------------------------------------------------------- an Engineer
session.sign_out(); session.sign_in("Eng1", PW3)
check("Engineer: push is open", perms.allowed("push"))
for n, fn in {**cases, **reads}.items():
    check(f"Engineer: {n} not denied", verdict(fn)[0] == "passed")
drive_ui("Engineer", True)

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

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


class FakeSftp:
    def __init__(self): self.calls = []
    def mkdir(self, p): self.calls.append(("mkdir", p))
    def remove(self, p): self.calls.append(("remove", p))
    def rmdir(self, p): self.calls.append(("rmdir", p))
    def lstat(self, p):
        import types
        return types.SimpleNamespace(st_mode=0o100644)
    def put(self, src, dst, callback=None): self.calls.append(("put", dst))
    def get(self, src, dst, callback=None, prefetch=True): self.calls.append(("get", src))      # (paramiko's own signature)


def drive_files(who, allowed):
    """The file browser's SFTP writes: New folder, Delete and Upload on the device. Browsing and downloading stay open."""
    import types
    import ui.filebrowser as FB
    sftp = FakeSftp(); rfs = FB.RemoteFs(sftp)
    worker = types.SimpleNamespace(sftp=sftp, cancel=types.SimpleNamespace(is_set=lambda: False),
                                   progress=types.SimpleNamespace(emit=lambda *a: None), ask=lambda *a: "replace")
    local_file = SP + os.sep + "up.txt"; open(local_file, "w").write("x")
    ops = {"mkdir": lambda: rfs.mkdir("/new"), "delete": lambda: rfs.delete("/old"),
           "upload": lambda: FB.copy_file(worker, FB.LocalFs(), local_file, rfs, "/up.txt", "Uploading up.txt", {"replace_all": True})}
    for n, fn in ops.items():
        v, msg = verdict(fn)
        check(f"{who}: file browser {n} " + ("allowed" if allowed else "denied"), (v == "passed") == allowed and (allowed or msg == TIP), (v, msg))
    check(f"{who}: nothing reached the device" if not allowed else f"{who}: the device got all three",
          (sftp.calls == []) if not allowed else {c[0] for c in sftp.calls} >= {"mkdir", "remove", "put"}, sftp.calls)
    check(f"{who}: file browser download stays open", verdict(lambda: FB.copy_file(worker, rfs, "/a", FB.LocalFs(), SP + os.sep + "dl.txt", "d", {"replace_all": True}))[0] == "passed"
          and ("get", "/a") in sftp.calls)
    check(f"{who}: the message shown is the approved one", FB.plain(perms.Denied()) == TIP)
    side_l, side_r = FB.Side("L", "local", "Upload", "tip"), FB.Side("R", "remote", "Download", "tip2")
    for sd in (side_l, side_r):
        sd.set_alive(True)
        for b in (sd.delete_btn, sd.action_btn, sd.mkdir_btn):
            b.setEnabled(True)
        sd.gate()
    for name, b in (("Upload", side_l.action_btn), ("device New folder", side_r.mkdir_btn), ("device Delete", side_r.delete_btn)):
        check(f"{who}: file browser {name} " + ("enabled" if allowed else "disabled with the tooltip"),
              (b.isEnabled() and b.toolTip() != TIP) if allowed else (not b.isEnabled() and b.toolTip() == TIP), (b.isEnabled(), b.toolTip()))
    check(f"{who}: this computer's New folder and Delete, and Download, stay enabled",
          all(b.isEnabled() and b.toolTip() != TIP for b in (side_l.mkdir_btn, side_l.delete_btn, side_r.action_btn)))


def drive_windows_and_proxmox(who, allowed):
    """Windows Services start/stop/restart/startup type (this PC and WinRM) and the Proxmox token: pushes too."""
    from core import pvekey, winmon, winservices as WS
    sent = []
    winmon.collect_local = lambda **k: sent.append(("local", k["script"])) or {"ok": True}
    winmon.collect_winrm = lambda dev, pw, **k: sent.append(("winrm", k["script"])) or {"ok": True}
    posted = []
    requests.post = lambda *a, **k: posted.append(a) or (_ for _ in ()).throw(RuntimeError("no network in tests"))
    for how in ("local", "winrm"):
        dev = {"name": "pc", "vendor": "windows", "host": "10.0.0.15", "platform": how, "username": "u", "password": "p"}
        for n, fn in {"control": lambda: WS.control(dev, "restart", "Spooler", "p"), "set_startup": lambda: WS.set_startup(dev, "manual", "Spooler", "p")}.items():
            v, msg = verdict(fn)
            check(f"{who}: services {n} ({how}) " + ("allowed" if allowed else "denied"), (v == "passed") == allowed and (allowed or msg == TIP), (v, msg))
    check(f"{who}: services " + ("sent to the computer" if allowed else "nothing sent to the computer"), bool(sent) == allowed, sent)
    v, msg = verdict(lambda: pvekey.create_token({"host": "10.0.0.9"}, "root@pam", "pw"))
    check(f"{who}: Proxmox token " + ("allowed" if allowed else "denied"), (v == "passed") == allowed and (allowed or msg == TIP), (v, msg))
    check(f"{who}: " + ("Proxmox sign-in attempted" if allowed else "nothing sent to Proxmox"), bool(posted) == allowed, posted)
    # the windows
    import ui.serviceswindow as SW
    rows = [{"name": "Spooler", "display": "Print Spooler", "state": "Stopped", "start": "Auto", "delayed": False}]
    WS.listing = lambda dev, password=None, timeout=45: (rows, "now")
    win = {"id": None, "name": "pc", "vendor": "windows", "host": "10.0.0.15", "port": 0, "platform": "winrm", "username": "u", "password": "p", "winopts": "", "site": "default"}
    d = SW.ServicesDialog(win); KEEP.append(d); d.show()
    for _ in range(100):
        app.processEvents(); time.sleep(0.02)
        if d.table.rowCount(): break
    d.table.selectRow(0); app.processEvents()
    check(f"{who}: Services Start " + ("enabled" if allowed else "disabled with the tooltip"),
          (d.start_btn.isEnabled() and d.start_btn.toolTip() != TIP) if allowed else (not d.start_btn.isEnabled() and d.start_btn.toolTip() == TIP), (d.start_btn.isEnabled(), d.start_btn.toolTip()))
    from PySide6.QtCore import QPoint
    m = d.build_menu(d.table.visualRect(d.table.model().index(0, 0)).center())
    acts = {a.text(): a for a in m.actions() if a.text()}
    sub = acts["Startup type"]
    check(f"{who}: Services menu Start and Startup type " + ("enabled" if allowed else "disabled with the tooltip"),
          (acts["Start"].isEnabled() and sub.isEnabled()) if allowed else (not acts["Start"].isEnabled() and not sub.isEnabled() and acts["Start"].toolTip() == TIP and sub.toolTip() == TIP))
    QMessageBox.exec = lambda self: QMessageBox.StandardButton.No          # the confirmation is answered No: nothing is sent
    sent.clear(); d.act("start")
    check(f"{who}: Services handler " + ("goes on" if allowed else "says why and sends nothing"), (d.status.text() != TIP) if allowed else (d.status.text() == TIP and not sent), d.status.text())
    d.busy = False
    # the device dialog's button
    import ui.inventory as I
    dlg = I.DeviceDialog(); KEEP.append(dlg); dlg.show(); app.processEvents()
    for vendor, gated in (("proxmox", True), ("paloalto", False)):
        dlg.vendor.setCurrentIndex(dlg.vendor.findData(vendor)); app.processEvents()
        b = dlg.get_key
        want = gated and not allowed
        check(f"{who}: {vendor} key button " + ("disabled with the tooltip" if want else "enabled"),
              (not b.isEnabled() and b.toolTip() == TIP) if want else (b.isEnabled() and b.toolTip() != TIP), (b.isEnabled(), b.toolTip()))
    from ui.keydialog import KeyDialog
    kd = KeyDialog({"host": "10.0.0.9"}, "proxmox"); KEEP.append(kd); kd.accept()
    check(f"{who}: key dialog " + ("asks for the sign-in" if allowed else "shows the approved message"), (kd.status.text() == TIP) != allowed and bool(kd.status.text()), kd.status.text())


# ---------------------------------------------------------------- sign-in off: nothing changes
db.init()
check("no keys file: sign-in off", not datakey.exists())
for n, fn in cases.items():
    check(f"off: {n} not denied", verdict(fn)[0] == "passed")
for n, fn in reads.items():
    check(f"off: {n} not denied", verdict(fn)[0] == "passed")
drive_ui("off", True)
drive_files("off", True)
drive_windows_and_proxmox("off", True)
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
drive_files("Tech", False)
drive_windows_and_proxmox("Tech", False)

# ---------------------------------------------------------------- an Engineer
session.sign_out(); session.sign_in("Eng1", PW3)
check("Engineer: push is open", perms.allowed("push"))
for n, fn in {**cases, **reads}.items():
    check(f"Engineer: {n} not denied", verdict(fn)[0] == "passed")
drive_ui("Engineer", True)
drive_files("Engineer", True)
drive_windows_and_proxmox("Engineer", True)

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

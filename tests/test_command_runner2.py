# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The Command Runner on Windows computers (PowerShell) and on Fortinet and Palo Alto firewalls (SSH with their own login), and the read-only guard.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, subprocess, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\cmdr2%d.db" % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roamingcmd%d" % int(time.time()))
from core import cmdrun as C, db, vendors
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def dev(name, vendor, host="10.0.0.9", **kw):
    d = dict(name=name, vendor=vendor, host=host, port=0, platform=kw.pop("platform", ""), username=kw.pop("username", ""), site="default", verify_ssl=0, ha_expected=0, enabled=1,
             location="", details="", folder_id=None)
    d.update(kw); d["id"] = db.save_device(d); return db.get_device(d["id"])

print("== which devices take commands")
sw = dev("sw1", "cisco", platform="cisco_ios"); fg = dev("fw1", "fortinet"); pa = dev("pa1", "paloalto"); mer = dev("mer1", "meraki")
ag = dev("pc-agent", "windows", platform="agent"); wr = dev("srv-winrm", "windows", platform="winrm", username="u"); lo = dev("this-pc", "windows", platform="local", host="localhost")
check("the kinds", [C.kind_of(d) for d in (sw, fg, pa, mer, ag, wr, lo)] == ["ssh", "cli", "cli", "", "windows", "windows", "windows"])
check("a switch can be commanded; a cloud-managed device cannot", C.runnable(sw)[0] and not C.runnable(mer)[0])
check("an agent computer cannot, and the reason says why (the tooltip says what to do)", not C.runnable(ag)[0] and C.runnable(ag)[1] == "reports by agent" and "WinRM" in C.HELP["reports by agent"])
check("a WinRM computer and this PC can", C.runnable(wr)[0] and C.runnable(lo)[0])
check("a firewall without an SSH login cannot, and the tooltip says where to set it", not C.runnable(fg)[0] and C.runnable(fg)[1] == "no SSH login" and "Edit device > Access" in C.HELP["no SSH login"])
check("... nor with only a user name", not C.runnable({**fg, "username": "admin"})[0])
STORE[("netcheck", "fw1:ssh")] = "sshpw"
check("with both it can", C.runnable({**fg, "username": "admin"})[0] and not C.runnable(fg)[0])
check("the SSH password is its own secret, apart from the API key", "ssh" in db.SECRET_KINDS and db.secret_name("fw1", "ssh") == "fw1:ssh" and vendors.CLI_TYPES == {"fortinet": "fortinet", "paloalto": "paloalto_panos"})

print("== the read-only guard for PowerShell")
good = [r"Get-Service", r"Get-Service | Where-Object { $_.Status -eq 'Running' }", r"Get-Process | Sort-Object CPU -Descending | Select-Object -First 5",
        r"gci C:\Windows -Filter *.log", r"hostname", r"ipconfig /all", r"whoami /groups", r"Get-EventLog -LogName System -Newest 20 | Format-Table -AutoSize",
        r"Get-ChildItem C:\ | Where-Object { $_.Length -gt 1000 }", r"Test-NetConnection 10.0.0.1 -Port 443", r"netsh interface ip show config", r"route print",
        r"sc query spooler", r"Get-Service ; hostname", r"w32tm /query /status", r"net share", r"Get-Content 'a;b|c.txt'",
        r"Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version", r"wevtutil qe System /c:5", r"arp -a", r""]
for c in good: check(f"looks only: {c or '(nothing)'}", C.read_only_ps(c))
blocked = [r"Restart-Service Spooler", r"Stop-Service x", r"Get-Service | Stop-Service", r"Remove-Item C:\x", r"Get-Service; Restart-Service x", r"$x = 5", r"Get-Service > out.txt",
           r"Get-Service | Out-File a.txt", r"Get-Process | ForEach-Object { $_.Kill() }", r"Get-Process | Where-Object { $_.Kill() }", r"Get-Date; $(calc)", r"& calc",
           r"Invoke-Expression 'x'", r"iex 'x'", r"net stop spooler", r"net user bob /add", r"sc stop x", r"sc config x start= disabled",
           r"netsh advfirewall set allprofiles state off", r"route add 1.1.1.1 mask 255.0.0.0 2.2.2.2", r"w32tm /resync", r"Get-Service | Where-Object { $_.Name = 'x' }",
           "Get-Service `n Stop-Service", r"Get-Service || Stop-Service", r"Set-Content a b", r"shutdown /r", r"powershell -c x", r"cmd /c del x", r"Get-Service |", r"| Get-Service",
           r"Get-Service | Where-Object { Remove-Item x }", r"Get-Service | Where-Object { $_.Name -eq 'a' } | Restart-Service", r"start notepad",
           r"Get-Content x | ForEach-Object { $_ }", 'Get-Service "$(calc)"', r"Get-Process | Select-Object { Stop-Process }"]
for c in blocked: check(f"asks first: {c}", not C.read_only_ps(c))
check("the network-device guard is unchanged, and now also stops 'request ...' (PAN-OS)", C.read_only("show version") and not C.read_only("request restart system") and not C.read_only("configure terminal"))
check("each kind of device is judged by its own rules", C.risky_commands([sw], ["hostname", "show version"]) == ["hostname"] and C.risky_commands([lo], ["hostname", "show version"]) == ["show version"]
      and C.risky_commands([sw, lo], ["hostname", "show version"]) == ["hostname", "show version"] and C.risky_commands([lo], ["hostname"]) == [])

print("== the script, and a real run")
cmds = ["hostname", "Get-Service NoSuchSvcXyz", "'it''s' + \" \"" , "Write-Output ('a' * 3)"]
script = C.ps_script(cmds)
check("commands travel as base64 and cannot break out of the script", "hostname" not in script and "NoSuchSvc" not in script and "FromBase64String" in script)
nasty = ["'; Remove-Item C:\\ -Recurse; '", "$(calc)", "`n", "\"; calc; \"", "x' | Out-Null; 'y"]
path = os.path.join(SP, "p.ps1"); open(path, "w", encoding="utf-8-sig").write("function T { " + C.ps_script(nasty) + " }")
chk = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('" + path + "',[ref]$null,[ref]$e); $e.Count"],
                     capture_output=True, text=True, timeout=90)
check("the script is valid PowerShell whatever the commands are", chk.stdout.strip() == "0", chk.stdout + chk.stderr)
r = C.run_on_device(lo, ["hostname", "Get-Service NoSuchSvcXyz", "Write-Output ('a' * 3)"], read_timeout=60)
check("a real run on this PC: every command has its output", r["ok"] and [c for c, _o in r["outputs"]] == ["hostname", "Get-Service NoSuchSvcXyz", "Write-Output ('a' * 3)"], r)
check("hostname is this computer's name", r["outputs"][0][1].strip().lower() == os.environ.get("COMPUTERNAME", "").lower(), r["outputs"][0])
check("an error is part of the output, not a failure of the run", "NoSuchSvcXyz" in r["outputs"][1][1] and r["outputs"][2][1].strip() == "aaa", r["outputs"])
r1 = C.run_on_device(lo, ["Get-Service | Select-Object -First 2 | Format-Table Name"], read_timeout=60)
check("one command works too (PowerShell turns a list of one into the item)", r1["ok"] and len(r1["outputs"]) == 1 and "Name" in r1["outputs"][0][1], r1)
ra = C.run_on_device(ag, ["hostname"])
check("an agent computer is refused with the reason", not ra["ok"] and "agent" in ra["error"], ra)
rm = C.run_on_device(mer, ["show x"])
check("a cloud-managed device is refused, saying what does take commands", not rm["ok"] and "SSH" in rm["error"] and "PowerShell" in rm["error"], rm)
import core.winmon as WM
seen = []
real_winrm = WM.collect_winrm
WM.collect_winrm = lambda d, pw, timeout=30, factory=None, script=None, parser=None: (seen.append((d["host"], d["username"], pw)), parser(json.dumps({"results": {"command": "hostname", "output": "SRV1"}})))[1]
STORE[("netcheck", "srv-winrm")] = "winpw"
r = C.run_on_device(wr, ["hostname"])
check("over WinRM it uses the device's stored login", r["ok"] and r["outputs"] == [("hostname", "SRV1")] and seen == [("10.0.0.9", "u", "winpw")], (r, seen))
WM.collect_winrm = real_winrm

print("== a firewall over SSH")
calls = []
class FakeConn:
    def __init__(self, **kw): calls.append(kw)
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def send_command(self, cmd, **k): return f"output of {cmd}"
real_connect = C.ConnectHandler
C.ConnectHandler = FakeConn
fg2 = dev("fw2", "fortinet", username="admin", host="10.0.0.1"); STORE[("netcheck", "fw2:ssh")] = "S3cret"; STORE[("netcheck", "fw2")] = "API-KEY-123"
r = C.run_on_device(fg2, ["get system status", "diagnose sys top"])
check("Fortinet: its own command line, with its SSH login, on the SSH port (not the API's)", r["ok"] and r["outputs"][0] == ("get system status", "output of get system status") and calls[-1]["device_type"] == "fortinet"
      and calls[-1]["username"] == "admin" and calls[-1]["password"] == "S3cret" and calls[-1]["host"] == "10.0.0.1" and calls[-1]["port"] == 22, calls[-1])
pa2 = dev("pa2", "paloalto", username="admin", host="10.0.1.1", port=443); STORE[("netcheck", "pa2:ssh")] = "pw2"
r = C.run_on_device(pa2, ["show system info"])
check("Palo Alto: PAN-OS, still on the SSH port though the device's port is 443", r["ok"] and calls[-1]["device_type"] == "paloalto_panos" and calls[-1]["port"] == 22, calls[-1])
db.set_setting("default_ssh_port", 2222)
C.run_on_device(fg2, ["get system status"]); check("the default SSH port setting applies", calls[-1]["port"] == 2222); db.set_setting("default_ssh_port", 22)
n = len(calls); r = C.run_on_device(fg, ["get system status"])
check("without a login it says what to do, and does not connect", not r["ok"] and "SSH user name and SSH password" in r["error"] and len(calls) == n, r)
check("the API key is never used as the SSH password", not any("API-KEY-123" in json.dumps(c, default=str) for c in calls))
C.ConnectHandler = real_connect

print("== the Command Runner window")
from PySide6.QtCore import Qt, QCoreApplication
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
import ui.tools2 as T2
cmdrun_name = lambda d: d["name"]
asked = []
QMessageBox.question = staticmethod(lambda *a, **k: (asked.append(a[2]), QMessageBox.StandardButton.Yes)[1])
R = T2.CommandRunnerTab(); R.show(); R.fill_devices()
def listed():
    return {R.devs.item(i).data(Qt.ItemDataRole.UserRole): R.devs.item(i) for i in range(R.devs.count()) if R.devs.item(i).data(Qt.ItemDataRole.UserRole)}
def header():
    return next((R.devs.item(i) for i in range(R.devs.count()) if R.devs.item(i).data(R.GROUP)), None)
items = listed()
check("what can take commands is listed to tick: network devices, Windows computers over WinRM or local, and firewalls with a login", {"sw1", "fw2", "pa2", "srv-winrm", "this-pc"} <= set(items) and "mer1" not in items, sorted(items))
check("the ones that can be commanded can be ticked", all(items[n].flags() & Qt.ItemFlag.ItemIsUserCheckable for n in ("sw1", "fw2", "pa2", "srv-winrm", "this-pc")))
h = header()
check("the three that cannot (an agent computer and two firewalls without a login) share one row instead of three", h is not None and "3 devices cannot take commands" in h.text() and not ({"pc-agent", "fw1", "pa1"} & set(items)), (h.text() if h else None, sorted(items)))
check("it starts closed, and says so with an arrow", h.text().startswith(chr(0x25b8)) and "Click to show" in h.toolTip() and "1 x reports by agent" in h.toolTip() and "2 x no SSH login" in h.toolTip(), h.toolTip())
check("it is a row to click, not something to tick", not (h.flags() & Qt.ItemFlag.ItemIsUserCheckable) and bool(h.flags() & Qt.ItemFlag.ItemIsEnabled))
R.devs.itemClicked.emit(h)
items = listed(); h = header()
check("clicking it opens it: they are listed under it, greyed, each with its reason", {"pc-agent", "fw1", "pa1"} <= set(items) and h.text().startswith(chr(0x25be))
      and not (items["pc-agent"].flags() & Qt.ItemFlag.ItemIsEnabled) and "reports by agent" in items["pc-agent"].text() and items["pc-agent"].text().startswith("    ")
      and "no SSH login" in items["fw1"].text() and "Edit device > Access" in items["fw1"].toolTip() and "WinRM" in items["pc-agent"].toolTip()
      and not (items["pa1"].flags() & Qt.ItemFlag.ItemIsEnabled) and "Click to hide" in h.toolTip())
check("and they sit under the row, after the ones to tick", R.devs.row(h) > max(R.devs.row(items[n]) for n in ("sw1", "fw2", "pa2", "srv-winrm", "this-pc")) and R.devs.row(items["fw1"]) > R.devs.row(h))
R.devs.itemClicked.emit(header()); items = listed()
check("clicking again closes it", not ({"pc-agent", "fw1", "pa1"} & set(items)) and header().text().startswith(chr(0x25b8)))
R.devs.itemClicked.emit(items["sw1"]); check("clicking a device does nothing to the row", header().text().startswith(chr(0x25b8)))
R._tick_all(True)
check("'All' ticks only what can be commanded", {d["name"] for d in R.checked_devices()} == {"sw1", "fw2", "pa2", "srv-winrm", "this-pc"})
R._tick_all(False); check("'None' clears", not R.checked_devices())
ran = {}
def fake_run(devs, cmds, workers=8, on_result=None, cancel=None, opts=None):
    ran["devs"], ran["cmds"] = sorted(d["name"] for d in devs), cmds
    out = [{"device": d["name"], "ok": True, "outputs": [(c, "x") for c in cmds], "error": "", "seconds": 0.1} for d in devs]
    for r in out: on_result(r)
    return out
real_many = C.run_many; C.run_many = fake_run
def tick(*names):
    for i in range(R.devs.count()):
        it = R.devs.item(i)
        if it.flags() & Qt.ItemFlag.ItemIsUserCheckable:
            it.setCheckState(Qt.CheckState.Checked if it.data(Qt.ItemDataRole.UserRole) in names else Qt.CheckState.Unchecked)
tick("this-pc"); R.commands.setPlainText("Get-Service | Where-Object { $_.Status -eq 'Stopped' }\nhostname"); asked.clear()
R.go.click(); pump = lambda cond, n=200: [QCoreApplication.processEvents() or time.sleep(0.02) for _ in range(n) if not cond()]
pump(lambda: R.go.isEnabled())
check("read-only PowerShell runs on a Windows computer without asking", ran.get("devs") == ["this-pc"] and not asked, (ran, asked))
ran.clear(); R.commands.setPlainText("Restart-Service Spooler"); R.go.click()
check("a changing PowerShell command is blocked by read-only mode, which says which", not ran and "Blocked" in R.status.text() and "Restart-Service Spooler" in R.status.text() and "'Read-only mode'" in R.status.text(), R.status.text())
tick("sw1"); ran.clear(); R.commands.setPlainText("hostname"); R.go.click()
check("'hostname' is fine on a Windows computer but blocked on a switch: judged by the kind of device", not ran and "hostname" in R.status.text(), R.status.text())
R.commands.setPlainText("show version"); R.go.click(); pump(lambda: R.go.isEnabled())
check("and 'show version' on a switch is fine", ran.get("devs") == ["sw1"])
tick("sw1", "this-pc"); ran.clear(); asked.clear(); R.commands.setPlainText("show version"); R.go.click(); pump(lambda: R.go.isEnabled())
check("ticking two kinds asks first, saying what is different", asked and "network device (SSH)" in asked[0] and "Windows computer (PowerShell)" in asked[0] and "same commands" in asked[0], asked)
check("and with 'show version' on a Windows computer it is not read-only, so read-only mode stops it, after asking", not ran and "Blocked" in R.status.text(), R.status.text())
R.safe.setChecked(False); tick("fw2"); ran.clear(); asked.clear(); R.commands.setPlainText("get system status"); R.go.click(); pump(lambda: R.go.isEnabled())
check("a firewall runs its command line", ran.get("devs") == ["fw2"] and not asked)
C.run_many = real_many
R.group.set_selected([]); R.fill_devices()
check("with devices to choose from, there is no empty message", R.devs.count() > 0 and not R.devs_hint.isVisibleTo(R))
real_candidates = R.candidates; R.candidates = lambda: []; R.fill_devices()
check("with none in the chosen groups, the list says so, in wording C", R.devs.count() == 0 and R.devs_hint.isVisibleTo(R) and R.devs_hint.head.text() == "No devices in these groups take commands"
      and R.devs_hint.sub.text() == "Try other groups, or see Edit device > Access.", (R.devs_hint.head.text(), R.devs_hint.sub.text()))
R.candidates = real_candidates; R.fill_devices()
only_fw1 = [d for d in real_candidates() if cmdrun_name(d) in ("sw1", "fw1")]
R.candidates = lambda: only_fw1; R.fill_devices()
check("a single device that cannot take commands is shown as it is, greyed with its reason, with no row to open", header() is None and R.devs.count() == 2 and "no SSH login" in R.devs.item(1).text()
      and not (R.devs.item(1).flags() & Qt.ItemFlag.ItemIsEnabled), [R.devs.item(i).text() for i in range(R.devs.count())])
R.candidates = real_candidates; R.fill_devices()
check("and it goes again once there are some", not R.devs_hint.isVisibleTo(R))
R.shutdown()

print("== the SSH login on a firewall's device dialog")
import ui.inventory as I
dlg = I.DeviceDialog(); dlg.show(); app.processEvents()
dlg.vendor.setCurrentIndex(dlg.vendor.findData("cisco")); app.processEvents()
check("a switch has the ordinary Username, and no SSH password box", dlg.access.labelForField(dlg.username).text() == "Username" and not dlg.ssh_pw.isVisibleTo(dlg.page_access))
dlg.vendor.setCurrentIndex(dlg.vendor.findData("fortinet")); app.processEvents()
check("a Fortinet firewall asks for an SSH user name and SSH password, and says what for", dlg.access.labelForField(dlg.username).text() == "SSH user name" and dlg.username.isVisibleTo(dlg.page_access)
      and dlg.ssh_pw.isVisibleTo(dlg.page_access) and "Command Runner" in dlg.ssh_pw.toolTip() and "API key" in dlg.username.placeholderText(), dlg.username.placeholderText())
dlg.vendor.setCurrentIndex(dlg.vendor.findData("paloalto")); app.processEvents()
check("so does Palo Alto, next to its API key", dlg.ssh_pw.isVisibleTo(dlg.page_access) and dlg.secret.isVisibleTo(dlg.page_access) and dlg.access.labelForField(dlg.secret).text() == "API key")
dlg.vendor.setCurrentIndex(dlg.vendor.findData("windows")); app.processEvents()
check("a Windows computer does not", not dlg.ssh_pw.isVisibleTo(dlg.page_access))
dlg.vendor.setCurrentIndex(dlg.vendor.findData("fortinet")); app.processEvents()
dlg.name.setText("fw-new"); dlg.host.setText("10.2.2.2"); dlg.username.setText("admin"); dlg.ssh_pw.setText("Typed-SSH-pw"); dlg.secret.setText("api-token")
check("the user name is part of the device, the password is a secret of its own", dlg.values()["username"] == "admin" and dlg.ssh_secrets() == {"ssh": "Typed-SSH-pw"} and "Typed-SSH-pw" not in json.dumps(dlg.values(), default=str))
check("it counts as an edit, so closing asks first", dlg._snapshot() != dlg._start)
tab = I.InventoryTab()
tab._save(dlg.values(), dlg.secret.text(), extra_secrets={**dlg.snmp_secrets(), **dlg.proxy_secrets(), **dlg.ssh_secrets()})
saved = [d for d in db.list_devices() if d["name"] == "fw-new"][0]
check("saved: the user name on the device, the SSH password and the API key as separate secrets", saved["username"] == "admin" and STORE[("netcheck", "fw-new:ssh")] == "Typed-SSH-pw" and STORE[("netcheck", "fw-new")] == "api-token")
check("and the Command Runner can now use it", C.runnable(saved)[0])
dlg2 = I.DeviceDialog(saved); dlg2.show(); app.processEvents()
check("reopened, the user name is there and the password says it is saved", dlg2.username.text() == "admin" and dlg2.ssh_pw.text() == "" and "saved" in dlg2.ssh_pw.placeholderText() and dlg2.ssh_secrets() == {})
db.move_device_secrets("fw-new", "fw-renamed")
check("renaming the device takes the SSH password with it", STORE.get(("netcheck", "fw-renamed:ssh")) == "Typed-SSH-pw" and ("netcheck", "fw-new:ssh") not in STORE)
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
dlg.reject(); dlg2.reject()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

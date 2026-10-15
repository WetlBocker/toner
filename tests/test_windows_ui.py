# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, socket, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\winui%d.db" % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roamingui%d" % int(time.time()))
from core import agents, db, discovery, sessions, vendors, winmon
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtWidgets import QApplication, QFileDialog, QMenu, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
import ui.inventory as I, ui.settings as S, ui.device_view as DV
from ui.winagent import AgentScriptDialog
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
warned, infos = [], []
QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2]))
QMessageBox.information = staticmethod(lambda *a, **k: infos.append(a[2]))
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

print("== the device dialog")
dlg = I.DeviceDialog()
dlg.vendor.setCurrentIndex(dlg.vendor.findData("windows"))
check("Windows is in the vendor list; its tab appears", dlg.tabs.isTabVisible(4) and dlg.tabs.tabText(4) == "Windows" and dlg.vendor.findData("windows") >= 0)
check("the platform choice becomes 'How to monitor' with the three ways", dlg.form.labelForField(dlg.platform).text() == "How to monitor" and dlg.form.isRowVisible(dlg.platform)
      and [dlg.platform.itemData(i) for i in range(dlg.platform.count())] == ["agent", "winrm", "local"])
check("an agent needs no user name, password or SSL setting; it offers the script", not dlg.access.isRowVisible(dlg.username) and not dlg.access.isRowVisible(dlg.secret) and not dlg.access.isRowVisible(dlg.verify)
      and dlg.win.isRowVisible(dlg.win_script) and not dlg.win.isRowVisible(dlg.win_auth))
check("the script button waits for the device to be saved", not dlg.win_script.isEnabled() and "Save the device first" in dlg.win_script.toolTip())
dlg.platform.setCurrentIndex(dlg.platform.findData("winrm"))
check("WinRM asks for the sign-in, HTTPS, user name, password and certificate checking", dlg.access.isRowVisible(dlg.username) and dlg.access.isRowVisible(dlg.secret) and dlg.access.isRowVisible(dlg.verify)
      and dlg.win.isRowVisible(dlg.win_auth) and dlg.win.isRowVisible(dlg.win_https) and not dlg.win.isRowVisible(dlg.win_script) and "Remote Management Users" in dlg.win_note.text())
check("a proxy or jump host is not offered (they cannot carry WinRM)", not dlg.access.isRowVisible(dlg.jump) and not dlg.access.isRowVisible(dlg.proxy_mode))
dlg.platform.setCurrentIndex(dlg.platform.findData("local"))
check("'This computer' fills in localhost and needs nothing else", dlg.host.text() == "localhost" and not dlg.access.isRowVisible(dlg.username) and not dlg.access.isRowVisible(dlg.secret))
dlg.vendor.setCurrentIndex(dlg.vendor.findData("cisco"))
check("back to another vendor: the Windows tab goes, SSH rows return", not dlg.tabs.isTabVisible(4) and dlg.access.isRowVisible(dlg.username) and dlg.form.labelForField(dlg.platform).text() == "Platform")

dlg = I.DeviceDialog(); dlg.vendor.setCurrentIndex(dlg.vendor.findData("windows")); dlg.platform.setCurrentIndex(dlg.platform.findData("winrm"))
dlg.name.setText("dc01"); dlg.host.setText("dc01.corp.example.com"); dlg.username.setText(r"CORP\monitor"); dlg.win_auth.setCurrentIndex(dlg.win_auth.findData("ntlm"))
dlg.win_https.setChecked(True); dlg.win_watch.setText("DNS, NTDS ; Netlogon"); dlg.win_ignore.setText("BackupAgent, Vendor*")
v = dlg.values()
check("the dialog's values carry the Windows settings", v["vendor"] == "windows" and v["platform"] == "winrm" and v["winopts"] == {"auth": "ntlm", "https": True, "watch": ["DNS", "NTDS", "Netlogon"], "ignore": ["BackupAgent", "Vendor*"]}, v)
check("other vendors save no Windows settings", (lambda x: (x.vendor.setCurrentIndex(x.vendor.findData("cisco")), x.values()["winopts"])[1] == "")(I.DeviceDialog()))
did = db.save_device({**v, "enabled": 1}); saved = db.get_device(did)
check("they are stored and read back", winmon.options(saved) == {"https": True, "auth": "ntlm", "watch": ["DNS", "NTDS", "Netlogon"], "ignore": ["BackupAgent", "Vendor*"]} and saved["platform"] == "winrm")
again = I.DeviceDialog(saved)
check("editing the device shows them", again.win_auth.currentData() == "ntlm" and again.win_https.isChecked() and again.win_watch.text() == "DNS, NTDS, Netlogon" and again.win_ignore.text() == "BackupAgent, Vendor*" and again.platform.currentData() == "winrm")

print("== testing a connection")
loc = I.DeviceDialog(); loc.vendor.setCurrentIndex(loc.vendor.findData("windows")); loc.platform.setCurrentIndex(loc.platform.findData("local")); loc.name.setText("this-pc")
infos.clear(); warned.clear(); loc.test()
check("'Test connection' on this computer really runs the checks", __import__("ui.toast", fromlist=["x"]).history and "Connected to localhost" in __import__("ui.toast", fromlist=["x"]).history[-1] and not warned, (infos, warned))
ag = I.DeviceDialog(); ag.vendor.setCurrentIndex(ag.vendor.findData("windows")); ag.name.setText("laptop-1"); ag.host.setText("laptop-1.corp.example.com")
infos.clear(); warned.clear(); ag.test()
check("testing an agent device with no report yet says how to set it up", warned and "agent script" in warned[0], (infos, warned))

print("== the agent script dialog")
aid = db.save_device({**ag.values(), "enabled": 1}); asaved = db.get_device(aid)
ed = I.DeviceDialog(asaved)
check("for a saved device the script button is ready", ed.win_script.isEnabled() and ed.win_script.toolTip() == "")
db.set_setting("agent_enabled", False); db.set_setting("agent_port", free_port()); db.set_setting("agent_bind", "127.0.0.1"); agents.stop()
sd = AgentScriptDialog("laptop-1", ed)
check("it warns when Toner is not listening", "not listening" in sd.status.text() and not sd.save_btn.isEnabled() and not sd.copy_btn.isEnabled())
sd.host.setText(""); warned.clear(); sd.create()
check("an empty address is refused", warned and not sd.script)
sd.host.setText("toner-host.corp.example.com"); sd.minutes.setValue(10); sd.create()
tok = STORE[("netcheck", "laptop-1:agent")]
check("the script is made for this device with its token, address, interval and pinned fingerprint", sd.script and tok in sd.script and f":{sd.port.value()}/report" in sd.script
      and "toner-host.corp.example.com" in sd.script and "$Minutes = 10" in sd.script and agents.fingerprint() in sd.script and sd.save_btn.isEnabled() and sd.copy_btn.isEnabled())
check("it is shown in the dialog", tok in sd.preview.toPlainText())
out = os.path.join(SP, "saved-agent.ps1"); QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (out, ""))
sd.save(); raw = open(out, "rb").read()
check("saving writes a UTF-8 file with a byte-order mark and Windows line endings", raw.startswith(b"\xef\xbb\xbf") and b"\r\n" in raw and tok.encode() in raw)
sd.copy(); check("copy puts the script on the clipboard", QApplication.clipboard().text() == sd.script)
first = tok; sd.create(); check("making it again keeps the same token", STORE[("netcheck", "laptop-1:agent")] == first)
sd.rotate.setChecked(True); sd.create()
check("asking for a new token replaces it, and the box clears itself", STORE[("netcheck", "laptop-1:agent")] != first and not sd.rotate.isChecked() and agents.device_for_token(first) == "")
db.set_setting("agent_enabled", True); agents.apply(); sd2 = AgentScriptDialog("laptop-1", ed)
check("when Toner is listening the dialog says so", "listening on port" in sd2.status.text()); agents.stop()

print("== Settings > Agents")
st = S.SettingsTab()
titles = [p.title for p in st.pages]
check("the page is in the Settings list, called just Agents", "Agents" in titles and "Windows agents" not in titles)
pg = st.pages[titles.index("Agents")]
port = free_port(); db.set_setting("agent_enabled", False); pg.load()
check("it shows the stored values and the certificate fingerprint", not pg.enabled.isChecked() and pg.print.text() == agents.fingerprint() and "Not listening" in pg.status.text() and str(pg.port.value()))
pg.enabled.setChecked(True); pg.port.setValue(port); pg.bind.setText("127.0.0.1"); pg.address.setText("toner.corp.example.com")
check("a bad listen address is a problem that stops the save", (pg.bind.setText("banana"), pg.validate())[1] and not (pg.bind.setText("127.0.0.1"), pg.validate())[1])
pg.save()
check("saving stores the settings and starts the receiver", db.get_setting("agent_enabled") is True and db.get_setting("agent_port") == port and agents.running() and agents.status()["port"] == port and f"Listening on port {port}" in pg.status.text())
check("the firewall command names the port", f"-LocalPort {port}" in pg.firewall.text() and "Inbound" in pg.firewall.text())
check("new agent scripts use the address given here", agents.address() == "toner.corp.example.com" and "toner.corp.example.com" in agents.script_for("laptop-1"))
agents.token_for("laptop-2")
import ssl, urllib.request
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request(f"https://127.0.0.1:{port}/report", data=json.dumps({"v": 1, "computer": "L2", "at": "2026-01-01T00:00:00Z"}).encode(), method="POST", headers={"Authorization": "Bearer " + agents.token_for("laptop-2")})
urllib.request.urlopen(req, context=ctx, timeout=10).read(); pg.refresh()
from ui.agentfleet import AgentFleet
fl = AgentFleet(); fl.refresh()
rows = {fl.table.item(i, 0).text(): [fl.table.item(i, j).text() for j in range(8)] for i in range(fl.table.rowCount())}
check("the table lists agents with the computer, last report, how long ago, where from, and notes", rows["laptop-2"][5] == "127.0.0.1" and rows["laptop-2"][4] in ("0 min", "1 min") and rows["laptop-1"][4] == "never"
      and rows["laptop-2"][1] == "L2" and "no report yet" in rows["laptop-1"][7], rows)
fl.table.selectRow([i for i in range(fl.table.rowCount()) if fl.table.item(i, 0).text() == "laptop-2"][0])
check("selecting a computer enables Revoke and Remove", fl.revoke.isEnabled() and fl.remove.isEnabled() and fl._selected() == ["laptop-2"])
db.save_device({"name": "laptop-2", "vendor": "windows", "host": "laptop-2", "port": 0, "platform": "agent", "username": "", "site": "d", "verify_ssl": 0, "ha_expected": 0, "enabled": 1})
fl._revoke(); fl.refresh()
rows = {fl.table.item(i, 0).text(): fl.table.item(i, 7).text() for i in range(fl.table.rowCount())}
check("Revoke stops the agent being accepted and says so, and the device stays", "revoked" in rows["laptop-2"] and any(d["name"] == "laptop-2" for d in db.list_devices()) and agents.device_for_token(agents.token_for("laptop-2", rotate=True)) == "laptop-2", rows)
fl.table.selectRow([i for i in range(fl.table.rowCount()) if fl.table.item(i, 0).text() == "laptop-1"][0])
fl._remove()
check("Remove deletes the device, its token and its records", not any(d["name"] == "laptop-1" for d in db.list_devices()) and "laptop-1" not in [x["device"] for x in agents.overview()] and ("netcheck", "laptop-1:agent") not in STORE)
pg.refresh()
check("Settings > Agents has no table any more, and says where the computers are", not hasattr(pg, "table") and "Inventory > Agents" in pg.computers.text())
pg.token_days.setValue(30); pg.save()
check("tokens can be set to be replaced, and it is saved", db.get_setting("agent_token_days") == 30 and (pg.load(), pg.token_days.value())[1] == 30)
pg.token_days.setValue(0); pg.save()
check("the page shows how long the certificate has left, in plain text when it is healthy", "more days" in pg.cert_note.text())
real_left = agents.cert_days_left; agents.cert_days_left = lambda: 12; pg.refresh()
check("and in red with advice when it is close to the end", "expires in 12 days" in pg.cert_note.text() and "d32f2f" in pg.cert_note.styleSheet()); agents.cert_days_left = real_left; pg.refresh()
check("the page is named Agents and says so in its status", pg.title == "Agents")
pkg = os.path.join(SP, "Toner-Agent.zip"); QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (pkg, ""))
pg.enroll.setChecked(True); infos.clear(); pg.minutes.setValue(9); pg._download()
check("a package is not made from settings that are not saved yet", infos and "Save your changes first" in infos[-1] and not os.path.exists(pkg))
pg.save(); infos.clear(); pg._download()
import zipfile
with zipfile.ZipFile(pkg) as zz: cfgz = json.loads(zz.read("toner-agent/agent.json"))
check("saving turns sign-up on, and the download makes a zip from the saved settings", db.get_setting("agent_enroll") is True and cfgz["minutes"] == 9 and cfgz["key"] == agents.enroll_key() and f":{port}/report" in cfgz["server"] and cfgz["pin"] == agents.fingerprint())
check("it tells you what to do with it", infos and "Install-TonerAgent.cmd" in infos[-1] and "private" in infos[-1])
check("the sign-up key is shown hidden, and matches", pg.key.text() == agents.enroll_key() and pg.key.echoMode().name == "Password")
k0 = agents.enroll_key(); pg._newkey()
check("a new key replaces it", agents.enroll_key() != k0 and pg.key.text() == agents.enroll_key())
pg.enroll.setChecked(False); pg.save(); os.remove(pkg); pg.enroll.setChecked(False); infos.clear(); pg._download()
check("with sign-up off the package is still offered but the question is asked (Yes answers it here)", os.path.exists(pkg) and zipfile.is_zipfile(pkg))
pg.enroll.setChecked(True); pg.save()
check("a status line mentions it when sign-up is on but the receiver is off", (pg.enabled.setChecked(False), pg.refresh(), "Sign-up needs the receiver" in pg.status.text())[2]); pg.enabled.setChecked(True)
old = pg.print.text(); pg._renew()
check("a new certificate changes the fingerprint and keeps listening", pg.print.text() != old and agents.running())
pg.enabled.setChecked(False); pg.save()
check("turning it off stops the receiver", not agents.running() and "Not listening" in pg.status.text())
th = S.ThresholdsPage()
check("the Windows limits are in Settings > Thresholds", {"win_events", "patch_days", "cert_days", "agent_silent"} <= set(th.spins))
ck = S.ChecksPage(); ck.load()
check("the Windows checks can be switched on and off in Settings > Checks", ck.tree.topLevelItemCount() >= 1 and any("Windows" == ck.tree.topLevelItem(i).text(0) for i in range(ck.tree.topLevelItemCount())))

print("== the main window")
db.set_setting("agent_enabled", True); db.set_setting("agent_port", free_port()); db.set_setting("agent_bind", "127.0.0.1")
w = A.Main()
check("Toner starts the receiver when it opens with it turned on", agents.running())
w.close()
check("and stops it when it closes", not agents.running())

print("== inventory and the device window")
tab = I.InventoryTab(); tab.refresh()
win = [d for d in db.list_devices() if d["name"] == "dc01"][0]
seen, launched = [], []
class FakeMenu(QMenu):
    def exec(self, *a, **k): seen.append([x.text() for x in self.actions()])
I.QMenu = FakeMenu
sessions.launch_rdp = lambda s: launched.append(s)
def select(name):
    tab.table.clearSelection()
    def walk(it):
        for i in range(it.childCount()):
            c = it.child(i)
            if c.text(0) == name: c.setSelected(True); return True
            if walk(c): return True
        return False
    root = tab.table.invisibleRootItem()
    for i in range(root.childCount()):
        if root.child(i).text(0) == name: root.child(i).setSelected(True); return True
        if walk(root.child(i)): return True
    return False
check("the windows device is in the list", select("dc01"))
tab.show_menu(tab.table.visualItemRect(tab.table.selectedItems()[0]).center())
check("its menu offers Remote Desktop instead of SSH", seen and "Open Remote Desktop" in seen[-1] and "Open SSH session" not in seen[-1], seen)
asked_rdp = []; tab.open_rdp_tab.connect(asked_rdp.append)
tab.open_rdp()
check("it asks for Remote Desktop to that device (the main window opens it in a tab)", asked_rdp and asked_rdp[-1]["name"] == "dc01")
rd = sessions.rdp_for_device(asked_rdp[-1])
check("which is on 3389; a WinRM device passes its user name", rd["host"] == "dc01.corp.example.com" and rd["port"] == 3389 and rd["username"] == r"CORP\monitor", rd)
check("an agent device has no user name to pass", sessions.rdp_for_device(asaved)["username"] == "")
view = DV.DeviceView(win)
check("the device window shows Remote Desktop, not SSH", view.buttons["rdp"].isVisibleTo(view) and not view.buttons["ssh"].isVisibleTo(view))
asked_view = []; view.rdp_requested.connect(asked_view.append)
view.act("rdp")
check("and the button asks for it too", asked_view and asked_view[-1]["name"] == win["name"])
other = DV.DeviceView({**win, "vendor": "cisco", "id": None})
check("a switch still has SSH and no Remote Desktop", other.buttons["ssh"].isVisibleTo(other) and not other.buttons["rdp"].isVisibleTo(other))

print("== discovery")
real = discovery._tcp_open
class S_:
    def close(self): pass
discovery._tcp_open = lambda ip, p, t: S_() if p in (5985, 3389) else None
r = discovery.probe("10.9.9.9", communities=(), ports=(22, 5985, 3389))
check("an address answering WinRM is suggested as a Windows computer, monitored over WinRM", r and r["vendor"] == "windows" and r["platform"] == "winrm", r)
discovery._tcp_open = lambda ip, p, t: S_() if p == 3389 else None
r = discovery.probe("10.9.9.8", communities=(), ports=(22, 5985, 3389))
check("Remote Desktop alone is not enough to call it Windows", r and r["vendor"] != "windows", r)
discovery._tcp_open = real
check("SNMP text naming Windows is recognised", discovery.hint_from_text("Hardware: Intel64 Family 6 - Software: Windows Version 10.0 (Build 20348)") == "windows")
added, skipped = discovery.add_to_inventory([{"ip": "10.9.9.9", "name": "found-win", "vendor": "windows", "platform": "winrm"}])
f = [d for d in db.list_devices() if d["name"] == "found-win"][0]
check("adding a discovered Windows computer makes a WinRM device", added == ["found-win"] and f["vendor"] == "windows" and f["platform"] == "winrm")
check("the default scan ports include WinRM", "5985" in str(db.DEFAULT_SETTINGS["discover_ports"]))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

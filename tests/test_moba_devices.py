# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# A MobaXterm import also adds devices: SSH, Telnet and Remote Desktop entries, with the vendor chosen by organization, folder or
# device (Detect Vendors works out what it can), or none (added anyway, to choose later); devices with no vendor yet; SSH
# sessions with no user name. The samples are made up, and nothing signs in to anything real.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, threading, time, types
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "md%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import backup, cmdrun, db, ifaces, orgs, runner, sessionimport as SI, sessions, vendordetect as VD, vendors
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def write(name, text, encoding="utf-8"):
    path = os.path.join(SP, name)
    with open(path, "w", encoding=encoding, newline="\r\n") as f:
        f.write(text)
    return path
def in_org(org, fn):
    with db.within(org):
        return fn()

MOBA = """[Bookmarks]
SubRep=
ImgNum=42
[Bookmarks_1]
SubRep=My Sessions
ImgNum=41
[Bookmarks_2]
SubRep=My Sessions\\Koch Foods
ImgNum=41
CINCIB-9300X-CORE= #109#0%10.5.1.1%22%netadmin%%-1%-1%%%22%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10#0# #-1
KATECORE-02= #109#0%10.5.1.2%22%%%-1%-1%%%%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10#0# #-1
edge-fw= #109#0%10.5.1.3%2222%admin%%-1%-1%%%%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10#0# #-1
old-router= #98#2%10.5.1.20%23%%%2%%%%%0%0%%1080%#MobaFont%10#0# #-1
kiosk-vnc= #128#5%10.5.1.40%5900%%%-1%%%%%0#MobaFont%10#0# #-1
typo-host= #109#0%cl2nocscr1..noc.example%22%netadmin%%-1%-1%%%%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10#0# #-1
[Bookmarks_3]
SubRep=My Sessions\\Koch Foods\\Plants
ImgNum=41
plant-sw= #109#0%10.5.2.1%22%netadmin%%-1%-1%%%%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10#0# #-1
dc01= #91#4%10.5.2.10%3389%KOCH\\administrator%0%-1%-1%-1%-1%0%0%-1%%%%%0%0%%-1%%-1%-1%0%-1%0%-1#MobaFont%10#0# #-1
[Bookmarks_4]
SubRep=My Sessions\\Jose Andres
ImgNum=41
ja-core= #109#0%10.7.0.1%22%netadmin%%-1%-1%%%%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10#0# #-1
"""
PASSWORDS = ("ssh22:netadmin@10.5.1.1 = Core!pass\r\nssh2222:admin@10.5.1.3 = Fw!pass\r\nrdp:KOCH\\administrator@10.5.2.10 = Rdp!pass\r\n"
             "netadmin@10.5.2.1 = Plant!pass\r\n")

# ================================================================ which entries can be devices
print("== which entries can also be devices")
found = SI.load(write("export.mobaconf", MOBA))
pw = SI.mobaxterm_passwords(PASSWORDS)
items = dict((it["name"], (i, it)) for i, it in SI.device_items(found))
check("SSH, Telnet and Remote Desktop entries can, with a usable address", set(items) == {"CINCIB-9300X-CORE", "KATECORE-02", "edge-fw",
      "old-router", "plant-sw", "dc01", "ja-core"}, sorted(items))
check("VNC stays a session only, and an invalid address is skipped (as it is for the session)", "kiosk-vnc" not in items and "typo-host" not in items)
check("Remote Desktop starts as Windows, the rest with no vendor", SI.first_vendor(items["dc01"][1]) == "windows"
      and SI.first_vendor(items["CINCIB-9300X-CORE"][1]) == "")
check("a device's stored password: by protocol and port, by protocol alone (Remote Desktop), or with none",
      (SI.device_password(items["CINCIB-9300X-CORE"][1], pw), SI.device_password(items["dc01"][1], pw), SI.device_password(items["plant-sw"][1], pw))
      == ("Core!pass", "Rdp!pass", "Plant!pass"))
check("none without a user name", SI.device_password(items["KATECORE-02"][1], pw) == "")

# ================================================================ adding them
print("== adding them to an organization's device list")
koch = orgs.create("Koch Foods", "KOCH")
def entry(name, **kw):
    it = dict(items[name][1])
    it["folder"] = it["folder"][1:]                                       # the top folder is the organization now
    return {**it, **kw}
in_org(koch, lambda: db.save_device(dict(name="already-here", vendor="cisco", host="10.5.1.2", port=0, platform="cisco_ios", username="",
                                          site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None)))
in_org(koch, lambda: db.save_device(dict(name="edge-fw", vendor="cisco", host="10.99.9.9", port=0, platform="cisco_ios", username="",
                                          site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None)))
r = in_org(koch, lambda: SI.add_devices([entry("CINCIB-9300X-CORE", vendor="cisco", platform="cisco_xe"), entry("KATECORE-02"),
                                         entry("edge-fw", vendor="cisco"), entry("old-router", vendor="juniper"),
                                         entry("plant-sw"), entry("dc01", vendor="windows", platform="winrm")], pw))
devs = {d["name"]: d for d in in_org(koch, db._devices_here)}
check("the new ones are added, the one at an address already there is skipped, and those without a vendor are counted",
      (r["added"], r["existing"], r["no_vendor"], r["bad"]) == (5, 1, 1, []), r)
c = devs["CINCIB-9300X-CORE"]
check("a device keeps the entry's name, address, user name and the vendor and platform chosen",
      (c["vendor"], c["platform"], c["host"], c["username"]) == ("cisco", "cisco_xe", "10.5.1.1", "netadmin"), c)
check("its stored password goes to the vault, never the database", in_org(koch, lambda: keyring.get_password(db.SERVICE, db.secret_name("CINCIB-9300X-CORE"))) == "Core!pass"
      and "Core!pass" not in open(db.org_path(koch), "rb").read().decode("latin-1"))
check("a name already taken by another device gets a number", "edge-fw (2)" in devs and devs["edge-fw (2)"]["host"] == "10.5.1.3")
check("an SSH vendor keeps a port other than 22", devs["edge-fw (2)"]["port"] == 2222)
check("Telnet and Remote Desktop use the vendor's own port", devs["old-router"]["port"] == 0 and devs["dc01"]["port"] == 0)
check("Remote Desktop becomes Windows over WinRM, with its user name and password",
      (devs["dc01"]["vendor"], devs["dc01"]["platform"], devs["dc01"]["username"]) == ("windows", "winrm", "KOCH\\administrator")
      and in_org(koch, lambda: keyring.get_password(db.SERVICE, db.secret_name("dc01"))) == "Rdp!pass")
p = devs["plant-sw"]
check("one left without a vendor is added anyway, in its folder", p["vendor"] == "" and p["platform"] == ""
      and in_org(koch, db.folder_paths).get(p["folder_id"]) == "Plants", (p, in_org(koch, db.folder_paths)))
check("its user name may be blank too", "KATECORE-02" not in devs or devs["KATECORE-02"]["username"] == "")
again = in_org(koch, lambda: SI.add_devices([entry("CINCIB-9300X-CORE", vendor="cisco"), entry("plant-sw")], pw))
check("importing again adds nothing", (again["added"], again["existing"]) == (0, 2), again)
check("nothing went to Global", db._devices_here() == [])

# ================================================================ a device with no vendor yet
print("== a device with no vendor yet")
check("it has a profile: a user name and password, no platforms, nothing that signs in", vendors.get("")["username"] is True
      and vendors.get("")["platforms"] == [] and vendors.get("")["kind"] == "" and vendors.get("unknown-thing") == {})
pdev = {**p, "org": koch, "host": "127.0.0.1", "port": 1}
rows = runner.run_one(pdev, db.get_thresholds())
check("a run checks its port, says a vendor is needed in the agreed words, and signs in to nothing",
      [(x.check, x.status) for x in rows] == [("reachability", "OK"), ("vendor", "N/A")]
      and rows[1].message == "No vendor chosen. Edit the device to choose one. Until then only its ping and port checks run.",
      [(x.check, x.status, x.message) for x in rows])
check("backups and the Command Runner leave it out", not backup.supported(pdev) and cmdrun.kind_of(pdev) == "")
try:
    ifaces.listing(pdev); check("it has no list of interfaces", False)
except ValueError:
    check("it has no list of interfaces", True)

# ================================================================ the editor
print("== editing it")
from PySide6.QtWidgets import QApplication, QDialog, QFileDialog, QMessageBox, QInputDialog
app = QApplication([])
import app as A
A.apply_look(app)
from ui import inventory as INV
dlg = INV.DeviceDialog({**p, "org": koch})
check("the editor shows (no vendor) for it", dlg.vendor.currentText() == "(no vendor)" and dlg.vendor.currentData() == "")
check("saving without choosing keeps it so", dlg.values()["vendor"] == "")
dlg.vendor.setCurrentIndex(dlg.vendor.findData("arista"))
check("choosing one sets the vendor and its platform", dlg.values()["vendor"] == "arista" and dlg.values()["platform"] == "arista_eos")
other = INV.DeviceDialog(c)
check("a device with a vendor isn't offered (no vendor)", other.vendor.findText("(no vendor)") == -1)

# ================================================================ SSH sessions without a user name
print("== an SSH session without a user name")
sid = sessions.save({"kind": "ssh", "name": "KATECORE-02", "host": "10.5.1.2", "port": 22, "username": ""})
check("it can be saved", sessions.get(sid)["username"] == "")
from ui import sessions as SUI
asked_user = []
QInputDialog.getText = staticmethod(lambda parent, title, label, *a, **k: (asked_user.append((title, label)), ("", False))[1])
pane = SUI.SessionPane.__new__(SUI.SessionPane)                               # just the connecting step, no window
pane.spec = {"kind": "ssh", "host": "10.5.1.2", "port": 22, "username": "", "name": "KATECORE-02", "options": {}}
pane.connected = lambda: False
pane.connect_now()
check("connecting asks for it, in the agreed words, and cancelling connects nothing",
      asked_user == [("User name", "User name for 10.5.1.2:")] and pane.spec["username"] == "", asked_user)

# ================================================================ Detect Vendors
print("== Detect Vendors")
check("what netmiko's detector answers maps to Toner's vendors and platforms", VD.NETMIKO["cisco_xe"] == ("cisco", "cisco_xe")
      and VD.NETMIKO["hp_procurve"] == ("hpe", "aruba_osswitch") and VD.NETMIKO["paloalto_panos"] == ("paloalto", "") and "linux" not in VD.NETMIKO)
calls = []
real_probe, real_resolve = VD.discovery.probe, VD.nettools.resolve_host
VD.nettools.resolve_host = lambda h: h
VD.discovery.probe = lambda ip, communities=(), ports=(), timeout=1: (calls.append((ip, communities, ports)),
                                                                     {"10.0.0.1": {"vendor": "mikrotik", "platform": "mikrotik_routeros"},
                                                                      "10.0.0.2": {"vendor": "cisco", "platform": "cisco_ios"},
                                                                      "10.0.0.3": {"vendor": "", "platform": ""},
                                                                      "10.0.0.4": {"vendor": "windows", "platform": "winrm"}}.get(ip))[1]
check("without signing in: what the device shows", VD.without_sign_in("10.0.0.1") == ("mikrotik", "mikrotik_routeros"))
check("it looks at the SSH banner, HTTPS and WinRM, and sends no SNMP community", calls[-1] == ("10.0.0.1", (), (22, 443, 5985, 5986)))
check("nothing answering is not a vendor", VD.without_sign_in("10.0.0.9") == ("", ""))
signed = []
VD.signing_in = lambda host, port, user, password, timeout=20: (signed.append((host, port, user)),
                                                                {"10.0.0.2": ("cisco", "cisco_nxos"), "10.0.0.3": ("arista", "arista_eos")}.get(host, ("", "")))[1]
e = lambda host, kind="ssh", user="netadmin", port=22: {"kind": kind, "host": host, "port": port, "username": user}
check("one vendor, one platform: no need to sign in", VD.detect(e("10.0.0.1"), "pw") == ("mikrotik", "mikrotik_routeros") and not signed)
check("Cisco has several platforms: it signs in to tell which", VD.detect(e("10.0.0.2"), "pw") == ("cisco", "cisco_nxos") and signed[-1] == ("10.0.0.2", 22, "netadmin"))
check("unknown from outside: signing in tells", VD.detect(e("10.0.0.3", port=2222), "pw") == ("arista", "arista_eos") and signed[-1][1] == 2222)
n = len(signed)
check("without a password it doesn't try to sign in", VD.detect(e("10.0.0.3"), "") == ("", "") and len(signed) == n)
check("nor without a user name", VD.detect(e("10.0.0.3", user=""), "pw") == ("", "") and len(signed) == n)
check("a Telnet entry signs in on its SSH port", VD.detect(e("10.0.0.3", kind="telnet", port=23), "pw") == ("arista", "arista_eos") and signed[-1][1] == 22)
check("a Remote Desktop entry is told from WinRM, never signed in to", VD.detect(e("10.0.0.4", kind="rdp"), "pw") == ("windows", "winrm") and len(signed) == n + 1)
keep = VD.signing_in
VD.signing_in = lambda *a, **k: ("", "")
check("when signing in fails, what was seen from outside stays", VD.detect(e("10.0.0.2"), "pw") == ("cisco", "cisco_ios"))
VD.signing_in = keep
got = VD.detect_all({1: e("10.0.0.1"), 2: e("10.0.0.3"), 3: e("10.0.0.9")}, {2: "pw"})
check("many at once", got == {1: ("mikrotik", "mikrotik_routeros"), 2: ("arista", "arista_eos"), 3: ("", "")}, got)
stop = threading.Event(); stop.set()
check("Stop starts no more", len(VD.detect_all({i: e("10.0.0.1") for i in range(50)}, {}, cancel=stop, workers=1)) < 50)
import netmiko
class FakeDetect:
    def __init__(self, **kw):
        FakeDetect.kw = kw
        self.connection = types.SimpleNamespace(disconnect=lambda: setattr(FakeDetect, "closed", True))
    def autodetect(self):
        return "hp_procurve"
real_sshdetect = netmiko.SSHDetect
netmiko.SSHDetect = FakeDetect
from importlib import reload
VD2 = reload(VD)
check("signing in uses netmiko's detector with the entry's login and the time-outs, then signs out",
      VD2.signing_in("10.0.0.5", 2222, "admin", "pw", 7) == ("hpe", "aruba_osswitch") and FakeDetect.kw["device_type"] == "autodetect"
      and (FakeDetect.kw["port"], FakeDetect.kw["username"], FakeDetect.kw["timeout"]) == (2222, "admin", 7) and FakeDetect.closed)
class Refused(FakeDetect):
    def __init__(self, **kw):
        raise OSError("refused")
netmiko.SSHDetect = Refused
check("a device that can't be signed in to is not a vendor", VD2.signing_in("10.0.0.5", 22, "admin", "pw") == ("", ""))
netmiko.SSHDetect = real_sshdetect
VD.discovery.probe, VD.nettools.resolve_host = real_probe, real_resolve

# ================================================================ the vendor window
print("== the vendor window")
from ui import vendorassign as VA
rows = [{**items[n][1], "org": org, "folder": folder} for n, org, folder in
        (("CINCIB-9300X-CORE", koch, []), ("KATECORE-02", koch, []), ("plant-sw", koch, ["Plants"]), ("dc01", koch, ["Plants"]),
         ("ja-core", None, []))]
def fake_detect(entries, passwords, on_done=None, cancel=None):
    fake_detect.asked = (sorted(entries), dict(passwords))
    for k in sorted(entries):
        v = {"CINCIB-9300X-CORE": ("cisco", "cisco_xe")}.get(entries[k]["name"], ("", ""))
        on_done(k, *v)
w = VA.VendorAssignDialog(rows, {0: "Core!pass"}, detect=fake_detect)
check("its title and note are the agreed ones", w.windowTitle() == "Choose each device's vendor"
      and "Pick rows (an organization's or folder's row picks everything in it), choose a vendor, and press Apply to selected. Devices left "
          "without a vendor are still added: edit them later to choose one. Remote Desktop sessions start as Windows. Detect Vendors checks "
          "the selected rows (or every row without a vendor): first what each device shows without signing in, then, using its user name "
          "and password, what it says after signing in over SSH." in [l.text() for l in w.findChildren(VA.QLabel)])
check("its columns, controls and buttons are the agreed ones", [w.tree.headerItem().text(i) for i in range(3)] == ["Name", "Host", "Vendor"]
      and {b.text() for b in w.findChildren(VA.QPushButton)} >= {"Apply to selected", "Detect Vendors", "Add devices", "Sessions only", "Cancel"}
      and w.pick.itemText(0) == "(no vendor)" and w.pick.findData("cisco") > 0 and w.pick.findData("wifi") == -1)
tops = [w.tree.topLevelItem(i).text(0) for i in range(w.tree.topLevelItemCount())]
check("rows are grouped by organization, then folder", tops == ["Koch Foods", "Global"]
      and [w.tree.topLevelItem(0).child(i).text(0) for i in range(w.tree.topLevelItem(0).childCount())] == ["(no folder)", "Plants"], tops)
check("Remote Desktop starts as Windows, the rest with no vendor", [v for v, _p in w.vendors()] == ["", "", "", "windows", ""])
plants = w.tree.topLevelItem(0).child(1)
check("a group with mixed vendors says so", plants.text(2) == "(several)")
w.tree.clearSelection(); plants.setSelected(True)
w.pick.setCurrentIndex(w.pick.findData("hpe")); w.apply()
check("a folder's row applies to everything in it", [v for v, _p in w.vendors()][2:4] == ["hpe", "hpe"] and plants.text(2) == "HPE Aruba")
w.tree.clearSelection(); w.tree.topLevelItem(1).setSelected(True)
w.pick.setCurrentIndex(w.pick.findData("juniper")); w.apply()
check("so does an organization's", w.vendors()[4] == ("juniper", "juniper_junos"))
w.tree.clearSelection(); w.tree.topLevelItem(0).child(1).child(0).setSelected(True)
w.pick.setCurrentIndex(0); w.apply()
check("and a single device's, including back to no vendor", w.vendors()[2] == ("", ""))
w.tree.clearSelection()
w.start_detect()
deadline = time.time() + 5
while not w.progress.text().startswith("Detected") and time.time() < deadline:
    app.processEvents(); time.sleep(0.01)
check("Detect Vendors (nothing selected) checks every row without a vendor, with the stored passwords", fake_detect.asked == ([0, 1, 2], {0: "Core!pass", 1: "", 2: ""}),
      fake_detect.asked)
check("what it finds fills the Vendor column; a vendor already there is never replaced", w.vendors() == [("cisco", "cisco_xe"), ("", ""), ("", ""),
      ("hpe", "aruba_aoscx"), ("juniper", "juniper_junos")], w.vendors())
check("it says how it went, in the agreed words", w.progress.text() == "Detected 1 of 3. The rest still have no vendor: choose one, or leave them to edit later.",
      w.progress.text())
check("Add devices is back once it's done", w.add_btn.isEnabled() and w.detect_btn.isEnabled() and w.stop_btn.isHidden())
slow = threading.Event()
def stuck(entries, passwords, on_done=None, cancel=None):
    stuck.cancel = cancel
    slow.wait(5)
w2 = VA.VendorAssignDialog(rows[:2], {}, detect=stuck)
w2.start_detect()
check("while it runs it shows progress and a Stop button, and Add devices waits", w2.progress.text() == "Detecting vendors: 0 of 2..."
      and not w2.stop_btn.isHidden() and not w2.add_btn.isEnabled())
w2.stop_detect()
check("Stop tells the detection to stop", stuck.cancel.is_set())
slow.set()
w3 = VA.VendorAssignDialog(rows[:1], {}, detect=fake_detect)
w3.done(VA.SESSIONS_ONLY)
check("Sessions only and Cancel are told apart from Add devices", w3.result() == VA.SESSIONS_ONLY)

# ================================================================ the whole import, in Global
print("== Inventory > More > Import, in Global")
for s in sessions.list_sessions():
    sessions.delete(s["id"], s.get("org"))
for d in in_org(koch, db._devices_here):                                            # start again: nothing in Koch Foods
    db.delete_device(d["id"], koch)
in_org(koch, lambda: db.save_device(dict(name="already-here", vendor="cisco", host="10.5.1.2", port=0, platform="cisco_ios", username="",
                                          site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None)))
from ui import orgassign as OA
OA.OrgAssignDialog.exec = lambda self: (self.apply_all_new(), True)[1]           # Import All Folders as New Organizations
def pick_vendors(self):
    koch_top = self.tree.topLevelItem(0)
    pick_vendors.shown = (koch_top.text(0), [koch_top.child(i).text(0) for i in range(koch_top.childCount())])
    self.tree.clearSelection()
    koch_top.child(0).setSelected(True)                                            # Koch Foods' own folder: Cisco
    self.pick.setCurrentIndex(self.pick.findData("cisco"))
    self.apply()
    return 1
VA.VendorAssignDialog.exec = pick_vendors
asked, told, picks = [], [], []
QMessageBox.question = staticmethod(lambda *a, **k: (asked.append(a[2]), QMessageBox.StandardButton.Yes)[1])
QMessageBox.information = staticmethod(lambda *a, **k: told.append(a[2]))
QMessageBox.warning = staticmethod(lambda *a, **k: told.append("WARN " + a[2]))
QMessageBox.exec = lambda self: setattr(self, "_clicked", next(b for b in self.buttons() if b.text() == "Choose file..."))
QMessageBox.clickedButton = lambda self: getattr(self, "_clicked", None)
QFileDialog.getOpenFileName = staticmethod(lambda *a, **k: (picks.pop(0), ""))
win = A.Main(); inv = win.inventory
picks[:] = [os.path.join(SP, "export.mobaconf"), write("MobaXterm Stored Passwords.txt", PASSWORDS.replace("\r\n", "\n"), "cp1252")]
inv.import_file()
ja = next(o["id"] for o in orgs.list_orgs() if o["name"] == "Jose Andres")
kd = {d["name"]: d for d in in_org(koch, db._devices_here)}
check("the vendor window shows the organizations made from the folders, with their folders", pick_vendors.shown == ("Koch Foods", ["(no folder)", "Plants"]),
      pick_vendors.shown)
check("the sessions are imported, the SSH one without a user name too", told and told[-1].startswith("Imported 8 sessions into Sessions"), told[-1:])
check("the result says how many devices were added, in the agreed words",
      "\nAdded 6 devices to the device list (1 were already there, 2 without a vendor).\n" in told[-1], told[-1:])
check("the folder given Cisco is Cisco; the one at an address already there is skipped",
      {n: kd[n]["vendor"] for n in ("CINCIB-9300X-CORE", "edge-fw", "old-router")} == {"CINCIB-9300X-CORE": "cisco", "edge-fw": "cisco", "old-router": "cisco"}
      and "KATECORE-02" not in kd and "already-here" in kd, sorted(kd))
check("Remote Desktop is Windows, and one left alone has no vendor, in its folder", kd["dc01"]["vendor"] == "windows" and kd["plant-sw"]["vendor"] == ""
      and in_org(koch, db.folder_paths).get(kd["plant-sw"]["folder_id"]) == "Plants")
check("each organization gets only its own devices", in_org(ja, lambda: [(d["name"], d["vendor"]) for d in db._devices_here()]) == [("ja-core", "")]
      and db._devices_here() == [])
check("the stored passwords come along", in_org(koch, lambda: keyring.get_password(db.SERVICE, db.secret_name("CINCIB-9300X-CORE"))) == "Core!pass")
check("a refused host is still skipped, with its reason", "typo-host: Host must be an IP address or DNS name" in told[-1] and "typo-host" not in kd)
check("the device list shows them straight away", inv.table.topLevelItemCount() > 0)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

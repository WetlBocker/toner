# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Sessions from MobaXterm, PuTTY and SecureCRT, through Inventory > More > Import. The samples are made up.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, types
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\si%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db, sessionimport as SI, sessions
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def write(name, text, encoding="utf-8"):
    path = os.path.join(SP, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding=encoding, newline="\r\n") as f:
        f.write(text)
    return path

# ================================================================ MobaXterm
MOBA = """[Misc]
PasswordsInRegistry=1
[Bookmarks]
SubRep=
ImgNum=42
[Bookmarks_1]
SubRep=My Sessions
ImgNum=41
[Bookmarks_2]
SubRep=My Sessions\\Acero Charter
ImgNum=41
core-sw1.acero.example= #109#0%10.1.1.1%22%netadmin%%-1%-1%%%22%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%0%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1#0# #-1
fw1.acero.example= #109#0%10.1.1.2%2222%admin%%-1%-1%%%%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10#0# #-1
dc01.acero.example= #91#4%10.1.1.10%3389%ACERO\\administrator%0%-1%-1%-1%-1%0%0%-1%%%%%0%0%%-1%%-1%-1%0%-1%0%-1#MobaFont%10#0# #-1
old-router= #98#2%10.1.1.20%23%%%2%%%%%0%0%%1080%#MobaFont%10#0# #-1
portal= #313#13%https://portal.acero.example%-1%-1%-1%-1%-1%-1%-1%0%0%0%-1%-1%-1%-1%-1#MobaFont%10#0# #-1
nouser-switch= #109#0%10.1.1.30%22%%%-1%-1%%%%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10#0# #-1
[Bookmarks_3]
SubRep=My Sessions\\Acero Charter\\Branch__PTVIRG__East
ImgNum=41
br-sw1= #109#0%10.2.1.1%22%netadmin%%-1%-1%%%%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10#0# #-1
[Bookmarks_4]
SubRep=My Sessions\\Beta Labs/West
ImgNum=41
lab-sw= #109#0%192.168.5.1%22%root%%-1%-1%%%%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10#0# #-1
[ImportExportSpecials]
MobaVersion=24.2
"""
PASSWORDS = ("ssh22:netadmin@10.1.1.1 = Core!pass\r\nnetadmin@10.1.1.1 = Core!pass\r\nssh2222:admin@10.1.1.2 = Fw pass = with equals\r\n"
             "admin@10.1.1.2 = Fw pass = with equals\r\nrdp:ACERO\\administrator@10.1.1.10 = Rdp!pass\r\nnetadmin@10.2.1.1 = Branch!pass\r\n")
print("== MobaXterm")
f = SI.load(write("export.mobaconf", MOBA))
by = {i["name"]: i for i in f.items}
check("SSH, Remote Desktop and Telnet sessions are read; the browser one is skipped and counted", dict(f.counts()) == {"ssh": 5, "rdp": 1, "telnet": 1}
      and dict(f.skipped) == {"browser": 1}, (dict(f.counts()), dict(f.skipped)))
check("host, port and user name come from the bookmark", (by["fw1.acero.example"]["host"], by["fw1.acero.example"]["port"], by["fw1.acero.example"]["username"])
      == ("10.1.1.2", 2222, "admin") and by["dc01.acero.example"]["username"] == "ACERO\\administrator" and by["old-router"]["port"] == 23)
check("SubRep 'My Sessions\\Acero Charter' puts the sessions in Acero Charter (the shared root is left out)",
      by["core-sw1.acero.example"]["folder"] == ["Acero Charter"], by["core-sw1.acero.example"]["folder"])
check("deeper folders keep their structure, with MobaXterm's escapes undone", by["br-sw1"]["folder"] == ["Acero Charter", "Branch;East"], by["br-sw1"]["folder"])
check("a / inside a folder name becomes -", by["lab-sw"]["folder"] == ["Beta Labs-West"], by["lab-sw"]["folder"])
check("the folders are counted", len(f.folders()) == 3)
mixed = SI.mobaxterm(MOBA.replace("[Bookmarks]\nSubRep=\nImgNum=42\n", "[Bookmarks]\nSubRep=\nImgNum=42\ntop= #109#0%10.9.9.9%22%u%%\n"))
check("when some sessions are at the top level, nothing is left out of the folder names",
      next(i for i in mixed.items if i["name"] == "br-sw1")["folder"] == ["My Sessions", "Acero Charter", "Branch;East"])
pw = SI.mobaxterm_passwords(PASSWORDS)
check("stored passwords: per port, without a protocol, and with ' = ' inside the password", pw[("ssh", "2222", "admin", "10.1.1.2")] == "Fw pass = with equals"
      and pw[("", "", "netadmin", "10.2.1.1")] == "Branch!pass" and pw[("rdp", "", "acero\\administrator", "10.1.1.10")] == "Rdp!pass")
check("an SSH session finds its password by port, else without a protocol", SI.password_for(by["fw1.acero.example"], pw) == "Fw pass = with equals"
      and SI.password_for(by["br-sw1"], pw) == "Branch!pass" and SI.password_for(by["lab-sw"], pw) == "")
check("Remote Desktop passwords are not used (Windows asks for them)", SI.password_for(by["dc01.acero.example"], pw) == "")

print("== saving")
r = SI.save(f, pw)
saved = {s["name"]: s for s in sessions.list_sessions()}
paths = sessions.folder_paths()
check("the sessions are added in their folders", r["added"] == 7 and paths[saved["core-sw1.acero.example"]["folder_id"]] == "Acero Charter"
      and paths[saved["br-sw1"]["folder_id"]] == "Acero Charter/Branch;East", (r, {n: paths.get(s["folder_id"]) for n, s in saved.items()}))
check("folders are created once", r["folders"] == 3 and len(sessions.list_folders()) == 3, (r, sessions.list_folders()))
check("an SSH session without a user name is added too, with the user name left blank (asked when connecting)", not r["bad"]
      and saved["nouser-switch"]["username"] == "", r["bad"])
check("passwords go to Credential Manager, and the session remembers it", r["passwords"] == 3 and sessions.password(saved["fw1.acero.example"]["id"]) == "Fw pass = with equals"
      and saved["fw1.acero.example"]["options"]["remember"] is True and not saved["lab-sw"]["options"]["remember"], r)
check("no password is kept in the database", "Core!pass" not in open(db.db_path(), "rb").read().decode("latin-1"))
check("Remote Desktop and Telnet keep their kind and port", saved["dc01.acero.example"]["kind"] == "rdp" and saved["dc01.acero.example"]["port"] == 3389
      and saved["old-router"]["kind"] == "telnet")
r2 = SI.save(f, pw)
check("importing the same file again adds nothing", r2["added"] == 0 and r2["existing"] == 7 and r2["folders"] == 0, r2)
clash = SI.Found("MobaXterm", [{"kind": "ssh", "name": "core-sw1.acero.example", "folder": ["Acero Charter"], "host": "10.1.1.99", "port": 22,
                                "username": "netadmin", "options": {}}])
r3 = SI.save(clash)
check("a different session with a name already used in that folder gets a number", r3["added"] == 1
      and any(s["name"] == "core-sw1.acero.example (2)" for s in sessions.list_sessions()), r3)

# ================================================================ PuTTY
REG = r'''Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions]

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\Default%20Settings]
"HostName"=""
"PortNumber"=dword:00000016

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\Core%20Switch%20A]
"HostName"="10.3.1.1"
"PortNumber"=dword:00000016
"Protocol"="ssh"
"UserName"="netops"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\jump]
"HostName"="ops@10.3.1.2"
"PortNumber"=dword:000008ae
"Protocol"="ssh"
"UserName"=""

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\console]
"HostName"=""
"Protocol"="serial"
"SerialLine"="COM4"
"SerialSpeed"=dword:00002580

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\old%20box]
"HostName"="10.3.1.9"
"PortNumber"=dword:00000017
"Protocol"="telnet"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\raw%20port]
"HostName"="10.3.1.10"
"Protocol"="raw"
'''
print("== PuTTY")
p = SI.load(write("putty.reg", REG, encoding="utf-16"))
pb = {i["name"]: i for i in p.items}
check("a .reg export (UTF-16, as regedit writes it) is read; Default Settings is left out", set(pb) == {"Core Switch A", "jump", "console", "old box"}, set(pb))
check("names are decoded and ports read from the dwords", pb["Core Switch A"]["port"] == 22 and pb["Core Switch A"]["username"] == "netops"
      and pb["old box"]["kind"] == "telnet" and pb["old box"]["port"] == 23)
check("user@host in the host name gives the user name", (pb["jump"]["host"], pb["jump"]["username"], pb["jump"]["port"]) == ("10.3.1.2", "ops", 2222), pb["jump"])
check("serial: the COM port and speed", (pb["console"]["kind"], pb["console"]["host"], pb["console"]["options"]["baud"]) == ("serial", "COM4", 9600))
check("raw TCP is skipped and counted; PuTTY has no folders", dict(p.skipped) == {"raw": 1} and not p.folders())

class Key:
    def __init__(self, name): self.name = name
    def __enter__(self): return self
    def __exit__(self, *a): return False
REGTREE = {"Core%20Switch%20A": {"HostName": "10.4.1.1", "PortNumber": 22, "Protocol": "ssh", "UserName": "netops"},
           "Default%20Settings": {"HostName": ""}}
def enum_key(k, i):
    names = list(REGTREE)
    if i >= len(names): raise OSError("no more")
    return names[i]
def enum_value(k, j):
    items = list(REGTREE[k.name].items())
    if j >= len(items): raise OSError("no more")
    return items[j][0], items[j][1], 1
fake = types.SimpleNamespace(HKEY_CURRENT_USER=1, OpenKey=lambda root, sub: Key(sub if root != 1 else "root"), EnumKey=enum_key, EnumValue=enum_value)
real = sys.modules.get("winreg"); sys.modules["winreg"] = fake
here = SI.putty_here()
sys.modules["winreg"] = real
check("the sessions saved on this computer are read from the registry", [(i["name"], i["host"]) for i in here.items] == [("Core Switch A", "10.4.1.1")], here.items)

# ================================================================ SecureCRT
XML = """<?xml version="1.0" encoding="UTF-8"?>
<VanDyke version="3.0">
  <key name="Sessions">
    <key name="Default"><string name="Protocol Name">SSH2</string><string name="Hostname"></string></key>
    <key name="Acero Charter">
      <key name="core-sw1"><string name="Hostname">10.1.1.1</string><string name="Protocol Name">SSH2</string>
        <dword name="[SSH2] Port">22</dword><string name="Username">netadmin</string><string name="Password V2">02:abcdef</string></key>
      <key name="Branch East">
        <key name="br-sw1"><string name="Hostname">10.2.1.1</string><string name="Protocol Name">SSH2</string>
          <dword name="[SSH2] Port">2022</dword><string name="Username">netadmin</string></key>
      </key>
      <key name="old-router"><string name="Hostname">10.1.1.20</string><string name="Protocol Name">Telnet</string><dword name="Port">23</dword></key>
      <key name="dc01"><string name="Hostname">10.1.1.10</string><string name="Protocol Name">RDP</string></key>
    </key>
    <key name="console"><string name="Protocol Name">Serial</string><string name="Com Port">COM3</string><dword name="Baud Rate">115200</dword></key>
  </key>
</VanDyke>
"""
print("== SecureCRT")
c = SI.load(write("crt.xml", XML))
cb = {i["name"]: i for i in c.items}
check("the XML export: folders and sessions, Default left out", set(cb) == {"core-sw1", "br-sw1", "old-router", "console"}, set(cb))
check("folders keep their structure", cb["core-sw1"]["folder"] == ["Acero Charter"] and cb["br-sw1"]["folder"] == ["Acero Charter", "Branch East"]
      and cb["console"]["folder"] == [])
check("ports, user names and serial speed", cb["br-sw1"]["port"] == 2022 and cb["core-sw1"]["username"] == "netadmin" and cb["old-router"]["port"] == 23
      and cb["console"]["options"]["baud"] == 115200)
check("Remote Desktop is skipped and counted; no password is taken from the export", dict(c.skipped) == {"rdp": 1}
      and all("02:" not in str(v) for i in c.items for v in i.values()))
root = os.path.join(SP, "VanDyke", "Config", "Sessions")
write(os.path.join("VanDyke", "Config", "Sessions", "__FolderData__.ini"), 'S:"Folder List"=Acero Charter\n')
write(os.path.join("VanDyke", "Config", "Sessions", "Default.ini"), 'S:"Protocol Name"=SSH2\n')
write(os.path.join("VanDyke", "Config", "Sessions", "Acero Charter", "core-sw1.ini"),
      'S:"Protocol Name"=SSH2\nS:"Hostname"=10.1.1.1\nD:"[SSH2] Port"=00000016\nS:"Username"=netadmin\n')
deep = write(os.path.join("VanDyke", "Config", "Sessions", "Acero Charter", "Branch East", "br-sw1.ini"),
             'S:"Protocol Name"=SSH2\nS:"Hostname"=10.2.1.1\nD:"[SSH2] Port"=000007e6\nS:"Username"=netadmin\n')
d = SI.load(deep)
db_ = {i["name"]: i for i in d.items}
check("an .ini file anywhere in the Sessions folder reads the whole folder, with its structure", set(db_) == {"core-sw1", "br-sw1"}
      and db_["br-sw1"]["folder"] == ["Acero Charter", "Branch East"] and db_["br-sw1"]["port"] == 2022 and db_["core-sw1"]["port"] == 22, d.items)

print("== other files")
try: SI.load(write("notes.txt", "x")); check("anything else is refused", False)
except ValueError: check("anything else is refused", True)
check("which files are session exports", SI.is_session_file("a.mobaconf") and SI.is_session_file("b.REG") and not SI.is_session_file("devices.csv"))

# ================================================================ through Inventory > More > Import
print("== Inventory > More > Import")
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox
app = QApplication([])
from ui import orgassign as _oa
_oa.OrgAssignDialog.exec = lambda self: True     # the import step (asked when an import has folders): keep its starting choices
from ui import vendorassign as _va
_va.VendorAssignDialog.exec = lambda self: _va.SESSIONS_ONLY     # the vendor step: sessions only here (tests/test_moba_devices.py adds devices)
import app as A
A.apply_look(app)
import ui.inventory as INV
for s in sessions.list_sessions(): sessions.delete(s["id"])
for fo in sorted(sessions.list_folders(), key=lambda x: -x["id"]): sessions.delete_folder(fo["id"])
asked, told, picks = [], [], []
QMessageBox.question = staticmethod(lambda *a, **k: (asked.append(a[2]), QMessageBox.StandardButton.Yes)[1])
QMessageBox.information = staticmethod(lambda *a, **k: told.append(a[2]))
QMessageBox.warning = staticmethod(lambda *a, **k: told.append("WARN " + a[2]))
QMessageBox.exec = lambda self: setattr(self, "_clicked", next(b for b in self.buttons() if b.text() == "Choose file..."))
QMessageBox.clickedButton = lambda self: getattr(self, "_clicked", None)
pwfile = write("MobaXterm Stored Passwords.txt", PASSWORDS.replace("\r\n", "\n"), encoding="cp1252")
QFileDialog.getOpenFileName = staticmethod(lambda *a, **k: (picks.pop(0), ""))
w = A.Main(); inv = w.inventory
check("More has Import... and Import PuTTY sessions on this computer...", "Import..." in inv.more_actions and "Import PuTTY sessions on this computer..." in inv.more_actions)
picks[:] = [os.path.join(SP, "export.mobaconf"), pwfile]
inv.import_file()
check("it says what it found, in the agreed words, before importing", asked and asked[-1] == "Found 8 sessions in 3 folders: 5 SSH, 1 Remote Desktop, 1 Telnet. "
      "1 browser sessions are skipped (Toner has no web sessions). They go to Sessions, in the same folders. Import them?", asked[-1:])
check("then the result, with the passwords", told and told[-1].startswith("Imported 7 sessions into Sessions (3 folders created, 0 already there skipped). "
      "Passwords added for 3 SSH sessions.") and "Skipped" not in told[-1], told[-1:])
check("the Sessions list shows them straight away, in their folders", w.sessions.tree.topLevelItemCount() >= 2
      and any(w.sessions.tree.topLevelItem(i).text(0).startswith("Acero Charter") for i in range(w.sessions.tree.topLevelItemCount())),
      [w.sessions.tree.topLevelItem(i).text(0) for i in range(w.sessions.tree.topLevelItemCount())])
check("no devices were added to the inventory", db.list_devices() == [])
picks[:] = [os.path.join(SP, "putty.reg")]; told.clear()
inv.import_file()
check("a PuTTY export says what it skipped and asks no password question", "1 raw TCP sessions are skipped (Toner has no raw TCP sessions)." in asked[-1]
      and told[-1].startswith("Imported 4 sessions into Sessions") and "Passwords" not in told[-1], (asked[-1:], told[-1:]))
sys.modules["winreg"] = fake; told.clear()
inv.import_putty_here()
sys.modules["winreg"] = real
check("Import PuTTY sessions on this computer reads the registry", told and told[-1].startswith("Imported 1 sessions"), told[-1:])
REGTREE.clear(); sys.modules["winreg"] = fake; told.clear()
inv.import_putty_here(); sys.modules["winreg"] = real
check("with none there it says so", told == ["No PuTTY sessions were found on this computer."], told)
picks[:] = [write("bad.mobaconf", "[Bookmarks]\nSubRep=\n")]; told.clear()
inv.import_file()
check("a file with no sessions in it says so instead of asking", told and told[-1].startswith("Found 0 sessions"), told)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

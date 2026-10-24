# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Tools > File transfer > Firmware Transfer (core/firmware.py, ui/firmware.py), against fake servers and fake Cisco devices.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import logging, os, re, socket, sys, time
SP = os.environ["SP"]
os.environ["NETCHECK_DB"] = os.path.join(SP, "fw%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "fwapp%d" % int(time.time()))
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import db, fileserver as F, firmware as FW, orgs, vault
db.init()
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ssh_shell import ShellServer
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def raises(fn):
    try: fn(); return None
    except FW.SourceError as e: return str(e)

# ---------------------------------------------------------------- the image folder every server serves
base = os.path.join(SP, "fwsrc%d" % int(time.time())); images = os.path.join(base, "firmware"); os.makedirs(os.path.join(images, "old"))
IMAGES = {"cat9k_iosxe.17.09.04a.SPA.bin": 3000, "c2960x-universalk9-mz.152-7.E9.bin": 2000, "asa9-18-4-smp-k8.bin": 1500,
          "nxos64-cs.10.3.4a.M.bin": 2500}
for n, size in IMAGES.items():
    open(os.path.join(images, n), "wb").write(os.urandom(size))
open(os.path.join(images, "half.bin" + F.PART), "wb").write(b"x")         # an unfinished upload: never offered
WANT = sorted(IMAGES, key=str.lower)
def names(files): return [f["name"] for f in files]

print("== which devices the wizard works on")
dev = lambda vendor, platform="": {"name": "x", "vendor": vendor, "platform": platform}
check("the four Cisco platforms", all(FW.eligible(dev("cisco", p))[0] for p in FW.PLATFORMS))
check("a Cisco device with no platform set is IOS, as everywhere in Toner", FW.platform_of(dev("cisco")) == "cisco_ios" and FW.eligible(dev("cisco"))[0])
check("another vendor is not, and the reason names it in the agreed words",
      FW.eligible(dev("juniper", "juniper_junos")) == (False, "Not a Cisco device (Juniper). The wizard handles Cisco IOS, IOS XE, NX-OS and ASA."), FW.eligible(dev("juniper")))
check("...also a device with no vendor yet", not FW.eligible(dev(""))[0] and "(no vendor set)" in FW.eligible(dev(""))[1])
check("which copy clients each platform has: IOS and ASA have no SFTP", not FW.can_fetch("cisco_ios", "sftp") and not FW.can_fetch("cisco_asa", "sftp")
      and FW.can_fetch("cisco_xe", "sftp") and FW.can_fetch("cisco_nxos", "sftp") and all(FW.can_fetch(p, x) for p in FW.PLATFORMS for x in ("ftp", "scp", "tftp")))
check("sizes read as people say them", [FW.human_size(n) for n in (512, 24 * 1024, 437 * 1024 ** 2, int(1.1 * 1024 ** 3), None)] == ["512 bytes", "24 KB", "437 MB", "1.1 GB", ""])

print("== the lines under the list")
src = {"own": False, "proto": "ftp", "host": "10.0.0.9", "port": 21, "folder": "/firmware"}
check("files found", FW.summary(src, [{}] * 14) == "14 files in /firmware on 10.0.0.9 (FTP).")
check("one file", FW.summary(src, [{}]) == "1 file in /firmware on 10.0.0.9 (FTP).")
check("none", FW.summary(src, []) == "No files in /firmware. Put the images there and click Test and list files again.")
check("Toner's own server is named as such", FW.summary({**src, "own": True, "proto": "sftp", "host": "10.0.0.5", "folder": "C:\\Firmware"}, [{}] * 2)
      == "2 files in C:\\Firmware on 10.0.0.5 (Toner's SFTP server).")
check("passwords never show: a known secret, and any password in a copy URL",
      FW.mask("copy ftp://toner:Pa55word!@10.0.0.5/x.bin flash:", []) == "copy ftp://toner:****@10.0.0.5/x.bin flash:"
      and FW.mask("login Pa55word! failed", ["Pa55word!"]) == "login **** failed"
      and FW.mask("copy scp://u:p@ss@h/x flash:", ["p@ss"]) == "copy scp://u:****@h/x flash:")
check("...an sftp or scp URL too", FW.mask("copy sftp://admin:s3cr3t@10.1.1.1/a.bin bootflash: vrf management", []) == "copy sftp://admin:****@10.1.1.1/a.bin bootflash: vrf management")
ls = ["total 12", "drwxr-xr-x 2 root root 4096 Jan  3 10:00 old", "-rw-r--r-- 1 root root 1500 Mar  4  2025 asa.bin",
      "-rw-r--r-- 1 ftp ftp 3000 Oct 22 09:15 cat9k file.bin", "lrwxrwxrwx 1 root root 7 Jan  3 10:00 link -> asa.bin"]
p = FW.parse_ls(ls)
check("ls -l / LIST lines: files only, with size, date and a name that has spaces", [(f["name"], f["size"]) for f in p] == [("asa.bin", 1500), ("cat9k file.bin", 3000)]
      and p[0]["modified"].year == 2025 and p[1]["modified"].hour == 9, p)

print("== another server: FTP")
ftp = F.FtpServer(base, "fwuser", "Ftp-pass-123", port=0, bind="127.0.0.1", passive_ports=(50500, 50510)); ftp.start()
fsrc = {"own": False, "proto": "ftp", "host": "127.0.0.1", "port": ftp.port, "user": "fwuser", "password": "Ftp-pass-123", "folder": "/firmware", "anonymous": False}
files = FW.list_files(fsrc)
check("lists the folder: files only (not the sub-folder, not an unfinished upload), by name", names(files) == WANT, names(files))
check("...with sizes and dates", {f["name"]: f["size"] for f in files} == IMAGES and all(f["modified"] for f in files))
check("a wrong password, in the agreed words", raises(lambda: FW.list_files({**fsrc, "password": "nope"})) == "The server refused the user name or password.")
check("a missing folder", raises(lambda: FW.list_files({**fsrc, "folder": "/nowhere"})) == "The folder /nowhere was not found on the server.")
closed = socket.socket(); closed.bind(("127.0.0.1", 0)); dead_port = closed.getsockname()[1]; closed.close()
msg = raises(lambda: FW.list_files({**fsrc, "port": dead_port}, timeout=5))
check("nothing listening", msg is not None and msg.startswith(f"Could not connect to 127.0.0.1 port {dead_port}: ") and msg.endswith("."), msg)
check("the password is in none of those lines", "Ftp-pass-123" not in str([raises(lambda: FW.list_files({**fsrc, "folder": "/nowhere"}))]))

class AnonSession(F._FtpSession):                       # a server that lets anonymous in and has no MLSD (an older server)
    def cmd_pass(self, arg):
        if self.user == "anonymous":
            self.logged_in = True; self.reply("230 Logged in."); return
        super().cmd_pass(arg)
    def cmd_mlsd(self, arg):
        self.reply("502 Command not implemented.")
real_session = F._FtpSession
F._FtpSession = AnonSession
anon = F.FtpServer(base, "fwuser", "Ftp-pass-123", port=0, bind="127.0.0.1", passive_ports=(50520, 50530)); anon.start()
files = FW.list_files({**fsrc, "port": anon.port, "anonymous": True, "user": "", "password": ""})
check("anonymous login, on a server without MLSD (read from LIST instead)", names(files) == WANT and {f["name"]: f["size"] for f in files} == IMAGES, names(files))
anon.stop(); F._FtpSession = real_session

print("== another server: SFTP and SCP")
sftp_dev = ShellServer(user="u", password="sftp-pw", sftp_root=base)
ssrc = {"own": False, "proto": "sftp", "host": "127.0.0.1", "port": sftp_dev.port, "user": "u", "password": "sftp-pw", "folder": "/firmware", "anonymous": False}
files = FW.list_files(ssrc)
check("SFTP lists the folder: files only (another server's files are all shown, whatever their names)",
      names(files) == sorted(WANT + ["half.bin" + F.PART], key=str.lower) and {f["name"]: f["size"] for f in files} == {**IMAGES, "half.bin" + F.PART: 1}, names(files))
from core import nettools
check("...the SSH host key was saved the way Settings > Security says", f"[127.0.0.1]:{sftp_dev.port}" in nettools.known_hosts_path().read_text(encoding="utf-8"))
check("a wrong password", raises(lambda: FW.list_files({**ssrc, "password": "nope"})) == "The server refused the user name or password.")
check("a missing folder", raises(lambda: FW.list_files({**ssrc, "folder": "/nowhere"})) == "The folder /nowhere was not found on the server.")
sftp_srv = F.SftpServer(base, "toner", "Sftp-pass-123", port=0, bind="127.0.0.1", host_key_path=os.path.join(SP, "fwhk")); sftp_srv.start()
files = FW.list_files({**ssrc, "proto": "scp", "port": sftp_srv.port, "user": "toner", "password": "Sftp-pass-123"})
check("an SCP server is listed over SFTP on the same login (Toner's SFTP / SCP server as another server)", names(files) == WANT, names(files))
LS_OUT = ("total 8\n-rw-r--r-- 1 root root 3000 Oct 22 09:15 cat9k_iosxe.17.09.04a.SPA.bin\n"
          "-rw-r--r-- 1 root root 1500 Mar  4  2025 asa9-18-4-smp-k8.bin\ndrwxr-xr-x 2 root root 4096 Jan  3 10:00 old\n").encode()
scp_only = ShellServer(user="u", password="scp-pw", exec_handler=lambda cmd: (LS_OUT, 0) if cmd.startswith("ls -l") else (b"", 127))
files = FW.list_files({**ssrc, "proto": "scp", "port": scp_only.port, "password": "scp-pw"})
check("an SCP server without SFTP is asked for ls -l instead", names(files) == ["asa9-18-4-smp-k8.bin", "cat9k_iosxe.17.09.04a.SPA.bin"] and scp_only.execs == ["ls -l /firmware"], (names(files), scp_only.execs))
missing = ShellServer(user="u", password="scp-pw", exec_handler=lambda cmd: (b"", 2))
check("...and a missing folder there", raises(lambda: FW.list_files({**ssrc, "proto": "scp", "port": missing.port, "password": "scp-pw", "folder": "/nowhere"}))
      == "The folder /nowhere was not found on the server.")

print("== Toner's own servers")
own_ftp = F.FtpServer(images, "toner", "Own-ftp-pass1", port=0, bind="127.0.0.1", passive_ports=(50540, 50550)); own_ftp.start()
own_tftp = F.TftpServer(images, port=0, bind="127.0.0.1"); own_tftp.start()
servers = {"ftp": own_ftp, "sftp": sftp_srv, "tftp": own_tftp}
choices = FW.own_choices(servers)
check("every protocol Toner is serving, the SFTP server twice (as SFTP and as SCP)", [c[1] for c in choices] == ["ftp", "sftp", "scp", "tftp"], [c[0] for c in choices])
check("...each saying its folder and port", choices[0][0] == f"FTP server: folder {own_ftp.root}, port {own_ftp.port}"
      and choices[2][0] == f"SCP (the SFTP / SCP server): folder {sftp_srv.root}, port {sftp_srv.port}" and choices[3][0].startswith("TFTP server: folder "), [c[0] for c in choices])
check("nothing running: no choices", FW.own_choices({"ftp": None, "sftp": None, "tftp": None}) == [] and
      FW.NONE_RUNNING == "None of Toner's file servers is running. Start one on the TFTP, SFTP / SCP or FTP Server page.")
osrc = FW.own_source("ftp", own_ftp, "10.0.0.5")
check("Toner's own source signs in with the server's own login, at the address the devices see", osrc["own"] and osrc["host"] == "10.0.0.5" and osrc["port"] == own_ftp.port
      and osrc["user"] == "toner" and osrc["password"] == "Own-ftp-pass1" and osrc["folder"] == own_ftp.root)
files = FW.list_files(FW.own_source("tftp", own_tftp, "10.0.0.5"))
check("its folder is listed from this computer, without the unfinished upload or the sub-folder (TFTP cannot list)", names(files) == WANT, names(files))
check("this computer's addresses are offered", FW.addresses() and all(a.count(".") == 3 for a in FW.addresses()))

print("== remembering the other server, per organization")
acme, beta = orgs.create("Acme", "ACME"), orgs.create("Beta", "BETA")
with db.within(acme):
    check("nothing remembered at first", FW.saved() is None)
    FW.remember(fsrc)
    s = FW.saved()
    check("remembered for this organization, with its password", s and s["host"] == "127.0.0.1" and s["user"] == "fwuser" and s["folder"] == "/firmware" and s["password"] == "Ftp-pass-123" and s["proto"] == "ftp")
check("the password is in the vault under the organization's name, not in its database", STORE.get(("netcheck", f"org{acme}/firmware-source")) == "Ftp-pass-123"
      and b"Ftp-pass-123" not in open(db.db_path(), "rb").read())
with db.within(beta):
    check("another organization does not see it", FW.saved() is None)
check("Global does not see it either", FW.saved() is None)
check("vault export carries it", f"org{acme}/firmware-source" in vault.known_names())
with db.within(acme):
    FW.remember({**fsrc, "anonymous": True, "password": ""})
    check("an anonymous login keeps no password", FW.saved()["anonymous"] and ("netcheck", f"org{acme}/firmware-source") not in STORE)
    FW.forget()
    check("forgetting clears both", FW.saved() is None and ("netcheck", f"org{acme}/firmware-source") not in STORE)

print("== the page")
from PySide6.QtCore import QCoreApplication, Qt
from PySide6.QtWidgets import QApplication
app = QApplication.instance() or QApplication([])
import app as A
A.apply_look(app)
from ui import firmware as UF
def pump(cond, n=400):
    for _ in range(n):
        QCoreApplication.processEvents(); time.sleep(0.02)
        if cond(): break
    QCoreApplication.processEvents()
def add(name, vendor, platform, org, host="10.0.0.1"):
    with db.within(org):
        db.save_device(dict(name=name, vendor=vendor, host=host, port=0, platform=platform, username="u", site="default", verify_ssl=0, ha_expected=0,
                            enabled=1, location="", details="", folder_id=None))
for n, v, p in (("sw-core", "cisco", "cisco_xe"), ("sw-access", "cisco", ""), ("nx1", "cisco", "cisco_nxos"), ("fw1", "cisco", "cisco_asa"),
                ("jun1", "juniper", "juniper_junos"), ("ar1", "arista", "arista_eos")):
    add(n, v, p, acme)
add("beta-sw", "cisco", "cisco_xe", beta)
live = {"ftp": None, "sftp": None, "tftp": None}
db.set_home(db.GLOBAL)
page = UF.FirmwareTab(servers=lambda: dict(live)); page.resize(1100, 760); page.show()
from ui import tools as T
tools = T.ToolsTab()
names_ = [tools.tabs.tabText(i) for i in range(tools.tabs.count())]
check("Tools > File transfer starts with Firmware Transfer", names_[names_.index("TFTP Server") - 1] == "Firmware Transfer", names_)
tools.shutdown()
check("in Global with organizations: only the line asking for one", page.pick_org.isVisibleTo(page) and page.pick_org.text() == "Pick an organization in the sidebar first."
      and not page.stack.isVisibleTo(page) and not page.next.isVisibleTo(page))
db.set_home(acme); page.refresh()
check("in an organization the steps show, starting at Devices", page.stack.isVisibleTo(page) and not page.pick_org.isVisibleTo(page) and page.step_line.text() == "Step 1 of 6: Devices")
lst = page.devices.list
def rows(): return [lst.item(i) for i in range(lst.count())]
def by_text(start): return next(it for it in rows() if it.text().lstrip().startswith(start))
check("the organization's Cisco devices can be ticked, each with address and platform; another organization's are not here",
      {it.text() for it in rows() if it.flags() & Qt.ItemFlag.ItemIsUserCheckable} == {"sw-core  (10.0.0.1, IOS XE)", "sw-access  (10.0.0.1, IOS)", "nx1  (10.0.0.1, NX-OS)", "fw1  (10.0.0.1, ASA)"},
      [it.text() for it in rows()])
head = next(it for it in rows() if it.data(UF.DevicesStep.GROUP))
check("the others share one row, closed", head.text() == "\u25b8 2 devices are not Cisco (click to show)" and not any(it.text().strip().startswith("jun1") for it in rows()))
lst.itemClicked.emit(head)
check("clicking it shows them, greyed, each with the reason as its tooltip", by_text("jun1").flags() == Qt.ItemFlag.NoItemFlags
      and by_text("jun1").toolTip() == "Not a Cisco device (Juniper). The wizard handles Cisco IOS, IOS XE, NX-OS and ASA." and "Arista" in by_text("ar1").toolTip()
      and next(it for it in rows() if it.data(UF.DevicesStep.GROUP)).text().startswith("\u25be "))
check("Back is off at the first step; Next waits for a tick", not page.back.isEnabled() and not page.next.isEnabled())
page.devices.tick_all.click()
check("Tick all ticks every Cisco device and Next is on", len(page.devices.ticked_keys()) == 4 and page.next.isEnabled())
page.devices.untick_all.click(); check("Untick all", not page.devices.ticked_keys() and not page.next.isEnabled())
by_text("sw-core").setCheckState(Qt.CheckState.Checked); by_text("fw1").setCheckState(Qt.CheckState.Checked)
check("ticking one is enough", page.next.isEnabled() and {d["name"] for d in page.devices.chosen()} == {"sw-core", "fw1"})

print("== the Image server step")
page.next.click()
sv = page.server
check("Step 2 of 6: Image server, Toner's own server chosen first", page.step_line.text() == "Step 2 of 6: Image server" and sv.own_btn.isChecked() and page.back.isEnabled())
check("nothing running: says so in the agreed words, and nothing to test", sv.own_none.isVisibleTo(sv) and sv.own_none.text() == FW.NONE_RUNNING and not sv.test.isEnabled())
check("no NX-OS device ticked: no VRF box", not sv.vrf_row.isVisibleTo(sv))
check("Next waits for a listing", not page.next.isEnabled())
live.update(servers); page.refresh()
check("Toner's servers appear once running", [sv.own.itemData(i) for i in range(sv.own.count())] == ["ftp", "sftp", "scp", "tftp"] and not sv.own_none.isVisibleTo(sv) and sv.test.isEnabled())
sv.address.setEditText("10.0.0.5")
sv.test.click(); check("Listing... while it reads", sv.status.text() == "Listing..." or sv.files)
pump(lambda: not sv.busy() and sv.status.text() != "Listing...")
check("the files are listed with size and date, and the summary line", sv.table.rowCount() == 4 and sorted(sv.table.item(r, 0).text() for r in range(4)) == WANT
      and sv.status.text() == f"4 files in {own_ftp.root} on 10.0.0.5 (Toner's FTP server).", sv.status.text())
check("the step is ready once files are listed", sv.ready())
sv.address.setEditText("10.0.0.6")
check("changing anything about the server clears the list: Next waits for Test again", not sv.ready() and sv.table.rowCount() == 0 and not page.next.isEnabled())

sv.other_btn.click()
check("another server: the form, FTP on port 21, anonymous offered", sv.where.currentIndex() == 1 and sv.proto.currentData() == "ftp" and sv.port.value() == 21 and sv.anonymous.isVisibleTo(sv))
check("Test waits for a host and a user name", not sv.test.isEnabled())
sv.proto.setCurrentIndex(sv.proto.findData("sftp")); check("SFTP: port 22, no anonymous", sv.port.value() == 22 and not sv.anonymous.isVisibleTo(sv))
sv.proto.setCurrentIndex(sv.proto.findData("ftp")); check("back to FTP: port 21", sv.port.value() == 21)
sv.host.setText("127.0.0.1"); sv.port.setValue(ftp.port); sv.user.setText("fwuser"); sv.password.setText("Ftp-pass-123"); sv.folder.setText("/firmware")
check("the password is shown as dots", sv.password.echoMode() == sv.password.EchoMode.Password)
sv.anonymous.setChecked(True); check("anonymous: no user name or password to type", not sv.user.isEnabled() and not sv.password.isEnabled()); sv.anonymous.setChecked(False)
sv.test.click(); pump(lambda: not sv.busy() and sv.status.text() != "Listing...")
check("listed from another FTP server", sv.status.text() == f"4 files in /firmware on 127.0.0.1 (FTP)." and sv.ready(), sv.status.text())
with db.within(acme):
    check("...and remembered for this organization (Remember is ticked by default)", sv.remember.isChecked() and FW.saved()["host"] == "127.0.0.1" and FW.saved()["password"] == "Ftp-pass-123")
sv.password.setText("wrong"); sv.test.click(); pump(lambda: not sv.busy() and sv.status.text() != "Listing...")
check("a wrong password is said plainly and Next stays off", sv.status.text() == "The server refused the user name or password." and not page.next.isEnabled())
check("the password is on screen nowhere but its own box", "Ftp-pass-123" not in sv.status.text() and "wrong" not in sv.status.text())
sv.password.setText("Ftp-pass-123"); sv.remember.setChecked(False); sv.test.click(); pump(lambda: not sv.busy() and sv.status.text() != "Listing...")
with db.within(acme):
    check("listing with Remember unticked forgets what was remembered", sv.ready() and FW.saved() is None and ("netcheck", f"org{acme}/firmware-source") not in STORE)
sv.remember.setChecked(True); sv.test.click(); pump(lambda: not sv.busy() and sv.status.text() != "Listing...")

print("== NX-OS, starting over, and another organization")
page.back.click(); check("Back goes to Devices with the ticks kept", page.step_line.text() == "Step 1 of 6: Devices" and set(page.devices.ticked_keys()) == {"sw-core", "fw1"})
by_text("nx1").setCheckState(Qt.CheckState.Checked); page.next.click()
check("an NX-OS device ticked: the VRF box shows, management by default", sv.vrf_row.isVisibleTo(sv) and sv.vrf.text() == "management")
page2 = UF.FirmwareTab(servers=lambda: dict(live)); page2.show(); page2.devices.tick_all.click(); page2.next.click()
check("a new page in the same organization starts from the remembered server", page2.server.other_btn.isChecked() and page2.server.host.text() == "127.0.0.1"
      and page2.server.password.text() == "Ftp-pass-123" and page2.server.folder.text() == "/firmware")
page.restart.click()
check("Start over: back to Devices, nothing ticked", page.step_line.text() == "Step 1 of 6: Devices" and not page.devices.ticked_keys())
by_text("sw-core").setCheckState(Qt.CheckState.Checked); page.next.click()
db.set_home(beta); page.refresh()
check("switching organization starts over with that organization's devices", page.step_line.text() == "Step 1 of 6: Devices"
      and [it.text() for it in rows()] == ["beta-sw  (10.0.0.1, IOS XE)"] and not page.devices.ticked_keys())
by_text("beta-sw").setCheckState(Qt.CheckState.Checked); page.next.click()
check("...and none of the other organization's server or login stays on screen", page.server.own_btn.isChecked() and page.server.host.text() == ""
      and page.server.user.text() == "" and page.server.password.text() == "" and page.server.folder.text() == "" and page.server.table.rowCount() == 0)
page.shutdown(); page2.shutdown()

# ================================================================ step 3: Check devices, against fake Cisco devices
from _cisco_fake import CiscoFake
print("== reading what the devices print")
check("show version: version, the image it booted, the mode", FW.parse_version("cisco_xe", 'Cisco IOS XE Software, Version 17.06.05\nSystem image file is "flash:packages.conf"\nInstallation mode is INSTALL\n')
      == {"version": "17.06.05", "image": "packages.conf", "mode": "INSTALL"}
      and FW.parse_version("cisco_nxos", " NXOS: version 10.2(5)\n  NXOS image file is: bootflash:///nxos64-cs.10.2.5.M.bin\n")["image"] == "nxos64-cs.10.2.5.M.bin"
      and FW.parse_version("cisco_asa", 'Cisco Adaptive Security Appliance Software Version 9.16(4)\nSystem image file is "disk0:/asa9-16-4-smp-k8.bin"\n')
      == {"version": "9.16(4)", "image": "asa9-16-4-smp-k8.bin", "mode": ""})
real_ios = ("Directory of flash:/\n\n    2  -rwx        1048   Mar 1 1993 00:02:43 +00:00  config.text\n"
            "    3  drwx         512   Mar 1 1993 00:02:43 +00:00  c2960x-universalk9-mz.152-7.E9\n"
            "  442  -rwx    26789376  Jun 12 2023 10:04:15 +00:00  c2960x-universalk9-mz.152-7.E9.bin\n\n122185728 bytes total (88324608 bytes free)\n")
check("dir on IOS: files with sizes, folders left out, total and free", FW.parse_dir(real_ios) ==
      {"files": {"config.text": 1048, "c2960x-universalk9-mz.152-7.E9.bin": 26789376}, "total": 122185728, "free": 88324608})
nx_dir = "  1979260416    Oct 22 10:00:00 2026  nxos64-cs.10.3.4a.M.bin\n        4096    Oct 22 10:00:00 2026  .rpmstore/\n\nUsage for bootflash://sup-local\n 2539487232 bytes used\n 50766032896 bytes free\n 53305520128 bytes total\n"
check("dir bootflash: on NX-OS (its totals are on separate lines)", FW.parse_dir(nx_dir) == {"files": {"nxos64-cs.10.3.4a.M.bin": 1979260416}, "total": 53305520128, "free": 50766032896})
check("no totals: unreadable", FW.parse_dir("% Invalid input detected at '^' marker.") is None)
check("boot statements per platform", FW.parse_boot("cisco_xe", "BOOT variable = flash:packages.conf;\nBoot Variables on next reload:\nBOOT variable = flash:x.bin;") == ["packages.conf"]
      and FW.parse_boot("cisco_ios", "BOOT path-list      : flash:/a.bin;flash:/b.bin\n") == ["a.bin", "b.bin"]
      and FW.parse_boot("cisco_nxos", "NXOS variable = bootflash:/nxos.10.bin\n") == ["nxos.10.bin"]
      and FW.parse_boot("cisco_asa", "boot system disk0:/asa9-16.bin\nboot system disk0:/asa9-12.bin\n") == ["asa9-16.bin", "asa9-12.bin"])
check("ping, IOS and NX-OS forms", FW.ping_ok("Success rate is 100 percent (5/5)") and not FW.ping_ok("Success rate is 0 percent (0/5)")
      and FW.ping_ok("5 packets transmitted, 4 packets received") and not FW.ping_ok("5 packets transmitted, 0 packets received, 100.00% packet loss"))
check("stack members' flash: flash-2: on IOS XE, flash2: on classic IOS", FW.member_fs("cisco_xe", 2) == "flash-2:" and FW.member_fs("cisco_ios", 3) == "flash3:"
      and FW.member_fs("cisco_xe", 1) == "flash:" and FW.member_fs("cisco_nxos", 1) == "bootflash:")
check("all selected devices at once, up to 8 for checking and 4 for copying", FW.CHECK_WORKERS == 8 and FW.TRANSFER_WORKERS == 4)

print("== collecting from the devices")
lab = orgs.create("Lab", "LAB")
src = FW.own_source("ftp", own_ftp, "127.0.0.1")
OK_REACH = {"127.0.0.1": {"ping": True, "ports": {own_ftp.port}}}
G = 1024 ** 3
fakes = {
    "ios1": CiscoFake("cisco_ios", "ios1", files={"c2960x-universalk9-mz.152-7.E9.bin": (26000000, "a" * 32), "c2960x-old.bin": (25000000, "b" * 32), "config.text": (4000, "")},
                      image="c2960x-universalk9-mz.152-7.E9.bin", reach=OK_REACH, fs_total=122185728),
    "stack1": CiscoFake("cisco_xe", "stack1", mode="INSTALL", members=3, files={"packages.conf": (8000, ""), "cat9k-rpbase.17.06.05.SPA.pkg": (500000000, "")},
                        reach=OK_REACH, fs_total=11 * G),
    "bundle1": CiscoFake("cisco_xe", "bundle1", mode="BUNDLE", files={"cat9k_iosxe.17.06.05.SPA.bin": (900000000, ""), "cat9k_iosxe.17.03.04.SPA.bin": (880000000, "")},
                         image="cat9k_iosxe.17.06.05.SPA.bin", reach=OK_REACH),
    "nx1": CiscoFake("cisco_nxos", "nx1", files={"nxos64-cs.10.2.5.M.bin": (1900000000, ""), "nxos.9.3.8.bin": (1600000000, "")}, image="nxos64-cs.10.2.5.M.bin",
                     reach=OK_REACH, vrf="management"),
    "asa1": CiscoFake("cisco_asa", "asa1", files={"asa9-16-4-smp-k8.bin": (118000000, ""), "asa9-12-4-smp-k8.bin": (110000000, ""), "asdm-7181.bin": (90000000, "")},
                      image="asa9-16-4-smp-k8.bin", boot=["disk0:/asa9-16-4-smp-k8.bin"], reach=OK_REACH),
    "noping": CiscoFake("cisco_ios", "noping", files={"a.bin": (1000, "")}, image="a.bin", reach={}),
    "closed": CiscoFake("cisco_xe", "closed", mode="BUNDLE", files={"a.bin": (1000, "")}, image="a.bin", reach={"127.0.0.1": {"ping": True, "ports": set()}}),
    "provisioned": CiscoFake("cisco_xe", "provisioned", mode="INSTALL", members=3, member_states={3: "Provisioned"}, files={"packages.conf": (8000, "")}, reach=OK_REACH),
}
PW = "Dev-pass-77"
for name, f in fakes.items():
    f.password = PW
    add(name, "cisco", f.platform, lab, host="127.0.0.1")
    with db.within(lab):
        d = next(x for x in db.list_devices() if x["name"] == name); db.save_device({**d, "port": f.port, "username": "admin"})
        db.set_secret(db.secret_name(name), PW)
add("nologin", "cisco", "cisco_ios", lab, host="127.0.0.1")
with db.within(lab):
    d = next(x for x in db.list_devices() if x["name"] == "nologin"); db.save_device({**d, "username": ""})
    labdevs = {d["name"]: d for d in db.list_devices()}
seen = []
t0 = time.time()
with db.within(lab):
    results = FW.collect_many([labdevs[n] for n in list(fakes) + ["nologin"]], src, on_result=seen.append)
took = time.time() - t0
R = {r["name"]: r for r in results}
check("every device answered, in the order given, each reported as it finished", [r["name"] for r in results] == list(fakes) + ["nologin"] and len(seen) == len(results), [r["name"] for r in results])
check("they were read in parallel (8 devices in about the time of a few)", took < 25, took)
r = R["ios1"]
check("IOS: version, the image it runs, no mode, free space, the boot file", r["version"] == "15.2(7)E9" and r["image"] == "c2960x-universalk9-mz.152-7.E9.bin" and r["mode"] == ""
      and len(r["flashes"]) == 1 and r["flashes"][0]["fs"] == "flash:" and r["flashes"][0]["total"] == 122185728 and r["flashes"][0]["free"] == 122185728 - 51004000
      and r["boot"] == ["c2960x-universalk9-mz.152-7.E9.bin"] and set(r["flashes"][0]["files"]) == {"c2960x-universalk9-mz.152-7.E9.bin", "c2960x-old.bin", "config.text"}, r)
check("...it reaches the server: ping and the FTP port, through its own telnet", r["ping"] is True and r["port"] is True and not r["held"] and r["note"] == "", r)
check("...and telnet was left cleanly (Ctrl-^ x, disconnect, confirmed)", any(l.startswith("telnet 127.0.0.1 ") for l in fakes["ios1"].commands) and "disconnect" in fakes["ios1"].commands, fakes["ios1"].commands)
r = R["stack1"]
check("IOS XE stack in INSTALL mode: every member under the primary, each with its own flash", r["mode"] == "INSTALL" and [(f["member"], f["role"], f["fs"]) for f in r["flashes"]]
      == [(1, "Active", "flash:"), (2, "Standby", "flash-2:"), (3, "Member", "flash-3:")] and all(f["free"] == 11 * G - 500008000 for f in r["flashes"]) and not r["held"], r["flashes"])
check("IOS XE BUNDLE: the mode and the bundle it boots", R["bundle1"]["mode"] == "BUNDLE" and R["bundle1"]["boot"] == ["cat9k_iosxe.17.06.05.SPA.bin"] and not R["bundle1"]["held"])
r = R["nx1"]
check("NX-OS: bootflash:, pinged through the management VRF (it reaches the server only there)", r["flashes"][0]["fs"] == "bootflash:" and r["ping"] is True and not r["held"]
      and "ping 127.0.0.1 vrf management" in fakes["nx1"].commands, fakes["nx1"].commands)
check("...no telnet client: the port is not checked, and it says so", r["port"] is None and r["note"] == f"Port {own_ftp.port} not checked (ping only)" and not any(l.startswith("telnet") for l in fakes["nx1"].commands))
r = R["asa1"]
check("ASA: disk0:, its boot system lines, ping only", r["flashes"][0]["fs"] == "disk0:" and r["boot"] == ["asa9-16-4-smp-k8.bin"] and r["note"].endswith("not checked (ping only)") and not r["held"])
check("a device that cannot ping the server is held back, saying so", R["noping"]["held"] == "Cannot reach 127.0.0.1 from the device (ping failed).")
check("one that pings it but finds the port closed", R["closed"]["held"] == f"Reaches 127.0.0.1, but port {own_ftp.port} is closed.", R["closed"]["held"])
check("a stack with a member that is not Ready", R["provisioned"]["held"] == "Stack member 3 is not Ready (Provisioned).")
check("a device with no login, without trying to sign in", R["nologin"]["held"] == "No user name or password: set one on the device or its profile.")
CHANGES = re.compile(r"^(copy|delete|install|boot|no |write|reload)", re.I)
def config_lines(cmds):
    """What was typed in configuration mode."""
    out, inside = [], False
    for l in cmds:
        if l.lower() in ("configure terminal", "conf t"): inside = True; continue
        if inside and l.lower() == "end": inside = False; continue
        if inside and l.strip(): out.append(l)            # (netmiko also presses Enter on its own)
    return out
check("nothing was changed on any device: only commands that read", not [l for f in fakes.values() for l in f.commands if CHANGES.match(l)],
      [l for f in fakes.values() for l in f.commands if CHANGES.match(l)])
check("...the only thing typed in configuration mode is netmiko's ASA sign-in setting the terminal width",
      all(config_lines(f.commands) == (["terminal width 511"] * f.commands.count("configure terminal") if f.platform == "cisco_asa" else []) for f in fakes.values()),
      {n: config_lines(f.commands) for n, f in fakes.items()})
with db.within(lab):
    sftp_src = FW.own_source("sftp", sftp_srv, "127.0.0.1")
    r = FW.collect(labdevs["asa1"], sftp_src)
    check("an ASA with an SFTP source is held back without signing in: it has no SFTP client", r["held"] == "ASA has no SFTP client: use FTP, SCP or TFTP.")
    check("...and IOS too", FW.collect(labdevs["ios1"], sftp_src)["held"] == "IOS has no SFTP client: use FTP, SCP or TFTP.")
    db.set_secret(db.secret_name("bundle1"), "wrong-password")
    r = FW.collect(labdevs["bundle1"], src)
    check("a wrong password: 'Could not sign in' with netmiko's reason", r["held"].startswith("Could not sign in: ") and "wrong-password" not in r["held"], r["held"])
    db.set_secret(db.secret_name("bundle1"), PW)
log = FW.log_path(labdevs["ios1"]).read_text(encoding="utf-8")
check("the session is written to firmware-<device>.log in the SSH logs folder", FW.log_path(labdevs["ios1"]).name == "firmware-ios1.log" and "show version" in log and "telnet 127.0.0.1" in log)
check("...without the device's password or the server's", PW not in log and "Own-ftp-pass1" not in log)

print("== the Check devices step")
db.set_home(lab)
page = UF.FirmwareTab(servers=lambda: dict(live)); page.resize(1200, 800); page.show()
def tick(*names):
    for i in range(page.devices.list.count()):
        it = page.devices.list.item(i)
        if it.flags() & Qt.ItemFlag.ItemIsUserCheckable:
            it.setCheckState(Qt.CheckState.Checked if it.data(Qt.ItemDataRole.UserRole) in names else Qt.CheckState.Unchecked)
tick("ios1", "stack1", "nx1", "asa1", "noping", "provisioned")
page.next.click()
sv = page.server; sv.own_btn.click(); sv.own.setCurrentIndex(sv.own.findData("ftp")); sv.address.setEditText("127.0.0.1")
sv.test.click(); pump(lambda: sv.ready())
check("Next leads on from the Image server step once files are listed", page.next.isEnabled())
page.next.click()
ck = page.check
check("Step 3 of 6: Check devices, with the agreed words", page.step_line.text() == "Step 3 of 6: Check devices"
      and "Toner signs in to each device and reads its software version, mode, free space and whether it can reach the server. Nothing is changed." in ck.intro.text())
check("it starts collecting at once; Back, Next and Start over wait", ck.running() and not page.next.isEnabled() and not page.back.isEnabled() and not page.restart.isEnabled()
      and ck.progress.text().startswith("Collecting from ") and ck.progress.text().endswith(" of 6 devices..."), ck.progress.text())
pump(lambda: not ck.running(), 1500)
tree = ck.tree
top = {tree.topLevelItem(i).text(0): tree.topLevelItem(i) for i in range(tree.topLevelItemCount())}
check("one row per device, in the order of the Devices list", list(top) == ["asa1", "ios1", "noping", "nx1", "provisioned", "stack1"], list(top))
check("the columns", [tree.headerItem().text(i) for i in range(tree.columnCount())] == ["Device", "Platform", "Version", "Mode", "Free space", "Reaches server", "Status"])
check("the summary line", ck.progress.text() == "6 devices: 4 ready, 2 held back.", ck.progress.text())
it = top["stack1"]
check("a stack shows its members under the primary, each with its free space", it.childCount() == 2 and it.child(0).text(0) == "Switch 2 (Standby)"
      and it.child(1).text(0) == "Switch 3 (Member)" and it.child(0).text(4) == FW.human_size(11 * G - 500008000) and it.isExpanded())
check("mode INSTALL; a ready device says Ready", it.text(3) == "INSTALL" and it.text(6) == "Ready" and it.text(5) == "Yes")
check("the mode is a dash where it does not apply", top["ios1"].text(3) == "–" and top["nx1"].text(1) == "NX-OS" and top["ios1"].text(2) == "15.2(7)E9")
check("NX-OS and ASA: ready, with the port note as the status", top["nx1"].text(6) == f"Port {own_ftp.port} not checked (ping only)" and top["asa1"].text(5) == "Yes")
check("held back: greyed, the reason as status and tooltip", top["noping"].text(6) == "Cannot reach 127.0.0.1 from the device (ping failed)." and top["noping"].text(5) == "No"
      and top["noping"].toolTip(6) == top["noping"].text(6) and top["noping"].foreground(0).color() != top["ios1"].foreground(0).color())
check("only ready devices go on", [r["name"] for r in ck.ready_results()] == ["asa1", "ios1", "nx1", "stack1"], [r["name"] for r in ck.ready_results()])
check("the step is ready, and Back and Start over are on again", ck.ready() and page.back.isEnabled() and page.restart.isEnabled())
fakes["noping"].reach = OK_REACH
ck.again.click(); check("Collect again runs it again", ck.running()); pump(lambda: not ck.running(), 1500)
check("...and a fixed device comes back ready", ck.progress.text() == "6 devices: 5 ready, 1 held back." and "noping" in [r["name"] for r in ck.ready_results()], ck.progress.text())
tick(); page.back.click(); page.back.click()
page.devices.untick_all.click(); tick("noping", "provisioned")
fakes["noping"].reach = {}
page.next.click(); pump(lambda: sv.ready()); page.next.click(); pump(lambda: not ck.running(), 1500)
check("when every device is held back, the step is not ready and Next stays off", ck.progress.text() == "2 devices: 0 ready, 2 held back." and not ck.ready()
      and not page.next.isEnabled(), ck.progress.text())
page.shutdown()
for f in fakes.values(): f.stop()
for s in (ftp, sftp_srv, own_ftp, own_tftp): s.stop()
for s in (sftp_dev, scp_only, missing): s.stop()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

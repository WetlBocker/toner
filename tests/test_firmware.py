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
import paramiko as _pm
_real_open_sftp = _pm.SSHClient.open_sftp
_pm.SSHClient.open_sftp = lambda self: (_ for _ in ()).throw(_pm.SSHException("EOF during negotiation"))   # what Wing FTP does for an FTP-only account
check("a login that works but gets no SFTP channel says so, not 'could not connect'",
      raises(lambda: FW.list_files(ssrc)) == "Signed in to 127.0.0.1, but the server did not start SFTP for this account. Check that the "
      "account is allowed to use SFTP (not only FTP) and has a home folder.")
_pm.SSHClient.open_sftp = _real_open_sftp
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
real_asa = ("\nDirectory of disk0:/\n\n89     -rwx  32738244     18:30:26 May 11 2020  asdm-792-152.bin\n4      drwx  4096         17:29:48 Nov 01 2018  log\n"
            "94     -rwx  107698176    19:56:14 Sep 26 2024  asa9-12-4-67-smp-k8.bin\n\n5 file(s) total size: 432483693 bytes\n"
            "8238170112 bytes total (7804764160 bytes free/94% free)\n")
check("dir disk0: on an ASA 5515 (its free line adds a percentage)", FW.parse_dir(real_asa) ==
      {"files": {"asdm-792-152.bin": 32738244, "asa9-12-4-67-smp-k8.bin": 107698176}, "total": 8238170112, "free": 7804764160})
check("boot statements per platform; on IOS XE the current and the next reload's both count", FW.parse_boot("cisco_xe", "BOOT variable = flash:packages.conf;\nBoot Variables on next reload:\nBOOT variable = flash:x.bin;") == ["packages.conf", "x.bin"]
      and FW.parse_boot("cisco_xe", "BOOT variable = flash:a.bin;\nBOOT variable = flash:a.bin;") == ["a.bin"]
      and FW.parse_boot("cisco_ios", "BOOT path-list      : flash:/a.bin;flash:/b.bin\n") == ["a.bin", "b.bin"]
      and FW.parse_boot("cisco_nxos", "NXOS variable = bootflash:/nxos.10.bin\n") == ["nxos.10.bin"]
      and FW.parse_boot("cisco_asa", "boot system disk0:/asa9-16.bin\nboot system disk0:/asa9-12.bin\n") == ["asa9-16.bin", "asa9-12.bin"])
check("ping, IOS and NX-OS forms", FW.ping_ok("Success rate is 100 percent (5/5)") and not FW.ping_ok("Success rate is 0 percent (0/5)")
      and FW.ping_ok("5 packets transmitted, 4 packets received") and not FW.ping_ok("5 packets transmitted, 0 packets received, 100.00% packet loss"))
check("stack members' flash: flash-2: on IOS XE, flash2: on classic IOS", FW.member_fs("cisco_xe", 2) == "flash-2:" and FW.member_fs("cisco_ios", 3) == "flash3:"
      and FW.member_fs("cisco_xe", 1) == "flash:" and FW.member_fs("cisco_nxos", 1) == "bootflash:")
check("all selected devices at once, up to 8 for checking and 4 for copying", FW.CHECK_WORKERS == 8 and FW.TRANSFER_WORKERS == 4)

print("== the fake device's own fetch (what a device's copy does)")
import _cisco_fake, paramiko
want = open(os.path.join(images, "asa9-18-4-smp-k8.bin"), "rb").read()
check("over SFTP and over SCP from Toner's SFTP / SCP server", _cisco_fake.fetch(f"sftp://toner:Sftp-pass-123@127.0.0.1:{sftp_srv.port}/firmware/asa9-18-4-smp-k8.bin") == want
      and _cisco_fake.fetch(f"scp://toner:Sftp-pass-123@127.0.0.1:{sftp_srv.port}/firmware/asa9-18-4-smp-k8.bin") == want)
def refused_host(h):
    try: _cisco_fake.LoopbackOnly().missing_host_key(None, h, None); return False
    except paramiko.SSHException: return True
check("it accepts host keys only from this computer's test servers", not refused_host(f"[127.0.0.1]:{sftp_srv.port}") and not refused_host("[::1]:22")
      and refused_host("10.0.0.5") and refused_host("[10.0.0.5]:22") and refused_host("evil.example"))

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

print("== an ASA whose login lands in user mode")
asa_en = CiscoFake("cisco_asa", "asa-en", enable_secret="En-pw-9", files={"asa9-16-4-smp-k8.bin": (118000000, "")}, image="asa9-16-4-smp-k8.bin", reach=OK_REACH)
asa_en.password = PW
add("asa-en", "cisco", "cisco_asa", lab, host="127.0.0.1")
with db.within(lab):
    d = next(x for x in db.list_devices() if x["name"] == "asa-en"); db.save_device({**d, "port": asa_en.port, "username": "admin"})
    db.set_secret(db.secret_name("asa-en"), PW)
    dev_en = next(x for x in db.list_devices() if x["name"] == "asa-en")
    r = FW.collect(dev_en, src)
check("without an enable password Toner is held in user mode, and says what to add", r["held"] == FW.NO_ENABLE, r["held"])
check("...it tried enable with the login password and was refused", "enable" in asa_en.commands and PW in asa_en.commands)
with db.within(lab):
    db.set_secret(db.secret_name("asa-en", "enable"), "En-pw-9")
    r = FW.collect(dev_en, src)
check("with the enable password on the device, the check reads the ASA's flash", not r["held"] and r["flashes"][0]["fs"] == "disk0:"
      and r["flashes"][0]["free"] is not None and r["version"] == "9.16(4)", r)
check("...the enable password was typed to the device, not the login password a second time", asa_en.commands.count("En-pw-9") >= 1)
HINT = " The device could not connect to 10.0.0.10 port 2121; Toner could, from this computer. Check the server's firewall from the device's side and, for FTP, its passive-mode settings."
asa_words = "%Error opening ftp://WetlesenFTP:****@10.0.0.10:2121/asa9-14-4-smp-k8.bin (Resource temporarily unavailable)"
check("a device that could not open the server gets the agreed hint", FW.cant_reach_hint(asa_words, {"proto": "ftp", "host": "10.0.0.10", "port": 2121}) == HINT
      and FW.cant_reach_hint("%Error opening tftp://10.0.0.10/x.bin (Timed out)", {"proto": "tftp", "host": "10.0.0.10", "port": 69})
      == " The device could not connect to 10.0.0.10 port 69; Toner could, from this computer. Check the server's firewall from the device's side.")
check("any other failure gets none", FW.cant_reach_hint("%Error opening ftp://x/y.bin (No such file or directory)", src) == "")
dead = {**src, "port": 1}                                        # nothing listens there: the device's copy is refused
r_tr = FW.transfer(dev_en, r, {"name": "asa9-18-1-smp-k8.bin", "size": 100, "md5": "0" * 32}, dead, poll=0.1)
check("the refused copy says so with the device's words, then where to look", not r_tr["ok"] and "refused" in r_tr["detail"].lower()
      and r_tr["detail"].endswith(" The device could not connect to 127.0.0.1 port 1; Toner could, from this computer. Check the server's firewall from the "
                                  "device's side and, for FTP, its passive-mode settings."), r_tr["detail"])
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

# ================================================================ step 4: Clean up
from core import audit
print("== what is offered for deleting")
r_ios, r_asa = R["ios1"], R["asa1"]
notes = {f["name"]: (f["note"], f["tickable"], f["ticked"]) for f in FW.cleanup_plan(r_ios)["flashes"][0]["files"]}
check("IOS: an old image is ticked; the running image cannot be ticked; other files are left unticked", notes ==
      {"c2960x-old.bin": ("old image", True, True), "c2960x-universalk9-mz.152-7.E9.bin": ("running image", False, False), "config.text": ("", True, False)}, notes)
notes = {f["name"]: f["note"] for f in FW.cleanup_plan(r_asa)["flashes"][0]["files"]}
check("ASA: ASDM is kept unless ticked", notes == {"asa9-12-4-smp-k8.bin": "old image", "asa9-16-4-smp-k8.bin": "running image", "asdm-7181.bin": "ASDM image"}, notes)
check("a file in the boot statement that is not running cannot be ticked either", FW.file_note({**r_ios, "boot": ["next.bin"]}, "next.bin") == ("in boot statement", False, False))
check("IOS XE in INSTALL mode: install remove inactive, no file list", FW.cleanup_plan(R["stack1"]) == {"install": True, "flashes": []})
check("a stack in BUNDLE mode lists every member's flash", [f["fs"] for f in FW.cleanup_plan({**R["stack1"], "mode": "BUNDLE"})["flashes"]] == ["flash:", "flash-2:", "flash-3:"])
check("each platform's delete that asks nothing", [FW.delete_command(p, FW.MAIN_FS[p], "x.bin") for p in FW.PLATFORMS] ==
      ["delete /force flash:x.bin", "delete /force flash:x.bin", "delete bootflash:x.bin no-prompt", "delete /noconfirm disk0:/x.bin"])
check("the free space line", FW.space_line("flash:", int(1.2 * G), 11 * G) == "flash: 1.2 GB free of 11.0 GB")

print("== the Clean up step")
fakes["stack1"].install_files = ["cat9k-rpbase.17.03.04.SPA.pkg"]
fakes["stack1"].fs["flash:"].files["cat9k-rpbase.17.03.04.SPA.pkg"] = [400000000, ""]
fakes["noping"].reach = OK_REACH
page.back.click(); page.back.click(); page.devices.untick_all.click(); tick("ios1", "stack1", "bundle1", "nx1", "asa1")
page.next.click(); pump(lambda: sv.ready()); page.next.click(); pump(lambda: not ck.running(), 1500)
check("Next leads on from Check devices", ck.ready() and page.next.isEnabled())
before = {n: {fs: dict(f.files) for fs, f in fakes[n].fs.items()} for n in fakes}
page.next.click()
cu = page.cleanup
check("Step 4 of 6: Clean up, with the agreed words", page.step_line.text() == "Step 4 of 6: Clean up" and cu.intro.text().startswith("Make room for the new image. Ticked files are deleted when you click Delete ticked files and confirm.")
      and cu.notice.text() == "Nothing is deleted until you confirm." and cu.delete.text() == "Delete ticked files")
def top_item(name): return next(cu.tree.topLevelItem(i) for i in range(cu.tree.topLevelItemCount()) if cu.tree.topLevelItem(i).text(0).startswith(name + " ("))
def file_item(dev, name):
    t = top_item(dev)
    for i in range(t.childCount()):
        fsrow = t.child(i)
        for j in range(fsrow.childCount()):
            if fsrow.child(j).text(0) == name: return fsrow.child(j)
t = top_item("ios1")
check("one row per device with its address; its flash with free and total space; its files under it", t.text(0) == "ios1 (127.0.0.1)"
      and t.child(0).text(0) == FW.space_line("flash:", 122185728 - 51004000, 122185728) and t.child(0).childCount() == 3)
check("the running image has no tick box", not (file_item("ios1", "c2960x-universalk9-mz.152-7.E9.bin").flags() & Qt.ItemFlag.ItemIsUserCheckable)
      and file_item("ios1", "c2960x-universalk9-mz.152-7.E9.bin").text(2) == "running image")
check("the old image is pre-ticked, with its size and note", file_item("ios1", "c2960x-old.bin").checkState(0) == Qt.CheckState.Checked
      and file_item("ios1", "c2960x-old.bin").text(1) == FW.human_size(25000000) and file_item("ios1", "c2960x-old.bin").text(2) == "old image")
check("IOS XE INSTALL: one ticked row to run install remove inactive", top_item("stack1").childCount() == 1 and top_item("stack1").child(0).text(0) == "Run install remove inactive"
      and top_item("stack1").child(0).checkState(0) == Qt.CheckState.Checked)
file_item("bundle1", "cat9k_iosxe.17.03.04.SPA.bin").setCheckState(0, Qt.CheckState.Unchecked)     # the technician keeps one
fakes["nx1"].protect = {"nxos.9.3.8.bin"}                                                          # and the switch refuses one
asked = []
cu.confirm = lambda title, body: (asked.append((title, body)), False)[1]
cu.delete.click()
check("Cancel: nothing at all is deleted on any device", asked and {n: {fs: dict(f.files) for fs, f in fakes[n].fs.items()} for n in fakes} == before
      and not any(l.startswith(("delete", "install remove")) for f in fakes.values() for l in f.commands))
title, body = asked[0]
check("the one confirmation names the number of devices", title == "Delete files on 4 devices?", title)
check("...and lists every file on every device, with sizes, and the install remove, in the page's order", body == (
      "asa1 (127.0.0.1)\n    disk0:/asa9-12-4-smp-k8.bin  " + FW.human_size(110000000) + "\n"
      "ios1 (127.0.0.1)\n    flash:c2960x-old.bin  " + FW.human_size(25000000) + "\n"
      "nx1 (127.0.0.1)\n    bootflash:nxos.9.3.8.bin  " + FW.human_size(1600000000) + "\n"
      "stack1 (127.0.0.1)\n    install remove inactive\n\n"
      "These files are deleted now and cannot be recovered. The running image and the files in the boot statement are not touched. Nothing is reloaded."), body)
check("a device with nothing ticked is not in it", "bundle1" not in body)
cu.confirm = lambda title, body: True
cu.delete.click()
check("Delete: Back, Next and Start over wait while it runs", cu.running() and not page.next.isEnabled() and not page.back.isEnabled() and not page.restart.isEnabled())
pump(lambda: not cu.running(), 1500)
check("each platform's own delete was sent", "delete /force flash:c2960x-old.bin" in fakes["ios1"].commands and "delete bootflash:nxos.9.3.8.bin no-prompt" in fakes["nx1"].commands
      and "delete /noconfirm disk0:/asa9-12-4-smp-k8.bin" in fakes["asa1"].commands)
check("the ticked files are gone, everything else is still there", "c2960x-old.bin" not in fakes["ios1"].fs["flash:"].files and "asa9-12-4-smp-k8.bin" not in fakes["asa1"].fs["disk0:"].files
      and {"c2960x-universalk9-mz.152-7.E9.bin", "config.text"} <= set(fakes["ios1"].fs["flash:"].files) and "asdm-7181.bin" in fakes["asa1"].fs["disk0:"].files
      and "cat9k_iosxe.17.03.04.SPA.bin" in fakes["bundle1"].fs["flash:"].files and not any(l.startswith("delete") for l in fakes["bundle1"].commands))
check("install remove inactive ran and its question was answered y", "install remove inactive" in fakes["stack1"].commands
      and fakes["stack1"].commands[fakes["stack1"].commands.index("install remove inactive") + 1] == "y" and "cat9k-rpbase.17.03.04.SPA.pkg" not in fakes["stack1"].fs["flash:"].files)
check("each row says what happened", file_item("ios1", "c2960x-old.bin").text(2) == "Deleted" and top_item("stack1").child(0).text(2) == "Deleted"
      and file_item("nx1", "nxos.9.3.8.bin").text(2) == "Failed: %Error deleting bootflash:nxos.9.3.8.bin (Permission denied)", file_item("nx1", "nxos.9.3.8.bin").text(2))
check("the free space is read again", top_item("ios1").child(0).text(0) == FW.space_line("flash:", 122185728 - 26004000, 122185728), top_item("ios1").child(0).text(0))
check("...and the next step works from it", R["ios1"]["flashes"][0]["free"] == 122185728 - 51004000 and
      next(r for r in page.check.ready_results() if r["name"] == "ios1")["flashes"][0]["free"] == 122185728 - 26004000)
rows = audit.recent()
check("one audit line per deletion, per device", any(a["action"] == "firmware delete" and a["detail"] == f"ios1: flash:c2960x-old.bin ({FW.human_size(25000000)})" for a in rows)
      and any(a["action"] == "firmware delete" and a["detail"] == f"asa1: disk0:/asa9-12-4-smp-k8.bin ({FW.human_size(110000000)})" for a in rows)
      and any(a["action"] == "firmware install remove inactive" and a["detail"] == "stack1: done" for a in rows)
      and any(a["action"] == "firmware failed" and a["detail"].startswith("nx1: delete bootflash:nxos.9.3.8.bin: %Error") for a in rows), [(a["action"], a["detail"]) for a in rows[:8]])
check("a deleted file's row has no tick box any more; Delete waits for a new tick", not file_item("ios1", "c2960x-old.bin").data(0, Qt.ItemDataRole.CheckStateRole)
      and not cu.delete.isEnabled())
check("Next works whether or not anything was deleted", cu.ready() and page.back.isEnabled())
check("no device was reloaded or had anything activated", not any("reload" in l or l.startswith(("install activate", "install commit")) for f in fakes.values() for l in f.commands))

# ================================================================ step 5: Images
import hashlib
MD5 = {n: hashlib.md5(open(os.path.join(images, n), "rb").read()).hexdigest() for n in IMAGES}
XE, IOS, NX, ASA = "cat9k_iosxe.17.09.04a.SPA.bin", "c2960x-universalk9-mz.152-7.E9.bin", "nxos64-cs.10.3.4a.M.bin", "asa9-18-4-smp-k8.bin"
print("== the image rules")
r_stack = next(r for r in page.check.ready_results() if r["name"] == "stack1")
check("free space: one flash, or each stack member", FW.free_text(R["asa1"]) == FW.human_size(R["asa1"]["flashes"][0]["free"])
      and FW.free_text(r_stack) == ", ".join(f"switch {n}: {FW.human_size(f['free'])}" for n, f in zip((1, 2, 3), r_stack["flashes"])))
tiny = {**R["ios1"], "flashes": [{**R["ios1"]["flashes"][0], "free": 1000, "files": {}}]}
check("an image that does not fit says where and how much is free, and does not block",
      FW.image_problems([(tiny, {"name": IOS, "size": 2000}, MD5[IOS])]) == [(f"ios1: {IOS} (2 KB) does not fit on flash: (1000 bytes free). Clean up first, or skip the device.", False)])
tiny_stack = {**r_stack, "flashes": [r_stack["flashes"][0], {**r_stack["flashes"][1], "free": 10, "files": {}}, r_stack["flashes"][2]]}
check("...on a stack it names the member", FW.image_problems([(tiny_stack, {"name": XE, "size": 3000}, MD5[XE])])[0][0].startswith(f"stack1: {XE} (3 KB) does not fit on switch 2 (10 bytes free)."))
check("a file of the same name already there counts as room", FW.room_for({**tiny, "flashes": [{**tiny["flashes"][0], "files": {IOS: 1500}}]}, IOS, 2000) == [])
check("an image with no hash blocks", FW.image_problems([(R["ios1"], {"name": IOS, "size": 2000}, "  ")]) == [("ios1: an image is chosen but no MD5 hash is typed.", True)])
check("a hash that is not 32 hexadecimal characters blocks", FW.image_problems([(R["ios1"], {"name": IOS, "size": 2000}, "abc123")]) == [("ios1: the MD5 hash must be 32 hexadecimal characters.", True)])
check("nothing chosen blocks", FW.image_problems([(R["ios1"], None, "")]) == [("No device has an image chosen.", True)])
osrc = FW.own_source("ftp", own_ftp, "127.0.0.1")
check("the copy URL carries the login and a port that is not the usual one", FW.copy_url(osrc, XE) == f"ftp://toner:Own-ftp-pass1@127.0.0.1:{own_ftp.port}/{XE}"
      and FW.copy_url({**osrc, "port": 21}, XE) == f"ftp://toner:Own-ftp-pass1@127.0.0.1/{XE}")
check("...another server's folder is in the path; TFTP has no login; anonymous FTP signs in as anonymous",
      FW.copy_url(fsrc, XE) == f"ftp://fwuser:Ftp-pass-123@127.0.0.1:{ftp.port}/firmware/{XE}"
      and FW.copy_url({"own": True, "proto": "tftp", "host": "10.0.0.5", "port": 69}, XE) == f"tftp://10.0.0.5/{XE}"
      and FW.copy_url({**fsrc, "anonymous": True, "port": 21}, XE) == f"ftp://anonymous:anonymous@127.0.0.1/firmware/{XE}")
check("the server as shown never has the password", FW.source_shown(osrc) == f"ftp://toner@127.0.0.1:{own_ftp.port}" and FW.source_shown({**fsrc, "proto": "sftp", "port": 22}) == "sftp://fwuser@127.0.0.1")
check("each platform's copy", [FW.copy_command(p, "URL", XE, "management") for p in FW.PLATFORMS] ==
      ["copy URL flash:", "copy URL flash:", "copy URL bootflash: vrf management", f"copy /noconfirm URL disk0:/{XE}"])

print("== the Images step")
check("Next leads on from Clean up", page.next.isEnabled())
page.next.click()
im = page.images
check("Step 5 of 6: Images, with the agreed words", page.step_line.text() == "Step 5 of 6: Images" and im.intro.text() ==
      "Choose the image for each device and type or paste its MD5 from Cisco's download page. Toner checks the hash on the device after the copy and stops that device if it differs.")
check("the columns", [im.table.horizontalHeaderItem(i).text() for i in range(im.table.columnCount())] == ["Device", "Version", "Mode", "Free space", "Reaches server", "Image", "MD5", "Fits"])
names_im = [im.table.item(i, 0).text() for i in range(im.table.rowCount())]
check("the devices that came through, in order", names_im == ["asa1", "bundle1", "ios1", "nx1", "stack1"], names_im)
row = {n: i for i, n in enumerate(names_im)}
pick = lambda n: im.table.cellWidget(row[n], 5)
md5box = lambda n: im.table.cellWidget(row[n], 6)
check("the rows are as tall as their editors; Image and MD5 fit; Fits stretches to the edge", im.table.rowHeight(row["ios1"]) >= pick("ios1").sizeHint().height()
      and im.table.columnWidth(5) >= pick("ios1").sizeHint().width() and im.table.columnWidth(6) >= im.table.fontMetrics().horizontalAdvance("0" * 32)
      and im.table.horizontalHeader().stretchLastSection() and sum(im.table.columnWidth(i) for i in range(8)) >= im.table.viewport().width(),
      (im.table.rowHeight(0), pick("ios1").sizeHint().height(), [im.table.columnWidth(i) for i in range(8)], im.table.viewport().width()))
check("each starts skipped; the drop-down holds the server's files", pick("ios1").currentText() == "(skip this device)" and
      [pick("ios1").itemText(i) for i in range(1, pick("ios1").count())] == WANT)
check("the stack's free space per member, and the freed space after Clean up", im.table.item(row["stack1"], 3).text().startswith("switch 1: ")
      and im.table.item(row["ios1"], 3).text() == FW.human_size(122185728 - 26004000))
check("Next reads Transfer and waits: no device has an image chosen", page.next.text() == "Transfer" and not page.next.isEnabled()
      and im.problems.text() == "No device has an image chosen.")
pick("ios1").setCurrentIndex(pick("ios1").findData(IOS))
check("an image without a hash blocks, saying so", not page.next.isEnabled() and im.problems.text() == "ios1: an image is chosen but no MD5 hash is typed.")
md5box("ios1").setText("not-a-hash")
check("a malformed hash blocks", not page.next.isEnabled() and im.problems.text() == "ios1: the MD5 hash must be 32 hexadecimal characters.")
md5box("ios1").setText(MD5[IOS].upper())
check("a good hash (any case) lets it go on; Fits says Yes", page.next.isEnabled() and im.problems.text() == "" and im.table.item(row["ios1"], 7).text() == "Yes")
im.table.setCurrentCell(row["stack1"], 5)
pick("stack1").setCurrentIndex(pick("stack1").findData(XE)); md5box("stack1").setText(MD5[XE])
check("the button names the platform of the row", im.same.text() == "Use for all IOS XE devices")
im.same.click()
check("Use for all IOS XE devices fills the other IOS XE device, and no other", pick("bundle1").currentData() == XE and md5box("bundle1").text() == MD5[XE]
      and pick("nx1").currentData() is None and pick("asa1").currentData() is None)
pick("nx1").setCurrentIndex(pick("nx1").findData(NX)); md5box("nx1").setText(MD5[NX])
pick("asa1").setCurrentIndex(pick("asa1").findData(ASA)); md5box("asa1").setText(MD5[ASA])
fakes["asa1"].fs["disk0:"].total = fakes["asa1"].fs["disk0:"].used() + 100                   # (as if the ASA's disk were full)
next(r for r in page.check.ready_results() if r["name"] == "asa1")["flashes"][0]["free"] = 100
im._sync()
check("an image that does not fit is a warning, not a stop", page.next.isEnabled() and im.table.item(row["asa1"], 7).text() == "No"
      and im.problems.text() == f"asa1: {ASA} (1 KB) does not fit on disk0: (100 bytes free). Clean up first, or skip the device.", im.problems.text())
pick("asa1").setCurrentIndex(0)
check("skipping it clears the warning", im.problems.text() == "" and im.table.item(row["asa1"], 7).text() == "")

print("== the Transfer confirmation")
asked = []
page.confirm_transfer = lambda title, body: (asked.append((title, body)), False)[1]
page.next.click()
check("Cancel: nothing is copied and the page stays on Images", asked and page.step_line.text() == "Step 5 of 6: Images"
      and not any(l.startswith("copy ") and "://" in l for f in fakes.values() for l in f.commands))
title, body = asked[0]
check("the title counts the devices", title == "Transfer images to 4 devices?", title)
shown = FW.source_shown(osrc)
check("each device with its image, size and server (no password), then what happens after the copy", body == (
      f"bundle1 (127.0.0.1): {XE}, 3 KB, from {shown}\n"
      f"ios1 (127.0.0.1): {IOS}, 2 KB, from {shown}\n"
      f"nx1 (127.0.0.1): {NX}, 2 KB, from {shown}\n"
      f"stack1 (127.0.0.1): {XE}, 3 KB, from {shown}\n\n"
      "For each device Toner copies the image, checks its MD5, puts it on every stack member and checks it there, then:\n"
      "• IOS XE in INSTALL mode: install add only.\n"
      "• IOS XE in BUNDLE mode and IOS: sets the boot statement and saves the configuration.\n"
      "• NX-OS: sets the boot variable and saves the configuration.\n"
      "• ASA: replaces the boot system line and saves the configuration.\n"
      "Nothing is reloaded. Up to 4 devices copy at once.") and "Own-ftp-pass1" not in body, body)

print("== the Transfer step")
FW.POLL_SECONDS = 0.1
for f in fakes.values(): f.copy_seconds = 1.5
fakes["bundle1"].corrupt = {XE}                                       # its copy arrives damaged
seen_progress = {}
page.confirm_transfer = lambda title, body: True
page.next.click()
tr = page.transfer
tr.job.step.connect(lambda key, step, prog, detail: prog is not None and seen_progress.setdefault(key, []).append(prog))
check("Step 6 of 6: Transfer; no going back; Stop is on", page.step_line.text() == "Step 6 of 6: Transfer" and not page.back.isEnabled() and tr.stop.isEnabled()
      and not page.next.isEnabled() and not page.restart.isEnabled())
check("the columns, and every device waiting or under way", [tr.table.horizontalHeaderItem(i).text() for i in range(4)] == ["Device", "Step", "Progress", "Detail"]
      and tr.table.rowCount() == 4)
pump(lambda: not tr.running(), 3000)
steps = {tr.table.item(i, 0).text(): (tr.table.item(i, 1).text(), tr.table.item(i, 3).text(), tr.table.cellWidget(i, 2)) for i in range(tr.table.rowCount())}
check("the good copies are Done", all(steps[n][0] == "Done" for n in ("ios1", "nx1", "stack1")), {n: s[:2] for n, s in steps.items()})
check("the Progress column fits its longest text", tr.table.columnWidth(2) >= tr.table.fontMetrics().horizontalAdvance("100 %  (999.9 MB of 999.9 MB)") + 16)
check("progress was polled from a second session and reached 100 %", all(any(0 < d < t for d, t in seen_progress.get(k, [])) for k in ("ios1", "stack1"))
      and steps["ios1"][2].value() == 1000 and steps["ios1"][2].format() == "100 %  (2 KB of 2 KB)", (seen_progress.get("ios1"), steps["ios1"][2].format()))
check("the image is on each device with the server's MD5", fakes["ios1"].fs["flash:"].files[IOS][1] == MD5[IOS] and fakes["nx1"].fs["bootflash:"].files[NX][1] == MD5[NX]
      and fakes["stack1"].fs["flash:"].files[XE][1] == MD5[XE])
check("the device fetched it from the URL Toner built (FTP, with Toner's FTP login)", f"copy ftp://toner:Own-ftp-pass1@127.0.0.1:{own_ftp.port}/{IOS} flash:" in fakes["ios1"].commands)
check("NX-OS copied through the VRF and checked with show file ... md5sum", f"copy ftp://toner:Own-ftp-pass1@127.0.0.1:{own_ftp.port}/{NX} bootflash: vrf management" in fakes["nx1"].commands
      and f"show file bootflash:{NX} md5sum" in fakes["nx1"].commands)
check("IOS checked with verify /md5 against the typed hash", f"verify /md5 flash:{IOS} {MD5[IOS]}" in fakes["ios1"].commands)
check("every stack member got the file, each checked", all(fakes["stack1"].fs[fs].files.get(XE, [0, ""])[1] == MD5[XE] for fs in ("flash-2:", "flash-3:"))
      and f"copy flash:{XE} flash-2:{XE}" in fakes["stack1"].commands and f"verify /md5 flash-3:{XE} {MD5[XE]}" in fakes["stack1"].commands)
damaged = hashlib.md5(open(os.path.join(images, XE), "rb").read() + b"damaged").hexdigest()
check("a bad hash stops that device with a clear line", steps["bundle1"][0] == "Failed" and steps["bundle1"][1] ==
      f"MD5 differs: the device computed {damaged} and you typed {MD5[XE]}. The file was left on flash; nothing else was changed on this device.", steps["bundle1"][1])
check("...and the others carried on", steps["ios1"][0] == "Done" and steps["stack1"][0] == "Done")
check("the line under the table", tr.status.text() == "Done: 3 of 4 devices have the new image, 1 failed. Nothing was reloaded.", tr.status.text())
check("Start over is on once it is finished; Back stays off", page.restart.isEnabled() and not page.back.isEnabled() and not tr.stop.isEnabled())
rows = audit.recent()
check("audit: each verified copy, with the server shown without its password", any(a["action"] == "firmware copy" and a["detail"] == f"ios1: {IOS} from {shown}/{IOS}, 2 KB, MD5 verified" for a in rows)
      and any(a["action"] == "firmware stack copy" and a["detail"] == f"stack1: {XE} to switch 3, MD5 verified" for a in rows)
      and any(a["action"] == "firmware failed" and a["detail"].startswith("bundle1: MD5 differs") for a in rows), [(a["action"], a["detail"]) for a in rows[:6]])
everything = " ".join(tr.table.item(i, j).text() for i in range(tr.table.rowCount()) for j in (1, 3)) + tr.status.text() + " ".join(a["detail"] for a in audit.recent(1000))
logs = "".join(FW.log_path(labdevs[n]).read_text(encoding="utf-8") for n in ("ios1", "nx1", "stack1", "bundle1"))
check("the FTP password is nowhere: screen, audit log, session logs", "Own-ftp-pass1" not in everything and "Own-ftp-pass1" not in logs and "copy ftp://toner:****@" in logs)
check("...nor the devices' password", PW not in everything and PW not in logs)
print("== after a verified copy (first run)")
check("IOS: the boot statement replaced, saved, and read back", config_lines(fakes["ios1"].commands)[-2:] == ["no boot system", f"boot system flash:{IOS}"]
      and "write memory" in fakes["ios1"].commands and fakes["ios1"].saved_boot == [f"flash:{IOS}"])
check("NX-OS: boot nxos, then copy running-config startup-config", config_lines(fakes["nx1"].commands)[-1:] == [f"boot nxos bootflash:{NX}"]
      and "copy running-config startup-config" in fakes["nx1"].commands and fakes["nx1"].saved_boot == [f"bootflash:{NX}"])
check("IOS XE in INSTALL mode: install add only, no boot change and nothing saved", f"install add file flash:{XE}" in fakes["stack1"].commands
      and fakes["stack1"].added == [XE] and not config_lines(fakes["stack1"].commands) and "write memory" not in fakes["stack1"].commands)
check("the device whose MD5 differed got no boot change at all", not config_lines(fakes["bundle1"].commands) and "write memory" not in fakes["bundle1"].commands)
rows = audit.recent()
check("audit: the boot change and the install add", any(a["action"] == "firmware boot" and a["detail"] == f"ios1: boot system flash:{IOS}, saved" for a in rows)
      and any(a["action"] == "firmware boot" and a["detail"] == f"nx1: boot nxos bootflash:{NX}, saved" for a in rows)
      and any(a["action"] == "firmware install add" and a["detail"] == f"stack1: flash:{XE}" for a in rows))
check("the reminder about activating and reloading", tr.note.isVisibleTo(tr) and tr.note.text() == FW.INSTALL_NOTE and FW.INSTALL_NOTE ==
      "IOS XE INSTALL mode: the image is added, not activated; run install activate and install commit in the maintenance window (that reloads). "
      "Other devices boot the new image at their next reload.")
tr.copy.click()
from PySide6.QtWidgets import QApplication as _QA
clip = _QA.clipboard().text()
check("Copy summary: a line per device, then the line under the table and the reminder", clip.splitlines()[:4] == [
      f"bundle1 (127.0.0.1): Failed - {steps['bundle1'][1]}", "ios1 (127.0.0.1): Done", "nx1 (127.0.0.1): Done", "stack1 (127.0.0.1): Done"]
      and clip.endswith("Done: 3 of 4 devices have the new image, 1 failed. Nothing was reloaded.\n" + FW.INSTALL_NOTE) and "Own-ftp-pass1" not in clip, clip)
check("nothing was reloaded, activated or committed", not [l for f in fakes.values() for l in f.commands if re.match(r"^(reload|install activate|install commit)", l)])

print("== Stop")
for f in fakes.values(): f.copy_seconds = 3.0; f.corrupt = set()
page.restart.click(); page.devices.untick_all.click(); tick("ios1", "stack1", "bundle1", "nx1", "asa1")
fakes["asa1"].fs["disk0:"].total = 8 * G
page.next.click()
check("Start over cleared the listing: the server must be listed again", not sv.ready() and not page.next.isEnabled())
sv.own_btn.click(); sv.own.setCurrentIndex(sv.own.findData("ftp")); sv.address.setEditText("127.0.0.1"); sv.test.click(); pump(lambda: sv.ready())
page.next.click(); pump(lambda: not ck.running(), 1500); page.next.click(); page.next.click()
check("back at Images for the second run", page.step_line.text() == "Step 5 of 6: Images", page.step_line.text())
for n, img in (("asa1", ASA), ("bundle1", XE), ("ios1", IOS), ("nx1", NX), ("stack1", XE)):
    pick(n).setCurrentIndex(pick(n).findData(img)); md5box(n).setText(MD5[img])
for f in fakes.values():
    for fs in f.fs.values(): fs.files.pop(XE, None); fs.files.pop(IOS, None); fs.files.pop(NX, None); fs.files.pop(ASA, None)
typed_before = {n: len(f.commands) for n, f in fakes.items()}
page.next.click()
pump(lambda: sum(tr.table.item(i, 1).text() == "Copying" for i in range(tr.table.rowCount())) >= 4, 500)
page.stop_question = lambda: False
check("closing Toner asks, and Keep going keeps it running", page.ask_stop() is False and tr.running())
page.stop_question = lambda: True
check("Stop: closing waits for the copies, then may close", page.ask_stop() is True and not tr.running())
steps = {tr.table.item(i, 0).text(): (tr.table.item(i, 1).text(), tr.table.item(i, 3).text()) for i in range(tr.table.rowCount())}
check("the four that were copying finished their copy, and nothing else", sum(s[0] == "Stopped" for s in steps.values()) == 4
      and all(s[1] == "Stopped after the copy (MD5 verified). Nothing else was changed on this device." for s in steps.values() if s[0] == "Stopped"), steps)
check("the fifth never started", sum(s[0] == "Not started (stopped)" for s in steps.values()) == 1, steps)
check("the Stopping line was shown, and Stop is off", "Stopping: devices that are copying finish their copy; nothing else is changed on them." in tr.status.text()
      or tr.status.text().startswith("Done: 0 of 5"), tr.status.text())
since = {n: f.commands[typed_before[n]:] for n, f in fakes.items()}
check("after Stop no stack member was copied to and nothing more was sent", not any(l.startswith(("copy flash:", "boot", "install add", "write")) for c in since.values() for l in c)
      and not any(l.startswith("copy ") for l in since["stack1"]), {n: [l for l in c if l.startswith("copy")] for n, c in since.items()})

print("== after a verified copy: ASA, a BUNDLE stack, and what can go wrong")
fakes["bstack"] = CiscoFake("cisco_xe", "bstack", mode="BUNDLE", members=2, files={"cat9k_iosxe.17.06.05.SPA.bin": (900, "")},
                            image="cat9k_iosxe.17.06.05.SPA.bin", reach=OK_REACH, password=PW, copy_seconds=0.5)
add("bstack", "cisco", "cisco_xe", lab, host="127.0.0.1")
with db.within(lab):
    d = next(x for x in db.list_devices() if x["name"] == "bstack"); db.save_device({**d, "port": fakes["bstack"].port, "username": "admin"})
    db.set_secret(db.secret_name("bstack"), PW)
for f in fakes.values():
    f.copy_seconds = 0.5
    for fs in f.fs.values():
        for n in (XE, IOS, NX, ASA): fs.files.pop(n, None)
fakes["stack1"].install_fail = "Super package already added. Add operation not allowed."
fakes["ios1"].ignore_boot = True
fakes["ios1"].boot = fakes["ios1"].saved_boot = ["flash:/c2960x-old.bin"]      # (so a change that does not take shows)
fakes["asa1"].boot = ["disk0:/asa9-16-4-smp-k8.bin", "disk0:/asa9-12-4-smp-k8.bin"]
page.restart.click(); page.refresh(); page.devices.untick_all.click(); tick("asa1", "bstack", "stack1", "ios1")
page.next.click(); sv.own_btn.click(); sv.own.setCurrentIndex(sv.own.findData("ftp")); sv.address.setEditText("127.0.0.1"); sv.test.click(); pump(lambda: sv.ready())
page.next.click(); pump(lambda: not ck.running(), 1500)
check("all four ready", ck.progress.text() == "4 devices: 4 ready, 0 held back.", ck.progress.text())
page.next.click(); page.next.click()
row = {im.table.item(i, 0).text(): i for i in range(im.table.rowCount())}
for n, img in (("asa1", ASA), ("bstack", XE), ("stack1", XE), ("ios1", IOS)):
    pick(n).setCurrentIndex(pick(n).findData(img)); md5box(n).setText(MD5[img])
typed_before = {n: len(f.commands) for n, f in fakes.items()}
page.next.click(); pump(lambda: not tr.running(), 3000)
steps = {tr.table.item(i, 0).text(): (tr.table.item(i, 1).text(), tr.table.item(i, 3).text()) for i in range(tr.table.rowCount())}
since = {n: f.commands[typed_before[n]:] for n, f in fakes.items()}
signin = lambda lines: [l for l in lines if l != "terminal width 511"]      # (netmiko's own ASA sign-in)
check("ASA: the running image's boot line goes, the new one comes first, another line stays after it, saved", steps["asa1"][0] == "Done"
      and signin(config_lines(since["asa1"])) == ["no boot system disk0:/asa9-16-4-smp-k8.bin", "no boot system disk0:/asa9-12-4-smp-k8.bin",
                                                  f"boot system disk0:/{ASA}", "boot system disk0:/asa9-12-4-smp-k8.bin"]
      and "write memory" in since["asa1"] and fakes["asa1"].saved_boot == [f"disk0:/{ASA}", "disk0:/asa9-12-4-smp-k8.bin"], (steps["asa1"], config_lines(since["asa1"]), fakes["asa1"].saved_boot))
check("ASA boot lines: with only the running image's line, just the new one; adding it back never doubles it",
      FW.boot_lines(R["asa1"], ASA, ["disk0:/asa9-16-4-smp-k8.bin"]) == ["no boot system disk0:/asa9-16-4-smp-k8.bin", f"boot system disk0:/{ASA}"]
      and FW.boot_lines(R["asa1"], ASA, [f"disk0:/{ASA}", "disk0:/asa9-16-4-smp-k8.bin"]) == [f"no boot system disk0:/{ASA}", "no boot system disk0:/asa9-16-4-smp-k8.bin", f"boot system disk0:/{ASA}"])
check("a BUNDLE stack: the image on both members, then boot system switch all", steps["bstack"][0] == "Done" and fakes["bstack"].fs["flash-2:"].files[XE][1] == MD5[XE]
      and config_lines(since["bstack"]) == ["no boot system", f"boot system switch all flash:{XE}"] and "write memory" in since["bstack"])
check("install add failing says so with the device's words", steps["stack1"] == ("Failed", "install add failed: FAILED: install_add : Super package already added. Add operation not allowed."), steps["stack1"])
check("a boot statement that did not take says what show boot says", steps["ios1"] == ("Failed", "The boot statement did not take: show boot says c2960x-old.bin."), steps["ios1"])
rows = audit.recent()
check("audit: the ASA's boot change, and the two failures", any(a["action"] == "firmware boot" and a["detail"] == f"asa1: boot system disk0:/{ASA}, saved" for a in rows)
      and any(a["action"] == "firmware boot" and a["detail"] == f"bstack: boot system switch all flash:{XE}, saved" for a in rows)
      and any(a["action"] == "firmware failed" and a["detail"].startswith("stack1: install add failed") for a in rows)
      and any(a["action"] == "firmware failed" and a["detail"].startswith("ios1: The boot statement did not take") for a in rows))
check("the line under the table", tr.status.text() == "Done: 2 of 4 devices have the new image, 2 failed. Nothing was reloaded.", tr.status.text())
check("still nothing reloaded, activated or committed, on any device", not [l for f in fakes.values() for l in f.commands if re.match(r"^(reload|install activate|install commit)", l)])
everything = " ".join(tr.table.item(i, j).text() for i in range(tr.table.rowCount()) for j in (1, 3)) + " ".join(a["detail"] for a in audit.recent(2000))
logs = "".join(FW.log_path(labdevs[n]).read_text(encoding="utf-8") for n in ("ios1", "asa1", "stack1", "nx1"))
check("over everything: the server's and the devices' passwords appear nowhere", "Own-ftp-pass1" not in everything + logs and PW not in everything + logs)
page.shutdown()
for f in fakes.values(): f.stop()
for s in (ftp, sftp_srv, own_ftp, own_tftp): s.stop()
for s in (sftp_dev, scp_only, missing): s.stop()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

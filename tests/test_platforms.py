# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Toner on Windows, Linux and macOS: where data lives, ping and traceroute (their flags and their output on each system),
# Wi-Fi through NetworkManager, PuTTY's session files, Remote Desktop through FreeRDP, Ansible on this computer, file locks.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, json
from pathlib import Path
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "plat%d.db" % int(time.time())); os.environ["APPDATA"] = SP
from core import platforms, pinger, wifi, sessionimport, sessions, db
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def as_platform(win=False, mac=False, linux=False):
    """Pretend to be another system for the parts that ask (the modules read the flags when they are called)."""
    for mod in (platforms, pinger):
        mod.WINDOWS, mod.MAC, mod.LINUX = win, mac, linux

real = (platforms.WINDOWS, platforms.MAC, platforms.LINUX)

print("== where data lives")
saved = os.environ.pop("APPDATA")
as_platform(linux=True); os.environ["XDG_DATA_HOME"] = "/tmp/xdg"
check("Linux: $XDG_DATA_HOME", platforms.user_data_root() == Path("/tmp/xdg"))
os.environ.pop("XDG_DATA_HOME")
check("...else ~/.local/share", platforms.user_data_root() == Path.home() / ".local" / "share")
as_platform(mac=True)
check("macOS: ~/Library/Application Support", platforms.user_data_root() == Path.home() / "Library" / "Application Support")
os.environ["APPDATA"] = saved
check("an APPDATA set by hand wins (Windows, and the tests)", platforms.user_data_root() == Path(saved))
as_platform(win=True)
check("program names get .exe on Windows only", platforms.exe("nmap") == "nmap.exe" and platforms.exe("bw.exe") == "bw.exe")
as_platform(linux=True)
check("...and stay as they are elsewhere", platforms.exe("nmap") == "nmap")

print("== ping and traceroute: the commands")
as_platform(win=True)
check("Windows: ping -n, -w in ms", pinger.ping_args("h", 4, 1500) == ["ping", "-n", "4", "-w", "1500", "h"])
check("Windows: tracert -d -h -w", pinger.trace_args("h", 30, 800) == ["tracert", "-d", "-h", "30", "-w", "800", "h"])
as_platform(linux=True)
check("Linux: ping -c, -W in whole seconds", pinger.ping_args("h", 4, 1500) == ["ping", "-c", "4", "-W", "2", "h"])
check("Linux: traceroute -n, one probe per hop", pinger.trace_args("h", 30, 800) == ["traceroute", "-n", "-q", "1", "-m", "30", "-w", "1", "h"])
as_platform(mac=True)
check("macOS: ping -c, -W in ms", pinger.ping_args("h", 1, 1000) == ["ping", "-c", "1", "-W", "1000", "h"])

print("== ping and traceroute: reading what they print")
WIN = """Reply from 10.0.0.1: bytes=32 time=12ms TTL=64
Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
    Minimum = 10ms, Maximum = 14ms, Average = 12ms"""
LIN = """64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.457 ms
4 packets transmitted, 3 received, 25% packet loss, time 3004ms
rtt min/avg/max/mdev = 0.401/0.457/0.512/0.040 ms"""
MAC = """64 bytes from 10.0.0.1: icmp_seq=0 ttl=64 time=1.234 ms
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 1.100/1.234/1.400/0.100 ms"""
check("one reply's time: Windows whole ms, Linux and macOS with decimals",
      pinger.parse_rtt(WIN) == 12.0 and pinger.parse_rtt(LIN) == 0.457 and pinger.parse_rtt(MAC) == 1.234 and pinger.parse_rtt("time<1ms") == 1.0)
check("the summary on Windows", pinger.parse_summary(WIN) == (25.0, 12.0))
check("...on Linux", pinger.parse_summary(LIN) == (25.0, 0.457), pinger.parse_summary(LIN))
check("...on macOS", pinger.parse_summary(MAC) == (0.0, 1.234), pinger.parse_summary(MAC))
check("no reply at all is 100% loss", pinger.parse_summary("ping: unknown host") == (100.0, None))
as_platform(linux=True)
check("a traceroute -n hop, and one that did not answer",
      pinger.parse_hop(" 3  192.168.1.1  0.512 ms") == (3, "192.168.1.1") and pinger.parse_hop(" 4  *") == (4, "*")
      and pinger.parse_hop("traceroute to 8.8.8.8 (8.8.8.8), 30 hops max") is None)
as_platform(win=True)
check("a tracert hop", pinger.parse_hop("  2     1 ms    <1 ms     1 ms  10.0.0.1") == (2, "10.0.0.1")
      and pinger.parse_hop("  5     *        *        *     Request timed out.") == (5, "*"))
as_platform(*real)

print("== Wi-Fi through NetworkManager (Linux)")
APS = "yes:Office:AA\\:BB\\:CC\\:DD\\:EE\\:FF:36:5180 MHz:78:270 Mbit/s:WPA2 WPA3:wlan0\nno::11\\:22\\:33\\:44\\:55\\:66:6:2437 MHz:40:54 Mbit/s:--:wlan0\n"
nets = wifi.parse_nm_networks(APS)
check("access points: name, BSSID (its colons unescaped), channel, band from the frequency, signal, security",
      nets[0]["ssid"] == "Office" and nets[0]["bssid"] == "aa:bb:cc:dd:ee:ff" and nets[0]["channel"] == 36 and nets[0]["band"] == "5 GHz"
      and nets[0]["signal"] == 78 and nets[0]["auth"] == "WPA2 WPA3", nets[0])
check("a hidden, open network", nets[1]["ssid"] == "(hidden)" and nets[1]["auth"] == "Open" and nets[1]["band"] == "2.4 GHz")
adapters = wifi.parse_nm_interfaces("wlan0:wifi:connected:Office\nlo:loopback:connected (externally):lo\n", APS)
a = wifi.current(adapters)
check("the adapter, shaped like Windows' (the Wi-Fi check and the tool read the same fields)",
      len(adapters) == 1 and a["connected"] and a["ssid"] == "Office" and a["signal_pct"] == 78 and a["channel_no"] == 36
      and a["band_text"] == "5 GHz" and a["rx"] == 270, a)
off = wifi.parse_nm_interfaces("wlan0:wifi:disconnected:--\n", "")
check("a Wi-Fi adapter that is not connected", off and not off[0]["connected"] and off[0]["state"] == "disconnected")
check("6 GHz is told apart by its frequency", wifi.band_of_freq("6115 MHz") == "6 GHz")

print("== PuTTY's session files (Linux, macOS)")
folder = Path(SP) / "putty-sessions"; folder.mkdir(exist_ok=True)
(folder / "core%20switch").write_text("HostName=10.1.1.1\nPortNumber=2222\nUserName=admin\nProtocol=ssh\n")
(folder / "Default%20Settings").write_text("HostName=\nProtocol=ssh\n")
(folder / "console").write_text("Protocol=serial\nSerialLine=/dev/ttyUSB0\nSerialSpeed=115200\n")
found = sessionimport.putty_files(str(folder))
by = {i["name"]: i for i in found.items}
check("each file is a session, its name decoded", "core switch" in by and by["core switch"]["host"] == "10.1.1.1" and by["core switch"]["port"] == 2222
      and by["core switch"]["username"] == "admin", list(by))
check("a serial console keeps its device and speed", by.get("console", {}).get("host") == "/dev/ttyUSB0" and by["console"]["options"]["baud"] == 115200)
check("a missing folder is simply nothing", sessionimport.putty_files(str(folder / "nope")).items == [])

print("== Remote Desktop through FreeRDP (Linux)")
s = {"name": "dc1", "host": "10.0.0.15", "port": 3389, "username": "CORP\\admin",
     "options": {"fullscreen": False, "width": 1280, "height": 800, "clipboard": True, "drives": True, "admin": True, "gateway": "gw.corp"}}
args = sessions.freerdp_args(s, "/usr/bin/xfreerdp3")
check("the server, the user and its domain apart, the window size", args[:1] == ["/v:10.0.0.15:3389"] and "/u:admin" in args and "/d:CORP" in args
      and "/size:1280x800" in args, args)
check("clipboard, a drive, an admin session, the gateway (FreeRDP 3's syntax)", "+clipboard" in args and any(a.startswith("/drive:home,") for a in args)
      and "/admin" in args and "/gateway:g:gw.corp" in args)
check("FreeRDP 2 is given its own gateway syntax", "/g:gw.corp" in sessions.freerdp_args(s, "/usr/bin/xfreerdp"))
check("a new server's certificate is trusted the first time (as SSH host keys are)", "/cert:tofu" in args)
check("the password is never an argument", not any(a.startswith("/p:") for a in args))
check("full screen", "/f" in sessions.freerdp_args({**s, "options": {**s["options"], "fullscreen": True}}))
sent = {}
class FakeProc:
    def __init__(self, argv, **k):
        sent["argv"], sent["stdin"] = argv, k.get("stdin")
        import io
        class Kept(io.StringIO):
            def close(self): pass                     # (kept readable after Toner closes it)
        self.stdin = Kept()
        sent["proc"] = self
real_popen, real_which, real_linux = sessions.subprocess.Popen, sessions.shutil.which, platforms.LINUX
sessions.subprocess.Popen = FakeProc
sessions.shutil.which = lambda n: "/usr/bin/xfreerdp3" if n == "xfreerdp3" else None
platforms.LINUX, platforms.WINDOWS, platforms.MAC = True, False, False
check("Linux asks for the password itself", sessions.asks_for_password())
sessions.launch_rdp(s, "s3cret")
check("FreeRDP is started with the password on standard input, not the command line",
      sent["argv"][0] == "/usr/bin/xfreerdp3" and "/from-stdin:force" in sent["argv"] and not any("s3cret" in a for a in sent["argv"])
      and sent["proc"].stdin.getvalue() == "s3cret\n")
sessions.shutil.which = lambda n: None
try:
    sessions.launch_rdp(s, "x"); check("no client: says how to get one", False)
except OSError as e:
    check("no client: says how to get one", "Install FreeRDP" in str(e), str(e))
sessions.subprocess.Popen, sessions.shutil.which = real_popen, real_which
platforms.WINDOWS, platforms.MAC, platforms.LINUX = real

print("== Ansible on this computer (Linux, macOS)")
from core import ansible
lb = ansible.LocalBackend("ansible-playbook")
check("it is described as this computer", lb.describe() == "this computer")
real_which = ansible.shutil.which
ansible.shutil.which = lambda n: None
okay, why = lb.check()
check("without Ansible it says how to install it", not okay and "Ansible is not installed on this computer" in why)
ansible.shutil.which = real_which
real_os = ansible.os.name
ansible.os.name = "posix"
db.set_setting("ansible_backend", "wsl")
check("off Windows, Ansible runs here rather than in WSL", isinstance(ansible.backend(), ansible.LocalBackend))
ansible.os.name = real_os

print("== VNC sessions")
check("VNC is a session type, on port 5900", sessions.NAMES.get("vnc") == "VNC" and sessions.DEFAULT_PORT["vnc"] == 5900)
check("its description says the viewer asks for the password",
      next(t for k, _l, _p, t in sessions.KINDS if k == "vnc") == "A remote screen through a VNC viewer. The viewer asks for the password.")
v = {"name": "mac mini", "host": "10.0.0.20", "port": 5901, "options": {"fullscreen": True, "viewonly": True}}
check("TigerVNC (and RealVNC, UltraVNC): host::port, full screen, view only",
      sessions.vnc_args(v, "/usr/bin/vncviewer") == ["/usr/bin/vncviewer", "-FullScreen", "-ViewOnly", "10.0.0.20::5901"])
check("macOS Screen Sharing: a vnc:// address", sessions.vnc_args(v, "/usr/bin/open") == ["/usr/bin/open", "vnc://10.0.0.20:5901"])
check("TightVNC for Windows: its own options", sessions.vnc_args(v, r"C:\Program Files\TightVNC\tvnviewer.exe")[1:] == ["-host=10.0.0.20", "-port=5901", "-viewonly=yes"])
check("Remmina: a vnc:// address", sessions.vnc_args(v, "/usr/bin/remmina") == ["/usr/bin/remmina", "-c", "vnc://10.0.0.20:5901"])
check("a VNC session needs a host", (lambda: (sessions.validate({"kind": "vnc", "name": "x", "host": ""}), False))
      if False else True)
try:
    sessions.validate({"kind": "vnc", "name": "x", "host": "", "port": 5900}); check("a VNC session needs a host", False)
except ValueError:
    check("a VNC session needs a host", True)
check("a VNC session saves", sessions.validate({"kind": "vnc", "name": "mac", "host": "10.0.0.20", "port": 5900}) == "mac")
real_which = sessions.shutil.which
sessions.shutil.which = lambda n: None
platforms.WINDOWS, platforms.MAC, platforms.LINUX = False, False, True
try:
    sessions.launch_vnc(v); check("no viewer on Linux: the agreed words", False)
except OSError as e:
    check("no viewer on Linux: the agreed words", str(e) == "No VNC viewer was found. Install TigerVNC (for example: sudo apt install tigervnc-viewer), then try again.", str(e))
sessions.shutil.which = real_which
platforms.WINDOWS, platforms.MAC, platforms.LINUX = real
from core import sessionimport as SI
moba = "[Bookmarks]\nSubRep=\nImgNum=42\nmac mini= #128#0%10.0.0.20%5901%%\n"
check("MobaXterm's VNC sessions are imported now, not skipped", [i["kind"] for i in SI.mobaxterm(moba).items] == ["vnc"] and SI.mobaxterm(moba).items[0]["port"] == 5901)

print("== Remote Desktop: the Client (Windows)")
platforms.WINDOWS, platforms.MAC, platforms.LINUX = True, False, False
check("Windows: Windows Remote Desktop unless the session says FreeRDP", sessions.rdp_client({}) == "windows"
      and sessions.rdp_client({"options": {"client": "freerdp"}}) == "freerdp")
check("FreeRDP is never embedded in a tab", not sessions.use_embedded({"options": {"client": "freerdp"}}))
check("FreeRDP's Windows client asks for the password itself", not sessions.asks_for_password({"options": {"client": "freerdp"}}))
platforms.WINDOWS, platforms.MAC, platforms.LINUX = False, False, True
check("Linux: always FreeRDP", sessions.rdp_client({"options": {"client": "windows"}}) == "freerdp")
platforms.WINDOWS, platforms.MAC, platforms.LINUX = real

print("== Install... (Linux)")
from core import installer
real_which, real_win = installer.shutil.which, installer.WINDOWS
have = {"apt-get", "pipx", "npm", "pkexec"}
installer.shutil.which = lambda n, path=None: f"/usr/bin/{n}" if n in have else None
installer.WINDOWS = False
installer._npm_global_writable = lambda: False
m = installer.methods("ansible")
check("Ansible: apt and pip (pipx), each with its command, in the agreed words",
      [x.text for x in m] == ["apt: sudo apt install ansible", "pip: pipx install ansible-core"], [x.text for x in m])
check("apt runs through pkexec (the system asks for the password, not Toner)", installer.command(m[0]) == ["pkexec", "apt-get", "install", "-y", "ansible"])
check("pipx needs no administrator", installer.command(m[1]) == ["pipx", "install", "ansible-core"])
b = installer.methods("bw")
check("the Bitwarden CLI: npm, through pkexec when its global folder isn't this user's",
      [x.text for x in b] == ["npm: npm install -g @bitwarden/cli"] and installer.command(b[0])[0] == "pkexec")
check("iperf3, nmap, FreeRDP, TigerVNC and NetworkManager come from apt",
      all([x.kind for x in installer.methods(t)] == ["apt"] for t in ("iperf3", "nmap", "freerdp", "vnc", "nmcli")))
have = {"apt-get"}
check("only the installers this computer has are offered", [x.kind for x in installer.methods("ansible")] == ["apt"] and installer.methods("bw") == [])
check("without pkexec, Toner can't ask for the password", not installer.can_elevate())
check("a pkexec with no password window is spotted", installer.needs_terminal("Error executing command as another user: No authentication agent found."))
installer.WINDOWS = True
check("nothing is offered on Windows", installer.methods("iperf3") == [])
installer.shutil.which, installer.WINDOWS = real_which, real_win
from PySide6.QtWidgets import QApplication
app = QApplication.instance() or QApplication([])
from ui import installdlg
installer.shutil.which = lambda n, path=None: f"/usr/bin/{n}" if n in {"apt-get", "pipx"} else None
installer.WINDOWS = False
d = installdlg.InstallDialog("ansible")
from PySide6.QtWidgets import QLabel, QRadioButton
check("the window, in the agreed words", d.windowTitle() == "Install Ansible"
      and any(l.text() == "Toner can install Ansible for you. Choose how:" for l in d.findChildren(QLabel))
      and [r.text() for r in d.findChildren(QRadioButton)] == ["apt: sudo apt install ansible", "pip: pipx install ansible-core"]
      and [x.text() for x in d.buttons.buttons()] == ["Install", "Copy command", "Cancel"])
check("apt without a password window: says to use a terminal, and Install is off",
      d.result.text() == "Toner can't ask for the administrator password here. Copy the command and run it in a terminal." and not d.go.isEnabled())
d.findChildren(QRadioButton)[1].setChecked(True)
check("pipx needs none, so Install is on", d.go.isEnabled() and d.result.text() == "")
d.copy_command()
check("Copy command copies it", QApplication.clipboard().text() == "pipx install ansible-core")
installer.shutil.which, installer.WINDOWS = real_which, real_win

print("== Copy Files with rsync (Linux, macOS)")
from core import rsync, xcopy
src = Path(SP) / "rs-src"; (src / "sub").mkdir(parents=True, exist_ok=True)
(src / "a.cfg").write_text("A"); (src / "sub" / "b.cfg").write_text("B"); (src / ".hidden").write_text("H")
dst = Path(SP) / "rs-dst"
a = rsync.build_args(str(src), str(dst))
check("a folder's contents go into the destination (source/), with the closing counts", a[-2:] == [str(src) + "/", str(dst) + "/"] and "-a" in a and "--stats" in a)
check("by default: replace what is there, leave hidden files and permissions", "--ignore-times" in a and "--exclude=.*" in a and "--no-perms" in a)
b = rsync.build_args(str(src), str(dst), subfolders=False, existing=xcopy.NEWER, hidden=True, keep_readonly=True, preview=True)
check("each option maps to rsync's own", "--exclude=*/" in b and "--update" in b and "--exclude=.*" not in b and "--no-perms" not in b
      and "--dry-run" in b and "--ignore-times" not in b, b)
c = rsync.build_args(str(src / "*.cfg"), str(dst))
check("a pattern is expanded here (no shell runs rsync)", c[-2:] == [str(src / "a.cfg"), str(dst) + "/"], c)
try:
    rsync.build_args(str(src / "*.nope"), str(dst)); check("a pattern that matches nothing is said so", False)
except ValueError as e:
    check("a pattern that matches nothing is said so", "Nothing matches" in str(e))
STATS = "Number of files: 3\nNumber of regular files transferred: 2\nTotal file size: 2 bytes\n"
check("the count comes from --stats", rsync.count_copied(STATS) == 2 and rsync.count_copied("Number of files transferred: 5") == 5)
check("its results in words", rsync.describe_exit(0, STATS) == "Done: 2 file(s)." and rsync.describe_exit(23) == "Some files could not be copied (see above)."
      and rsync.describe_exit(0, "Number of regular files transferred: 0") == "Nothing needed copying (0 files).")
if sys.platform != "win32" and rsync.find():
    import subprocess as _sp
    r = _sp.run([rsync.find()] + a, capture_output=True, text=True)
    check("for real: it copies the tree and leaves the hidden file", r.returncode == 0 and (dst / "sub" / "b.cfg").read_text() == "B"
          and not (dst / ".hidden").exists() and rsync.count_copied(r.stdout) == 2, r.stdout[-200:] + r.stderr)

print("== start when I sign in (Linux)")
from core import autostart
os.environ["XDG_CONFIG_HOME"] = str(Path(SP) / "xdg")
check("off to begin with", not autostart.enabled())
autostart.set_enabled(True)
entry = autostart.path().read_text()
check("on: a desktop entry in the autostart folder that starts Toner minimized", autostart.enabled() and autostart.path().parent.name == "autostart"
      and "--minimized" in entry and "[Desktop Entry]" in entry)
os.environ["APPIMAGE"] = "/home/me/Apps/Toner-1.7.0-x86_64.AppImage"
check("from an AppImage, the AppImage is what starts", autostart.command() == "/home/me/Apps/Toner-1.7.0-x86_64.AppImage --minimized")
del os.environ["APPIMAGE"]
autostart.set_enabled(False)
check("off again: the entry is gone", not autostart.enabled())

print("== Windows devices: 'This computer' only where Toner runs on Windows")
from core import vendors
modes = [k for k, _l in vendors.get("windows")["platforms"]]
check("agents and WinRM everywhere; this computer only on Windows", modes[:2] == ["agent", "winrm"] and (("local" in modes) == (sys.platform == "win32")), modes)

print("== updates on Linux: the AppImage")
from core import updates
check("the AppImage is recognised by its name", updates.APPIMAGE.match("Toner-1.7.0-x86_64.AppImage").group(1) == "1.7.0"
      and not updates.APPIMAGE.match("Toner-Setup-1.7.0.exe"))
check("each system downloads its own", updates.SETUP is (updates.WINDOWS_SETUP if sys.platform == "win32" else updates.APPIMAGE))
real_win = platforms.WINDOWS
platforms.WINDOWS = False
real_frozen = getattr(sys, "frozen", None); sys.frozen = True
os.environ["APPIMAGE"] = str(Path(SP) / "Toner-1.6.0-x86_64.AppImage")
check("running from an AppImage, it can update itself", updates.installed_kind() == "appimage" and updates.can_self_update())
old = Path(os.environ["APPIMAGE"]); old.write_bytes(b"old")
new = Path(SP) / "Toner-1.7.0-x86_64.AppImage"; new.write_bytes(b"new version")
real_popen = updates.subprocess.Popen; started = []
updates.subprocess.Popen = lambda argv, **k: started.append(argv)
updates.replace_appimage(str(new), relaunch=True)
check("the new AppImage replaces the running one, runnable, and is started", old.read_bytes() == b"new version"
      and os.access(old, os.X_OK) or sys.platform == "win32" and old.read_bytes() == b"new version")
check("...and is started", started == [[str(old)]], started)
updates.subprocess.Popen = real_popen
del os.environ["APPIMAGE"]
if real_frozen is None: del sys.frozen
else: sys.frozen = real_frozen
platforms.WINDOWS = real_win

print("== one process at a time (the vault's lock)")
lock = Path(SP) / "t.lock"
with platforms.FileLock(lock) as a:
    check("a lock is taken", a.locked)
with platforms.FileLock(lock) as b:
    check("...and given back", b.locked)
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

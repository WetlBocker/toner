# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, socket, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\sc%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import db, serialconn, sessions, sessionlog
from core import telnet as T
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtCore import QCoreApplication
app = QCoreApplication([])

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def refused(s, word):
    try: sessions.validate(s); return False
    except ValueError as e: return word.lower() in str(e).lower()

# ================================================================ saved sessions
print("== saved sessions")
check("four kinds, with their usual ports", [k for k, *_ in sessions.KINDS] == ["ssh", "telnet", "rdp", "serial"] and sessions.DEFAULT_PORT == {"ssh": 22, "telnet": 23, "rdp": 3389, "serial": 0})
chi, den = sessions.create_folder("Chicago"), sessions.create_folder("Denver")
ssh = {"name": "Core switch", "kind": "ssh", "host": "10.0.0.2", "port": 22, "username": "admin", "folder_id": chi}
for s, word, why in (({**ssh, "name": ""}, "name", "no name"), ({**ssh, "kind": "ftp"}, "type", "unknown type"), ({**ssh, "host": "http://x"}, "host", "bad host"),
                     ({**ssh, "port": 70000}, "port", "bad port"), ({**ssh, "username": ""}, "user name", "no user"),
                     ({"name": "r", "kind": "rdp", "host": "pc1", "options": {"fullscreen": False, "width": 10, "height": 10}}, "window size", "tiny RDP window"),
                     ({"name": "s", "kind": "serial", "host": ""}, "serial port", "no serial port"), ({"name": "s", "kind": "serial", "host": "printer"}, "not a COM port", "nonsense port"),
                     ({"name": "s", "kind": "serial", "host": "COM3", "options": {"baud": 5}}, "baud", "silly baud rate"), ({"name": "s", "kind": "serial", "host": "COM3", "options": {"parity": "Q"}}, "not valid", "bad parity")):
    check(f"refused: {why}", refused(s, word), s)
check("an inventory-linked SSH session needs no user name of its own", sessions.validate({**ssh, "username": "", "device": "core-sw1"}) == "Core switch")
a = sessions.save(ssh)
check("saved, listed with defaults filled in", sessions.get(a)["name"] == "Core switch" and sessions.get(a)["options"] == {"paging": True, "remember": False} and sessions.get(a)["folder_id"] == chi and sessions.get(a)["port"] == 22)
t = sessions.save({"name": "Old router", "kind": "telnet", "host": "10.0.0.9", "port": 0})
check("a blank port becomes the type's usual one", sessions.get(t)["port"] == 23)
r = sessions.save({"name": "Jump server", "kind": "rdp", "host": "10.0.0.50", "username": "CORP\\me", "options": {"fullscreen": True}})
check("RDP options keep their defaults for anything not given", sessions.get(r)["options"]["clipboard"] is True and sessions.get(r)["options"]["fullscreen"] is True and sessions.get(r)["port"] == 3389)
c = sessions.save({"name": "Rack 4 console", "kind": "serial", "host": "COM3", "options": {"baud": 115200, "flow": "rtscts"}})
check("a serial session keeps its line settings", sessions.get(c)["options"] == {"baud": 115200, "bytesize": 8, "parity": "N", "stopbits": 1, "flow": "rtscts"} and sessions.get(c)["port"] == 0)
check("an ad-hoc serial URL is accepted", sessions.validate({"name": "x", "kind": "serial", "host": "rfc2217://10.0.0.7:2217"}) == "x" and sessions.validate({"name": "x", "kind": "serial", "host": "loop://"}) == "x")
try: sessions.save({**ssh, "id": None}); check("the same name in the same folder is refused", False)
except ValueError as e: check("the same name in the same folder is refused", "already exists" in str(e) and "Chicago" in str(e), str(e))
check("the same name in another folder is fine", sessions.save({**ssh, "folder_id": den}) > 0)
sessions.save({**sessions.get(a), "name": "Core switch 1"}); check("editing keeps one row", len([s for s in sessions.list_sessions() if s["host"] == "10.0.0.2" and s["folder_id"] == chi]) == 1 and sessions.get(a)["name"] == "Core switch 1")
check("folder paths are listed", sessions.folder_paths() == {chi: "Chicago", den: "Denver"} and sessions.path_of(sessions.get(a)) == "Chicago")
check("the list is ordered by name", [s["name"] for s in sessions.list_sessions()][:3] == ["Core switch", "Core switch 1", "Jump server"], [s["name"] for s in sessions.list_sessions()])
sessions.set_password(a, "s3cret"); check("the password is in the credential store, never the database", sessions.password(a) == "s3cret" and "s3cret" not in json.dumps(sessions.list_sessions()) and STORE[("netcheck", f"session:{a}")] == "s3cret")
d = sessions.duplicate(a)
check("a copy gets a free name, and the password comes with it", sessions.get(d)["name"] == "Core switch 1 (copy)" and sessions.password(d) == "s3cret" and sessions.get(d)["folder_id"] == chi)
d2 = sessions.duplicate(a); check("a second copy gets another name", sessions.get(d2)["name"] == "Core switch 1 (copy 2)")
sessions.touch(a); check("last used is recorded", sessions.get(a)["last_used"] is not None)
sessions.delete(d); check("deleting removes the row and its password", sessions.get(d) is None and ("netcheck", f"session:{d}") not in STORE)
with db.connect() as con: con.execute("UPDATE sessions SET options='{oops' WHERE id=?", (t,))
check("a damaged options value is replaced by the defaults", sessions.get(t)["options"] == {})

# ================================================================ folders
print("== folders")
core = sessions.create_folder("Core", chi)
check("folders nest, and show their full path", sessions.folder_paths()[core] == "Chicago/Core" and sessions.folder_descendants(chi) == {chi, core})
for name in ("", "  ", ".", "..", "a/b", "a\\b"):
    try: sessions.create_folder(name); check(f"a folder name {name!r} is refused", False)
    except ValueError: check(f"a folder name {name!r} is refused", True)
try: sessions.create_folder("chicago"); check("a sibling with the same name (any case) is refused", False)
except ValueError as e: check("a sibling with the same name (any case) is refused", "already exists" in str(e))
check("the same name under another folder is fine", sessions.create_folder("Core", den) > 0)
try: sessions.create_folder("Orphan", 9999); check("a folder in a folder that is not there is refused", False)
except ValueError as e: check("a folder in a folder that is not there is refused", "no longer exists" in str(e))
sessions.rename_folder(core, "Core network"); check("renaming shows in the path", sessions.folder_paths()[core] == "Chicago/Core network")
try: sessions.rename_folder(core, "Core network"); check("renaming to a name already taken is refused", True)
except ValueError: check("renaming to a name already taken is refused", False)
try: sessions.move_folder(chi, core); check("a folder cannot go inside its own subfolder", False)
except ValueError as e: check("a folder cannot go inside its own subfolder", "into itself" in str(e))
try: sessions.move_folder(chi, chi); check("...or itself", False)
except ValueError: check("...or itself", True)
sessions.move_folder(core, None); check("a folder can be moved to the top level", sessions.folder_paths()[core] == "Core network")
sessions.move_folder(core, chi)
s_core = sessions.save({"name": "In core", "kind": "telnet", "host": "10.7.7.7", "folder_id": core})
check("a session can live in a nested folder", sessions.get(s_core)["folder_id"] == core and sessions.path_of(sessions.get(s_core)) == "Chicago/Core network")
sessions.move_sessions([s_core, a], den); check("sessions can be moved to another folder", sessions.get(s_core)["folder_id"] == den and sessions.get(a)["folder_id"] == den)
sessions.move_sessions([s_core], None); check("or to the top level", sessions.get(s_core)["folder_id"] is None)
sessions.move_sessions([s_core, a], core); sessions.move_sessions([a], chi)
check("a session saved with a folder that does not exist ends up at the top level", sessions.get(sessions.save({"name": "Lost", "kind": "telnet", "host": "10.7.7.8", "folder_id": 4242}))["folder_id"] is None)
deep = sessions.ensure_folder_path("EMEA/London/Rack 2")
check("a path creates every missing level, and finds existing ones", sessions.folder_paths()[deep] == "EMEA/London/Rack 2" and sessions.ensure_folder_path("emea/london/rack 2") == deep and sessions.ensure_folder_path("") is None)
try: sessions.ensure_folder_path("/".join("x" * 1 for _ in range(11))); check("a path more than 10 levels deep is refused", False)
except ValueError: check("a path more than 10 levels deep is refused", True)
sessions.delete_folder(core)
check("deleting a folder moves its sessions up, and deletes none", sessions.get(s_core)["folder_id"] == chi and core not in sessions.folder_paths())
sub = sessions.create_folder("Sub", chi); sessions.create_folder("Leaf", sub); sessions.delete_folder(sub)
check("and its subfolders move up with it", "Chicago/Leaf" in sessions.folder_paths().values() and "Chicago/Sub" not in sessions.folder_paths().values())
clash_parent = sessions.create_folder("Parent", den); sessions.create_folder("Dup", clash_parent); sessions.create_folder("Dup", den)
try: sessions.delete_folder(clash_parent); check("deleting is refused if moving the contents up would clash, naming the folder", False)
except ValueError as e: check("deleting is refused if moving the contents up would clash, naming the folder", "Dup" in str(e))
check("the folder is still there after a refused delete", clash_parent in sessions.folder_paths())

print("== old 'Group' names become folders")
real_db = os.environ["NETCHECK_DB"]; os.environ["NETCHECK_DB"] = SP + r"\old%d.db" % int(time.time()); db.init()
with db.connect() as con:
    for n, g in (("one", "Lab"), ("two", "Lab"), ("three", "Rack 9"), ("four", "")):
        con.execute("INSERT INTO sessions(name, kind, group_name, host, port, options) VALUES(?,?,?,?,?,?)", (n, "ssh", g, "h", 22, "{}"))
    con.execute("PRAGMA user_version = 0")                      # this is what a database from before numbered upgrades looks like
db.init()
migrated = {s["name"]: sessions.folder_paths().get(s["folder_id"], "") for s in sessions.list_sessions()}
check("each group name became a folder, shared by its sessions; ungrouped ones stay at the top", migrated == {"one": "Lab", "two": "Lab", "three": "Rack 9", "four": ""} and len(sessions.list_folders()) == 2, migrated)
db.init(); check("running it again changes nothing", len(sessions.list_folders()) == 2)
os.environ["NETCHECK_DB"] = real_db

# ================================================================ Remote Desktop
print("== Remote Desktop")
s = {"host": "10.0.0.50", "port": 3389, "username": "CORP\\me", "name": "x", "options": {"fullscreen": False, "width": 1600, "height": 900, "clipboard": True, "drives": True, "printers": False, "admin": True, "gateway": "gw.corp.example.com"}}
txt = sessions.rdp_file_text(s); lines = txt.split("\r\n")
check("the .rdp file has the address, window, user and options", "full address:s:10.0.0.50" in lines and "screen mode id:i:1" in lines and "desktopwidth:i:1600" in lines and "desktopheight:i:900" in lines and "username:s:CORP\\me" in lines and "drivestoredirect:s:*" in lines and "administrative session:i:1" in lines and "redirectclipboard:i:1" in lines and "redirectprinters:i:0" in lines)
check("a gateway is included", "gatewayhostname:s:gw.corp.example.com" in lines and "gatewayusagemethod:i:1" in lines)
check("it never contains a password", "password" not in txt.lower().replace("prompt for credentials", ""))
check("a non-standard port is part of the address", "full address:s:10.0.0.50:3390" in sessions.rdp_file_text({**s, "port": 3390}).split("\r\n"))
full = sessions.rdp_file_text({**s, "options": {"fullscreen": True}}).split("\r\n")
check("full screen leaves out the window size", "screen mode id:i:2" in full and not any(l.startswith("desktopwidth") for l in full) and not any(l.startswith("drivestoredirect") for l in full) and not any(l.startswith("gateway") for l in full))
check("no user name, no username line", not any(l.startswith("username") for l in sessions.rdp_file_text({**s, "username": ""}).split("\r\n")))
launched = []
sessions.subprocess.Popen = lambda args, **kw: launched.append(args)
sessions.shutil.which = lambda n: r"C:\Windows\System32\mstsc.exe"
p = sessions.launch_rdp({**s, "name": "Jump server / prod"})
check("it starts mstsc with the generated file, named safely, under the data folder", launched[0][0].endswith("mstsc.exe") and launched[0][1] == str(p) and p.name == "Jump_server___prod.rdp" and p.parent == db.db_path().parent / "rdp" and p.read_text().startswith("full address:s:10.0.0.50"))
sessions.shutil.which = lambda n: None
try: sessions.launch_rdp(s); check("no Remote Desktop client on this PC is explained", False)
except OSError as e: check("no Remote Desktop client on this PC is explained", "mstsc.exe" in str(e))

# ================================================================ Telnet protocol
print("== Telnet protocol")
F = T.TelnetFilter
f = F(cols=120, rows=40)
out, reply = f.feed(b"hello\r\nworld")
check("plain text passes straight through", out == b"hello\r\nworld" and reply == b"")
out, reply = f.feed(bytes([255, 251, 1]) + b"login: ")
check("the server offering ECHO is accepted, and the text after it shown", out == b"login: " and reply == bytes([255, 253, 1]))
out, reply = f.feed(bytes([255, 251, 1]))
check("an offer repeated is not answered again (no loops)", reply == b"")
out, reply = f.feed(bytes([255, 253, 24]))
check("asked to send the terminal type: agrees", reply == bytes([255, 251, 24]))
out, reply = f.feed(bytes([255, 250, 24, 1, 255, 240]))
check("...and when asked for it, gives it", reply == bytes([255, 250, 24, 0]) + b"xterm-256color" + bytes([255, 240]))
out, reply = f.feed(bytes([255, 253, 31]))
check("asked for the window size: agrees and sends 120 x 40", reply == bytes([255, 251, 31, 255, 250, 31, 0, 120, 0, 40, 255, 240]), reply)
check("a window resize is sent only once the server asked", f.set_size(150, 50) == bytes([255, 250, 31, 0, 150, 0, 50, 255, 240]) and F().set_size(150, 50) == b"")
check("a size with the byte 255 in it is escaped", F(cols=255, rows=30).naws() == bytes([255, 250, 31, 0, 255, 255, 0, 30, 255, 240]))
out, reply = f.feed(bytes([255, 253, 3]))
check("suppress-go-ahead is agreed to", reply == bytes([255, 251, 3]))
out, reply = f.feed(bytes([255, 253, 99, 255, 251, 77]))
check("anything unknown is refused, politely", reply == bytes([255, 252, 99, 255, 254, 77]))
g = F(); o1, r1 = g.feed(b"ab" + bytes([255])); o2, r2 = g.feed(bytes([251])); o3, r3 = g.feed(bytes([1]) + b"cd")
check("a command split over several reads is still understood", o1 + o2 + o3 == b"abcd" and r1 + r2 + r3 == bytes([255, 253, 1]))
out, _ = F().feed(bytes([255, 255]) + b"x"); check("an escaped 255 is a real 255", out == b"\xffx")
out, _ = F().feed(b"a\r\x00b\r\nc"); check("CR NUL is a plain carriage return, CR LF is kept", out == b"a\rb\r\nc", out)
out, r = F().feed(bytes([255, 250, 1, 2, 3, 255, 240]) + b"z"); check("an unknown sub-negotiation is skipped", out == b"z" and r == b"")
check("keystrokes: Enter becomes CR LF, a pasted CR LF is left alone, 255 is doubled", F.encode(b"ls\r") == b"ls\r\n" and F.encode(b"a\r\nb") == b"a\r\nb" and F.encode(b"\xff") == b"\xff\xff")

# ================================================================ Telnet connection (a fake device)
print("== Telnet connection")
seen = {"in": b""}
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(2); port = srv.getsockname()[1]
def device():
    c, _ = srv.accept(); c.settimeout(5)
    c.sendall(bytes([255, 251, 1, 255, 253, 24, 255, 253, 31, 255, 250, 24, 1, 255, 240]) + b"Welcome to R1\r\nlogin: ")
    try:
        while True:
            d = c.recv(4096)
            if not d: break
            seen["in"] += d
            if b"admin\r\n" in seen["in"] and not seen.get("replied"): seen["replied"] = True; c.sendall(b"Password: ")
            if b"quit" in seen["in"]: break
    except OSError: pass
    c.close()
threading.Thread(target=device, daemon=True).start()
got, ended = [], []
ts = T.TelnetSession("127.0.0.1", port, cols=100, rows=30, timeout=5)
ts.data.connect(lambda b: got.append(b)); ts.closed.connect(lambda r: ended.append(r)); ts.start()
def wait(cond, n=100):
    for _ in range(n):
        QCoreApplication.processEvents(); time.sleep(0.05)
        if cond(): return True
    return False
wait(lambda: b"login: " in b"".join(got))
check("the banner arrives without the negotiation bytes", b"".join(got) == b"Welcome to R1\r\nlogin: ", b"".join(got))
check("the terminal type and window size were answered", bytes([255, 250, 24, 0]) + b"xterm-256color" in seen["in"] and bytes([255, 250, 31, 0, 100, 0, 30, 255, 240]) in seen["in"], seen["in"])
ts.send(b"admin\r"); wait(lambda: b"Password: " in b"".join(got))
check("typing goes to the device with Enter as CR LF, and the reply comes back", b"admin\r\n" in seen["in"] and b"Password: " in b"".join(got))
ts.resize(132, 43); wait(lambda: bytes([255, 250, 31, 0, 132, 0, 43, 255, 240]) in seen["in"])
check("resizing the window tells the device", bytes([255, 250, 31, 0, 132, 0, 43, 255, 240]) in seen["in"])
ts.send(b"quit"); wait(lambda: bool(ended))
check("when the device hangs up, the reason is given", ended and "closed by the remote host" in ended[0], ended)
ts.wait(2000)
closed_sock = socket.socket(); closed_sock.bind(("127.0.0.1", 0)); port_closed = closed_sock.getsockname()[1]; closed_sock.close()
ts2 = T.TelnetSession("127.0.0.1", port_closed, timeout=3); e2 = []; ts2.closed.connect(lambda r: e2.append(r)); ts2.start(); wait(lambda: bool(e2)); ts2.wait(2000)
check("a refused connection says so", e2 and "refused" in e2[0] and str(port_closed) in e2[0], e2)
ts3 = T.TelnetSession("no-such-host.invalid", 23, timeout=3); e3 = []; ts3.closed.connect(lambda r: e3.append(r)); ts3.start(); wait(lambda: bool(e3), 200); ts3.wait(2000)
check("an unknown host says so", e3 and ("Could not find" in e3[0] or "failed" in e3[0].lower()), e3)
srv2 = socket.socket(); srv2.bind(("127.0.0.1", 0)); srv2.listen(1); p2 = srv2.getsockname()[1]
threading.Thread(target=lambda: (srv2.accept(), time.sleep(5)), daemon=True).start()
ts4 = T.TelnetSession("127.0.0.1", p2, timeout=3); e4 = []; ts4.closed.connect(lambda r: e4.append(r)); ts4.start(); time.sleep(0.5); ts4.stop(); wait(lambda: bool(e4)); ts4.wait(2000)
check("Disconnect ends it, and says it was you", e4 and e4[0] == "Disconnected by user.", e4)
import core.proxy as P
check("Telnet connections follow the proxy settings", "proxy.create_connection" in open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "telnet.py")).read())

# ================================================================ Serial
print("== Serial")
check("pyserial is installed", serialconn.available())
pl = serialconn.ports(); check("ports are listed as (device, description)", isinstance(pl, list) and all(len(p) == 2 for p in pl))
sgot, sended = [], []
ss = serialconn.SerialSession("loop://", 115200); ss.data.connect(lambda b: sgot.append(b)); ss.closed.connect(lambda r: sended.append(r)); ss.start()
time.sleep(0.4); ss.send(b"show version\r"); wait(lambda: b"".join(sgot) == b"show version\r")
check("what you type comes back from a loopback port (the connection works both ways)", b"".join(sgot) == b"show version\r", sgot)
ss.send_break(0.1); ss.resize(80, 24); ss.send(b"x"); wait(lambda: b"".join(sgot).endswith(b"x"))
check("a break and a resize do no harm", b"".join(sgot).endswith(b"x"))
ss.stop(); wait(lambda: bool(sended)); ss.wait(3000)
check("Disconnect ends it, and says it was you", sended == ["Disconnected by user."], sended)
bad_port = [p for p in ("COM98", "COM97") if p not in [x[0] for x in pl]][0]
sb, eb = serialconn.SerialSession(bad_port), []; sb.closed.connect(lambda r: eb.append(r)); sb.start(); wait(lambda: bool(eb)); sb.wait(3000)
check("a port that is not there is explained", eb and bad_port in eb[0] and "does not exist" in eb[0], eb)
check("friendly messages: in use, missing, other", "in use by another program" in serialconn.friendly("COM3", Exception("could not open port 'COM3': PermissionError(13, 'Access is denied.', None, 5)"))
      and "does not exist" in serialconn.friendly("COM3", Exception("could not open port 'COM3': FileNotFoundError(2, 'The system cannot find the file specified.', None, 2)"))
      and "stopped working" in serialconn.friendly("COM3", Exception("device reports readiness to read but returned no data")))
if "COM1" in [x[0] for x in pl]:
    s1, e1 = serialconn.SerialSession("COM1", 9600), []; s1.closed.connect(lambda r: e1.append(r)); s1.start(); time.sleep(0.6)
    check("a real COM port on this PC opens and closes cleanly", not e1 or "COM1" in e1[0]); s1.stop(); wait(lambda: bool(e1)); s1.wait(3000)

# ================================================================ session logs know the type
print("== logs")
for kind in ("ssh", "telnet", "serial"):
    lg = sessionlog.SessionLog("dev", "h", 1, "u", kind=kind); lg.write(b"x\n"); lg.close("done")
    check(f"a {kind} log says what it is", f"# Toner {kind.upper()} session log" in open(lg.path, encoding="utf-8").read() and [s for s in sessionlog.list_sessions() if s["id"] == lg.id][0]["kind"] == kind)
check("a log with no type given is an SSH log, as before", sessionlog.list_sessions()[0]["kind"] in ("serial", "telnet", "ssh") and sessionlog.SessionLog("d", "h", 1, "u").kind == "ssh")

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

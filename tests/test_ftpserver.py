# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away folder, so nothing on this computer is touched.
# Toner's FTP server (core/fileserver.py FtpServer), driven with Python's own ftplib as the client.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import ftplib, io, os, socket, sys, time
SP = os.environ["SP"]
from core import fileserver as F
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

base = os.path.join(SP, "ftp%d" % int(time.time())); root = os.path.join(base, "share"); os.makedirs(os.path.join(root, "sub"))
def put_file(rel, data):
    p = os.path.join(root, *rel.split("/")); open(p, "wb").write(data); return p
open(os.path.join(base, "outside.txt"), "wb").write(b"SECRET")
put_file("hello.txt", b"hello world"); put_file("sub/inner.bin", bytes(range(256)) * 10); put_file("big.bin", os.urandom(300000))
put_file("old.bin" + F.PART, b"half")                      # an unfinished upload is never listed or served
ev = []
PASV = (50200, 50210)
CRLF = b"\r\n"
def server(**kw):
    s = F.FtpServer(root, "toner", "S3cret-pass!", port=0, bind="127.0.0.1", passive_ports=PASV, on_event=ev.append, **kw); s.start(); return s
def client(s, user="toner", password="S3cret-pass!", pasv=True):
    c = ftplib.FTP(); c.connect("127.0.0.1", s.port, timeout=10); c.login(user, password); c.set_pasv(pasv); return c
def get(c, name):
    buf = io.BytesIO(); c.retrbinary(f"RETR {name}", buf.write); return buf.getvalue()
def refused(fn):
    try: fn(); return False
    except ftplib.error_perm: return True
def send_lines(sock, *lines):
    sock.sendall(b"".join(l.encode() + CRLF for l in lines))

print("== what the server needs")
for kw, why in (({"username": "", "password": "S3cret-pass!"}, "a user name"), ({"username": "u", "password": "short"}, "8 characters"),
                ({"username": "u", "password": "S3cret-pass!", "passive_ports": (60, 50)}, "a passive range in order")):
    try: F.FtpServer(root, kw.pop("username"), kw.pop("password"), **kw); check(f"needs {why}", False)
    except ValueError: check(f"needs {why}", True)
try: F.FtpServer(os.path.join(SP, "no-such-folder"), "u", "S3cret-pass!"); check("a missing folder is refused", False)
except ValueError: check("a missing folder is refused", True)

print("== logging in and looking around")
s = server()
check("starts", s.running and s.port > 0)
raw = socket.create_connection(("127.0.0.1", s.port), timeout=5); f = raw.makefile("rb")
check("greets as Toner", f.readline().startswith(b"220 Toner FTP"))
send_lines(raw, "PWD"); check("nothing before a login", f.readline().startswith(b"530"))
send_lines(raw, "USER toner", "PASS wrong"); f.readline(); check("a wrong password is 530", f.readline().startswith(b"530"))
raw.close()
try: client(s, password="wrong"); check("ftplib: wrong password is refused", False)
except ftplib.error_perm: check("ftplib: wrong password is refused", True)
try: client(s, user="admin"); check("wrong user name is refused", False)
except ftplib.error_perm: check("wrong user name is refused", True)
c = client(s)
check("the root is the shared folder, the unfinished upload hidden", c.pwd() == "/" and set(c.nlst()) == {"hello.txt", "sub", "big.bin"}, c.nlst())
lines = []; c.retrlines("LIST", lines.append)
check("LIST is in ls -l form with sizes", any(l.startswith("-rw") and l.endswith(" hello.txt") and " 11 " in l for l in lines) and any(l.startswith("d") and l.endswith(" sub") for l in lines), lines)
rows = dict(c.mlsd())
check("MLSD gives type, size and date", rows["hello.txt"]["type"] == "file" and rows["hello.txt"]["size"] == "11" and len(rows["hello.txt"]["modify"]) == 14 and rows["sub"]["type"] == "dir", rows)
check("SIZE", c.size("big.bin") == 300000)
check("MDTM is a 14-digit stamp", c.sendcmd("MDTM hello.txt")[4:].isdigit() and len(c.sendcmd("MDTM hello.txt")) == 18)
check("FEAT names what clients look for", "MLSD" in c.sendcmd("FEAT") and "UTF8" in c.sendcmd("FEAT") and "SIZE" in c.sendcmd("FEAT"))
check("SYST, NOOP, TYPE", c.sendcmd("SYST").startswith("215") and c.sendcmd("NOOP").startswith("200") and c.sendcmd("TYPE I").startswith("200") and c.sendcmd("TYPE A").startswith("200"))
c.cwd("sub"); check("CWD into a sub-folder", c.pwd() == "/sub" and c.nlst() == ["inner.bin"])
c.cwd(".."); check("CDUP / .. goes back up", c.pwd() == "/")
check("CWD to a missing folder is 550", refused(lambda: c.cwd("nowhere")) and c.pwd() == "/")
check("an unknown command is 502", refused(lambda: c.sendcmd("SITE CHMOD 777 x")))

print("== downloads")
check("passive download is intact", get(c, "big.bin") == open(os.path.join(root, "big.bin"), "rb").read())
check("a file in a sub-folder by path", get(c, "sub/inner.bin") == bytes(range(256)) * 10)
check("EPSV works too", c.sendcmd("EPSV").startswith("229") and get(c, "hello.txt") == b"hello world")
c.set_pasv(False)
check("active mode (PORT, as Cisco IOS uses by default) is intact", get(c, "big.bin") == open(os.path.join(root, "big.bin"), "rb").read())
check("active mode twice in a row (no fixed source port to clash)", get(c, "hello.txt") == b"hello world" and get(c, "hello.txt") == b"hello world")
c.set_pasv(True)
check("a missing file is 550", refused(lambda: get(c, "missing.bin")))
for n in ("../outside.txt", "sub/../../outside.txt", "..\\outside.txt", "C:/Windows/win.ini", "hello.txt::$DATA", "old.bin" + F.PART):
    try: got = get(c, n); leaked = b"SECRET" in got or b"half" in got
    except ftplib.error_perm: leaked = False
    check(f"escape attempt gets nothing: {n}", not leaked)
check("PORT to another address is refused (no bouncing)", refused(lambda: c.sendcmd("PORT 10,0,0,9,0,80")))
try: c.sendcmd("ABOR"); c.voidcmd("NLST"); check("a listing without PORT or PASV first is 425", False)
except ftplib.error_temp as e: check("a listing without PORT or PASV first is 425", str(e).startswith("425"), e)

print("== read-only by default")
check("STOR is refused", refused(lambda: c.storbinary("STOR new.txt", io.BytesIO(b"x"))) and not os.path.exists(os.path.join(root, "new.txt")))
check("DELE is refused", refused(lambda: c.delete("hello.txt")) and os.path.exists(os.path.join(root, "hello.txt")))
check("MKD is refused", refused(lambda: c.mkd("newdir")) and not os.path.exists(os.path.join(root, "newdir")))
check("RNFR is refused", refused(lambda: c.rename("hello.txt", "h2.txt")) and os.path.exists(os.path.join(root, "hello.txt")))
c.quit(); time.sleep(0.2)
check("logins, reads and refusals are reported", any(e["op"] == "login" and e["status"] == "ok" and e["note"] == "user toner" for e in ev)
      and any(e["op"] == "read" and e["path"] == "/big.bin" and e["bytes"] == 300000 and e["status"] == "ok" and "Mbit/s" in e["note"] for e in ev)
      and any(e["op"] == "write" and e["status"] == "denied" and "switched off" in e["note"] for e in ev)
      and any(e["op"] == "login" and e["status"] == "denied" for e in ev), [e for e in ev if e["status"] != "ok"][:5])
check("the password is in no event", not any("S3cret" in str(e) for e in ev))

print("== five wrong passwords lock the address out")
s.forgive("127.0.0.1")                                     # a success earlier forgave the address; start clean
t0 = time.time()
for _ in range(5):
    try: client(s, password="wrong")
    except Exception: pass
check("a wrong guess is slowed down", time.time() - t0 >= 4.5)
try: client(s); locked = False
except Exception: locked = True
check("...then even the right password is refused for a while", locked and any("too many" in e["note"] for e in ev))
s.stop(); check("stop", not s.running)

print("== uploads")
ev.clear(); s = server(allow_write=True, max_bytes=400000)
c = client(s)
c.storbinary("STOR up.txt", io.BytesIO(b"uploaded via ftp")); check("upload a new file", open(os.path.join(root, "up.txt"), "rb").read() == b"uploaded via ftp")
data = os.urandom(250000); c.storbinary("STOR up.bin", io.BytesIO(data)); check("a large upload is intact", open(os.path.join(root, "up.bin"), "rb").read() == data)
c.set_pasv(False); c.storbinary("STOR up2.bin", io.BytesIO(data)); c.set_pasv(True); check("an active-mode upload is intact", open(os.path.join(root, "up2.bin"), "rb").read() == data)
check("replacing is refused by default", refused(lambda: c.storbinary("STOR up.txt", io.BytesIO(b"over"))) and open(os.path.join(root, "up.txt"), "rb").read() == b"uploaded via ftp")
check("deleting is refused by default", refused(lambda: c.delete("up.txt")) and os.path.exists(os.path.join(root, "up.txt")))
c.mkd("made"); check("create a folder", os.path.isdir(os.path.join(root, "made")))
try: c.storbinary("STOR toobig.bin", io.BytesIO(os.urandom(500000))); refused_big = False
except (ftplib.error_temp, ftplib.error_perm, OSError, EOFError): refused_big = True     # (the server may reset the data connection first)
def leftovers(): return [n for n in os.listdir(root) if n.startswith("toobig")]
for _ in range(50):                                       # the server removes the unfinished file on its own thread
    if not leftovers(): break
    time.sleep(0.05)
check("an upload past the size limit is refused and nothing of it is kept", refused_big and not leftovers(), leftovers())
c.close(); time.sleep(0.2)
check("the refusal names the limit in words", any(e["op"] == "write" and e["path"] == "/toobig.bin" and e["status"] == "failed" and "391 KB limit" in e["note"] for e in ev),
      [e["note"] for e in ev if e["path"] == "/toobig.bin"])
c = client(s)                                             # (a fresh connection: the refused upload's 426 is still queued on the old one)
check("an upload cannot leave the folder", refused(lambda: c.storbinary("STOR ../escape.txt", io.BytesIO(b"x"))) or not os.path.exists(os.path.join(base, "escape.txt")))
check("...nor go into a folder that does not exist", refused(lambda: c.storbinary("STOR nodir/x.txt", io.BytesIO(b"x"))))
c.quit(); time.sleep(0.2)
check("uploads are reported", any(e["op"] == "write" and e["path"] == "/up.bin" and e["bytes"] == 250000 and e["status"] == "ok" for e in ev)
      and any(e["op"] == "mkdir" and e["path"] == "/made" and e["status"] == "ok" for e in ev))
s.stop()
s = server(allow_write=True, allow_overwrite=True); c = client(s)
c.storbinary("STOR up.txt", io.BytesIO(b"replaced")); check("replacing works once switched on", open(os.path.join(root, "up.txt"), "rb").read() == b"replaced")
c.rename("up.txt", "moved.txt"); check("rename", os.path.exists(os.path.join(root, "moved.txt")) and not os.path.exists(os.path.join(root, "up.txt")))
check("a rename cannot overwrite another file", refused(lambda: c.rename("moved.txt", "hello.txt")) and open(os.path.join(root, "hello.txt"), "rb").read() == b"hello world")
c.delete("moved.txt"); c.rmd("made"); check("delete a file and a folder", not os.path.exists(os.path.join(root, "moved.txt")) and not os.path.exists(os.path.join(root, "made")))
c.quit(); s.stop()

print("== a device that hangs up")
ev.clear(); s = server()
raw = socket.create_connection(("127.0.0.1", s.port), timeout=5); f = raw.makefile("rb"); f.readline()
send_lines(raw, "USER toner", "PASS S3cret-pass!"); f.readline(); f.readline()
raw.close(); time.sleep(0.5)                              # gone without QUIT, as a device may
check("the session just ends: nothing is reported as failed", not [e for e in ev if e["status"] == "failed"], ev)
c = client(s); check("and the server goes on serving", c.pwd() == "/"); c.quit(); s.stop()

print("== who may connect")
ev.clear(); s = server(allowed="10.0.0.0/8")
try: client(s); turned_away = False
except Exception: turned_away = True
time.sleep(0.2)
check("a client outside the allowed list is turned away, and it is reported", turned_away and any("allowed" in e["note"] for e in ev))
s.stop()
s = server(allowed="127.0.0.1"); c = client(s); check("a named client may", c.pwd() == "/"); c.quit(); s.stop()

print("== the passive address and a busy range")
s = F.FtpServer(root, "toner", "S3cret-pass!", port=0, bind="127.0.0.1", passive_ports=PASV, advertise="10.1.2.3"); s.start()
raw = socket.create_connection(("127.0.0.1", s.port), timeout=5); f = raw.makefile("rb"); f.readline()
send_lines(raw, "USER toner", "PASS S3cret-pass!", "PASV"); f.readline(); f.readline(); line = f.readline()
check("PASV tells the device the address it was asked to advertise", b"(10,1,2,3," in line, line)
m = line.split(b"(")[1].split(b")")[0].split(b",")
check("...on a port in the passive range", PASV[0] <= int(m[4]) * 256 + int(m[5]) <= PASV[1], line)
raw.close(); s.stop()
a = server(); b = F.FtpServer(root, "toner", "S3cret-pass!", port=a.port, bind="127.0.0.1", passive_ports=PASV)
try: b.start(); check("a port that is taken is reported", False)
except OSError: check("a port that is taken is reported", True)
a.stop()
check("a listing line is in the form clients parse", F._ls_line("x.bin", os.stat(os.path.join(root, "big.bin"))).startswith("-rw-r--r-- 1 toner toner       300000 "))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

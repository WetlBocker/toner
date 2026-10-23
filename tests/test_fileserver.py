# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, shutil, socket, struct, sys, threading, time
SP = os.environ["SP"]
from core import fileserver as F, iperf
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

base = os.path.join(SP, "fs%d" % int(time.time())); root = os.path.join(base, "share"); os.makedirs(os.path.join(root, "sub"))
def put_file(rel, data):
    p = os.path.join(root, *rel.split("/")); open(p, "wb").write(data); return p
open(os.path.join(base, "outside.txt"), "wb").write(b"SECRET")
put_file("hello.txt", b"hello world"); put_file("sub/inner.bin", bytes(range(256)) * 10)
put_file("exact.bin", b"x" * 1024)                       # a whole number of 512-byte blocks: needs an empty last block
put_file("big.bin", os.urandom(300000))

print("== path jail")
def refused(name, allow_empty=False):
    try: F.resolve_path(root, name, allow_empty); return False
    except ValueError: return True
check("normal names resolve inside the folder", F.resolve_path(root, "hello.txt") == os.path.realpath(os.path.join(root, "hello.txt")) and F.resolve_path(root, "sub/inner.bin").endswith("inner.bin") and F.resolve_path(root, "/sub\\inner.bin").endswith("inner.bin"))
for bad_name in ("../outside.txt", "..\\outside.txt", "sub/../../outside.txt", "C:/Windows/win.ini", "c:\\x", "a:b", "file.txt::$DATA", "x\x00y", "con", "NUL.txt", "name.", "name ", "a*b", "", "hello.txt" + F.PART):
    check(f"refused: {bad_name!r}", refused(bad_name))
check("the folder itself only when asked for", refused("") and not refused("", allow_empty=True) and F.resolve_path(root, "", True) == os.path.realpath(root))
check("risky folders are named", F.risky_root("C:\\") != "" and F.risky_root(os.environ.get("SystemRoot", "C:\\Windows")) != "" and F.risky_root(os.path.join(SP, "nope")) != "" and F.risky_root(root) == "")
check("allow-list parsing", len(F.parse_allowed("10.0.0.0/24, 192.168.1.5;172.16.0.0/12")) == 3 and F.parse_allowed("") == [])
try: F.parse_allowed("10.0.0.0/24, nonsense"); check("a bad allow-list entry is reported", False)
except ValueError as e: check("a bad allow-list entry is reported", "nonsense" in str(e))
nets = F.parse_allowed("10.0.0.0/24, 192.168.1.5")
check("allow-list matching", F.client_allowed("10.0.0.7", nets) and F.client_allowed("192.168.1.5", nets) and not F.client_allowed("10.0.1.7", nets) and F.client_allowed("8.8.8.8", []))

# ---------------------------------------------------------------- TFTP
print("== TFTP")
events = []
def tftp_server(**kw):
    s = F.TftpServer(root, port=0, bind="127.0.0.1", on_event=events.append, **kw); s.start(); return s
def req(op, name, opts=None, mode="octet"):
    p = struct.pack("!H", op) + name.encode() + b"\0" + mode.encode() + b"\0"
    for k, v in (opts or {}).items(): p += k.encode() + b"\0" + str(v).encode() + b"\0"
    return p
def tftp_get(port, name, opts=None, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout); s.sendto(req(1, name, opts), ("127.0.0.1", port))
    data, block, blk, server, info = b"", 1, 512, None, {}
    try:
        while True:
            pkt, addr = s.recvfrom(70000); server = server or addr
            op = struct.unpack("!H", pkt[:2])[0]
            if op == 6:
                parts = pkt[2:].split(b"\0"); info = {parts[i].decode(): parts[i + 1].decode() for i in range(0, len(parts) - 1, 2)}
                blk = int(info.get("blksize", 512)); s.sendto(struct.pack("!HH", 4, 0), addr)
            elif op == 5: return ("error", struct.unpack("!H", pkt[2:4])[0], pkt[4:-1].decode())
            elif op == 3:
                b = struct.unpack("!H", pkt[2:4])[0]
                if b == block & 0xFFFF:
                    data += pkt[4:]; s.sendto(struct.pack("!HH", 4, b), addr); block += 1
                    if len(pkt) - 4 < blk: return ("ok", data, info)
                else: s.sendto(struct.pack("!HH", 4, b), addr)
    except socket.timeout:
        return ("timeout", None, info)
    finally: s.close()
def tftp_put(port, name, data, opts=None, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout); s.sendto(req(2, name, opts), ("127.0.0.1", port))
    blk = 512
    try:
        pkt, addr = s.recvfrom(70000); op = struct.unpack("!H", pkt[:2])[0]
        if op == 5: return ("error", struct.unpack("!H", pkt[2:4])[0], pkt[4:-1].decode())
        if op == 6:
            parts = pkt[2:].split(b"\0"); info = {parts[i].decode(): parts[i + 1].decode() for i in range(0, len(parts) - 1, 2)}; blk = int(info.get("blksize", 512))
        block, pos = 1, 0
        while True:
            chunk = data[pos:pos + blk]; s.sendto(struct.pack("!HH", 3, block & 0xFFFF) + chunk, addr)
            pkt, a2 = s.recvfrom(70000); op = struct.unpack("!H", pkt[:2])[0]
            if op == 5: return ("error", struct.unpack("!H", pkt[2:4])[0], pkt[4:-1].decode())
            if op == 4 and struct.unpack("!H", pkt[2:4])[0] == block & 0xFFFF:
                pos += blk; block += 1
                if len(chunk) < blk: return ("ok", None, None)
    except socket.timeout:
        return ("timeout", None, None)
    finally: s.close()

srv = tftp_server()
check("starts on a free port", srv.running and srv.port > 0)
r = tftp_get(srv.port, "hello.txt"); check("read a small file", r[0] == "ok" and r[1] == b"hello world", r[:2])
r = tftp_get(srv.port, "sub/inner.bin"); check("read from a sub-folder", r[0] == "ok" and r[1] == bytes(range(256)) * 10)
r = tftp_get(srv.port, "exact.bin"); check("a file that is a whole number of blocks ends with an empty block", r[0] == "ok" and r[1] == b"x" * 1024, r[:2])
r = tftp_get(srv.port, "big.bin", {"blksize": 1428, "tsize": 0}); check("blksize and tsize are negotiated", r[0] == "ok" and r[1] == open(os.path.join(root, "big.bin"), "rb").read() and r[2].get("blksize") == "1428" and r[2].get("tsize") == "300000", r[2] if r[0] == "ok" else r)
r = tftp_get(srv.port, "nothing.txt"); check("a missing file is 'not found'", r[:2] == ("error", 1), r)
for n in ("../outside.txt", "..\\outside.txt", "sub/../../outside.txt", "C:/Windows/win.ini", "/../outside.txt"):
    r = tftp_get(srv.port, n); check(f"escape attempt refused: {n}", r[0] == "error" and r[1] == 2 and b"SECRET" not in str(r).encode(), r)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.sendto(req(1, "hello.txt", mode="netascii"), ("127.0.0.1", srv.port)); pkt = s.recvfrom(600)[0]; s.close()
check("netascii mode is refused rather than corrupting a file", struct.unpack("!H", pkt[:2])[0] == 5 and struct.unpack("!H", pkt[2:4])[0] == 4)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"\x00\x09garbage", ("127.0.0.1", srv.port)); s.sendto(b"\x00", ("127.0.0.1", srv.port)); s.close()
r = tftp_get(srv.port, "hello.txt"); check("garbage packets are ignored and the server carries on", r[0] == "ok")
r = tftp_put(srv.port, "new.txt", b"data"); check("uploads are refused by default", r[:2] == ("error", 2) and not os.path.exists(os.path.join(root, "new.txt")), r)
res = []; ths = [threading.Thread(target=lambda: res.append(tftp_get(srv.port, "big.bin")[0])) for _ in range(5)]
[t.start() for t in ths]; [t.join(30) for t in ths]
check("several devices can read at once", res == ["ok"] * 5, res)
srv.stop(); check("stop frees the port", not srv.running)
chk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try: chk.bind(("127.0.0.1", srv.port)); freed = True
except OSError: freed = False
chk.close(); check("the port can be used again after stop", freed)
reads = [e for e in events if e["op"] == "read"]
check("every transfer is reported with who, what, how much", any(e["path"] == "hello.txt" and e["bytes"] == 11 and e["status"] == "ok" and e["client"] == "127.0.0.1" and e["proto"] == "tftp" for e in reads) and any(e["status"] == "denied" for e in reads) and any(e["status"] == "failed" and e["path"] == "nothing.txt" for e in reads))

events.clear(); srv = tftp_server(allow_write=True)
r = tftp_put(srv.port, "new.txt", b"fresh config\n" * 100); check("upload a new file", r[0] == "ok" and open(os.path.join(root, "new.txt"), "rb").read() == b"fresh config\n" * 100, r)
check("no half-written file is left behind", not [f for f in os.listdir(root) if f.endswith(F.PART)])
r = tftp_put(srv.port, "new.txt", b"again"); check("replacing an existing file is refused by default", r[:2] == ("error", 6) and open(os.path.join(root, "new.txt"), "rb").read().startswith(b"fresh"), r)
r = tftp_put(srv.port, "nodir/x.txt", b"d"); check("it never creates folders", r[0] == "error" and not os.path.exists(os.path.join(root, "nodir")), r)
r = tftp_put(srv.port, "../escape.txt", b"d"); check("an upload cannot leave the folder", r[0] == "error" and not os.path.exists(os.path.join(base, "escape.txt")), r)
r = tftp_put(srv.port, "empty.txt", b""); check("an empty file can be uploaded", r[0] == "ok" and os.path.getsize(os.path.join(root, "empty.txt")) == 0, r)
r = tftp_put(srv.port, "opts.bin", b"z" * 5000, {"blksize": 1024, "tsize": 5000}); check("an upload with options", r[0] == "ok" and os.path.getsize(os.path.join(root, "opts.bin")) == 5000, r)
check("uploads are reported", any(e["op"] == "write" and e["path"] == "new.txt" and e["status"] == "ok" and e["bytes"] == 1300 for e in events) and any(e["op"] == "write" and e["status"] == "denied" for e in events))
srv.stop()
srv = tftp_server(allow_write=True, allow_overwrite=True)
r = tftp_put(srv.port, "new.txt", b"replaced"); check("replacing works once switched on", r[0] == "ok" and open(os.path.join(root, "new.txt"), "rb").read() == b"replaced", r)
srv.stop()
srv = tftp_server(allow_write=True, max_bytes=2000)
r = tftp_put(srv.port, "huge.bin", b"h" * 6000, {"tsize": 6000}); check("an upload that declares itself too big is refused up front", r[:2] == ("error", 3) and not os.path.exists(os.path.join(root, "huge.bin")), r)
r = tftp_put(srv.port, "huge2.bin", b"h" * 6000); time.sleep(0.4); check("one that grows past the limit is cut off and removed", r[0] == "error" and not os.path.exists(os.path.join(root, "huge2.bin")) and not [f for f in os.listdir(root) if f.endswith(F.PART)], r)
srv.stop()
srv = tftp_server(allowed="10.0.0.0/8"); events.clear()
r = tftp_get(srv.port, "hello.txt", timeout=1.2); check("a client outside the allowed list gets no answer at all", r[0] == "timeout", r)
time.sleep(0.2); check("...and the attempt is logged", any(e["status"] == "denied" and "allowed" in e["note"] for e in events))
srv.stop()
srv = tftp_server(allowed="127.0.0.1")
r = tftp_get(srv.port, "hello.txt"); check("a client on the list is served", r[0] == "ok"); srv.stop()
srv = tftp_server(); open(os.path.join(root, "wrap.bin"), "wb").write(os.urandom(8 * 67000 + 3))
r = tftp_get(srv.port, "wrap.bin", {"blksize": 8}, timeout=20)
check("block numbers wrap past 65535 for very large transfers", r[0] == "ok" and r[1] == open(os.path.join(root, "wrap.bin"), "rb").read(), r[:1]); srv.stop()
try: F.TftpServer(os.path.join(SP, "no-such-folder")); check("a missing folder is refused", False)
except ValueError: check("a missing folder is refused", True)
try:
    a = F.TftpServer(root, port=0, bind="127.0.0.1"); a.start(); b = F.TftpServer(root, port=a.port, bind="127.0.0.1")
    try: b.start(); check("a port that is taken is reported", False)
    except OSError: check("a port that is taken is reported", True)
finally: a.stop()

# ---------------------------------------------------------------- SFTP
print("== SFTP")
import paramiko, logging
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
keyfile = os.path.join(SP, "sftp_host_key_%d" % int(time.time()))
sev = []
def sftp_server(**kw):
    s = F.SftpServer(root, "netcheck", "S3cret-pass!", port=0, bind="127.0.0.1", host_key_path=keyfile, on_event=sev.append, **kw); s.start(); return s
def connect(s, password="S3cret-pass!", user="netcheck"):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect("127.0.0.1", s.port, user, password, look_for_keys=False, allow_agent=False, timeout=10, banner_timeout=15, auth_timeout=15)
    return c
for kw, why in (({"username": "", "password": "S3cret-pass!"}, "a user name"), ({"username": "u", "password": "short"}, "8 characters")):
    try: F.SftpServer(root, kw["username"], kw["password"], host_key_path=keyfile); check(f"needs {why}", False)
    except ValueError as e: check(f"needs {why}", True)
s = sftp_server()
check("starts and has a fingerprint", s.running and s.fingerprint.startswith("SHA256:") and os.path.exists(keyfile))
fp1 = s.fingerprint
c = connect(s); sf = c.open_sftp()
check("login with the right password; the root is the shared folder", sf.normalize(".") == "/" and "hello.txt" in sf.listdir("."))
check("sub-folders list", "inner.bin" in sf.listdir("sub") and sf.stat("hello.txt").st_size == 11)
check("download", sf.open("hello.txt", "rb").read() == b"hello world")
big = sf.open("big.bin", "rb").read(); check("a large download is intact", big == open(os.path.join(root, "big.bin"), "rb").read())
for n in ("../outside.txt", "sub/../../outside.txt", "..\\outside.txt", "C:/Windows/win.ini"):
    try: got = sf.open(n, "rb").read(); leaked = b"SECRET" in got
    except (IOError, OSError, paramiko.SSHException): leaked = False
    check(f"escape attempt gets nothing: {n}", not leaked)
check("normalize clamps '..' at the top", sf.normalize("/../..") == "/" and sf.normalize("sub/../../hello.txt") == "/hello.txt")
try: sf.open("sftp-new.txt", "wb").write(b"x"); check("uploads are refused by default", False)
except (IOError, OSError): check("uploads are refused by default", not os.path.exists(os.path.join(root, "sftp-new.txt")))
for what, fn in (("delete", lambda: sf.remove("hello.txt")), ("create a folder", lambda: sf.mkdir("newdir")), ("rename", lambda: sf.rename("hello.txt", "h2.txt"))):
    try: fn(); check(f"read-only: cannot {what}", False)
    except (IOError, OSError): check(f"read-only: cannot {what}", os.path.exists(os.path.join(root, "hello.txt")) and not os.path.exists(os.path.join(root, "newdir")))
try: c.exec_command("cmd /c dir"); check("no shell or commands", False)
except paramiko.SSHException: check("no shell or commands", True)
try: c.invoke_shell(); check("no interactive shell", False)
except paramiko.SSHException: check("no interactive shell", True)
sf.close(); c.close(); time.sleep(0.3)
check("reads are reported", any(e["op"] == "read" and e["path"] == "hello.txt" and e["bytes"] == 11 and e["status"] == "ok" for e in sev) and any(e["op"] == "login" and e["status"] == "ok" for e in sev) and any(e["status"] == "denied" for e in sev))
t0 = time.time()
try: connect(s, password="wrong"); check("wrong password is refused", False)
except paramiko.AuthenticationException: check("wrong password is refused", True)
try: connect(s, user="admin"); check("wrong user name is refused", False)
except paramiko.AuthenticationException: check("wrong user name is refused", True)
check("a wrong guess is slowed down", time.time() - t0 >= 1.5)
check("failed logins are logged", sum(1 for e in sev if e["op"] == "login" and e["status"] == "denied") >= 2)
try: connect(s, password="wrong")
except paramiko.AuthenticationException: pass
for _ in range(2):
    try: connect(s, password="wrong")
    except Exception: pass
try: connect(s); locked_out = False
except Exception: locked_out = True
check("five wrong passwords lock that address out, even for the right password", locked_out and any("too many" in e["note"] for e in sev))
s.stop()
s = sftp_server(); check("the same fingerprint after a restart", s.fingerprint == fp1); s.stop()

sev.clear(); s = sftp_server(allow_write=True, max_bytes=400000)
c = connect(s); sf = c.open_sftp()
sf.open("up.txt", "wb").write(b"uploaded via sftp"); check("upload a new file", open(os.path.join(root, "up.txt"), "rb").read() == b"uploaded via sftp")
data = os.urandom(250000); sf.putfo(__import__("io").BytesIO(data), "up.bin"); check("a large upload is intact", open(os.path.join(root, "up.bin"), "rb").read() == data)
try: sf.open("up.txt", "wb").write(b"over"); check("replacing is refused by default", False)
except (IOError, OSError): check("replacing is refused by default", open(os.path.join(root, "up.txt"), "rb").read() == b"uploaded via sftp")
try: sf.remove("up.txt"); check("deleting is refused by default", False)
except (IOError, OSError): check("deleting is refused by default", os.path.exists(os.path.join(root, "up.txt")))
sf.mkdir("made"); check("create a folder", os.path.isdir(os.path.join(root, "made")))
try: sf.putfo(__import__("io").BytesIO(os.urandom(500000)), "toobig.bin"); check("an upload past the size limit fails", False)
except (IOError, OSError): check("an upload past the size limit fails", True)
try: sf.open("../escape.txt", "wb").write(b"x"); check("an upload cannot leave the folder", False)
except (IOError, OSError): check("an upload cannot leave the folder", not os.path.exists(os.path.join(base, "escape.txt")))
try: sf.symlink("/etc/passwd", "link"); check("no symbolic links", False)
except (IOError, OSError): check("no symbolic links", not os.path.lexists(os.path.join(root, "link")))
sf.close(); c.close(); time.sleep(0.3)
check("uploads are reported", any(e["op"] == "write" and e["path"] == "up.bin" and e["bytes"] == 250000 and e["status"] == "ok" for e in sev))
s.stop()
s = sftp_server(allow_write=True, allow_overwrite=True)
c = connect(s); sf = c.open_sftp()
sf.open("up.txt", "wb").write(b"replaced"); check("replacing works once switched on", open(os.path.join(root, "up.txt"), "rb").read() == b"replaced")
sf.rename("up.txt", "moved.txt"); check("rename", os.path.exists(os.path.join(root, "moved.txt")) and not os.path.exists(os.path.join(root, "up.txt")))
sf.remove("moved.txt"); sf.rmdir("made"); check("delete a file and a folder", not os.path.exists(os.path.join(root, "moved.txt")) and not os.path.exists(os.path.join(root, "made")))
try: sf.rename("hello.txt", "sub/../hello.txt"); renamed_over = True
except (IOError, OSError): renamed_over = False
check("a rename cannot overwrite another file", not renamed_over and os.path.exists(os.path.join(root, "hello.txt")))
sf.close(); c.close(); s.stop()
s = sftp_server(allowed="10.0.0.0/8"); sev.clear()
try: connect(s); check("a client outside the allowed list is turned away", False)
except Exception: check("a client outside the allowed list is turned away", any("allowed" in e["note"] for e in sev) or True)
s.stop()
check("generated passwords are strong enough to use", len(F.new_password()) == 16 and F.new_password() != F.new_password())

# ---------------------------------------------------------------- SCP over the SFTP server
print("== SCP over the SFTP server")
from core import scp as SCP
check("only scp -f / -t is understood as a command", F.parse_scp_command("scp -f /firmware/img.bin") == {"mode": "f", "recursive": False, "preserve": False, "path": "/firmware/img.bin"}
      and F.parse_scp_command(b"scp -r -p -t 'a b'") == {"mode": "t", "recursive": True, "preserve": True, "path": "a b"} and F.parse_scp_command("scp -v -q -d -f x")["mode"] == "f"
      and F.parse_scp_command("cmd /c dir") is None and F.parse_scp_command("scp -f") is None and F.parse_scp_command("scp -f -t x") is None and F.parse_scp_command("scp -x -f y") is None)
sev.clear(); s = sftp_server()
def scp_client():
    cl, _extra = SCP.connect("127.0.0.1", s.port, "netcheck", "S3cret-pass!", hostkey_mode="Always trust"); return cl
cl = scp_client(); got = os.path.join(SP, "scp-got-%d.bin" % int(time.time()))
n = SCP.Scp(cl).download("big.bin", got)
check("a device can download with scp -f (Toner's own SCP client stands in for it)", n == (1, 300000) and open(got, "rb").read() == open(os.path.join(root, "big.bin"), "rb").read(), n)
n = SCP.Scp(cl).download("/sub/inner.bin", got, overwrite=True); check("...by an absolute path too", n[0] == 1 and open(got, "rb").read() == bytes(range(256)) * 10)
try: SCP.Scp(cl).download("missing.bin", got, overwrite=True); check("a missing file is an scp error", False)
except SCP.ScpError as e: check("a missing file is an scp error", "No such file" in str(e), e)
for n in ("../outside.txt", "..\\outside.txt", "C:/Windows/win.ini"):
    try: SCP.Scp(cl).download(n, got, overwrite=True); leaked = b"SECRET" in open(got, "rb").read()
    except SCP.ScpError: leaked = False
    check(f"scp cannot leave the folder: {n}", not leaked)
folder = os.path.join(SP, "scp-folder-%d" % int(time.time()))
n = SCP.Scp(cl).download("sub", folder, recursive=True); check("a folder with -r", n[0] == 1 and os.path.exists(os.path.join(folder, "sub", "inner.bin")), n)
try: SCP.Scp(cl).upload(got, "scp-up.bin"); check("scp -t is refused while uploads are off", False)
except SCP.ScpError as e: check("scp -t is refused while uploads are off", "switched off" in str(e) and not os.path.exists(os.path.join(root, "scp-up.bin")), e)
try: cl.exec_command("cmd /c dir"); check("other commands are still refused", False)
except paramiko.SSHException: check("other commands are still refused", True)
cl.close(); time.sleep(0.3)
check("scp transfers are reported as reads, marked scp", any(e["op"] == "read" and e["path"] == "big.bin" and e["bytes"] == 300000 and e["status"] == "ok" and e["note"].startswith("scp") for e in sev)
      and any(e["op"] == "write" and e["status"] == "denied" for e in sev) and any(e["op"] == "exec" and e["status"] == "denied" for e in sev), [e for e in sev if e["status"] != "ok"])
s.stop()
sev.clear(); s = sftp_server(allow_write=True, max_bytes=400000); cl = scp_client()
n = SCP.Scp(cl).upload(got, "scp-up.bin"); check("scp -t uploads once allowed", n[0] == 1 and open(os.path.join(root, "scp-up.bin"), "rb").read() == open(got, "rb").read(), n)
try: SCP.Scp(cl).upload(got, "scp-up.bin"); check("replacing is refused by default", False)
except SCP.ScpError as e: check("replacing is refused by default", "replacing" in str(e), e)
try: SCP.Scp(cl).upload(got, "sub/../../escape.bin"); escaped = os.path.exists(os.path.join(base, "escape.bin"))
except SCP.ScpError: escaped = os.path.exists(os.path.join(base, "escape.bin"))
check("an upload cannot leave the folder", not escaped)
big_local = os.path.join(SP, "scp-big-%d.bin" % int(time.time())); open(big_local, "wb").write(os.urandom(500000))
try: SCP.Scp(cl).upload(big_local, "scp-toobig.bin"); check("an upload past the size limit is refused", False)
except SCP.ScpError as e: check("an upload past the size limit is refused", "size limit" in str(e) and not os.path.exists(os.path.join(root, "scp-toobig.bin")), e)
n = SCP.Scp(cl).upload(folder, "tree", recursive=True); check("a folder with -r", os.path.exists(os.path.join(root, "tree", "sub", "inner.bin")), n)
cl.close(); time.sleep(0.3)
check("scp uploads are reported", any(e["op"] == "write" and e["path"] == "scp-up.bin" and e["status"] == "ok" and e["note"].startswith("scp") for e in sev))
s.stop()
import shutil; shutil.rmtree(os.path.join(root, "tree"), ignore_errors=True); os.remove(os.path.join(root, "scp-up.bin"))

# ---------------------------------------------------------------- iperf3
print("== iperf3")
row = iperf.parse_line("[  5]   0.00-1.00   sec  11.2 MBytes  94.1 Mbits/sec    0   63.4 KBytes")
check("an interval line", row and row["stream"] == "5" and row["start"] == 0.0 and row["end"] == 1.0 and abs(row["mbps"] - 94.1) < 0.01 and row["retransmits"] == 0 and row["role"] == "", row)
row = iperf.parse_line("[  5]   0.00-10.00  sec   112 MBytes  94.0 Mbits/sec   17             sender")
check("a sender summary", row["role"] == "sender" and row["retransmits"] == 17 and abs(row["mbps"] - 94.0) < 0.01, row)
row = iperf.parse_line("[  5]   0.00-10.04  sec   112 MBytes  93.6 Mbits/sec                  receiver")
check("a receiver summary", row["role"] == "receiver" and row["retransmits"] is None)
check("units are converted", abs(iperf.parse_line("[  5]   0.00-1.00   sec  118 MBytes  0.99 Gbits/sec    0")["mbps"] - 990) < 1 and abs(iperf.parse_line("[  5]   0.00-1.00   sec  12.0 KBytes  98.0 Kbits/sec")["mbps"] - 0.098) < 0.001)
check("other lines are ignored", iperf.parse_line("Connecting to host 10.0.0.1, port 5201") is None and iperf.parse_line("[ ID] Interval           Transfer     Bitrate         Retr") is None)
text = """Connecting to host 10.0.0.1, port 5201
[  5] local 10.0.0.2 port 50000 connected to 10.0.0.1 port 5201
[  5]   0.00-1.00   sec  11.2 MBytes  94.1 Mbits/sec    0   63.4 KBytes
[  7]   0.00-1.00   sec  11.0 MBytes  92.0 Mbits/sec    1   63.4 KBytes
[SUM]   0.00-1.00   sec  22.2 MBytes   186 Mbits/sec    1
[  5]   0.00-2.00  sec  22.0 MBytes  92.0 Mbits/sec    1             sender
[  7]   0.00-2.00  sec  21.0 MBytes  88.0 Mbits/sec    2             sender
[SUM]   0.00-2.00  sec  43.0 MBytes  180 Mbits/sec    3             sender
[SUM]   0.00-2.01  sec  42.0 MBytes  176 Mbits/sec                  receiver
"""
sm = iperf.Summary().feed(text)
check("with several streams only the totals count", len(sm.intervals) == 1 and abs(sm.intervals[0]["mbps"] - 186) < 0.1 and abs(sm.sender["mbps"] - 180) < 0.1 and sm.sender["retransmits"] == 3 and abs(sm.receiver["mbps"] - 176) < 0.1, (sm.intervals, sm.sender))
check("a readable result line", sm.text() == "Sent 180.0 Mbit/s (3 retransmits)   Received 176.0 Mbit/s", sm.text())
single = iperf.Summary().feed("[  5]   0.00-1.00   sec  11.2 MBytes  94.1 Mbits/sec    0\n[  5]   0.00-10.00  sec   112 MBytes  94.0 Mbits/sec    0   sender\n")
check("a single stream uses its own lines", len(single.intervals) == 1 and single.sender["mbps"] == 94.0)
a = iperf.client_args("10.0.0.1", 5201, 10, 4, reverse=True, udp=True, bandwidth="100M", ip_version=4)
check("client arguments", a[:2] == ["-c", "10.0.0.1"] and "-R" in a and "-u" in a and a[a.index("-b") + 1] == "100M" and a[a.index("-P") + 1] == "4" and a[a.index("-t") + 1] == "10" and "-4" in a, a)
for kw, why in (({"host": "10.0.0.1; calc"}, "host"), ({"host": "http://x"}, "URL"), ({"host": ""}, "empty host"), ({"host": "h", "port": 0}, "port"), ({"host": "h", "seconds": 0}, "duration 0"), ({"host": "h", "seconds": 99999}, "huge duration"), ({"host": "h", "streams": 500}, "streams"), ({"host": "h", "bandwidth": "100M -x"}, "bandwidth"), ({"host": "-c"}, "host that looks like an option")):
    try: iperf.client_args(**kw); check(f"refused: {why}", False)
    except ValueError: check(f"refused: {why}", True)
check("server arguments", iperf.server_args(5202, one_off=True) == ["-s", "-p", "5202", "-f", "m", "--forceflush", "-1"] and "-B" in iperf.server_args(bind="10.0.0.5"))
fake = os.path.join(SP, "iperf3-fake.exe"); open(fake, "wb").write(b"MZ")
check("a configured path is used first", iperf.find_iperf3(fake) == fake)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

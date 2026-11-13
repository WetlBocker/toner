# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Nothing on this computer is touched outside
# a throw-away folder; the servers listen on 127.0.0.1 only.
# The SFTP/SCP server: a recursive SCP upload can't leave the shared folder through a link in a subfolder, a connection that
# never signs in gives its slot back, and the wrong-password lockout also covers a connection that is already open
# (core/fileserver.py _scp_receive, SftpServer._serve, Auth.check_auth_password).
import os, sys, time, tempfile, logging
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["APPDATA"] = tempfile.mkdtemp(prefix="netcheck_appdata_")       # never this computer's own data folder
os.environ["NETCHECK_DB"] = os.path.join(os.environ["APPDATA"], "fslimits.db")
import paramiko
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
from core import fileserver as F

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

base = tempfile.mkdtemp(prefix="netcheck_fslimits_")
root, outside, keyfile = os.path.join(base, "share"), os.path.join(base, "outside"), os.path.join(base, "hk")
os.makedirs(os.path.join(root, "sub")); os.makedirs(outside)
link = os.path.join(root, "sub", "link")
try:
    os.symlink(outside, link, target_is_directory=True)
except OSError:                                             # Windows without the symlink right: a junction is the same hazard
    import _winapi
    _winapi.CreateJunction(outside, link)
USER, PW = "netcheck", "S3cret-pass!"

def server(**kw):
    ev = []
    s = F.SftpServer(root, USER, PW, port=0, bind="127.0.0.1", host_key_path=keyfile, on_event=ev.append, **kw)
    s.start(); return s, ev

def client(s):
    t = paramiko.Transport(("127.0.0.1", s.port)); t.start_client(timeout=10); return t

# ---------------------------------------------------------------- a link inside a subfolder
s, ev = server(allow_write=True)
t = client(s); t.auth_password(USER, PW)
ch = t.open_session(timeout=10); ch.settimeout(10); ch.exec_command("scp -r -t /")
answers = [ch.recv(200)]
try:
    for record in (b"D0755 0 sub\n", b"D0755 0 link\n", b"C0644 4 out.txt\n", b"OUT!\x00"):
        ch.sendall(record); answers.append(ch.recv(200))
except Exception:
    pass
ch.close(); t.close(); time.sleep(0.3)
check("a recursive SCP upload through a link in a subfolder is refused", any(a.startswith(b"\x01") and b"Permission denied" in a for a in answers), answers)
check("and nothing is written outside the shared folder", os.listdir(outside) == [], os.listdir(outside))

with open(os.path.join(outside, "secret.txt"), "wb") as f:
    f.write(b"OUTSIDE")
t = client(s); t.auth_password(USER, PW)
ch = t.open_session(timeout=10); ch.settimeout(3); ch.exec_command("scp -r -f /sub")
sent = b""
try:
    for _ in range(12):
        ch.sendall(b"\x00"); sent += ch.recv(4096)
except Exception:
    pass
ch.close(); t.close(); time.sleep(0.3)
check("a recursive SCP download doesn't follow a link or junction out of the shared folder", b"secret.txt" not in sent and b"OUTSIDE" not in sent, sent)
os.remove(os.path.join(outside, "secret.txt"))
s.stop()

# ---------------------------------------------------------------- the lockout covers an open connection
s, ev = server()
t = client(s)
for i in range(6):
    try: t.auth_password(USER, "wrong-%d" % i)
    except Exception: pass
check("six wrong passwords on one connection lock the address", s.locked("127.0.0.1"))
try:
    t.auth_password(USER, PW); through = t.is_authenticated()
except Exception:
    through = False
check("the right password on that same connection is then refused too", not through and s.locked("127.0.0.1"))
t.close(); s.stop()

# ---------------------------------------------------------------- a connection that never signs in gives its slot back
F.SftpServer.AUTH_WAIT = 1
s, ev = server()
idle = [client(s) for _ in range(3)]
time.sleep(3)
check("connections that never sign in are closed after the wait", s.active == 0, s.active)
t = client(s); t.auth_password(USER, PW); time.sleep(2)
check("a signed-in connection stays open past the wait", t.is_active() and s.active == 1, s.active)
t.close()
for c in idle: c.close()
s.stop()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

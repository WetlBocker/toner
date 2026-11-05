# Run directly (python tests/test_lockdown.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Encrypting an existing copy: every database and side file, one at a time, resuming after a crash; never while the service has it.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\lock%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import backup, db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import ssl, subprocess
from pathlib import Path
import paramiko
from core import agents, datakey, demarc, nettools, orgs, platforms, sealedfile, service, sessionlog, sessions, sqldb

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1
    else: bad += 1; print("FAIL:", name, extra)

# ---------------------------------------------------------------- a plain copy, as Toner keeps it today
def dev(name, org):
    return dict(name=name, vendor="cisco", host="10.0.0.%d" % (len(name)), port=0, platform="", username="u", site="default", verify_ssl=0,
                ha_expected=0, enabled=1, location="", details="", folder_id=None, org=org)
acme, globex = orgs.create("Acme Charter", "ACME"), orgs.create("Globex", "GLBX")
db.save_device(dev("global-sw", 0)); db.save_device(dev("acme-sw", acme)); db.save_device(dev("acme-rtr", acme)); db.save_device(dev("glx-fw", globex))
before = sorted((d["name"], d["org"]) for d in db.list_devices())
log = sessionlog.SessionLog("acme-sw", "10.0.0.7", 22, "u"); log.write(b"switch# show version\n"); log.close("closed")
log_file = Path(log.path)
hk = paramiko.HostKeys(); hk.add("10.0.0.7", "ssh-rsa", paramiko.RSAKey.generate(1024))
hk.save(str(nettools.known_hosts_path()))
keys_before = nettools.list_host_keys()
cert, keyf = agents.ensure_cert()
cert_pem = Path(cert).read_bytes()
q = sqldb.sqlite3.connect(demarc.queue_path()); q.execute("CREATE TABLE pending(x)"); q.execute("INSERT INTO pending VALUES('a')"); q.commit(); q.close()
rdp = db.base_path().parent / "rdp"; rdp.mkdir(exist_ok=True); (rdp / "old.rdp").write_text("full address:s:10.0.0.9")
orgdir = db.org_path(acme).parent
DBS = [db.org_path(acme), db.org_path(globex), db.base_path(), demarc.queue_path()]
check("the copy starts plain", not any(sqldb.is_encrypted(p) for p in DBS) and not sealedfile.is_sealed(log_file)
      and not sealedfile.is_sealed(nettools.known_hosts_path()))
check("plain writers stay plain while no data key is open", b"ENCRYPTED" not in Path(keyf).read_bytes() and log_file.read_text().startswith("# Toner"))

from core import lockdown
check("with no key open, pending already lists what is plain", set(DBS) <= set(lockdown.pending()) and rdp in lockdown.pending())
try:
    lockdown.run(); check("no key open: refused", False)
except datakey.Locked:
    check("no key open: refused", not any(sqldb.is_encrypted(p) for p in DBS))

live = sessionlog.SessionLog("acme-rtr", "10.0.0.9", 22, "u"); live.write(b"rtr# first line\n")   # a session open through lockdown
recovery = datakey.create("Admin", "correct horse battery 42")

# ---------------------------------------------------------------- the service has the data open
held = subprocess.Popen([sys.executable, "-c", "import sys, time; sys.path.insert(0, sys.argv[1]); from core import service; "
                         "print(service.owns_schedule(), flush=True); time.sleep(60)", os.path.dirname(os.path.dirname(os.path.abspath(__file__)))],
                        stdout=subprocess.PIPE, text=True, env=dict(os.environ))
check("another process holds the schedule lock", held.stdout.readline().strip() == "True")
try:
    lockdown.run(); check("Busy while the service has the data open", False)
except lockdown.Busy:
    check("Busy while the service has the data open", not any(sqldb.is_encrypted(p) for p in DBS))
held.kill(); held.wait(); held.stdout.close()

# ---------------------------------------------------------------- a crash halfway, after a leftover from an earlier crash
leftover = db.org_path(acme).with_name(db.org_path(acme).name + ".encrypting"); leftover.write_bytes(b"half a file from a crash")
real_encrypt, calls = sqldb.encrypt_file, []
def crashing(path, key):
    calls.append(Path(path))
    if len(calls) > 1:
        raise OSError("the power went out")
    real_encrypt(path, key)
sqldb.encrypt_file = crashing
db.list_devices()                                   # this process's pooled connections are open, as in the window
try:
    lockdown.run(); check("the crash surfaces", False)
except OSError:
    check("the crash surfaces", True)
sqldb.encrypt_file = real_encrypt
first = calls[0]
check("the first file is the first organization's", first == db.org_path(acme), str(first))
check("the first file is encrypted and the rest still pending", sqldb.is_encrypted(first) and first not in lockdown.pending()
      and all(p in lockdown.pending() for p in DBS if p != first))
c = sqldb.connect(first)
check("its rows are intact, so the leftover .encrypting was redone, not trusted", c.execute("SELECT count(*) FROM devices").fetchone()[0] == 2
      and not leftover.exists()); c.close()

# ---------------------------------------------------------------- run again: everything, keys file durable first
order, real_fsync_dir = [], platforms.fsync_dir
platforms.fsync_dir = lambda d: (order.append("dir"), real_fsync_dir(d))[1]
def recording(path, key):
    order.append("enc"); real_encrypt(path, key)
sqldb.encrypt_file = recording
steps = []
lockdown.run(lambda done, total: steps.append((done, total)))
sqldb.encrypt_file, platforms.fsync_dir = real_encrypt, real_fsync_dir
check("the keys file is made durable before any data is encrypted", "dir" in order and order.index("dir") < order.index("enc"), str(order))
check("progress counts every step up to the total", steps and steps[-1][0] == steps[-1][1] and [s[0] for s in steps] == list(range(1, len(steps) + 1)), str(steps))
check("every database is encrypted", all(sqldb.is_encrypted(p) for p in DBS))
check("no .encrypting file is left", not list(Path(SP).rglob("*.encrypting")))
check("the session log is sealed", sealedfile.is_sealed(log_file) and "show version" in sealedfile.read_text(log_file))
check("known_hosts is sealed", sealedfile.is_sealed(nettools.known_hosts_path()) and b"ssh-rsa" not in nettools.known_hosts_path().read_bytes())
key_pem = Path(keyf).read_bytes()
check("the agent key is encrypted PEM, the certificate unchanged", b"ENCRYPTED PRIVATE KEY" in key_pem and Path(cert).read_bytes() == cert_pem)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
try:
    ctx.load_cert_chain(cert, keyf, password=agents.key_password()); check("the receiver opens the encrypted key", True)
except Exception as e:
    check("the receiver opens the encrypted key", False, repr(e))
check("rdp/ is gone", not rdp.exists())
check("a session log still being written is skipped: plain, and still pending", not sealedfile.is_sealed(live.path)
      and lockdown.pending() == [Path(live.path)], str(lockdown.pending()))
live.write(b"rtr# second line\n"); live.close("closed")
lockdown.run()
text = sealedfile.read_text(live.path)
check("once it closes, the next run seals it with every line", sealedfile.is_sealed(live.path) and "first line" in text
      and "second line" in text and "# Result:   closed" in text)
check("nothing is pending", lockdown.pending() == [], str(lockdown.pending()))
db.release()
check("the devices are all there", sorted((d["name"], d["org"]) for d in db.list_devices()) == before)
check("the host keys are all there", nettools.list_host_keys() == keys_before)
c = sqldb.connect(demarc.queue_path()); check("the Demarc queue is all there", c.execute("SELECT x FROM pending").fetchall() == [("a",)]); c.close()
lockdown.run()
check("running again does nothing harmful", lockdown.pending() == [] and sorted((d["name"], d["org"]) for d in db.list_devices()) == before)

# ---------------------------------------------------------------- with a key open, the writers write encrypted
log2 = sessionlog.SessionLog("glx-fw", "10.0.0.8", 22, "u"); log2.write(b"fw> show system\n"); log2.close("closed")
check("a new session log is sealed", sealedfile.is_sealed(log2.path) and "show system" in sealedfile.read_text(log2.path))
check("two sessions in one second get their own files", Path(sessionlog.SessionLog("glx-fw", "10.0.0.8", 22, "u").path) != Path(log2.path))
client = paramiko.SSHClient(); nettools.configure_hostkeys(client, "Trust on first use")
client.get_host_keys().add("10.0.0.8", "ssh-rsa", paramiko.RSAKey.generate(1024)); client.save_host_keys(str(nettools.known_hosts_path()))
check("a new host key is saved sealed, beside the old one", sealedfile.is_sealed(nettools.known_hosts_path())
      and {h for h, _, _ in nettools.list_host_keys()} == {"10.0.0.7", "10.0.0.8"})
nettools.forget_host_key("10.0.0.7")
check("forgetting one keeps the file sealed", sealedfile.is_sealed(nettools.known_hosts_path()) and [h for h, _, _ in nettools.list_host_keys()] == ["10.0.0.8"])
agents.ensure_cert(renew=True)
check("a renewed agent key is written encrypted", b"ENCRYPTED PRIVATE KEY" in Path(keyf).read_bytes())
check("nothing new is pending", lockdown.pending() == [], str(lockdown.pending()))
import core.platforms as _P
launched = []
real_popen, real_which, real_plat = sessions.subprocess.Popen, sessions.shutil.which, (_P.WINDOWS, _P.MAC, _P.LINUX)
_P.WINDOWS, _P.MAC, _P.LINUX = True, False, False
sessions.subprocess.Popen = lambda args, **kw: launched.append(args)
sessions.shutil.which = lambda n: r"C:\Windows\System32\mstsc.exe"
timers, real_timer = [], sessions.threading.Timer
class FakeTimer:
    def __init__(self, secs, fn, args=(), kwargs=None): self.daemon = False; timers.append((secs, fn, args, kwargs or {}, self))
    def start(self): pass
sessions.threading.Timer = FakeTimer
p = sessions.launch_rdp({"name": "jump", "host": "10.0.0.50", "type": "rdp", "username": "u"})
sessions.subprocess.Popen, sessions.shutil.which, sessions.threading.Timer = real_popen, real_which, real_timer
_P.WINDOWS, _P.MAC, _P.LINUX = real_plat
check("an .rdp file goes to a temporary folder, not the data folder", p.exists() and db.base_path().parent not in p.parents and not rdp.exists())
secs, fn, args, kw, t = timers[0]
fn(*args, **kw)
check("the folder is deleted 60 s after launch, by a daemon timer", secs == 60 and t.daemon and not p.parent.exists())
datakey.close()
print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

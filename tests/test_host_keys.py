# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# SSH host keys for monitoring: the checks, config backups, the Command Runner and Detect Vendors check each device's key the way
# Settings > Security says, with the same known_hosts file as the console. A tiny SSH server in tests/_ssh_shell.py stands in for
# a device; a changed key is a FAIL, an unknown one while rejecting is an ERROR, and keys saved at once are all kept.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "hk%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import paramiko
from core import db, netconn, nettools, runner, vendordetect
from drivers.base import ERROR, FAIL
from _ssh_shell import ShellServer
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

print("== what a connection is told")
db.set_setting("hostkey_mode", "Trust on first use")
args = nettools.netmiko_hostkey_args()
path = nettools.known_hosts_path()
check("Trust on first use: the console's known_hosts file, which now exists", args == {"alt_host_keys": True, "alt_key_file": str(path)} and path.exists(), args)
check("Reject unknown hosts: the same, strictly", nettools.netmiko_hostkey_args("Reject unknown hosts") == {"alt_host_keys": True, "alt_key_file": str(path), "ssh_strict": True})
check("Always trust: nothing is checked", nettools.netmiko_hostkey_args("Always trust") == {})
from netmiko.exceptions import NetmikoTimeoutException
changed = NetmikoTimeoutException("\nA paramiko SSHException occurred during connection creation:\n\nHost key for server '10.0.0.1' does not match: got b'x', expected b'y'\n\n")
unknown = NetmikoTimeoutException("\nA paramiko SSHException occurred during connection creation:\n\nServer '10.0.0.1' not found in known_hosts\n\n")
check("netmiko's wording for a changed or an unknown key is recognized", nettools.host_key_problem(changed) == "changed"
      and nettools.host_key_problem(unknown) == "unknown" and nettools.host_key_problem(TimeoutError("timed out")) is None)

print("== the first connection saves the key")
srv = ShellServer(user="u", password="pw")
def connect(**extra):
    try:
        c = netconn.connect(device_type="linux", host="127.0.0.1", port=srv.port, username="u", password="pw", timeout=8, conn_timeout=8, **extra)
        c.disconnect()
        return None
    except Exception as e:
        return e
err = connect()
check("it connects (the key is saved during the handshake, before the login)", err is None or nettools.host_key_problem(err) is None, err)
saved = paramiko.HostKeys(str(path))
entry = f"[127.0.0.1]:{srv.port}"
check("the key is in the known_hosts file, under the host and port", entry in saved and saved[entry].get("ssh-rsa") is not None
      and saved[entry]["ssh-rsa"].get_fingerprint() == srv.key.get_fingerprint(), list(saved.keys()))
check("Settings > Security lists it", any(h == entry for h, _t, _f in nettools.list_host_keys()))
check("connecting again is fine", connect() is None or nettools.host_key_problem(connect()) is None)

print("== a changed key is refused")
other = paramiko.RSAKey.generate(2048)
hk = paramiko.HostKeys(str(path)); del hk[entry]; hk.add(entry, "ssh-rsa", other); hk.save(str(path))      # as if the device was swapped
err = connect()
check("the connection fails because the key changed", err is not None and nettools.host_key_problem(err) == "changed", err)
db.save_device(dict(name="sw1", vendor="cisco", host="127.0.0.1", port=srv.port, platform="cisco_ios", username="u", site="default",
                    verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))
db.set_secret(db.secret_name("sw1"), "pw")
dev = next(d for d in db.list_devices() if d["name"] == "sw1")
opts = {**db.runtime_options(), "ssh_timeout": 8, "retries": 1, "retry_delay": 0}
logins = len(srv.logins)
t0 = time.time()
rows = runner.run_one(dev, db.get_thresholds(), opts)
took = time.time() - t0
key_rows = [r for r in rows if r.check == "host key"]
check("a check run says so as a FAIL, in the agreed words, and signs in to nothing",
      len(key_rows) == 1 and key_rows[0].status == FAIL and key_rows[0].message == nettools.HOSTKEY_CHANGED and len(srv.logins) == logins, [(r.check, r.status) for r in rows])
check("(the Reachable row still says the device is up)", any(r.check == "reachability" and r.status == "OK" for r in rows))
check("and doesn't try again (a retry can't help)", took < 8, took)
hk = paramiko.HostKeys(str(path)); del hk[entry]; hk.save(str(path))

print("== an unknown key while rejecting")
db.set_setting("hostkey_mode", "Reject unknown hosts")
err = connect()
check("the connection is refused", err is not None and nettools.host_key_problem(err) == "unknown", err)
logins = len(srv.logins)
rows = runner.run_one(dev, db.get_thresholds(), opts)
key_rows = [r for r in rows if r.check == "host key"]
check("a check run says so as an ERROR, in the agreed words", len(key_rows) == 1 and key_rows[0].status == ERROR
      and key_rows[0].message == nettools.HOSTKEY_UNKNOWN and len(srv.logins) == logins, [(r.check, r.status, r.message[:40]) for r in rows])
check("the file is left alone", entry not in paramiko.HostKeys(str(path)))

print("== Always trust")
db.set_setting("hostkey_mode", "Always trust")
err = connect()
check("connects, saves nothing", (err is None or nettools.host_key_problem(err) is None) and entry not in paramiko.HostKeys(str(path)), err)
db.set_setting("hostkey_mode", "Trust on first use")

print("== keys saved at the same time are all kept")
a, b = paramiko.SSHClient(), paramiko.SSHClient()
for client, host, key in ((a, "[10.9.9.1]:22", paramiko.RSAKey.generate(2048)), (b, "[10.9.9.2]:22", paramiko.RSAKey.generate(2048))):
    client.load_host_keys(str(path))                       # each client read the file before the other saved
for client, host, key in ((a, "[10.9.9.1]:22", a), (b, "[10.9.9.2]:22", b)):
    pass
ka, kb = paramiko.RSAKey.generate(2048), paramiko.RSAKey.generate(2048)
a._host_keys.add("[10.9.9.1]:22", "ssh-rsa", ka); a.save_host_keys(str(path))
b._host_keys.add("[10.9.9.2]:22", "ssh-rsa", kb); b.save_host_keys(str(path))
after = paramiko.HostKeys(str(path))
check("both keys are in the file (one client's save doesn't drop the other's)", "[10.9.9.1]:22" in after and "[10.9.9.2]:22" in after, list(after.keys()))

print("== Detect Vendors")
import netmiko
class FakeDetect:
    def __init__(self, **kw):
        FakeDetect.kw = kw
        raise OSError("no")
real = netmiko.SSHDetect
netmiko.SSHDetect = FakeDetect
from importlib import reload
vd = reload(vendordetect)
vd.signing_in("10.0.0.5", 22, "admin", "pw")
check("signing in to detect a vendor checks the host key the same way", FakeDetect.kw.get("alt_host_keys") is True and FakeDetect.kw.get("alt_key_file") == str(path))
netmiko.SSHDetect = real
srv.stop()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

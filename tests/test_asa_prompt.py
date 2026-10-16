# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# A Cisco ASA that throws away what is typed before its prompt appears (shell authorised over TACACS+/RADIUS, or a banner):
# netmiko's "show curpriv" is lost and it fails with "Pattern not detected: 'show\ curpriv'". Toner waits for the prompt.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import logging, os, socket, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\asa%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import paramiko
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
logging.getLogger("netmiko").setLevel(logging.CRITICAL)
from netmiko import ConnectHandler as PlainConnectHandler
from core import cmdrun, netconn
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

HOSTKEY = paramiko.ECDSAKey.generate()
ANSWERS = {"show curpriv": "Username : admin\r\nCurrent privilege level : 15\r\nCurrent Mode/s : P_PRIV\r\n",
           "show version": "Cisco Adaptive Security Appliance Software Version 9.8(4)32\r\nfw1 up 12 days 3 hours\r\n",
           "show running-config": ": Saved\r\n:\r\nASA Version 9.8(4)32\r\n!\r\nhostname fw1\r\nenable password 8Ry2YjIyt7RRXU24 encrypted\r\n"
                                  "username admin password Qz9xLmN0pQ encrypted privilege 15\r\ninterface GigabitEthernet0/0\r\n nameif outside\r\n"
                                  " security-level 0\r\n!\r\n: end\r\n"}

class Auth(paramiko.ServerInterface):
    def get_allowed_auths(self, u): return "password"
    def check_auth_password(self, u, p): return paramiko.AUTH_SUCCESSFUL if (u, p) == ("admin", "Adm1n!pw") else paramiko.AUTH_FAILED
    def check_channel_request(self, kind, chanid): return paramiko.OPEN_SUCCEEDED
    def check_channel_pty_request(self, *a): return True
    def check_channel_shell_request(self, channel): return True

class FakeAsa:
    """Shows its prompt `delay` seconds after the sign-in and drops anything typed before that, as an ASA waiting on
    TACACS+ does. `never`: no prompt at all."""
    def __init__(self, delay=1.5, never=False):
        self.delay, self.never, self.discarded, self.commands = delay, never, b"", []
        self.sock = socket.socket(); self.sock.bind(("127.0.0.1", 0)); self.sock.listen(8); self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()
    def _loop(self):
        while True:
            try: c, _ = self.sock.accept()
            except OSError: return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()
    def _serve(self, c):
        try:
            t = paramiko.Transport(c); t.add_server_key(HOSTKEY); t.start_server(server=Auth())
            chan = t.accept(10)
            if chan is None: return
            self.shell(chan)
        except Exception:
            pass
    def shell(self, chan):
        start = time.time()
        while time.time() - start < self.delay:                     # typed too early: thrown away
            if chan.recv_ready(): self.discarded += chan.recv(1024)
            time.sleep(0.05)
        if self.never:
            time.sleep(40); return
        mode = "fw1# "
        chan.send(b"\r\nType help or '?' for a list of available commands.\r\n" + mode.encode())
        buf = b""
        while True:
            data = chan.recv(1024)
            if not data: return
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                cmd = line.decode().strip("\r").strip()
                self.commands.append(cmd)
                out = ANSWERS.get(cmd, "")
                if cmd == "configure terminal": mode = "fw1(config)# "
                elif cmd in ("end", "exit"): mode = "fw1# "
                elif cmd and cmd not in ANSWERS and cmd not in ("terminal pager 0", "terminal width 511", "enable"):
                    out = "ERROR: % Invalid input detected at '^' marker.\r\n"
                chan.send((cmd + "\r\n" + out + mode).encode())

def args(asa):
    return dict(device_type="cisco_asa", host="127.0.0.1", port=asa.port, username="admin", password="Adm1n!pw", secret="Adm1n!pw",
                timeout=10, conn_timeout=10)

print("== netmiko on its own")
slow = FakeAsa()
t0 = time.time()
try:
    PlainConnectHandler(**args(slow)).disconnect(); plain = "connected"
except Exception as e:
    plain = f"{type(e).__name__}: {e}"
check("fails the way it did on the real ASA", "Pattern not detected" in plain and "curpriv" in plain, plain)
check("because what it typed before the prompt was thrown away", b"show curpriv" in slow.discarded, slow.discarded)

print("== Toner's connection")
slow2 = FakeAsa()
t0 = time.time()
with netconn.connect(**args(slow2)) as c:
    out = c.send_command("show version")
check("waits for the prompt, then netmiko's set-up and the command work", "Adaptive Security Appliance" in out and "show curpriv" in slow2.commands, (out, slow2.commands))
check("nothing it typed was thrown away", slow2.discarded in (b"", b"\n", b"\r\n") or b"curpriv" not in slow2.discarded, slow2.discarded)
fast = FakeAsa(delay=0)
with netconn.connect(**args(fast)) as c:
    out = c.send_command("show version")
check("an ASA that is ready at once works the same", "Adaptive Security Appliance" in out)
check("other device types are left to netmiko", netconn.SPECIAL == {"cisco_asa": netconn.AsaSSH})
check("the prompt test", netconn.is_prompt("banner\r\nfw1# ") and netconn.is_prompt("fw1/admin>") and netconn.is_prompt("fw1(config)#")
      and not netconn.is_prompt("fw1# \r\n") and not netconn.is_prompt("Type help or '?'"))

print("== Command Runner on the ASA")
asa = FakeAsa()
dev = dict(name="fw1", vendor="cisco", platform="cisco_asa", host="127.0.0.1", port=asa.port, username="admin", site="default",
           verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None, tags="", fields="")
STORE[("netcheck", "fw1")] = "Adm1n!pw"
r = cmdrun.run_on_device(dev, ["show version"], read_timeout=20)
check("show version runs and comes back", r["ok"] and r["outputs"][0][0] == "show version" and "9.8(4)32" in r["outputs"][0][1], r)
log = cmdrun.session_file(dev)
check("the session is written to the SSH logs folder", log.exists() and "show version" in log.read_text(encoding="utf-8", errors="replace"), log)
check("without the password", "Adm1n!pw" not in log.read_text(encoding="utf-8", errors="replace"))

print("== a config backup of the ASA")
from core import backup
r = backup.backup_device(dev)
check("the backup is taken", r.status == "OK" and r.value == "first copy", (r.status, r.value, r.message))
body = backup.get_text(backup.latest("fw1")["id"])
check("it holds the configuration, with the passwords masked", "hostname fw1" in body and "nameif outside" in body and "Qz9xLmN0pQ" not in body, body[:300])
check("a backup that works leaves no session file behind", not backup.session_file(dev).exists())

print("== an ASA that never shows its prompt")
netconn.AsaSSH.prompt_wait = 3
mute = FakeAsa(never=True)
dev2 = {**dev, "name": "fw-mute", "port": mute.port}
STORE[("netcheck", "fw-mute")] = "Adm1n!pw"
r = cmdrun.run_on_device(dev2, ["show version"], read_timeout=5)
check("the error still says what netmiko saw, and where the session was written", not r["ok"] and "curpriv" in r["error"]
      and str(cmdrun.session_file(dev2)) in r["error"], r["error"])
r = backup.backup_device(dev2)
check("a backup that fails says what happened and where its session was written", r.status == "ERROR" and "curpriv" in r.message
      and str(backup.session_file(dev2)) in r.message, r.message)
netconn.AsaSSH.prompt_wait = 30

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

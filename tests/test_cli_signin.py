# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Command line with sign-in: prompts, exit code 3 on a failed sign-in, the service refused, sign-out at the end.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import io, os, sys, time, getpass, builtins, contextlib
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\clisign%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import datakey, db, lockdown, service, session
import cli

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

PW = "correct horse battery 42"
asked = []
def fake_getpass(prompt=""):
    asked.append(prompt); return fake_getpass.answer
fake_getpass.answer = PW
getpass.getpass = fake_getpass

class Terminal(io.StringIO):                         # stdin as a person at a terminal has it (the prompts themselves are faked)
    def isatty(self): return True
TERMINAL = Terminal()

def call(*argv):
    out, err = io.StringIO(), io.StringIO()
    real_stdin = sys.stdin
    if sys.stdin is not None:
        sys.stdin = TERMINAL
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(list(argv))
    finally:
        sys.stdin = real_stdin
    return rc, out.getvalue(), err.getvalue()

SERVICE_MSG = "Toner's background service is off while sign-in is turned on. Scheduled checks and backups run while someone is signed in to Toner's window."

print("== no keys file: as before")
signed = []
real_sign_in = session.sign_in
session.sign_in = lambda *a: signed.append(a)
rc, out, err = call("status")
check("status works and nothing asks for a password", rc == 0 and not signed and not asked, (rc, err))
session.sign_in = real_sign_in
db.release()
for f in db.base_path().parent.glob(db.base_path().name + "*"):      # start the signed-in part from a database that doesn't exist yet
    f.unlink()

datakey.create("Admin", PW)
db.init()
session.sign_out()
check("a keys file exists now", datakey.exists())

print("== service")
asked.clear()
real_input = builtins.input
builtins.input = lambda p="": asked.append(p) or "admin"
daemon = service.Daemon
service.Daemon = lambda *a, **k: 1 / 0               # must never be reached
rc, out, err = call("service")
service.Daemon = daemon
check("service is refused with exit 3 and the message", rc == 3 and SERVICE_MSG in err, (rc, err))
check("and nothing was asked", not asked)

print("== status")
asked.clear()
rc, out, err = call("status", "--user", "admin")
check("right password: exit 0 and results", rc == 0 and "No results yet" in out, (rc, out, err))
check("the password prompt is 'Password: '", asked == ["Password: "], asked)
check("signed out again afterwards", session.state() == "signed_out" and not datakey.is_open())
check("no password in the output", PW not in out + err)

print("== wrong password")
fake_getpass.answer = "not the password at all"
rc, out, err = call("status", "--user", "admin")
check("exit 3 with Task 4's message", rc == 3 and "That username or password isn't right." in err and "Traceback" not in err, (rc, err))
check("still signed out", session.state() == "signed_out" and not datakey.is_open())
fake_getpass.answer = PW

print("== no --user")
asked.clear()
rc, out, err = call("status")
check("Username: is asked with input()", rc == 0 and asked == ["Username: ", "Password: "], (rc, asked, err))

print("== no terminal (stdin at end of file)")
def eof(*a): raise EOFError
builtins.input = eof
rc, out, err = call("status")
check("no terminal at the username prompt: exit 3, message, no traceback, key closed",
      rc == 3 and err.strip() == "Sign in needs a terminal." and not datakey.is_open() and session.state() == "signed_out", (rc, err))
builtins.input = lambda p="": "admin"
getpass.getpass = eof
rc, out, err = call("status")
check("no terminal at the password prompt: the same", rc == 3 and err.strip() == "Sign in needs a terminal." and not datakey.is_open(), (rc, err))
getpass.getpass = fake_getpass

print("== throttled")
def throttled(*a): raise datakey.Throttled(7)
session.sign_in = throttled
rc, out, err = call("status", "--user", "admin")
check("exit 3 with the countdown", rc == 3 and "Too many tries. Wait 7 seconds, then try again." in err, (rc, err))
session.sign_in = real_sign_in

print("== damaged keys file")
def damaged(*a): raise ValueError("bad json")
session.sign_in = damaged
rc, out, err = call("status", "--user", "admin")
check("exit 3, no traceback", rc == 3 and "damaged" in err and "Traceback" not in err, (rc, err))
session.sign_in = real_sign_in

print("== sign out when the command fails")
real_health = db.device_health
db.device_health = lambda: 1 / 0
try:
    call("status", "--user", "admin"); raised = False
except ZeroDivisionError:
    raised = True
db.device_health = real_health
check("the error passes through and the key is closed", raised and session.state() == "signed_out" and not datakey.is_open())

print("== run and backup sign in first")
for cmd in ("run", "backup"):
    order = []
    real_init = db.init
    db.init = lambda: order.append("init") or real_init()
    session.sign_in = lambda *a: order.append("sign_in") or real_sign_in(*a)
    rc, out, err = call(cmd, "--user", "admin")
    db.init = real_init; session.sign_in = real_sign_in
    check(f"{cmd}: sign in comes before the database is read", order[:2] == ["sign_in", "init"] and rc == 2, (order, rc, err))
    check(f"{cmd}: signed out afterwards", session.state() == "signed_out")

print("== metrics stays signed in while serving")
state_while = []
class FakeServer:
    port = 1
    def __init__(self, *a): pass
    def start(self): pass
    def stop(self): state_while.append(session.state())
real_srv, real_pause = service.MetricsServer, getattr(cli.signal, "pause", None)
service.MetricsServer = FakeServer
cli.signal.pause = lambda: (state_while.append(session.state()), (_ for _ in ()).throw(KeyboardInterrupt))
rc, out, err = call("metrics", "--user", "admin")
service.MetricsServer = real_srv
check("signed in while serving, then signed out", rc == 0 and state_while == ["open", "open"] and session.state() == "signed_out", (rc, state_while, err))

print("== moving old backup passwords behind the backups key finds a database locked")
from core import backupsplit, sqldb
def locked_split(progress=None):
    raise sqldb.sqlite3.OperationalError("database is locked")
backupsplit.run, real_split = locked_split, backupsplit.run
rc, out, err = call("status", "--user", "admin")
backupsplit.run = real_split
check("exit 3 with the service message, no traceback, signed out",
      rc == 3 and err.strip() == "Toner's service is using the data. Stop it, then try again." and "Traceback" not in err
      and session.state() == "signed_out", (rc, err))

print("== any other split failure is skipped: the command runs (Ruling 18)")
import zlib
for error in (sqldb.sqlite3.OperationalError("disk I/O error"), sqldb.sqlite3.DatabaseError("file is not a database"), zlib.error("bad")):
    def failing_split(progress=None, e=error):
        raise e
    backupsplit.run = failing_split
    rc, out, err = call("status", "--user", "admin")
    check(f"{type(error).__name__} '{error}': exit 0, results, nothing on stderr",
          rc == 0 and "No results yet" in out and not err.strip() and session.state() == "signed_out", (rc, out, err))
backupsplit.run = real_split

print("== a copy that has not finished encrypting")
lockdown.pending, real_pending = (lambda: ["x.db"]), lockdown.pending
rc, out, err = call("status", "--user", "admin")
lockdown.pending = real_pending
check("exit 3 and signed out", rc == 3 and err.strip() and session.state() == "signed_out", (rc, err))

print("== no stdin at all (Toner.exe is a window program: it has none)")
from core import passvault
asked.clear()
real_stdin = sys.stdin
sys.stdin = None
builtins.input = real_input                          # the real one raises RuntimeError("input(): lost sys.stdin")
rc, out, err = call("status")
check("no --user: exit 3 and the message, no traceback", rc == 3 and err.strip() == "Sign in needs a terminal." and not asked, (rc, err))
rc, out, err = call("status", "--user", "admin")
check("--user given: the password isn't asked either (getpass would fight the shell for keys)",
      rc == 3 and err.strip() == "Sign in needs a terminal." and not asked and not datakey.is_open(), (rc, err, asked))
sys.stdin = real_stdin
print("== stdin from a pipe or a file (TonerCli.exe < x, Task Scheduler): getpass would wait on the console for keys")
real_call_stdin, TERMINAL.isatty = TERMINAL.isatty, lambda: False
asked.clear()
rc, out, err = call("status", "--user", "admin")
check("exit 3 and the message, nothing asked", rc == 3 and err.strip() == "Sign in needs a terminal." and not asked, (rc, err, asked))
TERMINAL.isatty = real_call_stdin
def lost(*a): raise RuntimeError("input(): lost sys.stdin")
builtins.input = lost
rc, out, err = call("status")
check("input() that lost sys.stdin: the same", rc == 3 and err.strip() == "Sign in needs a terminal.", (rc, err))
builtins.input = lambda p="": "admin"

print("== a copy whose old vault hasn't moved over yet (the upgrade stopped halfway)")
keys, vault = datakey.path().read_bytes(), passvault.path().read_bytes()
datakey.path().unlink()
passvault.create("old master password!", remember=False, carry={"a": "1"}); passvault.lock()
datakey.path().write_bytes(keys)
rc, out, err = call("status", "--user", "admin")
check("exit 3 with the unfinished-encrypting message, no traceback",
      rc == 3 and err.strip() == "Toner's data hasn't finished encrypting. Open Toner's window to finish, then try again."
      and session.state() == "signed_out" and not datakey.is_open(), (rc, err))
passvault.path().write_bytes(vault)

print("== encrypted data with netcheck.keys missing")
MISSING = ("Toner's data is encrypted, but netcheck.keys is missing from its data folder. Put netcheck.keys back next to netcheck.db, "
           "then start Toner again.")
datakey.path().unlink()
asked.clear()
rc, out, err = call("status")
check("exit 3 with the message, nothing asked, no key made", rc == 3 and err.strip() == MISSING and not asked and not datakey.exists(), (rc, err))
import app as A
A.console_streams = lambda: None
rc = A.run_cli(["status"])
check("Toner.exe cli: the same, and still no key", rc == 3 and not datakey.exists())
datakey.path().write_bytes(keys)

builtins.input = real_input
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

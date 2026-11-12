# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Command line with security keys (cli.py): the touch line, the key's own PIN without echo, the failures as exit 3, an account
# without keys as before, and a directory attempt that comes back at Duo after the PIN (the Duo skip wasn't earned).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import io, os, sys, time, getpass, builtins, contextlib, types
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\clikeys%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakekey
from core import datakey, db, dirsignin, fidokey, session
import cli

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

PW, KEYPIN = "correct horse battery 42", "key-pin-9"
prompts = []
answers = {"Password: ": PW, "Enter your security key's PIN: ": KEYPIN, "PIN: ": "246813", "Duo code: ": "135790"}
getpass.getpass = lambda prompt="": prompts.append(prompt) or answers[prompt]

class Terminal(io.StringIO):
    def isatty(self): return True
def call(*argv):
    out, err = io.StringIO(), io.StringIO()
    real = sys.stdin; sys.stdin = Terminal(); prompts.clear()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(list(argv))
    finally:
        sys.stdin = real
    return rc, out.getvalue(), err.getvalue()

datakey.create("Admin", PW); db.init()
fake = fakekey.install()
datakey.add_key(PW, *fake.register("Blue", os.urandom(32)), "Blue"); fake.pin = KEYPIN
session.sign_out()

print("== a keyed local account")
rc, out, err = call("status", "--user", "admin")
check("the terminal says to touch the key, then signs in", "Touch your security key" in out and rc == 0, (rc, out, err))
check("off Windows the key's PIN is asked without echo, in the approved words", prompts == ["Password: ", "Enter your security key's PIN: "], prompts)
check("no secret printed", not any(s in out + err for s in (PW, KEYPIN)))
fake.touch = False
rc, out, err = call("status", "--user", "admin")
check("not touched: the approved line on stderr and exit code 3", err.strip() == "The key wasn't touched. Sign in again." and rc == 3, (rc, err))
fake.touch, fake.plugged = True, False
rc, out, err = call("status", "--user", "admin")
check("no key plugged in: its sentence, exit 3", err.strip() == fidokey.NoKey.text and rc == 3, (rc, err))
fake.plugged, answers["Enter your security key's PIN: "] = True, "wrong"
rc, out, err = call("status", "--user", "admin")
check("wrong key PIN: its sentence, exit 3", err.strip() == fidokey.WrongKeyPin.text and rc == 3, (rc, err))
check("still signed out", session.state() == "signed_out" and not datakey.is_open())
answers["Enter your security key's PIN: "] = KEYPIN

print("== an account without keys")
session.sign_in("Admin", PW, key=fake.value); datakey.add_local("Plain", "quiet harbor 8812 lamp"); session.sign_out()
answers["Password: "] = "quiet harbor 8812 lamp"; fake.calls.clear()
rc, out, err = call("status", "--user", "plain")
check("an account without keys is as before", prompts == ["Password: "] and rc == 0 and "Touch" not in out and fake.calls == [], (rc, prompts, err))

print("== directory accounts (dirsignin faked: the command line's own steps)")
class Attempt: pass
log = []
def fake_dir(stages, first_stage="pin"):
    """begin -> first_stage; finish ends at the next of `stages` (each call); duo_push/duo_code move duo -> pin."""
    at = Attempt(); at.stage = first_stage; stages = list(stages)
    dirsignin.classify = lambda login: ("directory", {"kind": "ad"})
    dirsignin.begin = lambda login, pw: at
    dirsignin.after_password = lambda a: None
    def finish(a, pin, key=None):
        log.append(("finish", key is not None)); a.stage = stages.pop(0)
    def duo_push(a, cancel): log.append("duo"); a.stage = "pin"
    dirsignin.finish, dirsignin.duo_push = finish, duo_push
    return at
answers["Password: "] = "pw-bob"
cli._run = lambda a, ready=None: 0                # (the stubbed sign-in opens no data)
cli.lockdown.pending = lambda: []; cli.backupsplit.run = lambda *a: None
log.clear(); fake_dir(["done"])
rc, out, err = call("status", "--user", "bob@acme.com")
check("a keyed AD account: the key callable is passed to finish and it signs in", rc == 0 and log == [("finish", True)], (rc, prompts, log, err))
log.clear(); fake_dir(["duo", "done"])
rc, out, err = call("status", "--user", "bob@acme.com")
check("finish back at Duo: Duo runs, the PIN is asked again, finish gets the key again", rc == 0 and log == [("finish", True), "duo", ("finish", True)]
      and prompts == ["Password: ", "PIN: ", "PIN: "], (rc, log, prompts, err))
log.clear(); fake_dir(["duo", "duo"])
rc, out, err = call("status", "--user", "bob@acme.com")
check("guard against a loop (should be unreachable in real use): a second return at Duo ends in exit 3 after one Duo run", rc == 3 and err.strip() == cli.APPROVAL and log.count("duo") == 1, (rc, log, err))
log.clear(); fake_dir(["approve"])
rc, out, err = call("status", "--user", "bob@acme.com")
check("finish at approve: the approval sentence, exit 3", rc == 3 and err.strip() == cli.APPROVAL, (rc, err))
def key_fails(a, pin, key=None): key([types.SimpleNamespace()])
fake_dir([]); dirsignin.finish = key_fails; fake.touch = False
rc, out, err = call("status", "--user", "bob@acme.com")
check("a failed touch at the directory PIN: the sentence on stderr, exit 3", rc == 3 and err.strip() == fidokey.NotTouched.text, (rc, err))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Session: signed out, locked or open; the audit log names the Toner user; worker threads still read while locked.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import os, sys, time, threading, getpass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\sess%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import audit, datakey, db, passvault, session, sqldb

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

PW = "correct horse battery 42"
check("nobody signed in at the start", session.state() == "signed_out" and session.user() is None)
check("actor falls back to the OS user", audit.actor() == getpass.getuser())
recovery = datakey.create("Admin", PW)
db.init()
session.sign_out()
check("signed out", session.state() == "signed_out" and session.user() is None)
check("signed out closes the key", not datakey.is_open() and sqldb.current_key() is None)

seen = []
session.on_change(seen.append)
session.on_change(lambda s: 1 / 0)          # a broken listener must not stop the others
session.sign_in("admin", PW)
check("open", session.state() == "open")
check("user is the stored spelling", session.user() == "Admin")
check("actor is the Toner user", audit.actor() == "Admin")
def newest():
    return audit.recent(1)[0]
check("signed in is audited", newest()["action"] == "signed in" and newest()["actor"] == "Admin")
check("on_change got the state", seen == ["open"], seen)
try: session.sign_in("admin", PW); check("sign_in while open refused", False)
except RuntimeError: check("sign_in while open refused", True)

session.lock()
check("locked", session.state() == "locked" and session.user() == "Admin")
check("locked is audited", newest()["action"] == "locked")
got = []
def worker():
    try:
        with db.connect() as c:
            got.append(c.execute("SELECT count(*) FROM devices").fetchone()[0])
    except Exception as e:
        got.append(e)
t = threading.Thread(target=worker); t.start(); t.join()
check("worker threads still read while locked", len(got) == 1 and isinstance(got[0], int), got)
try: session.unlock("wrong"); check("wrong password refused", False)
except datakey.WrongPassword: check("wrong password refused", True)
check("still locked after a wrong password", session.state() == "locked")
check("unlock failed is audited", newest()["action"] == "unlock failed" and PW not in newest()["detail"])
session.unlock(PW)
check("unlock opens", session.state() == "open" and newest()["action"] == "unlocked")
try: session.unlock(PW); check("unlock while open refused", False)
except RuntimeError: check("unlock while open refused", True)

session.sign_out()
check("sign_out closes everything", session.state() == "signed_out" and not datakey.is_open()
      and sqldb.current_key() is None and not passvault.is_open())
try: session.lock(); check("lock while signed out refused", False)
except RuntimeError: check("lock while signed out refused", True)
check("actor falls back again", audit.actor() == getpass.getuser())

session.sign_in_recovery(recovery)
check("recovery sign-in", session.state() == "open" and session.user() is None)
check("recovery sign-in is audited", newest()["action"] == "signed in with the recovery key")
session.sign_out()
session.sign_in("admin", PW)
check("signed out is audited", [r["action"] for r in audit.recent(3)][:2] == ["signed in", "signed out"], audit.recent(3))

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

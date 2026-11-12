# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Session with a security key (core/session.py): sign-in with the key, unlock with a touch, the touch never under session's lock,
# and a sign-out or refusal during the touch still wins.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import os, sys, time, threading
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\sesskeys%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakekey
from core import audit, datakey, db, fidokey, session

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)


def raised(exc, fn):
    try:
        fn()
    except exc:
        return True
    except Exception as e:
        print("   (raised", type(e).__name__, e, ")")
    return False


def lock_free():
    """True when another thread can take session's lock now (the caller is inside a touch)."""
    got = []
    def take():
        if session._lock.acquire(timeout=2):
            got.append(1)
            session._lock.release()
    t = threading.Thread(target=take); t.start(); t.join()
    return got == [1]


PW = "correct horse battery 42"
datakey.create("Admin1", PW)
db.init()
fake = fakekey.install()
cred, val = fake.register("Blue", os.urandom(32))
datakey.add_key(PW, cred, val, "Blue")
session.sign_out()
seen = []
session.on_change(seen.append)

free = []
session.sign_in("Admin1", PW, key=lambda creds: free.append(lock_free()) or fake.value(creds))
check("sign in with the key: open, and the key's touch is not under session's lock", session.state() == "open" and free == [True])
check("a keyed sign-in without the key is refused, nothing open", session.sign_out() or (
    raised(datakey.KeyNeeded, lambda: session.sign_in("Admin1", PW)) and session.state() == "signed_out" and not datakey.is_open()))
session.sign_in("Admin1", PW, key=fake.value)
session.lock()
free.clear()
session.unlock(PW, present=lambda creds: free.append(lock_free()) or fake.present(creds))
check("unlock with presence: open, and the touch is not under session's lock", session.state() == "open" and free == [True])
session.lock()
fake.touch = False
check("unlock without the touch stays locked", raised(fidokey.NotTouched, lambda: session.unlock(PW, present=fake.present))
      and session.state() == "locked")
fake.touch = True
check("unlock of a keyed account without a key stays locked", raised(datakey.KeyNeeded, lambda: session.unlock(PW)) and session.state() == "locked")
session.sign_out()
session.sign_in("Admin1", PW, key=fake.value)
session.lock()
session.unlock(PW, present=fake.present)
session.sign_out()
session.sign_in("Admin1", PW, key=fake.value)                      # (the audit table opens with the key)
actions = [r["action"] for r in audit.recent(5)][1:][::-1]
session.sign_out()
check("sign in, lock, unlock with presence, sign out: the audit rows are today's", actions == ["signed in", "locked", "unlocked", "signed out"], actions)

# a sign-out, or a refusal, while the touch waits: the unlock doesn't open what is no longer locked
session.sign_in("Admin1", PW, key=fake.value)
session.lock()
check("signed out during the touch: refused, still signed out",
      raised(RuntimeError, lambda: session.unlock(PW, present=lambda creds: session.sign_out() or fake.present(creds)))
      and session.state() == "signed_out" and not datakey.is_open())
session.sign_in("Admin1", PW, key=fake.value)
session.lock()
check("refused during the touch: Refused, still locked",
      raised(session.Refused, lambda: session.unlock(PW, present=lambda creds: session.lock(reason="refused") or fake.present(creds)))
      and session.state() == "locked")
session.sign_out()

# a second sign-in while the first waits on its key
second = []
def key_then_try(creds):
    second.append(raised(RuntimeError, lambda: session.sign_in("Admin1", PW, key=fake.value)))
    return fake.value(creds)
seen.clear()
session.sign_in("Admin1", PW, key=key_then_try)
check("a second sign-in during the touch is refused; the first one signs in, told once", second == [True] and session.state() == "open"
      and seen == ["open"])
check("no secret in the audit log", not any(PW in str(r["detail"]) for r in audit.recent(200)))
session.sign_out()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

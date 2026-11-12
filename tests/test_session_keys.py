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

# unlock trusts the session, not the file: someone who knows the password and rewrites netcheck.keys still needs one of its keys
import base64, json
b64 = lambda b: base64.b64encode(b).decode("ascii")
attacker = fakekey.FakeKey()
acred, _ = attacker.register("Mine", os.urandom(32))


def forge(keys_list=None):
    """Admin1's record rewritten under the password: a plain record sealing junk, or (keys_list) its key list re-made."""
    d = datakey.read(); r = d["accounts"]["Admin1"]
    kek = datakey._kek(PW, base64.b64decode(r["kdf"]["salt"]), r["kdf"])
    if keys_list is None:
        for f in ("keys", "keys_n", "sealed_k"):
            r.pop(f, None)
        r["key"] = b64(datakey._enc(kek, os.urandom(64), datakey._aad("Admin1")))
    else:
        blob = {"list": [{"id": b64(c.id), "salt": b64(c.salt), "pub": b64(c.public), "name": "Mine", "added": "2026-11-12T00:00:00+00:00"} for c in keys_list],
                "wraps": [b64(os.urandom(60)) for _ in keys_list]}
        r["keys"] = b64(datakey._enc(kek, json.dumps(blob).encode(), datakey.KEYS_AAD + b"Admin1"))
    datakey._write(d)


session.sign_in("Admin1", PW, key=fake.value)
session.lock()
saved = datakey.read()
forge()
check("signed in with a key, the record made plain by hand: unlock without a key stays locked",
      raised(datakey.KeyNeeded, lambda: session.unlock(PW)) and session.state() == "locked")
fake.touch = False
check("...and without the touch", raised(fidokey.NotTouched, lambda: session.unlock(PW, present=fake.present)) and session.state() == "locked")
fake.touch = True
session.unlock(PW, present=fake.present)
check("...the session's own key still unlocks it", session.state() == "open")
datakey._write(saved)
session.lock()
forge([acred])
check("its key list re-made with another key by hand: that key doesn't unlock it",
      raised(fidokey.NotRegistered, lambda: session.unlock(PW, present=attacker.present)) and session.state() == "locked")
session.unlock(PW, present=fake.present)
check("...the session's own key still does", session.state() == "open")
datakey._write(saved)
datakey.remove_key(PW, 0)
session.lock()
session.unlock(PW)
check("the last key removed while signed in: the password alone unlocks, as for any account without keys", session.state() == "open")
gcred, gval = fake.register("Green", os.urandom(32))
datakey.add_key(PW, gcred, gval, "Green")
session.lock()
saved = datakey.read()
forge()
check("a first key added while signed in, the record made plain by hand: unlock still needs it",
      raised(datakey.KeyNeeded, lambda: session.unlock(PW)) and session.state() == "locked")
session.unlock(PW, present=fake.present)
check("...and it unlocks", session.state() == "open")
datakey._write(saved)

# ...however the file spells or files the account: every edit leaves a keyed session locked without one of its keys
import copy
session.lock()


def plain_as(spelling):
    """Admin1's record made plain, sealing junk under the password for `spelling`."""
    r = {k: v for k, v in saved["accounts"]["Admin1"].items() if k not in ("keys", "keys_n", "sealed_k")}
    kek = datakey._kek(PW, base64.b64decode(r["kdf"]["salt"]), r["kdf"])
    r["key"] = b64(datakey._enc(kek, os.urandom(64), datakey._aad(spelling)))
    return r


def edited(change):
    d = copy.deepcopy(saved)
    d["accounts"] = change(d["accounts"])
    datakey._write(d)


def stays_locked():
    """Unlock with no key, another key, and no touch: (all refused in words the lock screen has, still locked; what each did)."""
    did = []
    for present in (None, attacker.present, "no touch"):
        fake.touch = present != "no touch"
        try:
            session.unlock(PW, present=fake.present if present == "no touch" else present)
            did.append("open")
        except (datakey.KeyNeeded, fidokey.Failed, datakey.WrongPassword, datakey.Throttled) as e:
            did.append(type(e).__name__)
        except Exception as e:
            did.append("raised " + type(e).__name__)
        fake.touch = True
        if session.state() == "open":
            session.lock()
    return all(x in ("KeyNeeded", "NotRegistered", "NotTouched", "WrongPassword") for x in did), did


CASES = {"the record renamed to another letter case, made plain": lambda a: {"admin1": plain_as("admin1"), **{k: v for k, v in a.items() if k != "Admin1"}},
         "a second record whose name differs only in case, made plain": lambda a: {"admin1": plain_as("admin1"), **a},
         "the record's kind swapped": lambda a: {**a, "Admin1": {**a["Admin1"], "kind": "directory"}},
         "the record removed": lambda a: {k: v for k, v in a.items() if k != "Admin1"}}
for what, change in CASES.items():
    datakey.edit(lambda d: d.__setitem__("throttle", {"fails": 0, "until": 0}), signed_in=True)
    saved = datakey.read()
    edited(change)
    refused, did = stays_locked()
    datakey._write(saved)
    session.unlock(PW, present=fake.present)
    check(f"local, {what}: stays locked without its key; the file put back, its own key unlocks", refused and session.state() == "open", did)
    session.lock()
session.unlock(PW, present=fake.present)
session.sign_out()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

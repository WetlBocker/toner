# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The data key (core/datakey.py): sealed per local account and under a recovery key in netcheck.keys, the throttle on wrong
# passwords, an unknown name costing as much as a real check, a portable copy, and no secret in the file in any form.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\datakey%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1
    else: bad += 1; print("FAIL", name, extra)

import base64, importlib, re, shutil, statistics
from pathlib import Path
from core import sqldb
from core import datakey as D

PW, PW2 = "correct horse battery staple", "another long password 9"
WRONG_MSG = "That username or password isn't right."


def raises(fn, exc):
    try:
        fn()
    except exc as e:
        return e
    except Exception as e:
        print("   (raised", type(e).__name__, e, ")")
        return None
    return None


# sqldb.set_key takes 32 bytes or None, and never puts the key in its message
e = raises(lambda: sqldb.set_key(b"0123456789abcdef"), ValueError)
check("set_key refuses a short key", e is not None and "0123456789abcdef" not in str(e) and "3031" not in str(e))
check("set_key refuses a str", raises(lambda: sqldb.set_key("x" * 32), ValueError) is not None)
check("set_key left unchanged by a refusal", sqldb.current_key() is None)

# create
check("no file yet", not D.exists() and not D.is_open())
check("create refuses a weak password", raises(lambda: D.create("admin", "short"), ValueError) is not None and not D.exists())
check("create refuses a blank name", raises(lambda: D.create("   ", PW), ValueError) is not None and not D.exists())
r = D.create("  admin ", PW)
check("create opens", D.is_open() and D.exists())
key = sqldb.current_key()
check("sqldb has a 32-byte key", key is not None and len(key) == 32)
check("recovery key shape", re.fullmatch(r"[A-Z2-7]{4}(-[A-Z2-7]{4}){7}", r) is not None, r)
check("path beside the db", D.path() == db.base_path().with_suffix(".keys"))
check("create again refuses (would orphan the data)", raises(lambda: D.create("other", PW), FileExistsError) is not None)
check("name stored stripped", [a["name"] for a in D.accounts()] == ["admin"])
key = bytes(key)

# open with password / recovery
D.close()
check("close wipes", not D.is_open() and sqldb.current_key() is None)
D.open_with_password("admin", PW)
check("password opens the same key", D.is_open() and bytes(sqldb.current_key()) == key)
D.close()
D.open_with_recovery(r.lower().replace("-", " "))
check("recovery opens (case, spaces, dashes ignored)", D.is_open() and bytes(sqldb.current_key()) == key)

# a second account
D.add_local("JSmith", PW2)
check("add_local duplicate (case-insensitive) is NameTaken", raises(lambda: D.add_local("ADMIN", "a different pass phrase 7"), D.NameTaken) is not None)
check("add_local weak password refused", raises(lambda: D.add_local("bob", "password1234"), ValueError) is not None)
check("add_local refuses username in password", raises(lambda: D.add_local("bob", "bob is a long password"), ValueError) is not None)
acc = D.accounts()
check("accounts sorted, case kept", [a["name"] for a in acc] == ["admin", "JSmith"] and all(a["kind"] == "local" and a["created"] for a in acc), acc)
D.close()
D.open_with_password("jsmith", PW2)
check("second account opens the same key (name case-insensitive)", bytes(sqldb.current_key()) == key)
D.close()
D.open_with_password("ADMIN", PW)
check("first account still opens", bytes(sqldb.current_key()) == key)

# set_password
D.set_password("jsmith", "yet another pass phrase 3")
check("old password now wrong", raises(lambda: D.open_with_password("jsmith", PW2), D.WrongPassword) is not None)
D.close()
D.open_with_password("jsmith", "yet another pass phrase 3")
check("new password opens", bytes(sqldb.current_key()) == key)

# remove
D.remove("JSMITH")
check("remove works", [a["name"] for a in D.accounts()] == ["admin"])
check("removed account can't open", raises(lambda: D.open_with_password("jsmith", "yet another pass phrase 3"), D.WrongPassword) is not None)
check("remove last raises LastAccount", raises(lambda: D.remove("admin"), D.LastAccount) is not None)

# new recovery
r2 = D.new_recovery()
check("new recovery differs", r2 != r and re.fullmatch(r"[A-Z2-7]{4}(-[A-Z2-7]{4}){7}", r2) is not None)
D.close()
check("old recovery now wrong", raises(lambda: D.open_with_recovery(r), D.WrongPassword) is not None)
D.open_with_recovery(r2)
check("new recovery opens", bytes(sqldb.current_key()) == key)

# Locked: changes need the key
D.close()
check("add_local while closed is Locked", raises(lambda: D.add_local("bob", PW2), D.Locked) is not None)
check("new_recovery while closed is Locked", raises(lambda: D.new_recovery(), D.Locked) is not None)
D.open_with_password("admin", PW)

# throttle, on a fake clock: one counter for every password try, whatever the name
BAD = "wrong password here 1"
D.add_local("jsmith", PW2)
real_time = time.time
T = [real_time()]
time.time = lambda: T[0]
try:
    msgs = [raises(lambda: D.open_with_password("admin", BAD), D.WrongPassword) for _ in range(3)]
    msgs += [raises(lambda: D.open_with_password("nobody", BAD), D.WrongPassword) for _ in range(2)]
    check("five wrong across names (3 admin, 2 unknown): WrongPassword each", all(m is not None and str(m) == WRONG_MSG for m in msgs), msgs)
    e = raises(lambda: D.open_with_password("jsmith", BAD), D.Throttled)
    check("sixth, on a third name: Throttled 30", e is not None and e.seconds == 30 and str(e) == "Too many tries. Wait 30 seconds, then try again.", e)
    kdf_calls = [0]
    real_kek = D._kek
    D._kek = lambda *a: (kdf_calls.__setitem__(0, kdf_calls[0] + 1), real_kek(*a))[1]
    e1 = raises(lambda: D.open_with_password("nobody", PW), D.Throttled)
    e2 = raises(lambda: D.open_with_password("admin", PW), D.Throttled)
    e3 = raises(lambda: D.check_password("admin", PW), D.Throttled)
    D._kek = real_kek
    check("while throttled: unknown and real names (even the right password) all Throttled 30",
          all(e is not None and e.seconds == 30 for e in (e1, e2, e3)), (e1, e2, e3))
    check("a throttled try runs no scrypt", kdf_calls[0] == 0, kdf_calls)
    T[0] += 10
    e = raises(lambda: D.open_with_password("admin", PW), D.Throttled)
    check("remaining wait counts down", e is not None and e.seconds == 20, e and e.seconds)
    T[0] += 20
    waits = []
    for i in range(7):
        e = raises(lambda: D.open_with_password(("admin", "nobody", "jsmith")[i % 3], BAD), D.Throttled)
        waits.append(e and e.seconds)
        T[0] += e.seconds if e else 0
    check("doubles, capped at 900, across names", waits == [60, 120, 240, 480, 900, 900, 900], waits)
    D.close()
    D.open_with_password("admin", PW)                                    # the clock has moved past the last wait
    check("right password after the wait opens", D.is_open())
    msgs = [raises(lambda: D.open_with_password(n, BAD), D.WrongPassword) for n in ("jsmith", "nobody", "admin", "x", "admin")]
    check("the right password reset the shared count", all(m is not None for m in msgs))
    D.open_with_password("admin", PW)

    # failure count persists across a reload
    for _ in range(6):
        raises(lambda: D.open_with_password("admin", BAD), Exception)
    D = importlib.reload(D)
    e = raises(lambda: D.open_with_password("admin", PW), D.Throttled)
    check("after reload still throttled", e is not None and e.seconds == 30, e)
    T[0] += 30
    e = raises(lambda: D.open_with_password("nobody", BAD), D.Throttled)
    check("after reload the count is read back (next wrong is 60)", e is not None and e.seconds == 60, e)
    T[0] += 60
    D.open_with_password("admin", PW)

    # a clock moved back can't stretch a wait past the cap
    for _ in range(6):
        raises(lambda: D.open_with_password("admin", BAD), Exception)
    T[0] -= 100000
    e = raises(lambda: D.open_with_password("admin", PW), D.Throttled)
    check("clock back: wait capped at 900", e is not None and e.seconds == 900, e and e.seconds)
    T[0] += 900
    D.open_with_password("admin", PW)
    check("clock back: opens once the capped wait is over", D.is_open())

    # check_password: True/False, throttled the same way
    check("check_password right", D.check_password("Admin", PW) is True)
    check("check_password wrong", D.check_password("admin", BAD) is False)
    check("check_password unknown", D.check_password("nobody", PW) is False)
    for _ in range(3):
        D.check_password("jsmith", BAD)
    check("check_password sixth is Throttled", raises(lambda: D.check_password("admin", BAD), D.Throttled) is not None)

    # recovery has its own counter, both ways
    D.close()
    D.open_with_recovery(r2)
    check("recovery opens while passwords are throttled", D.is_open())
    T[0] += 30
    check("check_password resets", D.check_password("admin", PW) is True)
    for _ in range(5):
        raises(lambda: D.open_with_recovery("AAAA-AAAA"), D.WrongPassword)
    e = raises(lambda: D.open_with_recovery("AAAA-AAAA"), D.Throttled)
    check("recovery throttled on the sixth", e is not None and e.seconds == 30)
    check("password not throttled by recovery tries", D.check_password("admin", PW) is True)
    T[0] += 30
    D.open_with_recovery(r2)
    check("recovery reset after the wait", D.is_open())
finally:
    time.time = real_time

# an unknown name: same message, same cost
e1 = raises(lambda: D.open_with_password("nobody", PW), D.WrongPassword)
e2 = raises(lambda: D.open_with_password("admin", "wrong password here 2"), D.WrongPassword)
check("unknown name: same message", e1 is not None and e2 is not None and str(e1) == str(e2) == WRONG_MSG)
D.open_with_password("admin", PW)           # reset the count


def timed(fn):
    t = time.perf_counter(); fn(); return time.perf_counter() - t


real, fake, wrong = [], [], []
for _ in range(5):                          # reset between tries so the shared count never throttles
    real.append(timed(lambda: D.check_password("admin", PW)))
    fake.append(timed(lambda: D.check_password("nobody", PW)))
    D.check_password("admin", PW)
    wrong.append(timed(lambda: D.check_password("admin", BAD)))
    D.check_password("admin", PW)
real, fake, wrong = map(statistics.median, (real, fake, wrong))
check("unknown name takes >= 80% of a real check", fake >= 0.8 * real, f"{fake:.3f} vs {real:.3f}")
check("unknown name takes >= 80% of a wrong password on a real name", fake >= 0.8 * wrong, f"{fake:.3f} vs {wrong:.3f}")
print(f"   timing medians: right {real:.3f}s, unknown {fake:.3f}s, wrong {wrong:.3f}s")
D.check_password("nobody", PW)
check("unknown name adds no record", b"nobody" not in D.path().read_bytes() and [a["name"] for a in D.accounts()] == ["admin", "jsmith"])
check("no per-account counters", all(set(a) == {"kind", "kdf", "key", "created", "box_pub", "role"} for a in __import__("json").loads(D.path().read_text())["accounts"].values()))
D.check_password("admin", PW)

# no secret in the file in any form
blob = D.path().read_bytes()
raw_r2 = base64.b32decode(r2.replace("-", ""))
secrets = [PW.encode(), PW2.encode(), "yet another pass phrase 3".encode(), key, raw_r2, r.encode(), r2.encode(),
           r2.replace("-", "").encode(), base64.b32decode(r.replace("-", ""))]
leaks = []
for s in secrets:
    for form in (s, s.hex().encode(), s.hex().upper().encode(), base64.b64encode(s), base64.urlsafe_b64encode(s),
                 base64.b64encode(s).rstrip(b"=")):
        if form in blob:
            leaks.append(form[:6])
check("no password, key or recovery key in the file (raw, hex, base64)", not leaks, leaks)

# a portable copy opens anywhere
D.close()
other = Path(SP) / ("portable%d" % int(time.time())); other.mkdir()
shutil.copy(db.base_path(), other / "netcheck.db")
shutil.copy(D.path(), other / "netcheck.keys")
os.environ["NETCHECK_DB"] = str(other / "netcheck.db")
check("copy found", D.exists() and D.path() == other / "netcheck.keys")
D.open_with_password("admin", PW)
check("portable copy opens", bytes(sqldb.current_key()) == key)
D.close()

# accounts() reads under the same file lock the writers take (a writer's os.replace fails on Windows under a reader)
used = []
real_lock = D._FileLock
D._FileLock = lambda: (used.append(1), real_lock())[1]
D.accounts()
D._FileLock = real_lock
check("accounts() takes the file lock", used == [1], used)

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

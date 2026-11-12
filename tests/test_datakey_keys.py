# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Security keys on local accounts (core/datakey.py): the password opens the key list, a key's value opens the data key, the box
# key never changes with keys, removing the last key stores the account as before, and no secret reaches a log or the audit.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\dkkeys%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
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

import base64, json, logging, subprocess, threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakekey
from core import audit, fidokey, lockdown, sqldb
from core import datakey
from core.platforms import FileLock

PW, PW2, PW3, NEW_PW, TPW = "correct horse battery staple", "another long password 9", "a third quite long password 5", "a fresh reset password 4", "the tech's own long password 8"
captured_log = []


class Grab(logging.Handler):
    def emit(self, record):
        captured_log.append(self.format(record))


logging.getLogger().addHandler(Grab())
logging.getLogger().setLevel(logging.DEBUG)


def b64(b):
    return base64.b64encode(b).decode("ascii")


def raised(exc, fn):
    """True only when fn raises exc (its message goes to captured_log, so the secret check covers it too)."""
    try:
        fn()
    except exc as e:
        captured_log.append(f"{type(e).__name__}: {e}")
        return True
    except Exception as e:
        captured_log.append(f"{type(e).__name__}: {e}")
        print("   (raised", type(e).__name__, e, ")")
    return False


def throttle_fails():
    return datakey.read()["throttle"]["fails"]


def opens(name, pw, key):
    datakey.close()
    datakey.open_with_password(name, pw, key=key)
    return datakey.is_open() and bytes(sqldb.current_key()) == DATA_KEY


fake = fakekey.install()
datakey.create("Admin1", PW)
lockdown.run()                                                    # the database on the data key, so the audit rows land
DATA_KEY = bytes(sqldb.current_key())
plain_record = datakey.read()["accounts"]["Admin1"]
check("an account without keys has none", datakey.my_keys() == [] and not datakey.has_keys("Admin1") and "keys_n" not in plain_record)

# the first key
box_before = datakey.box_public("Admin1")
cred, val = fake.register("Blue", os.urandom(32)); datakey.add_key(PW, cred, val, "Blue")
k2_hex = datakey._k2.hex()
rec = datakey.read()["accounts"]["Admin1"]
check("the first key takes the password-only seal away, in the same write", "key" not in rec and rec["keys_n"] == 1 and "sealed_k" in rec)
check("the box key is the same", datakey.box_public("Admin1") == box_before)
check("the key's name is listed; its id, number and public half are not in the file in the clear", datakey.my_keys()[0]["name"] == "Blue"
      and all(b64(x) not in json.dumps(rec) and x.hex() not in json.dumps(rec) for x in (cred.id, cred.salt, cred.public)))
check("has_keys reads the hint", datakey.has_keys("admin1") and not datakey.has_keys("nobody"))
check("the other fields are as before", {k: v for k, v in rec.items() if k not in ("keys_n", "keys", "sealed_k")}
      == {k: v for k, v in plain_record.items() if k != "key"})
datakey.close()
check("close drops the keys and K2", datakey._keys is None and datakey._k2 is None and datakey.my_keys() == [])
check("the password alone no longer opens it", raised(datakey.KeyNeeded, lambda: datakey.open_with_password("Admin1", PW)))
check("...and nothing is left open", not datakey.is_open())
check("the password and the key open it", datakey.open_with_password("Admin1", PW, key=fake.value) == 0 and datakey.is_open()
      and bytes(sqldb.current_key()) == DATA_KEY and datakey.box_private() is not None and datakey.my_keys()[0]["name"] == "Blue")


def wrong_pw_with_key():
    datakey.close(); fake.calls.clear()
    datakey.open_with_password("Admin1", "not the password at all", key=fake.value)


check("a wrong password is refused before the key is asked, and counts as today", raised(datakey.WrongPassword, wrong_pw_with_key) and fake.calls == [] and throttle_fails() == 1)
fake.touch = False


def open_again():
    datakey.close()
    datakey.open_with_password("Admin1", PW, key=fake.value)


check("no touch: NotTouched, nothing open, no throttle count", raised(fidokey.NotTouched, open_again) and not datakey.is_open() and throttle_fails() == 0)
fake.touch = True


def open_with_other_fake():
    datakey.close()
    datakey.open_with_password("Admin1", PW, key=fakekey.FakeKey().value)


check("a key of another account: NotRegistered", raised(fidokey.NotRegistered, open_with_other_fake) and not datakey.is_open())
check("a key answering for one of the account's ids with the wrong value: NotRegistered (the wrap does not open)",
      raised(fidokey.NotRegistered, lambda: datakey.open_with_password("Admin1", PW, key=lambda creds: (creds[0].id, os.urandom(32)))) and not datakey.is_open())
check("an id that is none of the account's: NotRegistered",
      raised(fidokey.NotRegistered, lambda: datakey.open_with_password("Admin1", PW, key=lambda creds: (os.urandom(32), val))) and not datakey.is_open())

# the key is asked with no lock held: another thread can take both locks while it waits for the touch
held = []


def probe(creds):
    def other():
        got = datakey._lock.acquire(timeout=2)
        if got:
            datakey._lock.release()
        with FileLock(datakey.path().with_name(datakey.path().name + ".lock")) as f:
            held.append((got, f.locked))
    t = threading.Thread(target=other); t.start(); t.join()
    return fake.value(creds)


check("the key is asked with neither the module lock nor the file lock held", opens("Admin1", PW, probe) and held == [(True, True)], held)

# a second key
spare, spare_val = fake.register("Spare", os.urandom(32)); datakey.add_key(PW, spare, spare_val, "Spare")
check("the second key keeps the box key and K2", datakey.box_public("Admin1") == box_before and datakey._k2.hex() == k2_hex
      and [k["name"] for k in datakey.my_keys()] == ["Blue", "Spare"] and datakey.read()["accounts"]["Admin1"]["keys_n"] == 2)
second_key_opens = opens("Admin1", PW, lambda creds: fake.value([c for c in creds if c.id == spare.id]))
check("a second key works alone", second_key_opens)
fake.calls.clear()
check("unlock: the password and presence, without reading the value", datakey.check_password("Admin1", PW, present=fake.present)
      and fake.calls == ["present"] and "value" not in fake.calls)
check("unlock: a wrong password is False, and the key is not asked", fake.calls.clear() or (datakey.check_password("Admin1", "wrong wrong wrong", present=fake.present) is False and fake.calls == []))
check("unlock: a key of another account is NotRegistered",
      raised(fidokey.NotRegistered, lambda: datakey.check_password("Admin1", PW, present=fakekey.FakeKey().present)))
check("unlock: an id that is none of the account's is NotRegistered",
      raised(fidokey.NotRegistered, lambda: datakey.check_password("Admin1", PW, present=lambda creds: os.urandom(32))))
check("unlock with no way to ask: KeyNeeded", raised(datakey.KeyNeeded, lambda: datakey.check_password("Admin1", PW)))
check("a wrong password cannot add a key to a keyed account", raised(datakey.WrongPassword, lambda: datakey.add_key("nope", cred, val, "x"))
      and datakey.read()["accounts"]["Admin1"]["keys_n"] == 2)
check("a wrong password cannot remove", raised(datakey.WrongPassword, lambda: datakey.remove_key("nope", 0))
      and datakey.read()["accounts"]["Admin1"]["keys_n"] == 2)
fake.calls.clear()
datakey.set_password("Admin1", PW2)                               # your own password, while signed in
reopens_with = lambda pw, key: opens("Admin1", pw, key)
check("your keys still work with the new password, with no touch asked for the change", fake.calls == [] and reopens_with(PW2, fake.value)
      and [k["name"] for k in datakey.my_keys()] == ["Blue", "Spare"] and datakey._k2.hex() == k2_hex)
check("...and the old password does not", raised(datakey.WrongPassword, lambda: opens("Admin1", PW, fake.value)))
opens("Admin1", PW2, fake.value)
datakey.remove_key(PW2, 0)
check("removing one of two keeps the other", [k["name"] for k in datakey.my_keys()] == ["Spare"]
      and datakey.read()["accounts"]["Admin1"]["keys_n"] == 1)
check("...the removed one no longer opens it", raised(fidokey.NotRegistered, lambda: opens("Admin1", PW2, lambda creds: fake.value([cred])))
      and opens("Admin1", PW2, fake.value))
box_now = datakey.box_public("Admin1")
datakey.remove_key(PW2, 0)
rec = datakey.read()["accounts"]["Admin1"]
check("removing the last: stored as an account without keys is", set(rec) == set(plain_record) and list(rec) == list(plain_record)
      and rec["kdf"]["n"] == plain_record["kdf"]["n"] and reopens_with(PW2, None))
check("...with the box key kept", datakey.box_public("Admin1") == box_now and datakey.my_keys() == [] and not datakey.has_keys("Admin1"))
check("a wrong password cannot add or remove", raised(datakey.WrongPassword, lambda: datakey.add_key("nope", cred, val, "x"))
      and raised(IndexError, lambda: datakey.remove_key(PW2, 0)) and "keys_n" not in datakey.read()["accounts"]["Admin1"])

# an admin's reset of someone else
datakey.add_local("Tech1", TPW, role="Tech")
opens("Tech1", TPW, None)
tcred, tval = fake.register("Tech's", os.urandom(32)); datakey.add_key(TPW, tcred, tval, "Tech's")
check("the tech's key is on its own record", datakey.has_keys("Tech1") and not datakey.has_keys("Admin1"))
opens("Admin1", PW2, None)
datakey.set_password("Tech1", NEW_PW)
trec = datakey.read()["accounts"]["Tech1"]
reset_of_tech_by_admin_leaves_no_key_fields = not ({"keys_n", "keys", "sealed_k"} & set(trec)) and "key" in trec
tech_opens_with = lambda pw, key: opens("Tech1", pw, key) and datakey.my_keys() == []
check("an admin's reset of someone else clears their keys", reset_of_tech_by_admin_leaves_no_key_fields and tech_opens_with(NEW_PW, None))

# two processes adding at once (each signed in with the base key, then both add while contending on the file lock)
opens("Admin1", PW2, None)
base, base_val = fake.register("Base", os.urandom(32)); datakey.add_key(PW2, base, base_val, "Base")
CHILD = r"""
import base64, json, os, sys, time
sys.path.insert(0, sys.argv[2])
import keyring
keyring.set_password = keyring.get_password = keyring.delete_password = lambda *a: None
from core import datakey, fidokey
d = json.load(open(sys.argv[1])); u = base64.b64decode
datakey.open_with_password(d["name"], d["pw"], key=(lambda creds: (u(d["kid"]), u(d["kval"]))) if d.get("kid") else None)
if d.get("go"):
    open(d["ready"], "w").close()
    while not os.path.exists(d["go"]):
        time.sleep(0.005)
if d.get("remove"):
    datakey.remove_key(d["pw"], [k["name"] for k in datakey.my_keys()].index(d["remove"]))
else:
    datakey.add_key(d["pw"], fidokey.Cred(u(d["id"]), u(d["salt"]), u(d["pub"])), u(d["val"]), d["label"])
"""
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def child(tag, **d):
    """Another Toner process: signs in as d["name"] (with the key kid/kval when given), then adds the key in d or removes d["remove"]."""
    spec = os.path.join(SP, tag + ".json")
    with open(spec, "w") as f:
        json.dump(d, f)
    return subprocess.Popen([sys.executable, "-c", CHILD, spec, root], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def key_spec(c, v, label):
    return {"id": b64(c.id), "salt": b64(c.salt), "pub": b64(c.public), "val": b64(v), "label": label}


def run_child(tag, **d):
    k = child(tag, **d)
    out = k.communicate(timeout=120)[0]
    captured_log.append(out)
    return k.returncode == 0


go, kids, added, specs = os.path.join(SP, "go"), [], [], {}
for label in ("Left", "Right"):
    c, v = fake.register(label, os.urandom(32)); added.append(c)
    specs[label] = dict(name="Admin1", pw=PW2, kid=b64(base.id), kval=b64(base_val), **key_spec(c, v, label))
    kids.append(child(label, **specs[label], ready=os.path.join(SP, label + ".ready"), go=go))
while not all(os.path.exists(os.path.join(SP, l + ".ready")) for l in ("Left", "Right")) and all(k.poll() is None for k in kids):
    time.sleep(0.01)
open(go, "w").close()
outs = [k.communicate(timeout=120)[0] for k in kids]
captured_log.extend(outs)


def blob_names():
    crec = datakey.read()["accounts"]["Admin1"]
    kek = Scrypt(salt=base64.b64decode(crec["kdf"]["salt"]), length=32, n=crec["kdf"]["n"], r=crec["kdf"]["r"], p=crec["kdf"]["p"]).derive(PW2.encode())
    raw = base64.b64decode(crec["keys"])
    blob = json.loads(AESGCM(kek).decrypt(raw[:12], raw[12:], b"toner-datakey-keys:Admin1"))
    return sorted(k["name"] for k in blob["list"]), len(blob["wraps"]), crec["keys_n"]


# both signed in on the same key state: the first write wins, the second finds the file changed and is refused (never a lost key)
won = [l for l, k in zip(("Left", "Right"), kids) if k.returncode == 0]
lost = [l for l, k, o in zip(("Left", "Right"), kids, outs) if k.returncode != 0 and "core.datakey.Locked: Sign in first." in o]
check("two processes adding at once: one lands, the other is refused with Locked, list and wraps the same length",
      len(won) == 1 and len(lost) == 1 and blob_names() == (sorted(["Base"] + won), 2, 2), (won, lost, outs))
check("...and the refused one, signed in again, adds its key: both keys are there", run_child(lost[0] + "2", **specs[lost[0]]) if lost else False)
concurrent_adds_agree = (blob_names() == (["Base", "Left", "Right"], 3, 3)
                         and all(opens("Admin1", PW2, lambda creds, c=c: fake.value([x for x in creds if x.id == c.id])) for c in added))
check("two processes adding at once: both keys are there, list and wraps the same length", concurrent_adds_agree, outs)


# a key state changed in another process is never overwritten by this one's stale copy
file_text = lambda: open(datakey.path(), encoding="utf-8").read()
only = lambda c: (lambda creds: fake.value([x for x in creds if x.id == c.id]))
left = added[0]
check("(another process removes Left while this one is signed in)", datakey.is_open() and
      run_child("removeLeft", name="Admin1", pw=PW2, kid=b64(base.id), kval=b64(base_val), remove="Left"))
before = file_text()
check("A, signed in before: changing its own password is Locked, file unchanged", raised(datakey.Locked, lambda: datakey.set_password("Admin1", PW3))
      and file_text() == before)
g, gv = fake.register("Gamma", os.urandom(32))
check("...as are adding and removing a key", raised(datakey.Locked, lambda: datakey.add_key(PW2, g, gv, "Gamma"))
      and raised(datakey.Locked, lambda: datakey.remove_key(PW2, 0)) and file_text() == before)
check("...and the removed key is still gone", raised(fidokey.NotRegistered, lambda: opens("Admin1", PW2, only(left))))
check("signed in again, A can change its password and add a key", opens("Admin1", PW2, only(base))
      and datakey.set_password("Admin1", PW3) is None and datakey.add_key(PW3, g, gv, "Gamma") is None
      and opens("Admin1", PW3, only(g)) and sorted(k["name"] for k in datakey.my_keys()) == ["Base", "Gamma", "Right"])
opens("Tech1", NEW_PW, None)
tb, tbv = fake.register("TechB", os.urandom(32))
check("(another process adds Tech1's first key while it is signed in without one)", run_child("addTechB", name="Tech1", pw=NEW_PW, **key_spec(tb, tbv, "TechB"))
      and datakey.has_keys("Tech1"))
before = file_text()
ta, tav = fake.register("TechA", os.urandom(32))
check("A, signed in before: add_key is Locked, file unchanged", raised(datakey.Locked, lambda: datakey.add_key(NEW_PW, ta, tav, "TechA")) and file_text() == before)
check("A: changing its own password is Locked, file unchanged", raised(datakey.Locked, lambda: datakey.set_password("Tech1", PW3)) and file_text() == before)
check("signed in again, A can add a key and change its password, and both keys open it", opens("Tech1", NEW_PW, only(tb))
      and datakey.add_key(NEW_PW, ta, tav, "TechA") is None and datakey.set_password("Tech1", PW3) is None
      and opens("Tech1", PW3, only(tb)) and opens("Tech1", PW3, only(ta)) and [k["name"] for k in datakey.my_keys()] == ["TechB", "TechA"])

# a wrong password through add_key or remove_key counts on the shared throttle, as check_password's does
opens("Admin1", PW3, only(base))
reset = lambda: datakey.edit(lambda doc: doc.__setitem__("throttle", {"fails": 0, "until": 0}))


def outcomes(fn, n):
    out = []
    for _ in range(n):
        try:
            out.append("WrongPassword" if fn() is False else "ok")
        except (datakey.WrongPassword, datakey.Throttled) as e:
            out.append(type(e).__name__)
    return out


expected = ["WrongPassword"] * datakey.FREE_TRIES + ["Throttled"] * 2
reset()
via_check = outcomes(lambda: datakey.check_password("Admin1", "a wrong guess at it 1", present=fake.present), datakey.FREE_TRIES + 2)
reset()
d, dv = fake.register("Delta", os.urandom(32))
via_add = outcomes(lambda: datakey.add_key("a wrong guess at it 1", d, dv, "Delta"), datakey.FREE_TRIES + 2)
check("N wrong tries through add_key are throttled as N through check_password are", via_check == expected and via_add == expected, (via_check, via_add))
check("...and while the wait runs, even the right password is refused unchecked", raised(datakey.Throttled, lambda: datakey.add_key(PW3, d, dv, "Delta"))
      and len(datakey.my_keys()) == 3)
reset()
via_remove = outcomes(lambda: datakey.remove_key("a wrong guess at it 1", 0), datakey.FREE_TRIES + 1)
check("...through remove_key too", via_remove == expected[:-1] and len(datakey.my_keys()) == 3, via_remove)
reset()
check("a right password clears the count", raised(datakey.WrongPassword, lambda: datakey.add_key("a wrong guess at it 1", d, dv, "Delta"))
      and throttle_fails() == 1 and datakey.add_key(PW3, d, dv, "Delta") is None and throttle_fails() == 0)
raised(datakey.WrongPassword, lambda: datakey.add_key("a wrong guess at it 1", d, dv, "Delta"))
fake.touch = False
check("a key failure still does not count", throttle_fails() == 1
      and raised(fidokey.NotTouched, lambda: datakey.check_password("Admin1", PW3, present=fake.present)) and throttle_fails() == 0
      and raised(fidokey.NotTouched, lambda: opens("Admin1", PW3, fake.value)) and throttle_fails() == 0)
fake.touch = True
opens("Admin1", PW3, only(base))

# the audit rows: the key's name, never its id
rows = [(r["action"], r["detail"]) for r in audit.recent(200)]
check("adding and removing are audited with the key's name", ("security key added", "Blue") in rows and ("security key removed", "Blue") in rows
      and ("security key removed", "Spare") in rows and ("security key added", "Tech's") in rows, rows)
captured_log.extend(f"{a} {d}" for a, d in rows)
captured_log.extend(r["detail"] for r in audit.recent(200))
check("no key's id is in an audit row", not any(b64(c.id) in d or c.id.hex() in d for c in (cred, spare, tcred) for _, d in rows))
check("no secret in any log line of this test", captured_log and not any(s in line for line in captured_log
                                                                           for s in (PW, PW2, PW3, NEW_PW, TPW, val.hex(), b64(val), k2_hex)))

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

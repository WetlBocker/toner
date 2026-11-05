# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Box keys (core/datakey.py): each account and the recovery key seal an X25519 private key beside the data key; Part 1 files
# (32-byte seals, no box_pub, no role) are upgraded at sign-in, keep their data key, and survive a crash mid-upgrade.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\boxes%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
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

import base64, json, statistics
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from core import sqldb
from core import datakey as D

PW, PW2, PW3 = "correct horse battery staple", "another long password 9", "a third quite long password 5"


def pub_of(private):
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def b64(b):
    return base64.b64encode(b).decode("ascii")


def kek(secret, salt, kdf):
    return Scrypt(salt=salt, length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(secret.encode("utf-8"))


def seal1(secret, payload, aad, kdf):
    """A seal written the way Part 1 wrote it (independent of datakey's own code)."""
    salt, nonce = os.urandom(16), os.urandom(12)
    return {"kdf": {"name": "scrypt", "salt": b64(salt), **kdf}, "key": b64(nonce + AESGCM(kek(secret, salt, kdf)).encrypt(nonce, payload, aad))}


def unseal(secret, rec, aad):
    raw = base64.b64decode(rec["key"])
    return AESGCM(kek(secret, base64.b64decode(rec["kdf"]["salt"]), rec["kdf"])).decrypt(raw[:12], raw[12:], aad)


def raises(fn, exc):
    try:
        fn()
    except exc as e:
        return e
    except Exception as e:
        print("   (raised", type(e).__name__, e, ")")
    return None


def doc():
    return json.loads(D.path().read_text(encoding="utf-8"))


# create: box keys for the account and the recovery key
r = D.create("Admin1", PW)
d = doc()
acc = d["accounts"]["Admin1"]
payload = unseal(PW, acc, b"toner-datakey:Admin1")
check("create: account seal holds 64 bytes", len(payload) == 64, len(payload))
check("create: data key first", payload[:32] == bytes(sqldb.current_key()))
check("create: box_pub matches the sealed private", base64.b64decode(acc["box_pub"]) == pub_of(payload[32:]))
check("create: box_private() is the account's", D.box_private() == payload[32:] and D.box_public("admin1") == pub_of(payload[32:]))
check("create: signed_in_name is the stored spelling", D.signed_in_name() == "Admin1")
check("create: role Admin", acc.get("role") == "Admin" and D.accounts()[0]["role"] == "Admin", D.accounts())
code = r.replace("-", "")
rpay = unseal(code, d["recovery"], D.RECOVERY_AAD)
check("create: recovery seal holds 64 bytes, same data key", len(rpay) == 64 and rpay[:32] == payload[:32])
check("create: recovery box_pub matches", D.box_public(None) == pub_of(rpay[32:]) == base64.b64decode(d["recovery"]["box_pub"]))
D.close()
check("close: box_private and signed_in_name gone", D.box_private() is None and D.signed_in_name() is None)
D.open_with_recovery(r)
check("recovery sign-in: box_private is the recovery key's, no name", D.box_private() == rpay[32:] and D.signed_in_name() is None)
D.open_with_password("ADMIN1", PW)
check("password sign-in: box_private is the account's, stored spelling", D.box_private() == payload[32:] and D.signed_in_name() == "Admin1")

# roles on add_local
D.add_local("eng", PW2, role="Engineer")
D.add_local("plain", PW3)
check("add_local stores the role", {a["name"]: a["role"] for a in D.accounts()} == {"Admin1": "Admin", "eng": "Engineer", "plain": "Admin"}, D.accounts())
check("add_local refuses an unknown role", raises(lambda: D.add_local("x", "yet another long password 1", role="Root"), ValueError) is not None
      and D._find(doc(), "x") is None)
check("add_local: its own box key", D.box_public("eng") not in (None, D.box_public("Admin1")))

# set_password: a new box key, role kept; the signed-in account's box_private follows
old_pub = D.box_public("eng")
D.set_password("eng", PW3)
check("set_password: new box_pub", D.box_public("eng") not in (None, old_pub))
check("set_password: role kept", {a["name"]: a["role"] for a in D.accounts()}["eng"] == "Engineer")
old_pub = D.box_public("Admin1")
D.set_password("Admin1", PW2)
check("set_password on yourself: box_private follows the new box_pub", D.box_public("Admin1") != old_pub and pub_of(D.box_private()) == D.box_public("Admin1"))
old_pub = D.box_public(None)
r = D.new_recovery()
check("new_recovery: new recovery box_pub", D.box_public(None) not in (None, old_pub) and len(unseal(r.replace("-", ""), doc()["recovery"], D.RECOVERY_AAD)) == 64)

# read() and edit()
copy = D.read()
copy["accounts"].clear()
check("read() is a copy", D.read()["accounts"] and D.read() == doc())
D.edit(lambda d: d.setdefault("extra", 1))
check("edit() writes", doc().get("extra") == 1)
D.close()
check("edit() needs the key open", raises(lambda: D.edit(lambda d: None), D.Locked) is not None)


# ---------------------------------------------------------------- a Part 1 file
def part1(throttle=None, recovery_fails=0):
    key = os.urandom(32)
    code = base64.b32encode(os.urandom(20)).decode("ascii")
    accounts = {n: {"kind": "local", **seal1(pw, key, b"toner-datakey:" + n.encode(), D.PASSWORD_KDF), "created": "2026-01-01T00:00:00+00:00"}
                for n, pw in (("Old", PW), ("Two", PW2))}
    D._write({"format": D.FORMAT, "version": 1, "accounts": accounts,
              "recovery": {**seal1(code, key, D.RECOVERY_AAD, D.RECOVERY_KDF), "fails": recovery_fails, "until": 0},
              "throttle": throttle or {"fails": 0, "until": 0}})
    return key, code


key, code = part1({"fails": 3, "until": 0})
check("Part 1: no box_pub yet", D.box_public("Old") is None and D.box_public(None) is None)
check("Part 1: accounts() says Admin", [a["role"] for a in D.accounts()] == ["Admin", "Admin"], D.accounts())
before = doc()
fails = D.open_with_password("old", PW)
after = doc()
check("Part 1 password: opens with the same data key", bytes(sqldb.current_key()) == key)
check("Part 1 password: earlier failures reported, then cleared", fails == 3 and after["throttle"] == {"fails": 0, "until": 0}, (fails, after["throttle"]))
p = unseal(PW, after["accounts"]["Old"], b"toner-datakey:Old")
check("Part 1 password: re-sealed to 64 bytes, data key kept", len(p) == 64 and p[:32] == key)
check("Part 1 password: box_pub added and matches box_private", base64.b64decode(after["accounts"]["Old"]["box_pub"]) == pub_of(p[32:]) == pub_of(D.box_private()))
check("Part 1 password: created kept, other records untouched",
      after["accounts"]["Old"]["created"] == before["accounts"]["Old"]["created"] and after["accounts"]["Two"] == before["accounts"]["Two"]
      and after["recovery"] == before["recovery"])
check("Part 1 password: role reads Admin", {a["name"]: a["role"] for a in D.accounts()}["Old"] == "Admin")
priv = D.box_private()
D.close()
check("Part 1 password: opens again, same keys", D.open_with_password("Old", PW) == 0 and bytes(sqldb.current_key()) == key and D.box_private() == priv)
D.close()
D.open_with_password("Two", PW2)
check("Part 1: the second account upgrades too, same data key", bytes(sqldb.current_key()) == key and D.box_public("Two") == pub_of(D.box_private()))
D.close()

# a Part 1 recovery seal
key, code = part1({"fails": 2, "until": 0}, recovery_fails=4)
fails = D.open_with_recovery(code)
after = doc()
p = unseal(code, after["recovery"], D.RECOVERY_AAD)
check("Part 1 recovery: same data key, re-sealed to 64", bytes(sqldb.current_key()) == key and len(p) == 64 and p[:32] == key)
check("Part 1 recovery: its counter reported and cleared", fails == 4 and after["recovery"]["fails"] == 0 and after["recovery"]["until"] == 0)
check("Part 1 recovery: password counter untouched", after["throttle"] == {"fails": 2, "until": 0})
check("Part 1 recovery: box_pub matches box_private", D.box_public(None) == pub_of(p[32:]) == pub_of(D.box_private()) and D.signed_in_name() is None)
D.close()
check("Part 1 recovery: opens again", D.open_with_recovery(code) == 0 and bytes(sqldb.current_key()) == key and D.box_private() == p[32:])
D.close()

# a crash mid-upgrade leaves a file that still opens with the same password
key, code = part1()
before = D.path().read_bytes()
real_replace = os.replace
def crash(*a):
    raise OSError("power cut")
os.replace = crash
try:
    e = raises(lambda: D.open_with_password("Old", PW), OSError)
finally:
    os.replace = real_replace
check("crash mid-upgrade: the error says nothing secret", e is not None and str(e) == "power cut", e)
check("crash mid-upgrade: the file is unchanged and the key stays shut", D.path().read_bytes() == before and not D.is_open())
D.open_with_password("Old", PW)
check("crash mid-upgrade: opens afterwards with the same key, upgraded", bytes(sqldb.current_key()) == key and D.box_public("Old") is not None)

# one scrypt per attempt, an upgrade included
key, code = part1()
calls = [0]
real_kek = D._kek
D._kek = lambda *a: (calls.__setitem__(0, calls[0] + 1), real_kek(*a))[1]
try:
    D.open_with_password("Old", PW); n_upgrade = calls[0]
    D.open_with_password("Old", PW); n_plain = calls[0] - n_upgrade
    D.check_password("nobody", PW); n_unknown = calls[0] - n_upgrade - n_plain
finally:
    D._kek = real_kek
check("one scrypt per attempt (upgrade, plain, unknown name)", (n_upgrade, n_plain, n_unknown) == (1, 1, 1), (n_upgrade, n_plain, n_unknown))
D.open_with_password("Old", PW)


# an unknown name still costs what a real check costs
def timed(fn):
    t = time.perf_counter(); fn(); return time.perf_counter() - t


real, fake = [], []
for _ in range(5):
    real.append(timed(lambda: D.check_password("Old", PW)))
    fake.append(timed(lambda: D.check_password("nobody", PW)))
    D.check_password("Old", PW)
real, fake = statistics.median(real), statistics.median(fake)
check("unknown name takes >= 80% of a real (upgraded) check", fake >= 0.8 * real, f"{fake:.3f} vs {real:.3f}")
print(f"   timing medians: right {real:.3f}s, unknown {fake:.3f}s")

# nothing secret in the file
blob = D.path().read_bytes()
check("no key or private in the file", all(s not in blob for s in (key, b64(key).encode(), D.box_private(), b64(D.box_private()).encode())))
D.close()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The lock screen opens only for a password or PIN whose seal holds the data key the locked session already has: a seal written
# into netcheck.keys while Toner is locked, under a password or PIN of the writer's choosing, unlocks nothing
# (core/datakey.py check_password and _pin).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import os, sys, time, json, base64
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "unlocksame%d.db" % int(time.time()))
os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from core import datakey, db, directory, osstore, pinslot, roles, session

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

PEPPERS = {}
osstore.available = lambda: True
osstore.put = lambda n, v, file=None: PEPPERS.__setitem__(n, v)
osstore.get = lambda n, file=None: PEPPERS.get(n)
osstore.delete = lambda n: PEPPERS.pop(n, None)

PW, OTHER, PIN, OTHER_PIN = "correct horse battery 42", "some other phrase 913", "a long pin 4321", "another pin 77551"
b64 = lambda b: base64.b64encode(b).decode("ascii")
def doc(): return json.loads(datakey.path().read_text(encoding="utf-8"))
def put(d): datakey.path().write_text(json.dumps(d), encoding="utf-8")
def unlocks(fn):
    try:
        fn()
    except Exception:
        pass
    return session.state() == "open"

# ---------------------------------------------------------------- a local account's password
datakey.create("Admin1", PW); db.init(); datakey.close()
session.sign_in("Admin1", PW)
session.lock()
d = doc(); rec = d["accounts"]["Admin1"]
kept = (rec["kdf"], rec["key"])
salt, nonce = os.urandom(16), os.urandom(12)
kek = Scrypt(salt=salt, length=32, n=2 ** 16, r=8, p=1).derive(OTHER.encode("utf-8"))
rec["kdf"] = {"name": "scrypt", "salt": b64(salt), "n": 2 ** 16, "r": 8, "p": 1}
rec["key"] = b64(nonce + AESGCM(kek).encrypt(nonce, os.urandom(64), b"toner-datakey:Admin1"))     # a seal of something else
put(d)
check("a password whose seal was written while locked doesn't unlock", not unlocks(lambda: session.unlock(OTHER)), session.state())
d = doc(); d["accounts"]["Admin1"]["kdf"], d["accounts"]["Admin1"]["key"] = kept; put(d)
check("the account's own password still does", unlocks(lambda: session.unlock(PW)), session.state())

# ---------------------------------------------------------------- a directory account's PIN
ACME = {"id": "d1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
        "base_dn": "DC=acme,DC=com", "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc,DC=acme,DC=com",
        "groups": {"Admin": [], "Engineer": [], "Tech": ["CN=T,DC=acme,DC=com"]}, "duo": {"on": False, "host": "", "ikey": ""}}
roles.set_directories([ACME])
BOB = directory.User("6f1c2a4e-0000-4000-8000-000000000001", "bob@acme.com", "Bob", ("CN=T,DC=acme,DC=com",), True)
slot = pinslot.new("pin", datakey.new_slot_id(), PIN)
datakey.start_directory_account(BOB, "d1", slot)
roles.approve("bob@acme.com", slot)
session.sign_out(); datakey.close()
session.sign_in_pin("bob@acme.com", PIN)
session.lock()
d = doc(); rec = d["accounts"]["bob@acme.com"]
kept = (rec["slot"], rec["sealed"])
rec["slot"] = {"kind": "pin", "salt": b64(os.urandom(16)), **pinslot.KDF["pin"]}
rec["sealed"] = {"box": pinslot._box(pinslot._kek(rec["slot"], OTHER_PIN, None), os.urandom(64) + b"bob@acme.com", rec["slot_id"])}   # a seal of something else
put(d)
check("a PIN whose seal was written while locked doesn't unlock", not unlocks(lambda: session.unlock_pin(OTHER_PIN)), session.state())
d = doc(); d["accounts"]["bob@acme.com"]["slot"], d["accounts"]["bob@acme.com"]["sealed"] = kept; put(d)
check("the account's own PIN still does", unlocks(lambda: session.unlock_pin(PIN)), session.state())
session.sign_out()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

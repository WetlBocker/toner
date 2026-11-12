# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Security keys on AD and LDAP accounts (core/datakey.py, core/pinslot.py): the PIN opens the slot, a key opens what it holds,
# the box key never changes with keys, an admin's clear drops the slot, the new-PIN approval seals with no keys, SSO never has keys.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\dkdir%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import base64, copy, json, logging, threading
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakekey
from core import audit, datakey, db, directory, fidokey, helperclient, osstore, pinslot, roles, session, sqldb, tpm_windows
def _no_helper(): raise helperclient.NotRunning()
helperclient._connect, helperclient.installed, helperclient.not_installed = _no_helper, lambda: False, lambda: True   # no helper here
from core.platforms import FileLock

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

captured_log = []


class Grab(logging.Handler):
    def emit(self, record):
        captured_log.append(self.format(record))


logging.getLogger().addHandler(Grab())
logging.getLogger().setLevel(logging.DEBUG)


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


PEPPERS = {}                                            # the protected store, as a dict on every platform
osstore.available = lambda: True
osstore.put = PEPPERS.__setitem__
osstore.get = PEPPERS.get
osstore.delete = lambda n: PEPPERS.pop(n, None)


class FakeTpm:                                          # as tests/test_dirsignin.py's
    LockedOut = tpm_windows.LockedOut
    keys = {}

    @classmethod
    def lockout_threshold(cls): return 4
    @classmethod
    def lockout_window(cls): return 28800
    @classmethod
    def available(cls): return True

    @classmethod
    def create(cls, name, pin):
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.keys[name] = (k, pin)
        return k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    @classmethod
    def decrypt(cls, name, pin, data):
        if name not in cls.keys:
            raise FileNotFoundError(name)
        k, right = cls.keys[name]
        if pin != right:
            raise PermissionError("wrong PIN")
        return k.decrypt(data, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

    @classmethod
    def delete(cls, name): cls.keys.pop(name, None)


pinslot.tpm_windows = FakeTpm
pinslot.best_kind = lambda: "chip"

PW = "correct horse battery 42"
PIN, NEW_PIN, PIN3, SPIN, WRONG = "246813", "975318", "802461", "a long store pin 77", "135792"
CPIN, CPIN2 = "a long pin-only pin 3", "another pin-only pin 8"
DPIN, EPIN = "314158", "a long store pin of eve 6"
TECHS = "CN=Toner Techs,DC=acme,DC=com"
ACME = {"id": "d1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
        "base_dn": "DC=acme,DC=com", "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc,DC=acme,DC=com",
        "groups": {"Admin": [], "Engineer": [], "Tech": [TECHS]}, "duo": {"on": False, "host": "", "ikey": ""}}
SSO = {"id": "s1", "name": "Contoso", "kind": "oidc", "provider": "other", "issuer": "https://login.example.com", "client_id": "toner-app",
       "groups_claim": "groups", "id_claim": "sub", "suffixes": ["example.com"], "groups": {"Tech": ["g1"]},
       "group_names": {"g1": "Techs"}, "everyone": None}
ANA = directory.User("6f1c2a4e-0000-4000-8000-00000000000a", "ana", "Ana", (TECHS,), True)
BEN = directory.User("6f1c2a4e-0000-4000-8000-00000000000b", "ben", "Ben", (TECHS,), True)
CAT = directory.User("6f1c2a4e-0000-4000-8000-00000000000c", "cat", "Cat", (TECHS,), True)
DEE = directory.User("6f1c2a4e-0000-4000-8000-00000000000d", "dee", "Dee", (TECHS,), True)
EVE = directory.User("6f1c2a4e-0000-4000-8000-00000000000e", "eve", "Eve", (TECHS,), True)
SSO_USER = directory.User("sub-sso-user", "sso-user", "SSO User", ("g1",), True)


def doc():
    return json.loads(datakey.path().read_text(encoding="utf-8"))


def put(d):
    datakey.path().write_text(json.dumps(d), encoding="utf-8")


def rec_of(name):
    return datakey.read()["accounts"][name]


def as_admin():
    session.sign_out()
    session.sign_in("Admin1", PW)


def as_(name, pin, key=None):
    session.sign_out()
    datakey.open_with_pin(name, pin, key=key)


def new_account(user, directory_id, kind, pin):
    """A directory account started and approved by Admin1, as a first sign-in makes one."""
    session.sign_out()
    slot = pinslot.new(kind, datakey.new_slot_id(), pin)
    datakey.start_directory_account(user, directory_id, slot)
    as_admin()
    roles.approve(user.name, slot)
    session.sign_out()


def reset_counters():
    datakey.edit(lambda d: d.__setitem__("throttle", {"fails": 0, "until": 0}), signed_in=False)
    pinslot._fails_file().unlink(missing_ok=True)


def throttle_fails():
    return datakey.read()["throttle"]["fails"]


def inside(name, pin):
    """What the account's slot holds, opened as pinslot.open does."""
    r = rec_of(name)
    return pinslot.open(r["slot"], r["slot_id"], pin, r["sealed"])


b64 = lambda b: base64.b64encode(b).decode("ascii")


def forge_seal(name, secret):
    """A seal put in a chip slot's record by someone who can write netcheck.keys: the slot's public key is in the record, so no PIN is needed."""
    d = doc(); r = d["accounts"][name]
    r["sealed"] = pinslot.Slot(r["slot"], r["slot_id"]).seal(secret)
    put(d)


def unlocks(name, pin):
    """True when the PIN and the session's own key (the fake's) unlock it."""
    try:
        return datakey.check_pin(name, pin, present=fake.present) is True
    except Exception as e:
        print("   (raised", type(e).__name__, e, ")")
        return False


def forged_unlock(name, pin, attacker, acred):
    """The signed-in keyed session's unlock against forged seals: (a plain seal: refused with no key and with no touch; the session's
    own key unlocks; a key list naming another key: that key refused; the session's own key unlocks)."""
    saved_doc = doc()
    forge_seal(name, os.urandom(64) + name.encode("utf-8"))
    fake.touch = False
    plain = raised(datakey.KeyNeeded, lambda: datakey.check_pin(name, pin)) and raised(fidokey.NotTouched, lambda: datakey.check_pin(name, pin, present=fake.present))
    fake.touch = True
    own = unlocks(name, pin)
    entry = {"id": b64(acred.id), "salt": b64(acred.salt), "pub": b64(acred.public), "name": "Mine", "added": "2026-11-12T00:00:00+00:00"}
    forge_seal(name, b"K1" + json.dumps({"list": [entry], "wraps": [b64(os.urandom(60))], "sealed_k": b64(os.urandom(60))}).encode())
    listed = raised(fidokey.NotRegistered, lambda: datakey.check_pin(name, pin, present=attacker.present))
    own2 = unlocks(name, pin)
    put(saved_doc)
    reset_counters()
    return plain, own, listed, own2


# ---------------------------------------------------------------- set up: an Admin, the directories, ana (chip), ben (store), an SSO account
recovery = datakey.create("Admin1", PW)
db.init()
datakey.close()
as_admin()
roles.set_directories([ACME, SSO])
DATA_KEY = bytes(datakey._key)
new_account(ANA, "d1", "chip", PIN)
new_account(BEN, "d1", "store", SPIN)
new_account(CAT, "d1", "pin", CPIN)
new_account(DEE, "d1", "chip", DPIN)
new_account(EVE, "d1", "store", EPIN)
new_account(SSO_USER, "s1", "chip", PIN3)
fake = fakekey.install()
plain_record = rec_of("ana")
box_before = datakey.box_public("ana")
as_("ana", PIN)
check("an account without keys opens with the PIN alone, and has none", datakey.is_open() and datakey.my_keys() == []
      and not datakey.has_keys("ana") and "keyed" not in plain_record and "keys_n" not in plain_record)

# the first key
cred, val = fake.register("Blue", os.urandom(32))
datakey.add_key(PIN, cred, val, "Blue")
k2_hex = datakey._k2.hex()
rec = rec_of("ana")
SEAL = ("slot", "slot_id", "sealed")
check("the first key: keyed, keys_n 1, a fresh slot of the same kind, every other field as before", rec["keyed"] is True and rec["keys_n"] == 1
      and rec["slot_id"] != plain_record["slot_id"] and rec["slot"]["kind"] == "chip" and "Toner-" + plain_record["slot_id"] not in FakeTpm.keys
      and {k: v for k, v in rec.items() if k not in ("keyed", "keys_n") + SEAL} == {k: v for k, v in plain_record.items() if k not in SEAL})
reset_counters()
held_inside = inside("ana", PIN)
blob = json.loads(held_inside[2:])
check("the slot now holds K1 and the keys, not the data key", held_inside[:2] == b"K1" and set(blob) == {"list", "wraps", "sealed_k"}
      and DATA_KEY not in held_inside and [k["name"] for k in blob["list"]] == ["Blue"])
check("the key's id, number and public half are not in the file in the clear",
      all(base64.b64encode(x).decode() not in json.dumps(rec) and x.hex() not in json.dumps(rec) for x in (cred.id, cred.salt, cred.public)))
check("has_keys reads the hint; my_keys lists it", datakey.has_keys("ana") and datakey.my_keys()[0]["name"] == "Blue")
ATTACKER = fakekey.FakeKey()
ACRED, _ = ATTACKER.register("Mine", os.urandom(32))
got = forged_unlock("ana", PIN, ATTACKER, ACRED)
check("a first key added while signed in: a forged seal or key list doesn't unlock without it; it does", got == (True,) * 4, got)
datakey.close()
check("the PIN alone no longer opens a keyed account", raised(datakey.KeyNeeded, lambda: datakey.open_with_pin("ana", PIN)) and not datakey.is_open())
check("the PIN and the key open it, with the same box key as before", datakey.open_with_pin("ana", PIN, key=fake.value) == 0
      and datakey.box_public("ana") == box_before and bytes(sqldb.current_key()) == DATA_KEY and datakey.my_keys()[0]["name"] == "Blue"
      and datakey._k2.hex() == k2_hex)


def wrong_pin_with_key():
    datakey.close(); fake.calls.clear()
    datakey.open_with_pin("ana", WRONG, key=fake.value)


reset_counters()
check("a wrong PIN counts as today and never reaches the key", raised(pinslot.WrongPin, wrong_pin_with_key) and fake.calls == []
      and throttle_fails() == 1)
reset_counters()


def open_after_deleting_keyed_field():
    d = doc()
    for f in ("keyed", "keys_n"):
        d["accounts"]["ana"].pop(f)
    put(d)
    datakey.close()
    datakey.open_with_pin("ana", PIN)


saved = doc()
check("the keyed field cleared by hand does not open it without the key", raised(datakey.KeyNeeded, open_after_deleting_keyed_field)
      and not datakey.is_open())
put(saved)

fake.touch = False
check("no touch: NotTouched, nothing open, no count", raised(fidokey.NotTouched, lambda: datakey.open_with_pin("ana", PIN, key=fake.value))
      and not datakey.is_open() and throttle_fails() == 0)
fake.touch = True
check("a key of another account: NotRegistered", raised(fidokey.NotRegistered, lambda: datakey.open_with_pin("ana", PIN, key=fakekey.FakeKey().value))
      and not datakey.is_open() and throttle_fails() == 0)
check("one of its ids with the wrong value: NotRegistered", raised(fidokey.NotRegistered,
      lambda: datakey.open_with_pin("ana", PIN, key=lambda creds: (creds[0].id, os.urandom(32)))) and not datakey.is_open())

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


check("the key is asked with neither the module lock nor the file lock held", datakey.open_with_pin("ana", PIN, key=probe) == 0
      and held == [(True, True)], held)

# unlock: the PIN and a touch, never the value
fake.calls.clear()
check("unlock: the PIN and presence", datakey.check_pin("ana", PIN, present=fake.present) is True and fake.calls == ["present"])
fake.calls.clear()
check("unlock: a wrong PIN is False and the key is not asked", datakey.check_pin("ana", WRONG, present=fake.present) is False and fake.calls == [])
reset_counters()
check("unlock with no way to ask: KeyNeeded", raised(datakey.KeyNeeded, lambda: datakey.check_pin("ana", PIN)))
check("unlock: a key of another account is NotRegistered", raised(fidokey.NotRegistered, lambda: datakey.check_pin("ana", PIN, present=fakekey.FakeKey().present)))
fake.touch = False
check("unlock: no touch is NotTouched and not counted", raised(fidokey.NotTouched, lambda: datakey.check_pin("ana", PIN, present=fake.present))
      and throttle_fails() == 0)
fake.touch = True
got = forged_unlock("ana", PIN, ATTACKER, ACRED)
check("signed in with a key: a forged seal or key list doesn't unlock without it; it does", got == (True,) * 4, got)

# a seal copied into another account's record opens nothing there, keyed or not
d = doc()
d["accounts"]["ben"].update({f: d["accounts"]["ana"][f] for f in ("slot_kind", "slot", "slot_id", "sealed")})
put(d)
check("ana's keyed seal copied into ben's record: refused as a wrong PIN, with her PIN and her key",
      raised(pinslot.WrongPin, lambda: datakey.open_with_pin("ben", PIN, key=fake.value)) and throttle_fails() == 1)
reset_counters()
check("...and her PIN and her key don't unlock ben either", raised(fidokey.NotRegistered, lambda: datakey.check_pin("ben", PIN, present=fake.present)))
put(saved)
reset_counters()

# a second key, then the stale and wrong-PIN refusals
as_("ana", PIN, fake.value)
spare, spare_val = fake.register("Spare", os.urandom(32))
datakey.add_key(PIN, spare, spare_val, "Spare")
check("the second key keeps the box key and K2", datakey.box_public("ana") == box_before and datakey._k2.hex() == k2_hex
      and [k["name"] for k in datakey.my_keys()] == ["Blue", "Spare"] and rec_of("ana")["keys_n"] == 2)
only = lambda c: (lambda creds: fake.value([x for x in creds if x.id == c.id]))
check("each key opens it alone", all(datakey.open_with_pin("ana", PIN, key=only(c)) == 0 and datakey.box_public("ana") == box_before
                                     for c in (cred, spare)))

before_text = datakey.path().read_text(encoding="utf-8")
reset_counters()
check("a wrong PIN cannot add a key: WrongPin, counted, file unchanged but the count", raised(pinslot.WrongPin, lambda: datakey.add_key(WRONG, cred, val, "x"))
      and throttle_fails() == 1 and rec_of("ana") == json.loads(before_text)["accounts"]["ana"])
check("...nor remove one, counted on the same counter", raised(pinslot.WrongPin, lambda: datakey.remove_key(WRONG, 0)) and throttle_fails() == 2
      and rec_of("ana")["keys_n"] == 2)
reset_counters()
check("check_pin's wrong PIN counts the same", datakey.check_pin("ana", WRONG, present=fake.present) is False and throttle_fails() == 1)
reset_counters()
datakey.edit(lambda d: d.__setitem__("throttle", {"fails": 9, "until": time.time() + 60}), signed_in=False)
check("while a wait runs, add_key waits as check_pin does, even with the right PIN", raised(pinslot.PinLocked, lambda: datakey.add_key(PIN, cred, val, "x"))
      and raised(pinslot.PinLocked, lambda: datakey.check_pin("ana", PIN, present=fake.present)) and rec_of("ana")["keys_n"] == 2)
reset_counters()

# another process changed the seal since this one read it: nothing is written
as_("ana", PIN, fake.value)
this_process = (datakey._keys, datakey._k2, datakey._seen)
g, gv = fake.register("Gamma", os.urandom(32))
datakey.add_key(PIN, g, gv, "Gamma")                 # (as if another process: this one keeps what it held before)
datakey._keys, datakey._k2, datakey._seen = this_process
reset_counters()
before_text = datakey.path().read_text(encoding="utf-8")
check("a stale seal: add_key and remove_key are Locked, file unchanged", raised(datakey.Locked, lambda: datakey.add_key(PIN, g, gv, "Delta"))
      and raised(datakey.Locked, lambda: datakey.remove_key(PIN, 0)) and datakey.path().read_text(encoding="utf-8") == before_text)
as_("ana", PIN, fake.value)
check("signed in again, it holds the other process's keys and can remove one", [k["name"] for k in datakey.my_keys()] == ["Blue", "Spare", "Gamma"]
      and datakey.remove_key(PIN, 2) is None and [k["name"] for k in datakey.my_keys()] == ["Blue", "Spare"])

# removing the keys
datakey.remove_key(PIN, 0)
check("removing one of two keeps the other", [k["name"] for k in datakey.my_keys()] == ["Spare"] and rec_of("ana")["keys_n"] == 1
      and raised(fidokey.NotRegistered, lambda: datakey.open_with_pin("ana", PIN, key=only(cred))) and datakey.open_with_pin("ana", PIN, key=fake.value) == 0)
datakey.remove_key(PIN, 0)
check("the last key removed while signed in: the PIN alone unlocks, as for any account without keys", datakey.check_pin("ana", PIN) is True)
rec = rec_of("ana")
plain_again =(list(rec) == list(plain_record) and {k: v for k, v in rec.items() if k not in SEAL} == {k: v for k, v in plain_record.items() if k not in SEAL}
               and inside("ana", PIN) == DATA_KEY + datakey.box_private() + b"ana" and datakey.my_keys() == [] and not datakey.has_keys("ana"))
check("removing the last key: the slot seals today's payload again", plain_again and datakey.open_with_pin("ana", PIN) == 0
      and datakey.box_public("ana") == box_before)

# a store-kind slot (the KEK from the PIN and the pepper): add and remove
as_("ben", SPIN)
ben_plain, ben_box = rec_of("ben"), datakey.box_public("ben")
bc, bv = fake.register("Ben's", os.urandom(32))
datakey.add_key(SPIN, bc, bv, "Ben's")
datakey.close()
check("a store slot: keyed, the PIN alone refused, the PIN and the key open it", rec_of("ben")["keys_n"] == 1
      and raised(datakey.KeyNeeded, lambda: datakey.open_with_pin("ben", SPIN)) and datakey.open_with_pin("ben", SPIN, key=fake.value) == 0
      and datakey.box_public("ben") == ben_box)
datakey.remove_key(SPIN, 0)
check("...and removing it stores it as before", list(rec_of("ben")) == list(ben_plain) and datakey.open_with_pin("ben", SPIN) == 0)


# every key write on a chip or store slot moves to a fresh slot: no earlier seal put back opens again
def slot_here(r):
    return ("Toner-" + r["slot_id"]) in FakeTpm.keys if r["slot"]["kind"] == "chip" else ("pin:" + r["slot_id"]) in PEPPERS


def put_back(name, r):
    d = doc()
    d["accounts"][name] = r
    put(d)


never_opens = (pinslot.SlotMissing, pinslot.WrongPin)
for name, kind, pin in (("dee", "chip", DPIN), ("eve", "store", EPIN)):
    as_(name, pin)
    box = datakey.box_public(name)
    before_key = rec_of(name)
    k1, v1 = fake.register("One", os.urandom(32))
    datakey.add_key(pin, k1, v1, "One")
    now = rec_of(name)
    check(f"{kind}: the first key moves to a fresh slot of the same kind, the old one gone, the same box key, opened by PIN and key",
          now["slot_id"] != before_key["slot_id"] and now["slot"]["kind"] == kind and slot_here(now) and not slot_here(before_key)
          and datakey.box_public(name) == box and datakey.open_with_pin(name, pin, key=only(k1)) == 0)
    datakey.close()
    put_back(name, before_key)
    reset_counters()
    check(f"{kind}: the seal from before the first key put back by hand: the PIN no longer opens it",
          raised(never_opens, lambda: datakey.open_with_pin(name, pin)) and raised(never_opens, lambda: datakey.open_with_pin(name, pin, key=only(k1)))
          and not datakey.is_open())
    put_back(name, now)
    reset_counters()
    as_(name, pin, only(k1))
    k2c, v2c = fake.register("Two", os.urandom(32))
    datakey.add_key(pin, k2c, v2c, "Two")
    two = rec_of(name)
    datakey.remove_key(pin, 0)
    after = rec_of(name)
    check(f"{kind}: removing a key moves to a fresh slot too; the other key and the PIN open it, the same box key",
          after["slot_id"] != two["slot_id"] and not slot_here(two) and slot_here(after) and datakey.open_with_pin(name, pin, key=only(k2c)) == 0
          and datakey.box_public(name) == box and raised(fidokey.NotRegistered, lambda: datakey.open_with_pin(name, pin, key=only(k1))))
    datakey.close()
    put_back(name, two)
    reset_counters()
    check(f"{kind}: the two-key record put back by hand: the removed key and the PIN don't open it",
          raised(never_opens, lambda: datakey.open_with_pin(name, pin, key=only(k1))) and not datakey.is_open())
    put_back(name, after)
    reset_counters()
    as_(name, pin, only(k2c))
    real_written, slots_before = datakey.written, (set(FakeTpm.keys), set(PEPPERS))

    def failing(landed, real=real_written):
        if landed:
            raise OSError("the write didn't land")
        real(landed)
    datakey.written = failing
    k3, v3 = fake.register("Three", os.urandom(32))
    failed = raised(OSError, lambda: datakey.add_key(pin, k3, v3, "Three"))
    datakey.written = real_written
    check(f"{kind}: a failed write leaves the record, the old slot working and no new slot behind",
          failed and rec_of(name) == after and slot_here(after) and (set(FakeTpm.keys), set(PEPPERS)) == slots_before
          and datakey.open_with_pin(name, pin, key=only(k2c)) == 0 and [k["name"] for k in datakey.my_keys()] == ["Two"])
    datakey.remove_key(pin, 0)
    check(f"{kind}: removing the last key: a fresh slot with today's payload, opened by the PIN alone",
          not datakey.has_keys(name) and rec_of(name)["slot_id"] != after["slot_id"] and not slot_here(after)
          and datakey.open_with_pin(name, pin) == 0 and datakey.box_public(name) == box)

# an admin's clear, for a chip slot (ana) and a PIN-alone slot (cat), whose drop_slot has nothing to delete
def approve_new_slot(name, pin=NEW_PIN, kind="chip"):
    """The new-PIN approval as core/dirsignin.py makes it: a new slot, approved by Admin1. True once its seal holds no keys and
    the record has no key fields and no clear mark."""
    session.sign_out()
    slot = pinslot.new(kind, datakey.new_slot_id(), pin)
    as_admin()
    roles.approve(name, slot)
    session.sign_out()
    r = rec_of(name)
    return (r["slot_id"] == slot.slot_id and not {"keyed", "keys_n", "slot_gone"} & set(r) and inside(name, pin)[:2] != b"K1")


for name, kind, pin, new_pin in (("ana", "chip", PIN, NEW_PIN), ("cat", "pin", CPIN, CPIN2)):
    as_(name, pin)
    datakey.add_key(pin, cred, val, "Blue")
    as_admin()
    datakey.clear_keys(name)
    rec = rec_of(name)
    cleared = doc()

    def try_pin(name=name, pin=pin):
        datakey.close(); fake.calls.clear()
        datakey.open_with_pin(name, pin, key=fake.value)

    reset_counters()
    check(f"{kind}: an admin's clear drops the key fields, keeps the seal and marks the record", "keyed" not in rec and "keys_n" not in rec
          and rec.get("sealed") and rec.get("slot_gone") is True)
    check(f"{kind}: ...the next PIN finds no slot: SlotMissing, the key never asked, nothing open, not counted",
          raised(pinslot.SlotMissing, try_pin) and fake.calls == [] and not datakey.is_open() and throttle_fails() == 0)
    check(f"{kind}: ...unlock too", raised(pinslot.SlotMissing, lambda: datakey.check_pin(name, pin, present=fake.present)) and fake.calls == [])
    datakey.edit(lambda d: d.__setitem__("throttle", {"fails": 9, "until": time.time() + 60}), signed_in=False)
    check(f"{kind}: ...a running wait is honoured as for any PIN", raised(pinslot.PinLocked, try_pin))
    reset_counters()
    d = doc()
    del d["accounts"][name]["slot_gone"]
    put(d)
    check(f"{kind}: the mark deleted by hand does not open it without the key",
          raised(datakey.KeyNeeded if kind == "pin" else pinslot.SlotMissing, lambda: datakey.open_with_pin(name, pin)) and not datakey.is_open())
    put(cleared)
    check(f"{kind}: the next approval makes a seal with no keys, opened by the new PIN alone, and drops the mark",
          approve_new_slot(name, new_pin, kind) and datakey.open_with_pin(name, new_pin) == 0 and datakey.my_keys() == [])

check("an admin's clear is audited with the account and who cleared it", any(r["action"] == "security keys removed" and r["detail"] == "ana, by Admin1"
                                                                           for r in audit.recent(200)))
as_("cat", CPIN2)
d2, dv2 = fake.register("Delta", os.urandom(32))
datakey.add_key(CPIN2, d2, dv2, "Delta")
d = doc()                                               # an admin's clear in another process while cat stays signed in here
for f in ("keyed", "keys_n"):
    d["accounts"]["cat"].pop(f)
d["accounts"]["cat"]["slot_gone"] = True
put(d)
before_text = datakey.path().read_text(encoding="utf-8")
check("pin: a session open before the clear can't add or remove a key with the right PIN (Locked, file unchanged)",
      raised(datakey.Locked, lambda: datakey.add_key(CPIN2, cred, val, "Blue")) and raised(datakey.Locked, lambda: datakey.remove_key(CPIN2, 0))
      and datakey.path().read_text(encoding="utf-8") == before_text)
check("pin: ...and that account still finds no slot", raised(pinslot.SlotMissing, lambda: datakey.open_with_pin("cat", CPIN2, key=fake.value)))

as_("ana", NEW_PIN)
datakey.add_key(NEW_PIN, cred, val, "Blue")
forgot_pin_approval_leaves_no_key_fields = rec_of("ana")["keys_n"] == 1 and approve_new_slot("ana", PIN3)
check("a forgotten-PIN approval of a keyed account clears its key fields too", forgot_pin_approval_leaves_no_key_fields
      and datakey.open_with_pin("ana", PIN3) == 0 and datakey.my_keys() == [])

as_admin()
before_text = datakey.path().read_text(encoding="utf-8")
check("clear_keys refuses a local account and an SSO account", raised(ValueError, lambda: datakey.clear_keys("Admin1"))
      and raised(ValueError, lambda: datakey.clear_keys("sso-user")) and datakey.path().read_text(encoding="utf-8") == before_text)
as_("sso-user", PIN3)
check("an SSO account can't add a key", raised(ValueError, lambda: datakey.add_key(PIN3, cred, val, "x")) and "keys_n" not in rec_of("sso-user"))
captured_log.extend(f"{r['action']} {r['detail']}" for r in audit.recent(500))
session.sign_out()
check("no secret in any log line or audit row of this test", captured_log and not any(
    s in line for line in captured_log for s in (PW, PIN, NEW_PIN, PIN3, SPIN, CPIN, CPIN2, DPIN, EPIN, val.hex(), base64.b64encode(val).decode(), k2_hex)))

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

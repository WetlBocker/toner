# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# PIN slots (core/pinslot.py): the chip (a fake tpm_windows), the protected store (real on Windows, a dict elsewhere) and the
# PIN alone; wrong PINs, the chip's lockout, the shared wait in netcheck.keys, the PIN rules, removing a slot.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\pinslot%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
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
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)


def raises(fn, exc):
    try:
        fn()
    except exc as e:
        return e
    except Exception as e:
        print("   (raised", type(e).__name__, e, ")")
    return None


from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from core import datakey as D, osstore, pinslot as P, tpm_windows

D.create("admin", "correct horse battery staple")


class FakeTpm:
    """Keys by name, each an RSA key and its PIN; `locked` makes every decrypt refuse as the chip's lockout does."""
    LockedOut = tpm_windows.LockedOut
    keys, locked, up = {}, None, True

    @classmethod
    def available(cls):
        return cls.up

    @classmethod
    def create(cls, name, pin):
        if cls.locked:
            raise tpm_windows.LockedOut(cls.locked)
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.keys[name] = (k, pin)
        return k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    @classmethod
    def decrypt(cls, name, pin, data):
        if name not in cls.keys:
            raise FileNotFoundError(name)
        if cls.locked:
            raise tpm_windows.LockedOut(cls.locked)
        k, right = cls.keys[name]
        if pin != right:
            raise PermissionError("wrong PIN")
        return k.decrypt(data, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

    @classmethod
    def delete(cls, name):
        cls.keys.pop(name, None)


P.tpm_windows = FakeTpm
if sys.platform != "win32":             # the real store on Windows (DPAPI beside the test's keys file); a dict elsewhere
    PEPPERS = {}
    osstore.available = lambda: True
    osstore.put = PEPPERS.__setitem__
    osstore.get = PEPPERS.get
    osstore.delete = lambda n: PEPPERS.pop(n, None)


def fails():
    return D.read()["throttle"]["fails"]


def reset():
    D.edit(lambda doc: doc.__setitem__("throttle", {"fails": 0, "until": 0}))


SECRET = os.urandom(64)
PINS = {"chip": "482916", "store": "long store pin", "pin": "long plain pin"}
msgs = []

# ---------------------------------------------------------------- round trips, wrong PINs
for kind, pin in PINS.items():
    sid = "s-" + kind
    slot = P.new(kind, sid, pin)
    check(f"{kind}: rec kind", slot.rec["kind"] == kind)
    sealed = slot.seal(SECRET)
    check(f"{kind}: round trip", P.open(slot.rec, sid, pin, sealed) == SECRET)
    check(f"{kind}: a second seal opens too", P.open(slot.rec, sid, pin, slot.seal(b"two")) == b"two")
    e = raises(lambda: P.open(slot.rec, sid, pin[:-1] + "0", sealed), P.WrongPin)
    check(f"{kind}: wrong PIN raises WrongPin", e is not None)
    check(f"{kind}: WrongPin says the approved sentence", str(e) == "That PIN isn't right.", str(e))
    check(f"{kind}: a wrong PIN counts on the shared counter", fails() == 1, fails())
    check(f"{kind}: the right PIN then clears the count", P.open(slot.rec, sid, pin, sealed) == SECRET and fails() == 0)
    check(f"{kind}: another slot id can't open it", raises(lambda: P.open(slot.rec, sid + "x", pin, sealed),
                                                           (P.WrongPin, P.SlotMissing)) is not None)
    text = repr(slot.rec) + repr(sealed)
    check(f"{kind}: no PIN or secret in the record", pin not in text and SECRET.hex() not in text and repr(SECRET) not in text)
    msgs += [str(e), repr(e)]
    reset()

# ---------------------------------------------------------------- the chip's lockout, a missing key
slot = P.new("chip", "lock", "135790")
sealed = slot.seal(SECRET)
FakeTpm.locked = 1234
e = raises(lambda: P.open(slot.rec, "lock", "135790", sealed), P.PinLocked)
check("chip lockout raises PinLocked", e is not None)
check("PinLocked carries the chip's seconds", e is not None and e.seconds == 1234)
check("PinLocked says the approved sentence", str(e) == "Too many wrong PINs. Wait 1234 seconds, then try again.", str(e))
check("the chip's lockout isn't counted by Toner", fails() == 0, fails())
e = raises(lambda: P.new("chip", "during", "135790"), P.PinLocked)
check("a new chip slot during the lockout raises PinLocked", e is not None and e.seconds == 1234)
FakeTpm.locked = None
P.remove(slot.rec, "lock")
check("remove deletes the TPM key", "Toner-lock" not in FakeTpm.keys)
check("a missing TPM key raises SlotMissing", raises(lambda: P.open(slot.rec, "lock", "135790", sealed), P.SlotMissing) is not None)
check("chip key is named Toner- + slot id", "Toner-s-chip" in FakeTpm.keys)

# ---------------------------------------------------------------- remove: the pepper
slot = P.new("store", "gone", "long store pin")
sealed = slot.seal(SECRET)
check("the pepper is in the store", osstore.get("pin:gone") is not None and len(osstore.get("pin:gone")) == 32)
P.remove(slot.rec, "gone")
check("remove deletes the pepper", osstore.get("pin:gone") is None)
check("a missing pepper raises SlotMissing", raises(lambda: P.open(slot.rec, "gone", "long store pin", sealed), P.SlotMissing) is not None)
check("SlotMissing isn't counted", fails() == 0, fails())
P.remove(P.new("pin", "plain", "long plain pin").rec, "plain")      # nothing on the computer to delete: no error
check("remove of a pin slot is harmless", True)

# ---------------------------------------------------------------- the PIN rules
check("chip 123456 is simple", P.problem("chip", "123456") == "Avoid simple PINs like 123456.")
check("chip 111111 is simple", P.problem("chip", "111111") == "Avoid simple PINs like 123456.")
check("chip 987654 is simple", P.problem("chip", "987654") == "Avoid simple PINs like 123456.")
check("chip 12345 is short", P.problem("chip", "12345") == "Use 6 digits.")
check("chip 1234567 is long", P.problem("chip", "1234567") == "Use 6 digits.")
check("chip letters", P.problem("chip", "12a456") == "Use 6 digits.")
check("chip non-ASCII digits", P.problem("chip", "١٢٣٤٥٧") == "Use 6 digits.")
check("chip 482916 is fine", P.problem("chip", "482916") is None)
check("store 1234567 is short", P.problem("store", "1234567") == "Use at least 8 characters.")
check("pin 1234567 is short", P.problem("pin", "1234567") == "Use at least 8 characters.")
check("store 12345678 is fine", P.problem("store", "12345678") is None)
e = raises(lambda: P.new("chip", "bad", "123456"), ValueError)
check("new refuses a simple PIN", e is not None and str(e) == "Avoid simple PINs like 123456." and "Toner-bad" not in FakeTpm.keys)

# ---------------------------------------------------------------- best_kind
P.best_kind.cache_clear()
check("best_kind: chip on Windows with a TPM, else the store or the PIN",
      P.best_kind() == ("chip" if sys.platform == "win32" else "store"))
FakeTpm.up = False
P.best_kind.cache_clear()
check("best_kind: no TPM means the store", P.best_kind() == "store")
osstore_available = osstore.available
osstore.available = lambda: False
P.best_kind.cache_clear()
check("best_kind: no store means the PIN alone", P.best_kind() == "pin")
osstore.available = osstore_available
FakeTpm.up = True
P.best_kind.cache_clear()

# ---------------------------------------------------------------- five wrong PINs, then the wait (kept in the file)
slot = P.new("pin", "five", "long plain pin")
sealed = slot.seal(SECRET)
five = [raises(lambda: P.open(slot.rec, "five", "wrong pin %d" % i, sealed), P.WrongPin) for i in range(5)]
check("five wrong PINs each raise WrongPin", all(five))
check("the count is in the keys file", fails() == 5, fails())
e = raises(lambda: P.open(slot.rec, "five", "wrong pin 6", sealed), P.PinLocked)
check("the sixth wrong PIN raises PinLocked(30)", e is not None and e.seconds == 30, e and e.seconds)
e = raises(lambda: P.open(slot.rec, "five", "long plain pin", sealed), P.PinLocked)
check("while the wait runs even the right PIN waits", e is not None and 0 < e.seconds <= 30)
check("the wait survives reopening the keys file", D.read()["throttle"]["until"] > time.time() and fails() == 6)
e2 = raises(lambda: D.open_with_password("admin", "correct horse battery staple"), D.Throttled)
check("one counter: a password waits too", e2 is not None)
msgs += [str(e), repr(e)]
reset()
check("after the wait the right PIN opens", P.open(slot.rec, "five", "long plain pin", sealed) == SECRET)

# ---------------------------------------------------------------- no secret in an exception
check("no PIN in an exception", not any(p in m for m in msgs for p in list(PINS.values()) + ["wrong pin"]), msgs)

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

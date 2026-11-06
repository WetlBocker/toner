# Run by hand on a Windows computer with a TPM (not part of run_all.py, which runs only test_*.py; CI has no TPM):
#     python tests/manual_tpm_check.py             the chip: a key with a PIN, right and wrong PINs, a PIN slot, delete
#     python tests/manual_tpm_check.py --lockout   also wrong PINs until Windows refuses every PIN, and the wait it gives
# Each run spends one of Windows' 4 wrong-PIN tries per 8 hours (a standard user's defaults). --lockout spends them all: this
# user's TPM PINs are then refused until the oldest failure is 8 hours old. A throw-away data folder: Toner's data isn't touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ["SP"] = _tmp.mkdtemp(prefix="netcheck_tpm_")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "tpm.db"); os.environ["APPDATA"] = SP
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from core import datakey, pinslot, tpm_windows

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  pass", name)
    else: bad += 1; print("  FAIL", name, extra)


def outcome(fn):
    try:
        return fn()
    except Exception as e:
        return e


if sys.platform != "win32":
    sys.exit("This check needs Windows.")
OAEP = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
name, slot_id, PIN = "Toner-check-" + os.urandom(6).hex(), "check-" + os.urandom(6).hex(), "482916"
started = time.time()
check("the chip is available (provider opens, a test key is made and deleted)", tpm_windows.available())
sealed = None
try:
    try:
        der = tpm_windows.create(name, PIN)
    except tpm_windows.LockedOut as e:
        sys.exit(f"Windows is refusing the chip's PINs now (a lockout). Wait up to {e.seconds} seconds, then run this again.")
    pub = serialization.load_der_public_key(der)
    check("create: an RSA-2048 key with a PIN", pub.key_size == 2048)
    data = pub.encrypt(b"manual check", OAEP)
    check("decrypt with the right PIN", outcome(lambda: tpm_windows.decrypt(name, PIN, data)) == b"manual check")
    r = outcome(lambda: tpm_windows.decrypt(name, "000000", data))
    check("a wrong PIN is refused (PermissionError)", isinstance(r, PermissionError), repr(r))
    r = outcome(lambda: tpm_windows.decrypt(name, PIN, data))
    check("the right PIN still works after one wrong one", r == b"manual check", repr(r))

    datakey.create("admin", "correct horse battery staple")      # the throw-away keys file holds Toner's own count
    slot = pinslot.new("chip", slot_id, PIN)
    sealed = slot.seal(b"slot secret")
    check("a chip PIN slot opens", outcome(lambda: pinslot.open(slot.rec, slot_id, PIN, sealed)) == b"slot secret")

    if "--lockout" in sys.argv:
        r, tries = None, 0
        while not isinstance(r, tpm_windows.LockedOut) and tries < 64:
            tries += 1
            r = outcome(lambda: tpm_windows.decrypt(name, "%06d" % (100000 + tries), data))
        check(f"wrong PINs end in LockedOut (after {tries})", isinstance(r, tpm_windows.LockedOut), repr(r))
        if isinstance(r, tpm_windows.LockedOut):
            print(f"        the wait: up to {r.seconds} seconds")
        r = outcome(lambda: tpm_windows.decrypt(name, PIN, data))
        check("during the lockout even the right PIN is refused", isinstance(r, tpm_windows.LockedOut), repr(r))
        r = outcome(lambda: pinslot.open(slot.rec, slot_id, PIN, sealed))
        check("the PIN slot shows the lockout as PinLocked", isinstance(r, pinslot.PinLocked), repr(r))
    else:
        print("  skip the lockout (run with --lockout)")
finally:
    tpm_windows.delete(name)
    pinslot.remove({"kind": "chip"}, slot_id)
r = outcome(lambda: tpm_windows.decrypt(name, PIN, b"x" * 256))
check("delete: the key is gone (FileNotFoundError)", isinstance(r, FileNotFoundError), repr(r))
if sealed is None:
    check("remove: the slot was never made, so its removal can't be checked (see the failures above)", False)
else:
    r = outcome(lambda: pinslot.open({"kind": "chip"}, slot_id, PIN, sealed))
    check("remove: the slot's key is gone (SlotMissing)", isinstance(r, pinslot.SlotMissing), repr(r))
print(f"\n{ok} passed, {bad} failed  ({time.time() - started:.0f} s)"); sys.exit(1 if bad else 0)

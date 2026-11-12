# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The security-key seam (core/fidokey.py) against a software key standing in for fido2's client: the requests it builds, the
# value and presence checks, the key's own failures in the approved words, and the fake (tests/fakekey.py) keeping the same promises.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\fidokey%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
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

import hashlib, hmac, inspect, io, logging, threading
from types import SimpleNamespace
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.client import ClientError, PinRequiredError
from fido2.cose import ES256
from fido2.ctap import CtapError
from fido2.utils import websafe_decode, websafe_encode as websafe
from fido2.webauthn import (Aaguid, AttestationObject, AttestedCredentialData, AuthenticationExtensionsClientOutputs, AuthenticationResponse,
                            AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, AuthenticatorData, CollectedClientData, RegistrationResponse)
from core import fidokey
import fakekey

SALT, KEY_PIN = os.urandom(32), "1234"
F = AuthenticatorData.FLAG


class Stub:
    """A software key behind fido2's client interface: it signs with a real P-256 key, answers prf like hmac-secret, asks for its PIN the
    way the library does off Windows (through the UserInteraction fidokey hands over) and raises the library's own errors."""
    def __init__(self, prf=True, give_value=True, has_pin=True):
        self.key, self.secret, self.cred_id = ec.generate_private_key(ec.SECP256R1()), os.urandom(32), os.urandom(32)
        self.prf, self.give_value, self.has_pin = prf, give_value, has_pin
        self.calls, self.challenges, self.events, self.pins_asked = [], [], [], 0
        self.created = self.got = self.ask_pin = None
        self.forge = self.blocked = self.always_uv = self.bad_challenge = False
        self.wrong, self.fail, self.client_fail, self.value_len = 0, None, None, 32

    def client(self, window, ask_pin):
        if self.client_fail is not None:
            raise self.client_fail
        self.ask_pin = ask_pin
        return self

    def _gate(self, uv, event):
        self.events.append(event)
        if self.fail is not None:
            raise self.fail                                    # what the transport raises, not the library's ClientError
        if event is not None and event.is_set():
            raise ClientError.ERR.TIMEOUT()                    # what the library raises when the event is set before the touch
        if uv != "required" and not self.always_uv:            # always_uv: a key set to always verify asks its PIN for presence too
            return
        if not self.has_pin:
            raise ClientError.ERR.CONFIGURATION_UNSUPPORTED("User verification not configured/supported")
        if self.blocked:
            raise ClientError.ERR.BAD_REQUEST(CtapError(CtapError.ERR.PIN_BLOCKED))
        pin = self.ask_pin() if self.ask_pin else KEY_PIN     # no ask_pin: Windows asks in its own dialog
        self.pins_asked += 1
        if pin is None:
            raise PinRequiredError()
        if pin != KEY_PIN:
            self.wrong += 1                                    # a CTAP2 key answers the third wrong PIN in a row with PIN_AUTH_BLOCKED
            raise ClientError.ERR.BAD_REQUEST(CtapError(CtapError.ERR.PIN_AUTH_BLOCKED if self.wrong >= 3 else CtapError.ERR.PIN_INVALID))
        self.wrong = 0

    def _value(self, salt):
        return hmac.new(self.secret, salt, hashlib.sha256).digest()[:self.value_len]

    def _sign(self, data):
        return (ec.generate_private_key(ec.SECP256R1()) if self.forge else self.key).sign(data, ec.ECDSA(hashes.SHA256()))

    def make_credential(self, options, event=None):
        self.calls.append("make"); self.created = options
        uv = options["authenticatorSelection"]["userVerification"]
        self._gate(uv, event)
        cd = CollectedClientData.create(CollectedClientData.TYPE.CREATE, os.urandom(32) if self.bad_challenge else options["challenge"], fidokey.ORIGIN)
        data = AttestedCredentialData.create(Aaguid.NONE, self.cred_id, ES256.from_cryptography_key(self.key.public_key()))
        auth = AuthenticatorData.create(hashlib.sha256(options["rp"]["id"].encode()).digest(), F.UP | F.AT | (F.UV if uv == "required" else 0), 0, data)
        prf = (options.get("extensions") or {}).get("prf")
        ext = {} if not (self.prf and prf) else {"prf": {"enabled": True, **({"results": {"first": self._value(prf["eval"]["first"])}} if self.give_value else {})}}
        return RegistrationResponse(raw_id=self.cred_id, response=AuthenticatorAttestationResponse(client_data=cd, attestation_object=AttestationObject.create("none", auth, {})),
                                    client_extension_results=AuthenticationExtensionsClientOutputs(ext))

    def get_assertion(self, options, event=None):
        self.calls.append("get"); self.got = options; self.challenges.append(options["challenge"])
        self._gate(options["userVerification"], event)
        allowed = [d["id"] if isinstance(d["id"], bytes) else websafe_decode(d["id"]) for d in options["allowCredentials"]]
        if self.cred_id not in allowed:
            raise ClientError.ERR.DEVICE_INELIGIBLE(CtapError(CtapError.ERR.NO_CREDENTIALS))
        cd = CollectedClientData.create(CollectedClientData.TYPE.GET, options["challenge"], fidokey.ORIGIN)
        auth = AuthenticatorData.create(hashlib.sha256(options["rpId"].encode()).digest(), F.UP | (F.UV if options["userVerification"] == "required" else 0), 1)
        prf = (options.get("extensions") or {}).get("prf")
        ext = {}
        if self.prf and prf:
            salt = (prf.get("evalByCredential") or {}).get(websafe(self.cred_id), prf.get("eval"))["first"]
            ext = {"prf": {"results": {"first": self._value(salt)}}}
        resp = AuthenticationResponse(raw_id=self.cred_id, response=AuthenticatorAssertionResponse(client_data=cd, authenticator_data=auth, signature=self._sign(auth + cd.hash)),
                                      client_extension_results=AuthenticationExtensionsClientOutputs(ext))
        return SimpleNamespace(get_response=lambda i: [resp][i])


def raised(exc, fn):
    """The exception fn raised if it is an `exc`; otherwise a stand-in whose text says what happened, so a check on it fails."""
    try:
        fn()
    except exc as e:
        return e
    except Exception as e:
        return SimpleNamespace(text=f"raised {type(e).__name__} instead")
    return SimpleNamespace(text="nothing raised")

def on(stub, fn):
    """fn with fidokey talking to stub."""
    def run():
        fidokey._client = stub.client
        return fn()
    return run

REAL_CLIENT = fidokey._client

print("== registration")
stub = Stub()
fidokey._client = stub.client
cred, val = fidokey.register("Blue key", SALT)
check("registration asks under toner.invalid, cross-platform, with the key's PIN required and the number in the request",
      stub.created["rp"]["id"] == "toner.invalid" and stub.created["authenticatorSelection"]["authenticatorAttachment"] == "cross-platform"
      and stub.created["authenticatorSelection"]["userVerification"] == "required" and stub.created["extensions"] == {"prf": {"eval": {"first": SALT}}}, stub.created)
check("it gives the credential and a 32-byte value", cred.id == stub.cred_id and cred.salt == SALT and len(val) == 32 and val == stub._value(SALT) and cred.public)
check("the stored public half is the key's own", ES256.from_cryptography_key(stub.key.public_key()) == cbor.decode(cred.public))
stub_without_result = Stub(give_value=False)
cred2, val_late = on(stub_without_result, lambda: fidokey.register("Blue key", SALT))()
check("no value at registration: it reads it once more", stub_without_result.calls == ["make", "get"] and val_late == stub_without_result._value(SALT), stub_without_result.calls)
stub_no_prf = Stub(prf=False)
check("a key without the feature is refused in the approved words", raised(fidokey.Unsupported, on(stub_no_prf, lambda: fidokey.register("Blue key", SALT))).text
      == "This key can't be used: it doesn't support what Toner needs (FIDO2 hmac-secret).")

print("== the value")
fidokey._client = stub.client
other = fidokey.Cred(id=os.urandom(32), salt=os.urandom(32), public=cred.public)
cid, val2 = fidokey.value([other, cred])
check("the value is read with the key's PIN required, each credential with its own number",
      stub.got["userVerification"] == "required" and stub.got["extensions"]["prf"]["evalByCredential"] == {websafe(other.id): {"first": other.salt}, websafe(cred.id): {"first": SALT}}, stub.got)
check("a prf request always carries eval (the library drops one without on Windows)", "eval" in stub.got["extensions"]["prf"])
check("it answers with the credential that answered and the same value as at registration", cid == cred.id and val2 == val)

print("== presence")
c1 = fidokey.present([cred]); got1 = stub.got
c2 = fidokey.present([cred])
check("presence is a touch alone, on a fresh challenge each time", c1 == c2 == cred.id and got1["userVerification"] == "discouraged"
      and "extensions" not in got1 and stub.challenges[-2] != stub.challenges[-1], got1)
stub.forge = True
check("a signature that does not match what was registered is not presence", isinstance(raised(fidokey.NotRegistered, lambda: fidokey.present([cred])), fidokey.NotRegistered))
stub.forge = False
check("a key that holds none of the account's credentials", isinstance(raised(fidokey.NotRegistered, lambda: fidokey.value([other])), fidokey.NotRegistered))

print("== the key's own PIN and failures")
pins = Stub()
cred_p, _ = on(pins, lambda: fidokey.register("Blue key", SALT))()
pins.pins_asked = 0
log = io.StringIO(); handler = logging.StreamHandler(log); root = logging.getLogger(); level = root.level
root.addHandler(handler); root.setLevel(logging.DEBUG)
try:
    tries = [raised(fidokey.Failed, on(pins, lambda: fidokey.value([cred_p], ask_pin=lambda: "9876"))) for _ in range(3)]
finally:
    root.removeHandler(handler); root.setLevel(level)
captured_log = log.getvalue() + "".join(f"{t!r}{t}" for t in tries)
check("a wrong key PIN in the approved words", [type(t) for t in tries[:2]] == [fidokey.WrongKeyPin] * 2 and tries[0].text == "That key PIN isn't right.", tries)
check("three wrong key PINs: the retry message, and the PIN is in no log", isinstance(tries[2], fidokey.KeyPinRetry)
      and tries[2].text == "Too many wrong PINs. Unplug the key, plug it back in and try again." and pins.pins_asked == 3 and "9876" not in captured_log, (tries, pins.pins_asked))
pins.blocked = True
check("a key whose PIN is locked for good", raised(fidokey.KeyPinLocked, on(pins, lambda: fidokey.value([cred_p], ask_pin=lambda: KEY_PIN))).text
      == "The key's PIN is locked. The key has to be reset before it can be used again.")
check("a key with no PIN set, off Windows", raised(fidokey.NoKeyPin, on(Stub(has_pin=False), lambda: fidokey.register("Blue key", SALT, ask_pin=lambda: KEY_PIN))).text
      == "This key has no PIN yet. Set one with the key's own software, then add it here.")
check("Cancel on the PIN question: not touched", raised(fidokey.NotTouched, on(Stub(), lambda: fidokey.register("Blue key", SALT, ask_pin=lambda: None))).text
      == "The key wasn't touched. Sign in again.")

import fido2.hid                                                         # loads this OS's HID backend before the platform is pretended
real_list, real_platform = fido2.hid.CtapHidDevice.list_devices, sys.platform
fido2.hid.CtapHidDevice.list_devices = classmethod(lambda cls: iter(()))
sys.platform = "linux"
try:
    fidokey._client = REAL_CLIENT
    nokey = raised(fidokey.NoKey, lambda: fidokey.value([cred], ask_pin=lambda: KEY_PIN))
finally:
    fido2.hid.CtapHidDevice.list_devices, sys.platform = real_list, real_platform
check("no key plugged in", nokey.text == "Toner can't find a security key. Plug yours in and try again.")

from fido2.hid import ConnectionFailure
for exc, want in ((OSError("the key was unplugged"), fidokey.NoKey), (ConnectionFailure(), fidokey.NoKey),
                  (CtapError(CtapError.ERR.PIN_INVALID), fidokey.WrongKeyPin)):
    in_call, at_client, at_make = Stub(), Stub(), Stub()
    in_call.fail, at_client.client_fail, at_make.fail = exc, exc, exc
    got = (raised(want, on(in_call, lambda: fidokey.value([cred], ask_pin=lambda: KEY_PIN))), raised(want, on(at_client, lambda: fidokey.present([cred]))),
           raised(want, on(at_make, lambda: fidokey.register("Blue key", SALT))))
    check(f"{type(exc).__name__} from the key, or while finding it, is {want.__name__}", all(isinstance(g, want) for g in got), [getattr(g, "text", g) for g in got])
bad_reg = Stub(); bad_reg.bad_challenge = True
check("a registration the server can't verify: Unsupported", isinstance(raised(fidokey.Unsupported, on(bad_reg, lambda: fidokey.register("Blue key", SALT))), fidokey.Unsupported))
short = Stub(); short.value_len = 16
check("a registration value that is not 32 bytes: Unsupported", isinstance(raised(fidokey.Unsupported, on(short, lambda: fidokey.register("Blue key", SALT))), fidokey.Unsupported))
always = Stub()
cred_a, _ = on(always, lambda: fidokey.register("Blue key", SALT, ask_pin=lambda: KEY_PIN))()
always.always_uv, always.pins_asked, asked = True, 0, []
present_with_pin = on(always, lambda: fidokey.present([cred_a], ask_pin=lambda: asked.append(1) or KEY_PIN))
check("a key that always verifies: presence asks its PIN through ask_pin, still asking for no verification itself",
      present_with_pin() == cred_a.id and asked == [1] and always.pins_asked == 1 and always.got["userVerification"] == "discouraged", (asked, always.got))

cancel = threading.Event(); cancel.set()
cancelled = Stub()
check("cancel set before the touch: NotTouched", isinstance(raised(fidokey.NotTouched, on(cancelled, lambda: fidokey.value([cred], cancel=cancel))), fidokey.NotTouched)
      and cancelled.events == [cancel])

print("== the fake")
real = {n: getattr(fidokey, n) for n in ("register", "value", "present")}
fake = fakekey.install()
same = all(inspect.signature(getattr(fake, n)) == inspect.signature(f) for n, f in real.items())
fcred, fval = fidokey.register("Blue key", SALT)
round_trip = fidokey.value([other, fcred]) == (fcred.id, fval) and fidokey.present([fcred]) == fcred.id and len(fval) == 32 and fcred.salt == SALT
fake.pin = KEY_PIN
wrong_pin = raised(fidokey.WrongKeyPin, lambda: fidokey.value([fcred], ask_pin=lambda: "0000"))
fake.touch = False
untouched = raised(fidokey.NotTouched, lambda: fidokey.present([fcred]))
fake.touch, fake.plugged = True, False
unplugged = raised(fidokey.NoKey, lambda: fidokey.value([fcred]))
fake.plugged = True
stranger = raised(fidokey.NotRegistered, lambda: fidokey.present([other]))
fake_round_trip_matches_the_contract = (same and round_trip and isinstance(wrong_pin, fidokey.WrongKeyPin) and isinstance(untouched, fidokey.NotTouched)
                                        and isinstance(unplugged, fidokey.NoKey) and isinstance(stranger, fidokey.NotRegistered)
                                        and fake.calls == ["register", "value", "present", "value", "present", "value", "present"])
check("the fake keeps the same promises", fake_round_trip_matches_the_contract, (same, round_trip, wrong_pin, untouched, unplugged, stranger, fake.calls))
for n, f in real.items():
    setattr(fidokey, n, f)

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

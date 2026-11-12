"""The one place Toner talks to a FIDO2 security key (python-fido2). Everything else imports this module, never fido2, and tests
replace register/value/present with tests/fakekey.py.

    register(label, salt)   a new credential on the key the person touches, and the key's 32-byte value for salt (hmac-secret / prf)
    value(creds)            the same value again: the key's own PIN and a touch, from whichever of creds the key holds
    present(creds)          a touch alone: the key signs a fresh challenge, checked against the public half it registered

Windows talks to the key through its own WebAuthn dialog (the only way without administrator rights) and asks for the key's PIN
itself; Linux and macOS talk to the first key over HID and ask for its PIN through ask_pin. Every failure is a Failed whose text
is the approved message; neither it nor a log ever carries the key's PIN or value.
"""
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass

from fido2 import cbor
from fido2.client import ClientError, DefaultClientDataCollector, Fido2Client, PinRequiredError, UserInteraction
from fido2.cose import CoseKey
from fido2.ctap import CtapError
from fido2.ctap2.extensions import AuthenticatorExtensionsPRFOutputs
from fido2.server import Fido2Server
from fido2.utils import websafe_encode
from fido2.webauthn import Aaguid, AttestedCredentialData

RP_ID = "toner.invalid"                       # a name no website can have, so no web page can ask a key for Toner's value
ORIGIN = "https://" + RP_ID


class Failed(Exception):
    text: str

    def __init__(self):
        super().__init__(self.text)

class NoKey(Failed): text = "Toner can't find a security key. Plug yours in and try again."
class NotRegistered(Failed): text = "That key isn't registered to this account."
class NotTouched(Failed): text = "The key wasn't touched. Sign in again."
class Unsupported(Failed): text = "This key can't be used: it doesn't support what Toner needs (FIDO2 hmac-secret)."
class WrongKeyPin(Failed): text = "That key PIN isn't right."
class KeyPinRetry(Failed): text = "Too many wrong PINs. Unplug the key, plug it back in and try again."
class KeyPinLocked(Failed): text = "The key's PIN is locked. The key has to be reset before it can be used again."
class NoKeyPin(Failed): text = "This key has no PIN yet. Set one with the key's own software, then add it here."


@dataclass(frozen=True)
class Cred:
    id: bytes
    salt: bytes
    public: bytes                             # the key's COSE public key, CBOR-encoded


_CTAP = {CtapError.ERR.PIN_INVALID: WrongKeyPin, CtapError.ERR.PIN_AUTH_BLOCKED: KeyPinRetry, CtapError.ERR.PIN_BLOCKED: KeyPinLocked,
         CtapError.ERR.PIN_NOT_SET: NoKeyPin, CtapError.ERR.NO_CREDENTIALS: NotRegistered, CtapError.ERR.UNSUPPORTED_ALGORITHM: Unsupported,
         CtapError.ERR.UNSUPPORTED_OPTION: Unsupported}


def _failed(e: ClientError) -> Failed:
    if isinstance(e.cause, CtapError):
        return _CTAP.get(e.cause.code, NotTouched)()
    if isinstance(e, PinRequiredError):
        return NotTouched()                   # ask_pin returned None: the person cancelled
    if e.code == ClientError.ERR.CONFIGURATION_UNSUPPORTED:
        # the library says so when a key has no PIN (or other user verification) set up and the request requires one
        return NoKeyPin() if "User verification not configured" in str(e.cause) else Unsupported()
    if e.code == ClientError.ERR.DEVICE_INELIGIBLE:
        return NotRegistered()
    return NotTouched()                       # timeouts, cancels, and on Windows every dismissal of its dialog (an OSError)


def _client(window, ask_pin):
    collector = DefaultClientDataCollector(ORIGIN)
    if sys.platform == "win32":
        from fido2.client.windows import WindowsClient
        return WindowsClient(collector, handle=window)
    from fido2.hid import CtapHidDevice
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is None:
        raise NoKey()

    class Ask(UserInteraction):
        def request_pin(self, permissions, rp_id):
            return ask_pin() if ask_pin else None
    return Fido2Client(dev, client_data_collector=collector, user_interaction=Ask())


def _call(method, options, cancel):
    try:
        return method(options, event=cancel)
    except ClientError as e:
        raise _failed(e) from None


def _first(results) -> bytes | None:
    prf = AuthenticatorExtensionsPRFOutputs.from_dict(results.get("prf"))
    return prf.results.first if prf and prf.results else None


def _data(c: Cred) -> AttestedCredentialData:
    return AttestedCredentialData.create(Aaguid.NONE, c.id, CoseKey.parse(cbor.decode(c.public)))


def _assert(creds, uv, extensions, ask_pin, cancel, window):
    """The key's signed answer for one of creds, verified against its registered public half: (credential id, the client's response)."""
    if not creds:
        raise NotRegistered()
    server, datas = Fido2Server({"id": RP_ID, "name": "Toner"}), [_data(c) for c in creds]
    request, state = server.authenticate_begin(datas, user_verification=uv)         # a fresh random challenge every time
    got = _call(_client(window, ask_pin).get_assertion, {**request["publicKey"], **extensions}, cancel).get_response(0)
    try:
        return server.authenticate_complete(state, datas, got).credential_id, got
    except ValueError:                        # a signature that does not verify, or a credential that is not one of creds
        raise NotRegistered() from None


def register(label: str, salt: bytes, *, ask_pin=None, cancel=None, window=None) -> tuple[Cred, bytes]:
    server = Fido2Server({"id": RP_ID, "name": "Toner"})
    create, state = server.register_begin({"id": os.urandom(16), "name": label, "displayName": label},
                                          user_verification="required", authenticator_attachment="cross-platform")
    # the library drops an empty prf request on Windows, so the number goes in at registration too
    made = _call(_client(window, ask_pin).make_credential, {**create["publicKey"], "extensions": {"prf": {"eval": {"first": salt}}}}, cancel)
    data = server.register_complete(state, made).credential_data
    cred = Cred(data.credential_id, salt, cbor.encode(data.public_key))
    prf = AuthenticatorExtensionsPRFOutputs.from_dict(made.client_extension_results.get("prf"))
    if not (prf and prf.enabled):
        raise Unsupported()
    first = _first(made.client_extension_results)
    if first is None:                         # some keys only give the value on a read, not at registration
        return cred, value([cred], ask_pin=ask_pin, cancel=cancel, window=window)[1]
    return cred, first


def value(creds: Sequence[Cred], *, ask_pin=None, cancel=None, window=None) -> tuple[bytes, bytes]:
    if not creds:
        raise NotRegistered()
    prf = {"eval": {"first": creds[0].salt}, "evalByCredential": {websafe_encode(c.id): {"first": c.salt} for c in creds}}
    cid, got = _assert(creds, "required", {"extensions": {"prf": prf}}, ask_pin, cancel, window)
    first = _first(got.client_extension_results)
    if first is None or len(first) != 32:
        raise Unsupported()
    return cid, first


def present(creds: Sequence[Cred], *, cancel=None, window=None) -> bytes:
    return _assert(creds, "discouraged", {}, None, cancel, window)[0]

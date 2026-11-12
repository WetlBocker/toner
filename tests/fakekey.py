"""A security key for tests, in place of core/fidokey.py's real one (tests/ is on sys.path when run as a script:  import fakekey).

    key = fakekey.install()      # core.fidokey.register/value/present now talk to this fake
    key.plugged = False          # the next call raises NoKey
    key.touch = False            # ... NotTouched (as does a cancel Event that is set)
    key.pin = "1234"             # value() and register() ask ask_pin (when given) and refuse another answer with WrongKeyPin
    key.calls                    # "register" / "value" / "present", in order

Each credential it registers keeps a random secret; its value for a salt is HMAC-SHA256(secret, salt), as a real key's is stable.
A credential it never registered raises NotRegistered.
"""
import hashlib, hmac, os
from collections.abc import Sequence

from core import fidokey
from core.fidokey import Cred


class FakeKey:
    def __init__(self):
        self.plugged, self.touch, self.pin, self.calls, self.secrets = True, True, None, [], {}

    def _touch(self, cancel, ask_pin=None):
        if not self.plugged:
            raise fidokey.NoKey()
        if ask_pin is not None and self.pin is not None:
            answer = ask_pin()
            if answer is None:
                raise fidokey.NotTouched()
            if answer != self.pin:
                raise fidokey.WrongKeyPin()
        if not self.touch or (cancel is not None and cancel.is_set()):
            raise fidokey.NotTouched()

    def _mine(self, creds):
        cred = next((c for c in creds if c.id in self.secrets), None)
        if cred is None:
            raise fidokey.NotRegistered()
        return cred

    def register(self, label: str, salt: bytes, *, ask_pin=None, cancel=None, window=None) -> tuple[Cred, bytes]:
        self.calls.append("register")
        self._touch(cancel, ask_pin)
        cred = Cred(os.urandom(32), salt, b"fake public key")
        self.secrets[cred.id] = os.urandom(32)
        return cred, hmac.new(self.secrets[cred.id], salt, hashlib.sha256).digest()

    def value(self, creds: Sequence[Cred], *, ask_pin=None, cancel=None, window=None) -> tuple[bytes, bytes]:
        self.calls.append("value")
        self._touch(cancel, ask_pin)
        cred = self._mine(creds)
        return cred.id, hmac.new(self.secrets[cred.id], cred.salt, hashlib.sha256).digest()

    def present(self, creds: Sequence[Cred], *, cancel=None, window=None) -> bytes:
        self.calls.append("present")
        self._touch(cancel)
        return self._mine(creds).id


def install() -> FakeKey:
    key = FakeKey()
    fidokey.register, fidokey.value, fidokey.present = key.register, key.value, key.present
    return key

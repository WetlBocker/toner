# Run directly (python tests/test_envelope.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Envelope crypto: X25519 wraps, Ed25519 signatures, canonical JSON and fingerprints.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\env%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import backup, db
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

import base64
from cryptography.exceptions import InvalidTag
from core import envelope as E

def raises(exc, fn, *a):
    try: fn(*a)
    except exc: return True
    except Exception: return False
    return False

priv, pub = E.new_box_key()
check("box keys are 32 bytes", len(priv) == 32 and len(pub) == 32)
secret, aad = os.urandom(32), b"role:admin"
blob = E.wrap(pub, secret, aad)
check("wrap/unwrap round trip", E.unwrap(priv, blob, aad) == secret)
check("blob holds ephemeral key + nonce + tag", len(base64.b64decode(blob)) == 32 + 12 + len(secret) + 16)
check("wrong key raises InvalidTag", raises(InvalidTag, E.unwrap, E.new_box_key()[0], blob, aad))
check("aad off by one byte raises InvalidTag", raises(InvalidTag, E.unwrap, priv, blob, b"role:admin\x00"))
raw = bytearray(base64.b64decode(blob)); raw[-1] ^= 1
check("tampered blob raises InvalidTag", raises(InvalidTag, E.unwrap, priv, base64.b64encode(bytes(raw)).decode(), aad))
check("short blob raises ValueError", raises(ValueError, E.unwrap, priv, base64.b64encode(b"x" * 10).decode(), aad))
check("two wraps differ", E.wrap(pub, secret, aad) != blob)

spriv, spub = E.new_signing_key()
data = b"the role rules"
sig = E.sign(spriv, data)
check("sign/verify", E.verify(spub, data, sig) is True)
check("flipped data byte fails", E.verify(spub, b"the role rulez", sig) is False)
check("another key's signature fails", E.verify(spub, data, E.sign(E.new_signing_key()[0], data)) is False)
check("not base64 gives False", E.verify(spub, data, "not base64") is False)
check("empty signature gives False", E.verify(spub, data, "") is False)
check("bad public key gives False", E.verify(b"short", data, sig) is False)

check("canonical", E.canonical({"b": 1, "a": "é"}) == '{"a":"é","b":1}'.encode())
check("fingerprint is sha256 hex", E.fingerprint(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

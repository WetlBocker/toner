# Run directly (python tests/test_sealedfile.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Sealed side files: AES-GCM frames under the data key, appends, tamper detection, plain files, and the locked state.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\seal%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import backup, db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from pathlib import Path
from core import sqldb, sealedfile as S

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1
    else: bad += 1; print("FAIL:", name, extra)

def raises(exc, fn, *a):
    try: fn(*a)
    except exc: return True
    except Exception: return False
    return False

d = Path(SP) / "sealtest"; d.mkdir(exist_ok=True)
sqldb.set_key(os.urandom(32))

p = d / "a.txt"
S.write_text(p, "abc")
raw = p.read_bytes()
check("starts with magic", raw.startswith(S.MAGIC))
check("plaintext not in file", b"abc" not in raw)
check("round trip", S.read_text(p) == "abc" and S.is_sealed(p))
S.write_text(p, "héllo")
check("rewrite, unicode", S.read_text(p) == "héllo")
check("no temp file left", not list(d.glob("*.tmp")))

q = d / "log.txt"
a = S.Appender(q); a.write("one\n"); a.write("two\n"); a.close()
check("appender frames read back", S.read_text(q) == "one\ntwo\n")
a = S.Appender(q); a.write("three\n"); a.close()
check("reopened appender continues", S.read_text(q) == "one\ntwo\nthree\n")
check("appender plaintext hidden", b"one" not in q.read_bytes())

# a crash mid-append leaves a short final frame; reading stops cleanly before it
q.write_bytes(q.read_bytes() + b"\x00\x00\x00\x40abc")
check("short final frame ignored", S.read_text(q) == "one\ntwo\nthree\n")

b = bytearray(p.read_bytes()); b[-1] ^= 1; p.write_bytes(bytes(b))
check("tamper raises ValueError", raises(ValueError, S.read_bytes, p))

moved = d / "moved.txt"
S.write_text(p, "abc"); moved.write_bytes(p.read_bytes())
check("frame can't move to another file", raises(ValueError, S.read_bytes, moved))

pl = d / "plain.txt"; pl.write_text("plain\n")
check("plain file reads as is", S.read_text(pl) == "plain\n" and not S.is_sealed(pl))
check("appender refuses plain file", raises(S.Locked, S.Appender, pl))
check("seal_existing seals plain", S.seal_existing(pl) is True and S.is_sealed(pl) and S.read_text(pl) == "plain\n")
check("seal_existing second call", S.seal_existing(pl) is False)
check("seal_existing missing file", S.seal_existing(d / "nope") is False)

sqldb.set_key(None)
check("write locked without key", raises(S.Locked, S.write_bytes, d / "x", b"1"))
check("read sealed locked without key", raises(S.Locked, S.read_bytes, p))
check("appender locked without key", raises(S.Locked, S.Appender, d / "y"))
(d / "p3.txt").write_text("hi")
check("plain read needs no key", S.read_text(d / "p3.txt") == "hi")

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

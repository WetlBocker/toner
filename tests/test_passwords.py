# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Password rules: at least 12 characters, not a common password (any case, or one plus digits), no username in it.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\pw%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import passwords as P

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

check("min length is 12", P.MIN_LENGTH == 12)
check("short mentions 12", "12" in (P.problem("short") or ""))
check("empty reports the length rule", "12" in (P.problem("") or ""))
check("common + digits is too common", "too common" in (P.problem("password1234") or ""))
check("common is case-insensitive", "too common" in (P.problem("PassWord123456") or ""))
check("username inside is refused", "username" in (P.problem("jsmith-jsmith", "jsmith") or ""))
check("username match ignores case", "username" in (P.problem("xx-JSMITH-xx-yy", "jsmith") or ""))
check("passphrase is fine", P.problem("correct horse battery staple") is None)
check("passphrase with a username is fine", P.problem("correct horse battery staple", "jsmith") is None)
check("list loads 9000+ entries", len(P._common()) >= 9000)

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

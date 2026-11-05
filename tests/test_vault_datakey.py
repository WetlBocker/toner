# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The vault opens with the data key: an old master-password vault is adopted (and its remembered key removed), a wrong key
# is refused, a new vault is made when there is none, signing in opens it, and Settings > Security has no master password left.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, json
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\vdk%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import datakey, db, passvault, session, sqldb

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def raises(fn, kind):
    try: fn()
    except kind as e: return e
    except Exception: return None
    return None

NATIVE = {}
class _NativeKeyring:                                  # Linux and macOS keep the remembered key in the system keyring: a stand-in
    def set_password(self, s, u, p): NATIVE[(s, u)] = p
    def get_password(self, s, u): return NATIVE.get((s, u))
    def delete_password(self, s, u): NATIVE.pop((s, u), None)
if sys.platform != "win32":
    passvault._native_keyring = lambda: _NativeKeyring()

k, wrong = os.urandom(32), os.urandom(32)

print("== an old vault")
passvault.create("old master password!", remember=False, carry={"a": "1"})
check("sealed by a master password", passvault.uses_master())
passvault.adopt(k)
passvault.lock()
check("after adopt the file says datakey", json.load(open(passvault.path(), encoding="utf-8"))["kdf"] == {"name": "datakey"})
passvault.open_with(k)
check("it opens with the data key, its passwords kept", passvault.get("a") == "1")
check("no longer sealed by a master password", not passvault.uses_master())
passvault.lock()
e = raises(lambda: passvault.unlock("old master password!"), Exception)
check("the old master password no longer opens it", e is not None and "old master password!" not in str(e) and not passvault.is_open(), repr(e))

print("== a remembered old vault")
os.remove(passvault.path())
passvault.create("old master password!", remember=True, carry={"a": "1"})
check("remembered before adopt", passvault.remembered())
passvault.adopt(k)
check("the -key file is gone after adopt", not passvault.key_path().exists() and not passvault.remembered())
check("...and the system keyring has no copy left", not NATIVE)
passvault.lock()
check("unlock_remembered can no longer open it", not passvault.unlock_remembered())

print("== a wrong key")
e = raises(lambda: passvault.open_with(wrong), passvault.WrongPassword)
check("open_with(wrong_key) raises WrongPassword", e is not None and not passvault.is_open())
check("...with nothing secret in the message", e is not None and wrong.hex() not in str(e) and k.hex() not in str(e))

print("== an old vault is never overwritten by open_with")
os.remove(passvault.path()); passvault.lock()
passvault.create("old master password!", remember=False, carry={"keep": "me"})
passvault.lock()
before = open(passvault.path(), "rb").read()
e = raises(lambda: passvault.open_with(k), passvault.Locked)
check("open_with on a master-password vault refuses, saying the upgrade must run", e is not None and not passvault.is_open(), repr(e))
check("...and leaves the file as it was", open(passvault.path(), "rb").read() == before)
check("there is no way left to re-seal it with a master password", not hasattr(passvault, "change_master") and not hasattr(passvault, "set_remembered"))

print("== no vault yet")
os.remove(passvault.path()); passvault.lock()
passvault.open_with(k)
check("open_with makes one", passvault.exists() and passvault.is_open() and passvault.names() == [] and not passvault.uses_master())
passvault.put("b", "2")
passvault.lock()
passvault.open_with(k)
check("put works and it reopens", passvault.get("b") == "2")
raw = open(passvault.path(), encoding="utf-8").read()
check("the file shows neither the data key nor the password", k.hex() not in raw and "\"2\"" not in raw)

print("== signing in opens the vault")
passvault.lock(); os.remove(passvault.path())
PW = "correct horse battery 42"
recovery = datakey.create("Admin", PW)
db.init()
session.sign_out()
session.sign_in("admin", PW)
check("sign_in opens the vault with the data key", passvault.is_open() and not passvault.uses_master())
passvault.put("c", "3")
session.sign_out()
check("sign_out locks it", not passvault.is_open())
check("sign_in opens it again with its passwords", (session.sign_in("admin", PW) or True) and passvault.get("c") == "3")
session.sign_out()

print("== sign_out is failure-safe")
session.sign_in("admin", PW)
real = passvault.lock
def boom(): raise OSError("lock failed")
passvault.lock = boom
e = raises(session.sign_out, OSError)
passvault.lock = real
check("a failing step still raises", e is not None)
check("...but the key closes and the state is signed out", session.state() == "signed_out" and not datakey.is_open() and sqldb.current_key() is None)
passvault.lock()

print("== Settings > Security")
from PySide6.QtWidgets import QApplication
app = QApplication.instance() or QApplication([])
import ui.settings_pages.security as SEC
session.sign_in("admin", PW)
pg = SEC.SecurityPage(); pg.load()
check("no Change master password, no Remember on this computer", not hasattr(pg, "change_master") and not hasattr(pg, "remember"))
check("Lock now is enabled once signed in", pg.lock_now.isEnabled())
pg.lock_now.click()
check("Lock now locks the session", session.state() == "locked")
pg.show_vault()
check("...and is disabled while locked", not pg.lock_now.isEnabled())
session.unlock(PW); session.sign_out()
pg.show_vault()
check("disabled while nobody is signed in, and clicking it does nothing", not pg.lock_now.isEnabled() and (pg._lock() or True) and session.state() == "signed_out")
session.sign_in_recovery(recovery); pg.show_vault()
check("signed in with the recovery key: disabled (there is no password to unlock with)", passvault.is_open() and not pg.lock_now.isEnabled())
session.sign_out()


print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

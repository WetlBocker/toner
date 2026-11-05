# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Roles: the signed rules, the two role keys granted per account, tamper falling back to Tech, the last Admin, and perms' checks.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\roles%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from core import audit, datakey, db, envelope, perms, roles, session, sqldb

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

PW, PW2, PW3, PW4, PW5 = ("correct horse battery 42", "another long password 9", "a third quite long password 5",
                          "engineers have long passwords 7", "old timer from part one 3")
KEYS = [k for k, _ in perms.PERMISSIONS]

def doc():
    return json.loads(datakey.path().read_text(encoding="utf-8"))

def put(d):
    datakey.path().write_text(json.dumps(d), encoding="utf-8")

def as_(name, pw=None):
    session.sign_out()
    if name is None:
        session.sign_in_recovery(recovery)
    else:
        session.sign_in(name, pw)

def tamper_rows():
    return sum(r["action"] == "roles were changed outside Toner" for r in audit.recent(5000))

def part1_record(name, pw, key):
    """An account written the way Part 1 wrote it: the data key alone, no box key, no role."""
    salt, nonce = os.urandom(16), os.urandom(12)
    kdf = datakey.PASSWORD_KDF
    k = Scrypt(salt=salt, length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(pw.encode())
    b = lambda x: base64.b64encode(x).decode()
    return {"kind": "local", "kdf": {"name": "scrypt", "salt": b(salt), **kdf},
            "key": b(nonce + AESGCM(k).encrypt(nonce, key, b"toner-datakey:" + name.encode())), "created": "2026-01-01T00:00:00+00:00"}


# ---------------------------------------------------------------- sign-in not set up
check("no keys file: state off", roles.state() == "off")
check("no keys file: every permission allowed", all(perms.allowed(k) for k in KEYS))
check("no keys file: is_admin", perms.is_admin())
perms.require("push")                                   # doesn't raise

# ---------------------------------------------------------------- a Part 1 file opened by its Admin
recovery = datakey.create("Admin1", PW)
db.init()
d = doc()
d["accounts"]["Old"] = part1_record("Old", PW5, bytes(datakey._key))
for a in d["accounts"].values():
    a.pop("role", None)                                 # Part 1 had no roles
put(d)
part1 = datakey.path().read_text(encoding="utf-8")
check("Part 1 file: unsigned", roles.state() == "unsigned", roles.state())
session.sign_out()
check("signed out: nothing allowed", not perms.allowed("tool:snmp") and not perms.is_admin())

as_("Admin1", PW)
check("Admin's first sign-in: state ok", roles.state() == "ok", roles.state())
d = doc()
check("rules_key is the rules_pub fingerprint",
      db.get_setting("rules_key") == envelope.fingerprint(base64.b64decode(d["rules_pub"])), db.get_setting("rules_key"))
check("the Admin holds both role keys", roles.holds("rules") and roles.holds("backups"))
check("backups_public matches what is held", roles.backups_public() == base64.b64decode(d["backups_pub"]) and roles.backups_private())
check("the recovery key has grants for both", set(d.get("recovery_grants", {})) == {"rules", "backups"}, d.get("recovery_grants"))
check("every Part 1 account is an Admin", roles.role_of("Admin1") == roles.role_of("old") == "Admin")
check("Admin: every permission", all(perms.allowed(k) for k in KEYS) and perms.is_admin())

# ---------------------------------------------------------------- a second Admin, a Tech and an Engineer
datakey.add_local("Admin2", PW2, role="Admin")
datakey.add_local("Tech1", PW3, role="Tech")
datakey.add_local("Eng1", PW4, role="Engineer")
check("adding accounts keeps the rules signed", roles.state() == "ok", roles.state())
roles.sync_grants()
as_("Admin2", PW2)
check("second Admin holds both keys", roles.holds("rules") and roles.holds("backups"))
as_("Tech1", PW3)
check("a Tech holds neither", not roles.holds("rules") and not roles.holds("backups") and roles.backups_private() is None)

# ---------------------------------------------------------------- the checks
check("Tech: push and unmasked off", not perms.allowed("push") and not perms.allowed("unmasked"))
check("Tech: Appearance on, Security off", perms.allowed("settings:Appearance") and not perms.allowed("settings:Security"))
check("Tech: SNMP on", perms.allowed("tool:snmp"))
e = raises(lambda: perms.require("push"), perms.Denied)
check("Tech: require(push) raises Denied with the approved text", e is not None and str(e) == "Your role doesn't allow this. Ask an admin.", e)
check("Tech: not an admin", not perms.is_admin())
check("Tech can't set roles", raises(lambda: roles.set_role("Tech1", "Admin"), datakey.Locked) is not None)
check("Tech can't set permissions", raises(lambda: roles.set_permissions("Tech", {"push": True}), datakey.Locked) is not None)
as_("Eng1", PW4)
check("Engineer: every key allowed", all(perms.allowed(k) for k in KEYS))
check("Engineer: not an admin", not perms.is_admin())
check("Engineer holds the backups key (unmasked on), not the rules key", roles.holds("backups") and not roles.holds("rules"))
session.sign_out()
check("signed out: SNMP not allowed", not perms.allowed("tool:snmp"))
check("signed out: no role keys", not roles.holds("rules") and not roles.holds("backups"))

# ---------------------------------------------------------------- a Part 1 Admin with no box key
as_("Old", PW5)
check("Part 1 Admin: no grants yet, nothing raises", not roles.holds("backups") and not roles.holds("rules"))
check("Part 1 Admin: gained a box key at sign-in", "box_pub" in doc()["accounts"]["Old"])
check("Part 1 Admin: its box key not vouched for yet", doc().get("attested", {}).get("Old") is None)
as_("Admin1", PW)                                       # another Admin's sign-in syncs the grants
check("TOFU: the late box key is vouched for at the next sync", doc().get("attested", {}).get("Old") == doc()["accounts"]["Old"]["box_pub"]
      and roles.state() == "ok")
as_("Old", PW5)
check("Part 1 Admin: holds both after another Admin synced", roles.holds("rules") and roles.holds("backups"))

# ---------------------------------------------------------------- unmasked for Techs
as_("Admin1", PW)
roles.set_permissions("Tech", {"unmasked": True})
row = audit.recent(1)[0]
check("permission change audited", row["action"] == "role permissions changed" and row["detail"] == "Tech: See passwords in config backups on", row)
check("Tech's permissions stored", roles.permissions("Tech")["unmasked"] and not roles.permissions("Tech")["push"])
as_("Tech1", PW3)
check("Tech with unmasked holds the backups key", roles.holds("backups") and not roles.holds("rules") and perms.allowed("unmasked"))
as_("Admin1", PW)
roles.set_permissions("Tech", {"unmasked": False})
check("turning it off drops the Tech's grant", "backups" not in doc()["grants"].get("Tech1", {}), doc()["grants"].get("Tech1"))
as_("Tech1", PW3)
check("the Tech no longer holds it", not roles.holds("backups"))
as_("Admin1", PW)
check("set_permissions refuses Admin", raises(lambda: roles.set_permissions("Admin", {"push": False}), ValueError) is not None)
check("set_permissions refuses an unknown key", raises(lambda: roles.set_permissions("Tech", {"nope": True}), ValueError) is not None)

# ---------------------------------------------------------------- roles and the last Admin
roles.set_role("Admin2", "Engineer")
row = audit.recent(1)[0]
check("role change audited", row["action"] == "role changed" and row["detail"] == "Admin2: Admin to Engineer", row)
check("role_of follows", roles.role_of("admin2") == "Engineer")
check("a demoted Admin loses the rules grant", "rules" not in doc()["grants"].get("Admin2", {}))
roles.set_role("Old", "Tech")
e = raises(lambda: roles.set_role("Admin1", "Tech"), ValueError)
check("demoting the last Admin refused", e is not None and str(e) == "Toner needs at least one Admin.", e)
e = raises(lambda: datakey.remove("Admin1"), ValueError)
check("removing the last Admin refused", e is not None and str(e) == "Toner needs at least one Admin.", e)
check("still an Admin", roles.role_of("Admin1") == "Admin" and "Admin1" in doc()["accounts"])
roles.set_role("Admin2", "Admin")
roles.set_role("Admin1", "Engineer")                    # your own, while another Admin remains
check("own demotion allowed while another Admin remains", roles.role_of("Admin1") == "Engineer")
check("own demotion lets go of the rules key", not roles.holds("rules"))
as_("Admin2", PW2)
roles.set_role("Admin1", "Admin")
datakey.remove("Old")
check("removing an account drops its grants and keeps the rules signed",
      "Old" not in doc().get("grants", {}) and roles.state() == "ok", roles.state())

# ---------------------------------------------------------------- a new password re-wraps the grants
datakey.set_password("Admin1", PW + "x")
as_("Admin1", PW + "x")
check("after a password reset the Admin still holds both", roles.holds("rules") and roles.holds("backups"))
datakey.set_password("Admin1", PW)                      # your own password
as_("Admin1", PW)
check("after changing your own password you still hold both", roles.holds("rules") and roles.holds("backups"))
recovery = datakey.new_recovery()
as_(None)
check("a new recovery key holds both", roles.holds("rules") and roles.holds("backups"))

# ---------------------------------------------------------------- tampering
session.sign_out()
good = datakey.path().read_text(encoding="utf-8")
def once(label, change):
    as_("Admin1", PW)
    before = tamper_rows()
    session.sign_out()
    d = doc()
    change(d)
    put(d)
    as_("Admin1", PW)
    for _ in range(3):
        roles.state(); perms.allowed("push"); roles._cache = None
    check(f"tamper {label}: state tampered", roles.state() == "tampered", roles.state())
    check(f"tamper {label}: an Admin gets Tech", roles.role_of("Admin1") == "Tech" and not perms.is_admin())
    check(f"tamper {label}: Tech's permissions", not perms.allowed("push") and perms.allowed("tool:snmp")
          and roles.permissions("Engineer") == perms.DEFAULTS["Tech"])
    check(f"tamper {label}: one audit row", tamper_rows() - before == 1, tamper_rows() - before)
    session.sign_out()
    datakey.path().write_text(good, encoding="utf-8")

once("(a) a role edited by hand", lambda d: d["accounts"]["Tech1"].__setitem__("role", "Admin"))
once("(b) rules_sig deleted", lambda d: d.pop("rules_sig"))
once("(c) the Part 1 file put back", lambda d: (d.clear(), d.update(json.loads(part1))))
once("(d) backups_pub replaced", lambda d: d.__setitem__("backups_pub", base64.b64encode(envelope.new_box_key()[1]).decode()))
as_("Admin1", PW)
check("the good file is ok again", roles.state() == "ok" and roles.role_of("Admin1") == "Admin")
session.sign_out()

# ---------------------------------------------------------------- the repair
d = doc()
d["accounts"]["Tech1"]["role"] = "Engineer"
put(d)
as_("Admin1", PW)
check("tampered: an Admin can't save roles", raises(lambda: roles.set_permissions("Tech", {}), perms.Denied) is not None)
old_key = db.get_setting("rules_key")
as_(None)
check("recovery sign-in on a tampered file: still tampered", roles.state() == "tampered")
check("the recovery key is still an Admin", roles.role_of(None) == "Admin")
roles.set_permissions("Tech", {})
check("repair: state ok", roles.state() == "ok", roles.state())
check("repair: a new rules key", db.get_setting("rules_key") not in ("", old_key))
check("repair: signs what the file shows", roles.role_of("Tech1") == "Engineer" and roles.role_of("Admin1") == "Admin")
as_("Admin1", PW)
check("after the repair an Admin holds the new rules key", roles.state() == "ok" and roles.holds("rules") and roles.holds("backups"))

# ---------------------------------------------------------------- box keys: only vouched-for ones get grants
def b64(b):
    return base64.b64encode(b).decode()

def opened_by(private):
    """True when any wrap in the file opens with this private box key."""
    d = doc()
    wraps = [(k, n, w) for n, g in d.get("grants", {}).items() for k, w in g.items()]
    wraps += [(k, None, w) for k, w in d.get("recovery_grants", {}).items()]
    for kind, name, w in wraps:
        try:
            envelope.unwrap(private, w, b"toner-role-key:" + kind.encode() + b":" + (name or "").encode())
            return True
        except Exception:
            pass
    return False

roles.set_role("Tech1", "Tech")
as_("Tech1", PW3)
before = datakey.path().read_bytes()
check("a Tech can't reset an Admin's password", raises(lambda: datakey.set_password("Admin2", "a brand new admin password 7"),
                                                       perms.Denied) is not None and datakey.path().read_bytes() == before)
check("a Tech can't replace the recovery key", raises(datakey.new_recovery, perms.Denied) is not None
      and datakey.path().read_bytes() == before)
session.sign_out()

evil, evil_pub = envelope.new_box_key()
d = doc(); d["accounts"]["Admin2"]["box_pub"] = b64(evil_pub); d["grants"].pop("Admin2", None); put(d)
as_("Admin1", PW)
check("an Admin's box_pub swapped by hand: no grant wrapped to it", roles.state() == "ok" and "Admin2" not in doc()["grants"]
      and not opened_by(evil), doc()["grants"].keys())
as_("Admin2", PW2)
check("...and the real Admin2 holds nothing (its box key isn't the record's)", not roles.holds("rules") and not roles.holds("backups"))
session.sign_out()
swapped = datakey.path().read_text(encoding="utf-8")
evil2, evil2_pub = envelope.new_box_key()
d = doc(); d["recovery"]["box_pub"] = b64(evil2_pub); d["recovery_grants"] = {}; put(d)
as_("Admin1", PW)
check("the recovery box_pub swapped by hand: no grant wrapped to it", doc()["recovery_grants"] == {} and not opened_by(evil2))
session.sign_out()
d = doc(); d.pop("rules_sig"); put(d)
as_(None)
check("a recovery sign-in whose box key isn't the record's holds nothing", not roles.holds("rules") and not roles.holds("backups"))
check("...and can't run the repair", raises(lambda: roles.set_permissions("Tech", {}), perms.Denied) is not None)
session.sign_out()
datakey.path().write_text(swapped, encoding="utf-8")
d = doc(); d.pop("rules_sig"); put(d)
as_(None)
roles.set_permissions("Tech", {})
check("a repair with Admin2's box_pub still swapped: ok, and still no grant to it",
      roles.state() == "ok" and "Admin2" not in doc()["grants"] and not opened_by(evil), roles.state())
as_("Admin1", PW)
datakey.set_password("Admin2", PW2 + "y")
as_("Admin2", PW2 + "y")
check("an Admin's password reset vouches for the new box key", roles.holds("rules") and roles.holds("backups")
      and doc().get("attested", {}).get("Admin2") == doc()["accounts"]["Admin2"]["box_pub"])
datakey.set_password("Admin2", PW2)

# ---------------------------------------------------------------- the repair after (d) keeps the backups key
as_("Admin1", PW)
orig_priv, orig_pub = roles.backups_private(), roles.backups_public()
as_("Eng1", PW4)
check("the Engineer holds the backups key", roles.backups_private() == orig_priv)
session.sign_out()
d = doc(); d["backups_pub"] = b64(envelope.new_box_key()[1]); put(d)
as_(None)
check("(d): the recovery key still holds the real backups key", roles.backups_private() == orig_priv)
roles.set_permissions("Tech", {})
check("repair after (d): ok, the original backups key back", roles.state() == "ok" and roles.backups_public() == orig_pub)
as_("Eng1", PW4)
check("repair after (d): the Engineer still holds the original backups key", roles.backups_private() == orig_priv)

# ---------------------------------------------------------------- signing out: the key closes before the state says so
as_("Tech1", PW3)
datakey.close()                                         # the moment inside sign_out
check("key closed, state not yet signed out: nothing allowed", session.state() == "open" and not perms.allowed("push")
      and not perms.allowed("tool:snmp") and not perms.is_admin())
session.sign_out()

# ---------------------------------------------------------------- database errors
as_("Admin1", PW)
rows = tamper_rows()
real_get = db.get_setting
def locked(key):
    if key == "rules_key":
        raise sqldb.sqlite3.OperationalError("database is locked")
    return real_get(key)
db.get_setting = locked
roles._invalidate()
check("a locked database is an error, not a tampered file", raises(roles.state, sqldb.sqlite3.OperationalError) is not None)
db.get_setting = real_get
check("...and no audit row", tamper_rows() == rows and roles.state() == "ok")
session.sign_out()
d = doc(); d.pop("rules_sig"); put(d)
real_log = audit.log
audit.log = lambda *a, **k: False                       # the audit write fails
as_("Admin1", PW)
audit.log = real_log
rows = tamper_rows()
roles._cache = None
check("a tamper row that didn't get written is written next time", roles.state() == "tampered" and tamper_rows() == rows + 1)
roles._cache = None
check("...once", roles.state() == "tampered" and tamper_rows() == rows + 1)
session.sign_out()
as_(None)
roles.set_permissions("Tech", {})                       # put it right for what follows

# ---------------------------------------------------------------- session wiring
orig = roles.unlock
roles.unlock = lambda: 1 / 0
session.sign_out()
check("a failing unlock doesn't leave a half-open session",
      raises(lambda: session.sign_in("Admin1", PW), ZeroDivisionError) is not None and session.state() == "signed_out" and not datakey.is_open())
roles.unlock = orig

# ---------------------------------------------------------------- no secrets in the audit
as_("Admin1", PW)
d = doc()
secrets = [d["rules_pub"], d["rules_sig"], d["backups_pub"], d["recovery"]["box_pub"]]
secrets += [a["box_pub"] for a in d["accounts"].values() if "box_pub" in a]
secrets += [w for g in d["grants"].values() for w in g.values()] + list(d["recovery_grants"].values())
details = [r["detail"] or "" for r in audit.recent(5000)]
check("no audit detail holds a key, a wrap or a signature",
      not any(s in x or s[:16] in x for s in secrets for x in details) and not any("wrap" in x or "sig" in x for x in details))
session.sign_out()

# ---------------------------------------------------------------- the keys file deleted while signed in
as_("Admin2", PW2)
gone = datakey.path().with_name("moved.keys")
os.replace(datakey.path(), gone)
roles._cache = None
check("keys file deleted while signed in: not sign-in off", roles.state() == "tampered" and not perms.allowed("push")
      and not perms.is_admin(), roles.state())
os.replace(gone, datakey.path())
session.sign_out()

# ---------------------------------------------------------------- a first start: signed in before the database is set up
os.environ["NETCHECK_DB"] = SP + (r"\first%d.db").replace("\\", os.sep) % int(time.time())
datakey.create("First", PW); datakey.close()
session.sign_in("First", PW)
check("database not ready: still unsigned, nothing raises", roles.state() == "unsigned" and not roles.holds("rules"), roles.state())
db.init()
check("once it is ready the Admin's role keys are made", roles.state() == "ok" and roles.holds("rules") and roles.holds("backups"),
      roles.state())
session.sign_out()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

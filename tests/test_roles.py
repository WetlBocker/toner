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

def signed_ok():
    """The database's copy of what was last signed is what the file's signature covers."""
    return db.get_setting("rules_signed") == roles._signed(doc()).decode("utf-8")

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
check("rules_signed written at the upgrade", signed_ok())
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
check("rules_signed written when an account is added", signed_ok())
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
check("rules_signed written by the sync's re-sign", signed_ok())
check("TOFU: the late box key is vouched for at the next sync", doc().get("attested", {}).get("Old") == doc()["accounts"]["Old"]["box_pub"]
      and roles.state() == "ok")
as_("Old", PW5)
check("Part 1 Admin: holds both after another Admin synced", roles.holds("rules") and roles.holds("backups"))

# ---------------------------------------------------------------- unmasked for Techs
as_("Admin1", PW)
roles.set_permissions("Tech", {"unmasked": True})
check("rules_signed written by set_permissions", signed_ok())
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
check("rules_signed written by set_role", signed_ok())
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
check("stored_permissions: the stored values, not the Tech fallback while tampered", roles.stored_permissions("Engineer") == perms.DEFAULTS["Engineer"] and roles.permissions("Engineer") == perms.DEFAULTS["Tech"])
old_key = db.get_setting("rules_key")
as_(None)
check("recovery sign-in on a tampered file: still tampered", roles.state() == "tampered")
check("the recovery key is still an Admin", roles.role_of(None) == "Admin")
roles.set_permissions("Tech", {})
check("repair: state ok", roles.state() == "ok", roles.state())
check("rules_signed written by the repair", signed_ok())
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
check("rules_signed written by a password reset", signed_ok())

# a repair takes the box keys from the database's copy of what was last signed, not from the tampered file
session.sign_out()
evil3, evil3_pub = envelope.new_box_key()
d = doc(); d["accounts"]["Admin2"]["box_pub"] = d["attested"]["Admin2"] = b64(evil3_pub); d["grants"].pop("Admin2", None); put(d)
as_(None)
check("Admin2's box key and its attested value swapped: tampered", roles.state() == "tampered")
roles.set_permissions("Tech", {})
check("repair: the swapped key isn't attested and gets no grant", roles.state() == "ok" and doc()["attested"]["Admin2"] != b64(evil3_pub)
      and "Admin2" not in doc()["grants"] and not opened_by(evil3) and signed_ok())
as_("Admin1", PW)
datakey.set_password("Admin2", PW2)                     # an Admin's reset puts Admin2 right
session.sign_out()
real = doc()["recovery_attested"]
evil4, evil4_pub = envelope.new_box_key()
d = doc(); d["recovery_attested"] = b64(evil4_pub); d["recovery_grants"] = {}; put(d)
as_(None)
roles.set_permissions("Tech", {})
check("repair: the recovery key's attested value comes from the database", roles.state() == "ok"
      and doc()["recovery_attested"] == real and not opened_by(evil4))

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
session.sign_out()
d = doc(); d["backups_pub"] = b64(envelope.new_box_key()[1]); d["accounts"]["Tech1"]["role"] = "Engineer"; put(d)
as_(None)
check("backups_pub swapped and a role edited: the recovery key can't vouch for its backups key", roles.backups_private() is None)
roles.set_permissions("Tech", {})
check("repair: backups_pub comes back from the database", roles.state() == "ok" and roles.backups_public() == orig_pub)
as_("Eng1", PW4)
check("...and the Engineer still holds the original backups key", roles.backups_private() == orig_priv)
as_("Admin1", PW)
roles.set_role("Tech1", "Tech")
db.set_setting("rules_signed", "")                      # nothing kept (a copy from before this setting): the repair still works
session.sign_out()
d = doc(); d.pop("rules_sig"); put(d)
as_(None)
roles.set_permissions("Tech", {})
check("repair with no rules_signed: falls back, ok", roles.state() == "ok" and roles.backups_public() == orig_pub and signed_ok())

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

# ---------------------------------------------------------------- a Part 1 recovery key resets the only Admin's password
def seal1(secret, payload, aad, kdf):
    """A seal written the way Part 1 wrote it: the data key alone, no box key."""
    salt, nonce = os.urandom(16), os.urandom(12)
    k = Scrypt(salt=salt, length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(secret.encode())
    return {"kdf": {"name": "scrypt", "salt": b64(salt), **kdf}, "key": b64(nonce + AESGCM(k).encrypt(nonce, payload, aad))}

os.environ["NETCHECK_DB"] = SP + (r"\part1rec%d.db").replace("\\", os.sep) % int(time.time())
datakey.create("Solo", PW)
db.init()
code = "B" * 32
d = doc()
d["accounts"] = {"Solo": part1_record("Solo", PW, bytes(datakey._key))}
d["recovery"] = {**seal1(code, bytes(datakey._key), datakey.RECOVERY_AAD, datakey.RECOVERY_KDF), "fails": 0, "until": 0}
put(d)
session.sign_out()
check("hand-built Part 1 file: no box keys, no roles", all("box_pub" not in r and "role" not in r for r in (doc()["accounts"]["Solo"], doc()["recovery"])))
session.sign_in("Solo", PW)
check("Part 1 file with a Part 1 recovery key: upgraded by its Admin", roles.state() == "ok" and roles.holds("rules") and roles.holds("backups")
      and doc()["recovery_grants"] == {} and doc()["recovery_attested"] is None)
datakey.add_local("Tek", PW3, role="Tech")
session.sign_out()
session.sign_in_recovery(code)
check("the Part 1 recovery key's first sign-in: no grants yet", roles.state() == "ok" and not roles.holds("rules"))
e = raises(lambda: datakey.set_password("Solo", PW2), Exception)
check("...but it can reset the only Admin's password", e is None and roles.state() == "ok" and roles.holds("rules"), e)
check("...vouching for the new box key and its own", doc()["attested"]["Solo"] == doc()["accounts"]["Solo"]["box_pub"]
      and doc()["recovery_attested"] == doc()["recovery"]["box_pub"] and signed_ok())
session.sign_out()
session.sign_in("Solo", PW2)
check("the reset Admin holds the rules key and the backups key", roles.holds("rules") and roles.holds("backups"))
session.sign_out()
session.sign_in_recovery(code)
check("the recovery key holds the rules key now", roles.state() == "ok" and roles.holds("rules") and roles.holds("backups"))
session.sign_out()
session.sign_in("Tek", PW3)
check("a Tech still can't reset an Admin", raises(lambda: datakey.set_password("Solo", PW4), perms.Denied) is not None)
session.sign_out()

# a backups key planted for the recovery key is refused, also where the database keeps no copy of the rules
session.sign_in("Solo", PW2)
db.set_setting("rules_signed", "")
session.sign_out()
planted, planted_pub = envelope.new_box_key()
d = doc()
d["backups_pub"] = b64(planted_pub)
d["recovery_grants"]["backups"] = envelope.wrap(base64.b64decode(d["recovery"]["box_pub"]), planted, b"toner-role-key:backups:")
put(d)
session.sign_in_recovery(code)
check("planted backups key: tampered, and not taken", roles.state() == "tampered" and roles.backups_private() != planted)
roles.set_permissions("Tech", {})
check("...nor held by the repair's own sign-in (no copy kept)", roles.state() == "ok" and roles.backups_private() != planted)
session.sign_out()

# ---------------------------------------------------------------- a keys file put back from before a demotion
def fresh(label):
    global recovery
    os.environ["NETCHECK_DB"] = SP + (r"\%s%d.db" % (label, int(time.time()))).replace("\\", os.sep)
    recovery = datakey.create("Admin1", PW); db.init(); datakey.close()
    session.sign_in("Admin1", PW)

fresh("rollback")
datakey.add_local("Bob", PW3, role="Admin")
roles.sync_grants()
as_("Bob", PW3)
check("rollback: Bob as an Admin holds both role keys", roles.holds("rules") and roles.holds("backups"))
saved = datakey.path().read_bytes()                     # Bob keeps a copy of netcheck.keys
as_("Admin1", PW)
roles.set_role("Bob", "Tech")
demoted = datakey.path().read_bytes()
rows = tamper_rows()
session.sign_out()
datakey.path().write_bytes(saved)                       # and puts it back: no crypto, no database
as_("Bob", PW3)
check("rollback: the older, validly signed file reads tampered", roles.state() == "tampered", roles.state())
check("rollback: Bob is a Tech and holds nothing", roles.role_of("Bob") == "Tech" and not perms.is_admin()
      and not roles.holds("rules") and not roles.holds("backups"))
check("rollback: one audit row", tamper_rows() - rows == 1, tamper_rows() - rows)
session.sign_out()
datakey.path().write_bytes(demoted)

# a write that fails never becomes a false tamper
as_("Admin1", PW)
key, signed = roles._held["rules"], db.get_setting("rules_signed")
real_replace = os.replace
def failing_replace(*a, **k):
    raise OSError("disk full")
os.replace = failing_replace
try:
    e = raises(lambda: roles.set_role("Bob", "Engineer"), OSError)
finally:
    os.replace = real_replace
roles._invalidate()
check("a failed write: the error is raised, the file and rules_signed untouched", e is not None and datakey.path().read_bytes() == demoted
      and db.get_setting("rules_signed") == signed)
check("...state ok, Bob still a Tech, the same rules key held", roles.state() == "ok" and roles.role_of("Bob") == "Tech"
      and roles._held.get("rules") is key, roles.state())
session.sign_out()
d = doc(); d["accounts"]["Bob"]["role"] = "Admin"; put(d)
as_(None)
key, signed = roles._held.get("rules"), db.get_setting("rules_signed")
os.replace = failing_replace
try:
    e = raises(lambda: roles.set_permissions("Tech", {}), OSError)
finally:
    os.replace = real_replace
check("a repair whose write fails: no new rules key held, rules_signed untouched",
      e is not None and roles._held.get("rules") is key and db.get_setting("rules_signed") == signed)
roles.set_permissions("Tech", {})
check("...and the repair works once the disk does", roles.state() == "ok" and signed_ok() and roles.role_of("Bob") == "Admin")
session.sign_out()

# ---------------------------------------------------------------- two Admin sign-ins in a row: the second writes nothing
as_("Admin1", PW)
mtime = datakey.path().stat().st_mtime_ns
writes, real_set = [], db.set_setting
db.set_setting = lambda key, value: (writes.append(key), real_set(key, value))[1]
try:
    as_("Admin1", PW)
finally:
    db.set_setting = real_set
check("a second Admin sign-in with nothing changed writes neither the keys file nor rules_signed",
      datakey.path().stat().st_mtime_ns == mtime and "rules_signed" not in writes and roles.state() == "ok", writes)
session.sign_out()

# ---------------------------------------------------------------- an account planted by hand gets no keys from the repair
as_("Admin1", PW)
d = doc()
d["accounts"]["Ghost"] = datakey._account("Ghost", PW4, bytes(datakey._key), role="Admin")[0]
session.sign_out()
put(d)
as_(None)
check("a planted account: tampered", roles.state() == "tampered")
roles.set_permissions("Tech", {})
check("the repair attests nothing for it", roles.state() == "ok" and doc()["attested"]["Ghost"] == "" and "Ghost" not in doc()["grants"],
      doc()["attested"].get("Ghost"))
as_("Admin1", PW)                                       # an Admin's sync doesn't vouch for it either
as_("Ghost", PW4)
check("...and Ghost holds nothing", not roles.holds("rules") and not roles.holds("backups"))
session.sign_out()

# ---------------------------------------------------------------- the Global database deleted and the file reset to Part 1
fresh("dbswap")
datakey.add_local("Tech1", PW3, role="Tech")
from core import backup, orgs
acme = orgs.create("Acme", "ACME")
with db.within(acme):
    backup.store("a-sw", "hostname a-sw\ninterface Gi0/1\n", mask=True)
session.sign_out()
db.release()
p = db.base_path()
for suf in ("", "-wal", "-shm"):
    q = p.with_name(p.name + suf)
    if q.exists():
        os.replace(q, str(q) + ".aside")
d = doc()
for k in roles._PART2:
    d.pop(k, None)
d["accounts"]["Tech1"]["role"] = "Admin"
put(d)
session.sign_in("Tech1", PW3)
db.init()                                               # the window does this at start
roles._invalidate()
check("db swap: an organization file that kept backups trips the wire", roles.state() == "tampered" and not perms.is_admin()
      and not roles.holds("rules") and not roles.holds("backups") and not perms.allowed("push"), roles.state())
session.sign_out()

# ---------------------------------------------------------------- a recovery key planted by a Tech is not the root of trust
fresh("recswap")
datakey.add_local("Tech1", PW3, role="Tech")
as_("Admin1", PW)                                       # (the Admin's sync)
rk = db.get_setting("rules_key")
as_("Tech1", PW3)                                       # the Tech opens the data key with only their password
shown, rec, _ = datakey._new_recovery(bytes(datakey._key))
d = doc(); d["recovery"] = rec; put(d)
session.sign_out()
session.sign_in_recovery(shown)
check("planted recovery seal: the rules still verify, it holds nothing", roles.state() == "ok" and not roles.holds("rules"))
check("...set_role refused", raises(lambda: roles.set_role("Tech1", "Admin"), datakey.Locked) is not None and roles.role_of("Tech1") == "Tech")
check("...a password reset refused", raises(lambda: datakey.set_password("Admin1", PW4), perms.Denied) is not None)
check("...no re-key, no grants", db.get_setting("rules_key") == rk and not roles.holds("rules") and not roles.holds("backups"))
as_("Admin1", PW)
as_("Tech1", PW3)
check("after the real Admin signs in, the Tech is still a Tech holding nothing", roles.role_of("Tech1") == "Tech"
      and not roles.holds("backups") and not roles.holds("rules"))
session.sign_out()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

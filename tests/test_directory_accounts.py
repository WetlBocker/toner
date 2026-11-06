# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Directory accounts in netcheck.keys: a started account, an Admin's (or the recovery key's) approval sealing the data key into
# the PIN slot, the PIN opening it, role keys following the approved role, the signed directories, and removing a directory.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\diracct%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import copy, json
from core import audit, datakey, db, directory, osstore, perms, pinslot, roles, session

PEPPERS = {}                                            # the protected store, as a dict on every platform
osstore.available = lambda: True
osstore.put = PEPPERS.__setitem__
osstore.get = PEPPERS.get
osstore.delete = lambda n: PEPPERS.pop(n, None)

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

PW, PW2 = "correct horse battery 42", "engineers have long passwords 7"
PIN, PIN2 = "a long pin 4321", "another long pin 99"
ADMINS, ENGINEERS, TECHS = "CN=Toner Admins,DC=acme,DC=com", "CN=Toner Engineers,DC=acme,DC=com", "CN=Toner Techs,DC=acme,DC=com"
ACME = {"id": "d1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
        "base_dn": "DC=acme,DC=com", "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc,DC=acme,DC=com",
        "groups": {"Admin": [ADMINS], "Engineer": [ENGINEERS], "Tech": [TECHS]}, "duo": {"on": False, "host": "", "ikey": ""}}
BOB = directory.User("6f1c2a4e-0000-4000-8000-000000000001", "bob@acme.com", "Bob Jones", (TECHS,), True)
CAROL = directory.User("6f1c2a4e-0000-4000-8000-000000000002", "carol@acme.com", "Carol Hill", (ENGINEERS,), True)

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

def pin_in(name, pin):
    """A directory account's sign-in (Task 5 adds session.sign_in_pin; this is the same steps)."""
    session.sign_out()
    session._opened(lambda: datakey.open_with_pin(name, pin), "signed in", name)

def signed_ok():
    return db.get_setting("rules_signed") == roles._signed(doc()).decode("utf-8")

def rows(action):
    return [r for r in audit.recent(5000) if r["action"] == action]


# ---------------------------------------------------------------- set up: an Admin, an Engineer, a directory
recovery = datakey.create("Admin1", PW)
db.init()
datakey.close()
as_("Admin1", PW)
datakey.add_local("Eng1", PW2, role="Engineer")
data_key = bytes(datakey._key)
check("a local file reads ok before any directory", roles.state() == "ok", roles.state())
as_("Eng1", PW2)
check("an Engineer can't add a directory", raises(lambda: roles.set_directories([ACME]), (datakey.Locked, perms.Denied)) is not None
      and "directories" not in doc())
as_("Admin1", PW)
roles.set_directories([ACME])
check("directory added: stored, signed, audited", doc()["directories"] == [ACME] and roles.state() == "ok" and signed_ok()
      and rows("directory added")[0]["detail"] == "ACME")
check("plain LDAP is refused", raises(lambda: roles.set_directories([{**ACME, "security": "none"}]), ValueError) is not None)
check("an unknown field (a secret) is refused", raises(lambda: roles.set_directories([{**ACME, "password": "x"}]), ValueError) is not None
      and raises(lambda: roles.set_directories([{**ACME, "duo": {**ACME["duo"], "skey": "x"}}]), ValueError) is not None)
session.sign_out()

# ---------------------------------------------------------------- a first sign-in starts an unapproved account (key closed)
bob_slot = pinslot.new("pin", BOB.guid, PIN)
datakey.start_directory_account(BOB, "d1", bob_slot)
rec = datakey.directory_account("BOB@acme.com")
check("started: an unapproved directory record", rec is not None and rec["kind"] == "directory" and rec["directory"] == "d1"
      and rec["guid"] == BOB.guid and rec["display"] == "Bob Jones" and rec["sealed"] is None and rec["approved_role"] is None
      and rec["groups_role"] == "Tech" and rec["slot_kind"] == "pin" and rec["slot"] == bob_slot.rec and rec["box_pub"], rec)
check("needs_approval: first", roles.needs_approval("bob@acme.com") == "first")
check("directory_account of a local name: None", datakey.directory_account("Admin1") is None)
check("a start under a local account's name is refused",
      raises(lambda: datakey.start_directory_account(directory.User("g9", "admin1", "x", (TECHS,), True), "d1",
                                                      pinslot.new("pin", "g9", PIN)), ValueError) is not None)
check("a start under another guid's name is refused",
      raises(lambda: datakey.start_directory_account(directory.User("g8", "bob@acme.com", "x", (TECHS,), True), "d1",
                                                      pinslot.new("pin", "g8", PIN)), ValueError) is not None)
check("a start for an unknown directory is refused",
      raises(lambda: datakey.start_directory_account(BOB, "nope", bob_slot), ValueError) is not None)
check("a start with a slot made for another id is refused",
      raises(lambda: datakey.start_directory_account(BOB, "d1", pinslot.new("pin", "other", PIN)), ValueError) is not None)
datakey.start_directory_account(BOB, "d1", bob_slot)  # the same person starting again replaces the unapproved record
check("the same guid may start again while unapproved", datakey.directory_account("bob@acme.com")["sealed"] is None)
check("the PIN can't open an unapproved account", raises(lambda: datakey.open_with_pin("bob@acme.com", PIN), pinslot.WrongPin) is not None)

# the password calls treat a directory account as a wrong password, never a KeyError
check("check_password on a directory account: False", datakey.check_password("bob@acme.com", PIN) is False)
check("open_with_password on a directory account: WrongPassword",
      raises(lambda: datakey.open_with_password("bob@acme.com", PIN), datakey.WrongPassword) is not None)
datakey.check_password("Admin1", PW)                    # (clears the shared count)
check("accounts() lists it", any(a["name"] == "bob@acme.com" and a["kind"] == "directory" and a["role"] == "Tech"
                                 for a in datakey.accounts()), datakey.accounts())

# ---------------------------------------------------------------- an Engineer can't approve; an Admin can
as_("Eng1", PW2)
before = datakey.path().read_bytes()
check("an Engineer can't approve: Denied", raises(lambda: roles.approve("bob@acme.com", bob_slot), perms.Denied) is not None
      and datakey.path().read_bytes() == before)
check("an unapproved account leaves the rules ok", roles.state() == "ok", roles.state())
check("set_password on a directory account fails as a wrong password",
      raises(lambda: datakey.set_password("bob@acme.com", "a brand new password 12"), datakey.WrongPassword) is not None)
as_("Admin1", PW)
check("approving with another slot is refused", raises(lambda: roles.approve("bob@acme.com", pinslot.new("pin", BOB.guid, PIN2)),
                                                        ValueError) is not None)
roles.approve("bob@acme.com", bob_slot)
r = rows("sign-in approved")
check("approved: audited naming both", len(r) == 1 and r[0]["detail"] == "bob@acme.com, approved by Admin1", r)
rec = datakey.directory_account("bob@acme.com")
check("approved: sealed, approved role Tech, box key attested", rec["sealed"] and rec["approved_role"] == "Tech"
      and doc()["attested"]["bob@acme.com"] == rec["box_pub"] and roles.state() == "ok" and signed_ok())
check("needs_approval: none", roles.needs_approval("bob@acme.com") is None)
check("an approved record is never replaced by a start",
      raises(lambda: datakey.start_directory_account(BOB, "d1", bob_slot), ValueError) is not None)
session.sign_out()

check("check_pin: right and wrong", datakey.check_pin("bob@acme.com", PIN) is True and datakey.check_pin("bob@acme.com", PIN2) is False)
fails = datakey.open_with_pin("bob@acme.com", PIN)
check("open_with_pin opens the same data key and returns the earlier fails", bytes(datakey._key) == data_key and fails == 1, fails)
datakey.close()
pin_in("bob@acme.com", PIN)
check("signed in with the PIN: a Tech, holding no role keys", roles.role_of("bob@acme.com") == "Tech" and not perms.is_admin()
      and not roles.holds("backups") and not roles.holds("rules") and roles.state() == "ok")
session.sign_out()

# ---------------------------------------------------------------- the groups move Bob to Engineer: approve again for the backups key
datakey.set_groups_role("bob@acme.com", "Engineer")
check("Tech to Engineer: needs_approval changed", roles.needs_approval("bob@acme.com") == "changed")
pin_in("bob@acme.com", PIN)
check("...permissions follow the groups, keys the approval", roles.role_of("bob@acme.com") == "Engineer" and perms.allowed("push")
      and not roles.holds("backups") and roles.state() == "ok")
as_("Admin1", PW)
check("an Admin's sync doesn't grant the backups key before approval", "backups" not in doc()["grants"].get("bob@acme.com", {}))
roles.approve("bob@acme.com")
check("approved again: approved role Engineer", datakey.directory_account("bob@acme.com")["approved_role"] == "Engineer"
      and roles.needs_approval("bob@acme.com") is None and len(rows("sign-in approved")) == 2)
pin_in("bob@acme.com", PIN)
check("...and Bob holds the backups key", roles.holds("backups") and not roles.holds("rules"))
session.sign_out()

# ---------------------------------------------------------------- the recovery key can approve
carol_slot = pinslot.new("store", CAROL.guid, PIN2)
datakey.start_directory_account(CAROL, "d1", carol_slot)
as_(None)
roles.approve("carol@acme.com", carol_slot)
check("the recovery key approves", datakey.directory_account("carol@acme.com")["approved_role"] == "Engineer" and roles.state() == "ok"
      and rows("sign-in approved")[0]["detail"].startswith("carol@acme.com, approved by "))
pin_in("carol@acme.com", PIN2)
check("Carol opens with her PIN and holds the backups key", bytes(datakey._key) == data_key and roles.holds("backups"))
session.sign_out()

# ---------------------------------------------------------------- groups_role edited to Admin: permissions only, never keys
d = doc(); d["accounts"]["bob@acme.com"]["groups_role"] = "Admin"; put(d)
pin_in("bob@acme.com", PIN)
check("groups_role edited to Admin: is_admin this session, rules still ok", perms.is_admin() and roles.state() == "ok")
check("...but no rules key", not roles.holds("rules"))
as_("Admin1", PW)
check("...and an Admin's sync wraps no rules grant to it", "rules" not in doc()["grants"].get("bob@acme.com", {}))
check("...the next approval would be 'changed'", roles.needs_approval("bob@acme.com") == "changed")
session.sign_out()
datakey.set_groups_role("bob@acme.com", "Engineer")
check("set_groups_role refuses an unknown role", raises(lambda: datakey.set_groups_role("bob@acme.com", "Root"), ValueError) is not None)

# ---------------------------------------------------------------- online_at is capped at now
datakey.set_online("bob@acme.com", time.time() + 3600)
check("set_online an hour ahead is stored as now", datakey.directory_account("bob@acme.com")["online_at"] <= time.time())
d = doc(); d["accounts"]["bob@acme.com"]["online_at"] = time.time() + 3600; put(d)
check("online_at edited an hour ahead is read as now", datakey.directory_account("bob@acme.com")["online_at"] <= time.time())
as_("Admin1", PW)
check("online_at and groups_role aren't signed: still ok", roles.state() == "ok")
session.sign_out()

# ---------------------------------------------------------------- hand-edits of signed fields read "tampered"
good = datakey.path().read_text(encoding="utf-8")
def tampered(label, change):
    d = doc(); change(d); put(d)
    as_("Admin1", PW)
    check(f"tamper {label}: tampered", roles.state() == "tampered", roles.state())
    session.sign_out()
    datakey.path().write_text(good, encoding="utf-8")

tampered("a directory's server", lambda d: d["directories"][0].__setitem__("servers", ["evil.example.com"]))
tampered("the group map", lambda d: d["directories"][0]["groups"]["Admin"].append(TECHS))
tampered("the Duo host", lambda d: d["directories"][0]["duo"].__setitem__("host", "api-evil.duosecurity.com"))
tampered("an approved role", lambda d: d["accounts"]["bob@acme.com"].__setitem__("approved_role", "Admin"))
tampered("an approval removed", lambda d: d["accounts"]["bob@acme.com"].__setitem__("approved_role", None))
tampered("the directories removed", lambda d: d.pop("directories"))
as_("Admin1", PW)
check("the good file reads ok again", roles.state() == "ok")

real_rk = roles._rules_key
roles._rules_key = lambda: None
check("a directory account in an unsigned (Part 1) file reads tampered",
      roles._state_of({"accounts": {"x": {"kind": "directory"}}}) == "tampered"
      and roles._state_of({"accounts": {"x": {"kind": "local"}}}) == "unsigned")
roles._rules_key = real_rk

# ---------------------------------------------------------------- removing an account, changing and removing a directory
DAVE = directory.User("6f1c2a4e-0000-4000-8000-000000000003", "dave@acme.com", "Dave", (TECHS,), True)
datakey.start_directory_account(DAVE, "d1", pinslot.new("store", DAVE.guid, PIN))
check("dave's pepper is here", osstore.get("pin:" + DAVE.guid) is not None)
datakey.remove("dave@acme.com")
check("removing a directory account removes its slot", datakey.directory_account("dave@acme.com") is None
      and osstore.get("pin:" + DAVE.guid) is None and roles.state() == "ok")
roles.set_directories([{**ACME, "servers": ["dc1.acme.com", "dc2.acme.com"]}])
check("directory changed: audited, signed", rows("directory changed")[0]["detail"] == "ACME" and roles.state() == "ok" and signed_ok())
check("the store slot's pepper is here", osstore.get("pin:" + CAROL.guid) is not None)
roles.set_directories([])
check("directory removed: its accounts are gone, audited, signed", "bob@acme.com" not in doc()["accounts"]
      and "carol@acme.com" not in doc()["accounts"] and doc()["directories"] == [] and rows("directory removed")[0]["detail"] == "ACME"
      and roles.state() == "ok" and signed_ok())
check("...their grants are gone", not any(n in doc()["grants"] for n in ("bob@acme.com", "carol@acme.com")))
check("...and their slots", osstore.get("pin:" + CAROL.guid) is None)
check("...the PIN no longer opens", raises(lambda: datakey.open_with_pin("bob@acme.com", PIN), pinslot.WrongPin) is not None)

# ---------------------------------------------------------------- no secrets in the audit
d = doc()
secrets = [base64 for base64 in (d["rules_pub"], d["rules_sig"], d["backups_pub"]) if base64]
details = [r["detail"] or "" for r in audit.recent(5000)]
check("no audit detail holds a key or a PIN", not any(s[:16] in x for s in secrets for x in details)
      and not any(p in x for p in (PIN, PIN2, PW) for x in details))
session.sign_out()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

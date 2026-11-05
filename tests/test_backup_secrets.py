# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Config backup passwords behind the backups key: masked bodies, the encrypted secret, who can read it, the upgrade that moves
# old unmasked bodies (resuming after a stop), moving a device between organizations, and the roles tripwire.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\bsec%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import backup, db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import zlib
from core import backupsplit, datakey, lockdown, orgs, roles, session, sqldb

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

PW, PW3, PW4 = "correct horse battery 42", "a third quite long password 5", "engineers have long passwords 7"
SECRET = "Sup3rS3cretPW"
HIDDEN_ROLE = "Passwords are hidden for your role."
HIDDEN_GRANT = "An admin needs to sign in to this copy once before you can see passwords in backups."

def cfg(enable="5 $1$mERr$TopEnableHash", extra=""):
    return (f"hostname sw\nenable secret {enable}\nusername admin privilege 15 secret 0 {SECRET}\n"
            f"interface Gi0/1\n description uplink{extra}\n")

def dev(name, org):
    return dict(name=name, vendor="cisco", host="10.0.0.1", port=0, platform="cisco_ios", username="u", site="default", verify_ssl=0,
                ha_expected=0, enabled=1, location="", details="", folder_id=None, org=org)

def rows(path):
    """Every config_backups row of one database file, as stored."""
    c = sqldb.connect(path)
    c.row_factory = sqldb.sqlite3.Row
    try:
        return [dict(r) for r in c.execute("SELECT * FROM config_backups ORDER BY id")]
    finally:
        c.close()

def body(r):
    return zlib.decompress(r["body"]).decode("utf-8")

def newest(device, org=None):
    with db.within(org):
        return backup.list_backups(device)[0]

# ---------------------------------------------------------------- sign-in off: as before
acme, globex = orgs.create("Acme", "ACME"), orgs.create("Globex", "GLBX")
DEVS = (("g-sw", 0), ("a-sw", acme), ("x-sw", globex))
VERSIONS = [cfg(), cfg(extra="\n shutdown")]
for name, org in DEVS:
    db.save_device(dev(name, org))
    with db.within(org):
        for t in VERSIONS:
            backup.store(name, t, mask=False)
DBS = [db.base_path(), db.org_path(acme), db.org_path(globex)]
g = rows(DBS[0])
check("sign-in off: mask=False keeps the body unmasked, no secret", all(SECRET in body(r) and r["secret"] is None for r in g), g)
check("sign-in off: get_text(unmasked=True) is the body", SECRET in backup.get_text(g[0]["id"], unmasked=True))
check("sign-in off: no reason to show", backup.secrets_hidden_reason(newest("g-sw")) is None)
check("before sign-in, nothing to split (no backups key)", roles.backups_public() is None)
backup.store("m-sw", cfg(), mask=True)
check("sign-in off, mask=True: the body masked, marked looked at ('')", rows(DBS[0])[-1]["secret"] == "" and SECRET not in body(rows(DBS[0])[-1]))
with db.connect() as c:                             # as a version stored before this change: not looked at yet
    c.execute("UPDATE config_backups SET secret=NULL WHERE device='m-sw'")
m_body = rows(DBS[0])[-1]["body"]

with db.within(globex), db.connect() as c:          # Globex's file as Toner kept it before this change: no secret column
    c.execute("DROP INDEX idx_backups_unchecked")
    c.execute("ALTER TABLE config_backups DROP COLUMN secret")
    c.execute("PRAGMA user_version = 12")

# ---------------------------------------------------------------- sign-in set up, then the Admin's first sign-in
datakey.create("Admin1", PW)
part1 = datakey.path().read_text(encoding="utf-8")   # (no Admin has opened it yet: what the tripwire below puts back)
lockdown.run()
datakey.close()
session.sign_in("Admin1", PW)
check("the Admin's sign-in made the backups key", roles.backups_public() is not None and roles.holds("backups"))
check("pending lists the three databases with unmasked bodies", set(backupsplit.pending()) == set(DBS), backupsplit.pending())

seen = []
def stop_after_first(done, total):
    seen.append((done, total))
    if done:
        raise RuntimeError("stopped")
try:
    backupsplit.run(stop_after_first)
except RuntimeError:
    pass
check("stopped after the first database: two still pending", len(backupsplit.pending()) == 2 and seen == [(0, 3), (1, 3)],
      (backupsplit.pending(), seen))
backupsplit.run()
check("run again: nothing pending", backupsplit.pending() == [])
before = {p: rows(p) for p in DBS}
backupsplit.run()
check("a third run changes nothing", {p: rows(p) for p in DBS} == before)
m = [r for r in rows(DBS[0]) if r["device"] == "m-sw"]
check("a masked version from before: marked looked at, its body untouched", len(m) == 1 and m[0]["secret"] == "" and m[0]["body"] == m_body, m)
db.init()                                           # what the window does next: the migration finds the column there already
with db.within(globex):
    check("Globex's file is up to date", db.schema_version() == db.SCHEMA_VERSION)

for (name, org), p in zip(DEVS, DBS):
    rs = [r for r in rows(p) if r["device"] == name]
    check(f"{name}: every body masked, every row has a secret",
          len(rs) == 2 and all(SECRET not in body(r) and "<masked>" in body(r) and r["secret"] for r in rs), rs)
    check(f"{name}: the masked body is what masking gives", [body(r) for r in rs] == [backup.clean(t) for t in VERSIONS])
    check(f"{name}: unmasked=True gives each version's own text back",
          [backup.get_text(r["id"], org, unmasked=True) for r in rs] == [backup.clean(t, mask=False) for t in VERSIONS])
    check(f"{name}: unmasked=False gives the masked text", SECRET not in backup.get_text(rs[0]["id"], org))

# ---------------------------------------------------------------- an Admin storing
state, row, _, _ = backup.store("g-sw", cfg(extra="\n description new"), mask=False)
r = rows(DBS[0])[-1]
check("Admin, mask=False: body masked, secret set", state == "changed" and SECRET not in body(r) and r["secret"], (state, r))
check("Admin: unmasked=True gives the password back", SECRET in backup.get_text(row["id"], unmasked=True))
check("Admin: unmasked=False doesn't", SECRET not in backup.get_text(row["id"]))
check("Admin: no reason to show", backup.secrets_hidden_reason(newest("g-sw")) is None)
state, row2, added, removed = backup.store("g-sw", cfg(enable="5 $1$mERr$OtherHash", extra="\n description new"), mask=False)
check("only the enable secret changed: 'changed', with no line added or removed in the masked text",
      state == "changed" and (added, removed) == (0, 0), (state, added, removed))
check("...and the new enable secret is in the secret",
      "OtherHash" in backup.get_text(row2["id"], unmasked=True) and "OtherHash" not in backup.get_text(row2["id"]))
check("the same text again: 'unchanged'",
      backup.store("g-sw", cfg(enable="5 $1$mERr$OtherHash", extra="\n description new"), mask=False)[0] == "unchanged")
state, row3, _, _ = backup.store("g-sw", cfg(extra="\n description masked"), mask=True)
check("Admin, mask=True: no secret, marked looked at", rows(DBS[0])[-1]["secret"] == "" and not newest("g-sw")["has_secret"]
      and backupsplit.pending() == [])
with db.connect() as c:
    c.execute("UPDATE config_backups SET secret='bm90IGEgd3JhcA==' WHERE id=?", (row2["id"],))
check("a secret that doesn't open: the masked body", backup.get_text(row2["id"], unmasked=True) == body(
    [r for r in rows(DBS[0]) if r["id"] == row2["id"]][0]))

# ---------------------------------------------------------------- moving a device to another organization
orgs.move_devices([d for d in db.list_devices() if d["name"] == "a-sw"], globex)
with db.within(globex):
    moved = backup.list_backups("a-sw")
check("moved: both versions in Globex's file, with their secrets", len(moved) == 2 and all(v["has_secret"] for v in moved), moved)
check("moved: the secret still opens there",
      [backup.get_text(v["id"], globex, unmasked=True) for v in reversed(moved)] == [backup.clean(t, mask=False) for t in VERSIONS])

# ---------------------------------------------------------------- a Tech and an Engineer
datakey.add_local("Tech1", PW3, role="Tech")
datakey.add_local("Eng1", PW4, role="Engineer")
session.sign_out()
session.sign_in("Tech1", PW3)
state, trow, _, _ = backup.store("g-sw", cfg(extra="\n description tech"), mask=False)
r = rows(DBS[0])[-1]
check("Tech, mask=False: the secret is still written", state == "changed" and r["secret"] and SECRET not in body(r))
check("Tech: unmasked=True gives the masked text", SECRET not in backup.get_text(trow["id"], unmasked=True))
check("Tech: the approved sentence", backup.secrets_hidden_reason(newest("g-sw")) == HIDDEN_ROLE, backup.secrets_hidden_reason(newest("g-sw")))
session.sign_out()
session.sign_in("Eng1", PW4)
check("Engineer with the grant: sees the password", SECRET in backup.get_text(trow["id"], unmasked=True)
      and backup.secrets_hidden_reason(newest("g-sw")) is None)
roles._held.pop("backups")                          # the permission, but no grant yet
check("Engineer without a grant: masked text", SECRET not in backup.get_text(trow["id"], unmasked=True))
check("Engineer without a grant: the approved sentence", backup.secrets_hidden_reason(newest("g-sw")) == HIDDEN_GRANT)

# ---------------------------------------------------------------- where it runs: the window's sign-in, and the command line's
def unsplit():
    """Put an unmasked body back in Globex's file, as a copy restored from before sign-in would have it."""
    with db.within(globex), db.connect() as c:
        rid = c.execute("SELECT MAX(id) FROM config_backups").fetchone()[0]
        c.execute("UPDATE config_backups SET body=?, secret=NULL WHERE id=?", (backup._pack(backup.clean(cfg(), mask=False)), rid))
    return rid

from PySide6.QtWidgets import QApplication, QDialog
qapp = QApplication.instance() or QApplication([])
import app as A, cli, getpass, io
from ui import setupdlg, signinwindow
setupdlg.carry_credential_manager = lambda: None
rid = unsplit()
session.sign_out()
signinwindow.SignInWindow.exec = lambda self: (session.sign_in("Tech1", PW3), QDialog.DialogCode.Accepted)[1]
check("the window's start splits what is left, whoever signs in", A.sign_in_at_start() is True and backupsplit.pending() == []
      and SECRET not in backup.get_text(rid, globex) and rows(DBS[2])[-1]["secret"])
rid = unsplit()
session.sign_out()
class Terminal(io.StringIO):
    def isatty(self): return True
real_stdin, sys.stdin, getpass.getpass = sys.stdin, Terminal(), lambda prompt="": PW4
try:
    check("the command line's sign-in splits it too", cli._sign_in(cli.argparse.Namespace(user="Eng1")) is None
          and backupsplit.pending() == [] and SECRET in backup.get_text(rid, globex, unmasked=True))
finally:
    sys.stdin = real_stdin

# ---------------------------------------------------------------- the secret is encrypted on disk
everything = [r for p in DBS for r in rows(p)]
secrets = [r["secret"] if isinstance(r["secret"], bytes) else r["secret"].encode() for r in everything if r["secret"]]
check("no secret holds the password's bytes", len(secrets) >= 8 and not any(SECRET.encode() in s for s in secrets), len(secrets))
check("no body holds the password", not any(SECRET in body(r) for r in everything))

# ---------------------------------------------------------------- the tripwire: a Part 1 keys file put back over this database
session.sign_out()
session.sign_in("Admin1", PW)
db.set_setting("rules_key", "")                     # (as if the setting were lost too)
session.sign_out()
datakey.path().write_text(part1, encoding="utf-8")
session.sign_in("Admin1", PW)
check("Part 1 file over a database that keeps secrets: tampered, not upgraded",
      roles.state() == "tampered" and db.get_setting("rules_key") == "" and not roles.holds("backups"), roles.state())
session.sign_out()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

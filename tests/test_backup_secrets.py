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
from core import backupsplit, datakey, envelope, lockdown, orgs, roles, session, sqldb

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
check("sign-in off, mask=True: the body masked, not looked at yet (NULL: '' would trip the roles tripwire at the first sign-in)",
      rows(DBS[0])[-1]["secret"] is None and SECRET not in body(rows(DBS[0])[-1]))
m_body = rows(DBS[0])[-1]["body"]

# hardening findings stored before findings were masked: they quote the password
OLD_FINDING = "type 7 (reversible) secrets: username admin password 7 0822455D0A16"
NEW_FINDING = "type 7 (reversible) secrets: username admin password <masked>"
def findings(org):
    with db.within(org), db.connect() as c:
        return [r[0] for r in c.execute("SELECT message FROM scan_results ORDER BY id")]
for org in (0, globex):
    with db.within(org), db.connect() as c:
        sid = c.execute("INSERT INTO scans(started_at) VALUES('2026-01-01 00:00:00')").lastrowid
        c.executemany("INSERT INTO scan_results(scan_id, device, check_name, status, value, message) VALUES(?,?,?,?,?,?)",
                      [(sid, "g-sw", "Hardening: Type 7 secrets", "WARN", "", OLD_FINDING),
                       (sid, "g-sw", "Reachability", "OK", "", "password 7 is not a finding")])

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
check("old hardening findings are masked in every database, other checks untouched",
      findings(0) == findings(globex) == [NEW_FINDING, "password 7 is not a finding"], (findings(0), findings(globex)))
before = {p: rows(p) for p in DBS}, findings(0), findings(globex)
backupsplit.run()
check("a third run changes nothing", ({p: rows(p) for p in DBS}, findings(0), findings(globex)) == before)
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

# ---------------------------------------------------------------- hardening reads what this sign-in may see (Ruling 15)
from core import hardening
session.sign_out()
session.sign_in("Admin1", PW)
backup.store("g-sw", cfg(extra="\n!\nservice password-encryption\nusername ops password 7 0822455D0A16\nsnmp-server community Comm5ecret RW"),
             mask=False)
g_sw = [d for d in db.list_devices() if d["name"] == "g-sw"][0]
def type7():
    return next((r.status, r.message) for r in hardening.scan(g_sw) if r.check == "Hardening: " + hardening.LABELS["type 7"])
got = type7()
check("masking off, an Admin: the type 7 password is judged", got[0] == "WARN" and got[1].startswith("type 7 (reversible) secrets: "), got)
msgs = [r.message for r in hardening.scan(g_sw)]
check("...and no finding quotes a secret (Ruling 17)", any("<masked>" in m for m in msgs)
      and not any(v in m for m in msgs for v in (SECRET, "0822455D0A16", "TopEnableHash", "Comm5ecret")), msgs)

# ---------------------------------------------------------------- the Assistant is told the masked text, even of an Admin's compare
from PySide6.QtWidgets import QApplication, QDialog
qapp = QApplication.instance() or QApplication([])
from ui import configs as C
db.save_device(dev("cmp-sw", 0))
backup.store("cmp-sw", cfg(), mask=False)
backup.store("cmp-sw", cfg().replace(SECRET, "N3wS3cretPW"), mask=False)
page = C.ConfigsTab()
page.select_device("cmp-sw"); qapp.processEvents()
page.vers.selectAll(); qapp.processEvents()
ctx = page.screen_context()
check("an Admin comparing two versions sees the passwords", SECRET in page.text.toPlainText() and "N3wS3cretPW" in page.text.toPlainText())
check("...the Assistant's context holds neither", ctx["view"] == "comparison" and "<masked>" in ctx["text"]
      and not any(v in ctx["text"] for v in (SECRET, "N3wS3cretPW")), ctx)
page.view.setCurrentIndex(page.view.findData("diff")); page.vers.selectRow(0); qapp.processEvents()
ctx = page.screen_context()
check("...nor in the changes view", ctx["view"] == "changes from the previous version" and SECRET in page.text.toPlainText()
      and "<masked>" in ctx["text"] and not any(v in ctx["text"] for v in (SECRET, "N3wS3cretPW")), ctx)
page.deleteLater()

session.sign_out()
session.sign_in("Tech1", PW3)
got = type7()
check("a Tech: the masked result", got == ("N/A", f"service password-encryption is on; whether type 7 secrets remain cannot be told, {hardening.MASKED}"), got)

# ---------------------------------------------------------------- where it runs: the window's sign-in, and the command line's
def unsplit():
    """Put an unmasked body back in Globex's file, as a copy restored from before sign-in would have it."""
    with db.within(globex), db.connect() as c:
        rid = c.execute("SELECT MAX(id) FROM config_backups").fetchone()[0]
        c.execute("UPDATE config_backups SET body=?, secret=NULL WHERE id=?", (backup._pack(backup.clean(cfg(), mask=False)), rid))
    return rid

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

# ---------------------------------------------------------------- a split that fails never stops Toner starting (Ruling 18)
good = unsplit()                                    # Globex: an unmasked body to move
with db.connect() as c:                             # Global: a damaged body not looked at yet
    damaged = c.execute("SELECT MAX(id) FROM config_backups").fetchone()[0]
    kept = dict(c.execute("SELECT body, secret FROM config_backups WHERE id=?", (damaged,)).fetchone())
    c.execute("UPDATE config_backups SET body=?, secret=NULL WHERE id=?", (b"not zlib at all", damaged))
broken = db.org_path(999)
broken.write_bytes(b"this is not a database file " * 200)
session.sign_out()
check("a damaged version and a broken organization file: Toner still starts", A.sign_in_at_start() is True)
g = [r for r in rows(DBS[2]) if r["id"] == good][0]
check("...the other versions are moved", g["secret"] and SECRET not in body(g))
check("...the damaged one stays NULL, the broken file untouched",
      [r["secret"] for r in rows(DBS[0]) if r["id"] == damaged] == [None] and broken.read_bytes() == b"this is not a database file " * 200)
with db.connect() as c:
    c.execute("UPDATE config_backups SET body=?, secret=? WHERE id=?", (kept["body"], kept["secret"], damaged))
broken.unlink()

asked = []
real_warning, real_run = setupdlg.QMessageBox.warning, backupsplit.run
setupdlg.QMessageBox.warning = lambda *a: (asked.append(a[2]), setupdlg.QMessageBox.StandardButton.Close)[1]
for error, want in (("disk I/O error", []), ("database is locked", [setupdlg.BUSY])):
    unsplit()
    session.sign_out()
    asked.clear()
    backupsplit.run = lambda progress=None, e=error: (_ for _ in ()).throw(sqldb.sqlite3.OperationalError(e))
    check(f"split fails with '{error}': Toner starts" + (", after the busy sentence and Close" if want else ", no busy sentence"),
          A.sign_in_at_start() is True and asked == want, asked)
backupsplit.run, setupdlg.QMessageBox.warning = real_run, real_warning

# ---------------------------------------------------------------- an id deleted and used again between the look and the write
rid = unsplit()                                     # Globex's newest version (a-sw's), unmasked again
real_wrap, hooked = envelope.wrap, []
def racing(*a):
    if not hooked:
        with db.within(globex), db.connect() as c:
            c.execute("DELETE FROM config_backups WHERE id=?", (rid,))
        with db.within(globex):
            hooked.append(backup.store("a-sw", cfg(extra="\n description reused"), mask=True)[1]["id"])
    return real_wrap(*a)
envelope.wrap = racing
try:
    backupsplit.run()
finally:
    envelope.wrap = real_wrap
r = [r for r in rows(DBS[2]) if r["id"] == rid]
check("the id used again keeps its own version, not the old text", hooked == [rid] and r and r[0]["secret"] == ""
      and "description reused" in body(r[0]) and SECRET not in body(r[0]), (hooked, r))

# ---------------------------------------------------------------- versions looked at by an older masker are masked again, once
FG_OLD = 'config system snmp community\n    edit 1\n        set name "Mon7f3"\n    next\nend\n'
session.sign_out()
session.sign_in("Admin1", PW)                       # a role that may see unmasked text
pub = roles.backups_public()
c = sqldb.connect(DBS[0])
with c:
    ins = "INSERT INTO config_backups(device, taken_at, sha, size, lines, body, added, removed, secret) VALUES(?,?,?,?,?,?,?,?,?)"
    plain_id = c.execute(ins, ("fg-old", "2026-01-01 00:00:00", "a" * 64, len(FG_OLD), 5, backup._pack(FG_OLD), 0, 0, "")).lastrowid
    kept_secret = envelope.wrap(pub, backup._pack(FG_OLD + "    set passwd hunter2\n"), backup.aad("b" * 64))
    kept_id = c.execute(ins, ("fg-old2", "2026-01-01 00:00:00", "b" * 64, len(FG_OLD), 5, backup._pack(FG_OLD), 0, 0, kept_secret)).lastrowid
    c.execute("DELETE FROM settings WHERE key=?", (backupsplit._DONE,))          # as an older Toner left the file
c.close()
check("a file looked at by an older masker is pending again", DBS[0] in backupsplit.pending(), backupsplit.pending())
backupsplit.run()
by_id = {r["id"]: r for r in rows(DBS[0])}
plain, kept = by_id[plain_id], by_id[kept_id]
check("its community name is masked in the body, and its sha stays", "Mon7f3" not in body(plain) and "set name <masked>" in body(plain)
      and plain["sha"] == "a" * 64, body(plain))
check("...the body as it was is kept, encrypted (an upgrade throws nothing away)", plain["secret"] and backup.get_text(plain_id, unmasked=True) == FG_OLD
      and "Mon7f3" not in backup.get_text(plain_id))
check("a version with its own secret keeps that secret, its body masked", kept["secret"] == kept_secret and "Mon7f3" not in body(kept)
      and "hunter2" in backup.get_text(kept_id, unmasked=True))
check("the file is marked done: nothing pending, and another run changes nothing",
      backupsplit.pending() == [] and (backupsplit.run(), rows(DBS[0]))[1] == list(by_id.values()))

# ---------------------------------------------------------------- the secret is encrypted on disk
everything = [r for p in DBS for r in rows(p)]
secrets = [r["secret"] if isinstance(r["secret"], bytes) else r["secret"].encode() for r in everything if r["secret"]]
check("no secret holds the password's bytes", len(secrets) >= 8 and not any(SECRET.encode() in s for s in secrets), len(secrets))
check("no body holds the password", not any(SECRET in body(r) for r in everything))
import base64
from cryptography.exceptions import InvalidTag
wrapped = [r for r in everything if r["secret"]]
def plain_zlib(r):
    try:
        zlib.decompress(base64.b64decode(r["secret"]))
        return True
    except Exception:
        return False
check("a secret isn't just zlib under base64", wrapped and not any(plain_zlib(r) for r in wrapped))
other = envelope.new_box_key()[0]
def other_opens(r):
    try:
        envelope.unwrap(other, r["secret"], backup.aad(r["sha"]))
        return True
    except (InvalidTag, ValueError):
        return False
check("another key can't open a secret", not any(other_opens(r) for r in wrapped))

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

# ---------------------------------------------------------------- the tripwire passes over an organization file that isn't a database
os.environ["NETCHECK_DB"] = SP + (r"\bsec2_%d.db").replace("\\", os.sep) % int(time.time())
datakey.create("Admin9", PW)
part1 = datakey.path().read_text(encoding="utf-8")
db.init()
acme2 = orgs.create("Acme Two", "AC2")
junk = db.org_path(acme2).with_name("0.db")         # (looked at before Acme Two's 1.db)
junk.write_bytes(b"this is not a database file " * 200)
datakey.close()
session.sign_in("Admin9", PW)
check("Part 1 keys file and a non-database organization file: sign-in completes and upgrades",
      roles.state() == "ok" and roles.holds("backups") and db.get_setting("rules_key") != "", roles.state())
with db.within(acme2):
    backup.store("o-sw", cfg(), mask=False)
check("...a secret kept in Acme Two's file", any(r["secret"] for r in rows(db.org_path(acme2))))
db.set_setting("rules_key", "")
session.sign_out()
datakey.path().write_text(part1, encoding="utf-8")
session.sign_in("Admin9", PW)
check("...and the tripwire still fires past the broken file: tampered, not upgraded",
      roles.state() == "tampered" and db.get_setting("rules_key") == "" and not roles.holds("backups"), roles.state())
session.sign_out()

m = backup.mask_secrets
check("a password ending in a brace is still masked", m("username a password P@ss{") == "username a password <masked>")
check("enable password minimum / username x password minimum are secrets, masked", m("enable password minimum") == "enable password <masked>" and m("username x password minimum") == "username x password <masked>")
check("only the length settings and a bare block opener are left alone", m("   password minimum length 15") == "   password minimum length 15" and m("    password {") == "    password {" and m("password maximum attempts 3") == "password maximum attempts 3")
check("ArubaOS-Switch's password minimum-length N is left alone; a secret shaped like it is masked", m("password minimum-length 15") == "password minimum-length 15"
      and m("password minimum-length") == "password <masked>" and m("username x password minimum-length 15") == "username x password <masked>")

print("== SNMP community names in every vendor's format, and their look-alikes left alone")
junos = m("snmp {\n    community Mon7f3 {\n        authorization read-only;\n    }\n    community public;\n    trap-group traps {\n        version v2;\n    }\n}\n"
          "policy-options {\n    community CUSTOMERS members 65000:100;\n}\nset snmp community \"Mon 7f3\" authorization read-only\n"
          "set snmp v3 snmp-community idx1 community-name \"$9$abc\"")
check("Junos: unquoted communities in snmp, the set form and v3's community-name", 'community "<masked>" {' in junos and 'community "<masked>";' in junos
      and 'set snmp community "<masked>" authorization read-only' in junos and 'community-name "<masked>"' in junos
      and not any(s in junos for s in ("Mon7f3", "Mon 7f3", "public", "$9$abc")), junos)
check("...a BGP community and a trap group keep their names", "community CUSTOMERS members 65000:100;" in junos and "trap-group traps {" in junos, junos)
forti = m('config system snmp community\n    edit 1\n        set name "Mon7f3"\n        config hosts\n            edit 1\n                set ip 10.0.0.5 255.255.255.255\n'
          '            next\n        end\n    next\n    edit 2\n        set name "public"\n    next\nend\nconfig firewall address\n    edit "web"\n        set name "web-server"\n    next\nend')
check("FortiOS: each community's set name, past a nested config block", forti.count("set name <masked>") == 2 and "Mon7f3" not in forti and '"public"' not in forti, forti)
check("...a set name outside the community list is left alone", 'set name "web-server"' in forti and "set ip 10.0.0.5" in forti, forti)
pan = m("<snmp-setting><access-setting><version><v2c><snmp-community-string>Mon7f3</snmp-community-string></v2c></version></access-setting></snmp-setting>\n"
        "<snmptrap><entry name=\"t\"><version><v2c><server><entry name=\"s\"><manager>10.0.0.5</manager><community>trapC0mm</community></entry></server></v2c></version></entry></snmptrap>\n"
        "<v3><users><entry name=\"u\"><authpwd>-AQ==abc</authpwd><privpwd>-AQ==def</privpwd></entry></users></v3>")
check("PAN-OS: the v2c community, a trap server's community and v3's passwords", not any(s in pan for s in ("Mon7f3", "trapC0mm", "-AQ==")) and pan.count("<masked>") == 4
      and "<manager>10.0.0.5</manager>" in pan, pan)
ros = m("/snmp\nset enabled=yes trap-community=trapC0mm\n/snmp community\nset [ find default=yes ] name=Mon7f3\nadd addresses=10.0.0.0/8 \\\n    name=\"second one\" write-access=no\n"
        "/interface ethernet\nset [ find default-name=ether1 ] name=wan\n/snmp community add name=inline")
check("RouterOS: names under /snmp community (a continued line too), the one-line form and trap-community", ros.count("name=<masked>") == 3 and "trap-community=<masked>" in ros
      and not any(s in ros for s in ("Mon7f3", "second one", "trapC0mm", "=inline")), ros)
check("...an interface's name is left alone", "set [ find default-name=ether1 ] name=wan" in ros and "addresses=10.0.0.0/8" in ros, ros)
check("masking twice changes nothing more", all(m(t) == t for t in (junos, forti, pan, ros)))

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

# Run by hand: python tests/manual_secret_check.py
# Signs in to the real Toner data on this computer and reports, for each device, whether its saved password can be read.
# It never prints a password: only "missing", "empty" or the length and the kind of text. Read only, apart from the
# "signed in" audit row a sign-in writes.
import getpass, os, string, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import db, extstore, passvault, profiles, session

passvault.install()
session.sign_in(input("Username: "), getpass.getpass("Password: "))
db.init()                                  # the database is encrypted: it opens only after the sign-in
print("vault open:", passvault.is_open(), "| vault entries:", len(passvault.names()))
print("password store:", extstore.active(), "| keep a copy in Toner's vault:", extstore.keep_copies())


def kind_of(v):
    if v is None:
        return "missing"
    if v == "":
        return "empty"
    printable = all(ch in string.printable for ch in v)
    b64ish = len(v) >= 40 and all(ch in string.ascii_letters + string.digits + "+/=_-" for ch in v)
    return f"{len(v)} chars, {'base64-like' if b64ish else 'text' if printable else 'binary-looking'}"


names = passvault.names()
for org in [db.GLOBAL] + [r["id"] for r in db.org_rows()]:
    with db.within(org):
        for dev in db.list_devices():
            d = dict(dev)
            d.setdefault("org", org)
            n = d.get("name", "?")
            print(f"{org!s:>10}  {n:<20} looks for {db.secret_name(n)!r}: {kind_of(profiles.secret(d, 'main'))}")
            near = [x for x in names if n.casefold() in x.casefold()]
            print(" " * 12, "vault names with it:", near[:8] or "none")
print("vault names that aren't org-prefixed (first 25):", sorted(x for x in names if "/" not in x)[:25])
prefixes = {}
for x in names:
    p = x.split("/", 1)[0] if "/" in x else "(global)"
    prefixes[p] = prefixes.get(p, 0) + 1
print("vault names per prefix:", dict(sorted(prefixes.items())))
print("password-manager links:", len(extstore.links()), "| changes waiting for it:", len(extstore.pending()))
print("credential_manager_carried:", db.get_setting("credential_manager_carried"))
print("audit, about vaults, passwords and sign-in (newest last):")
with db.within(db.GLOBAL), db.connect() as c:
    rows = c.execute("SELECT at, actor, action, detail FROM audit WHERE action LIKE '%password%' OR action LIKE '%vault%' "
                     "OR action LIKE '%sign%' OR action LIKE '%encrypt%' OR action LIKE '%Credential%' OR action LIKE '%store%' "
                     "ORDER BY rowid DESC LIMIT 40").fetchall()
for r in reversed(rows):
    print("  ", *[str(v)[:90] for v in r])
try:
    left = passvault.left_in_credential_manager()
    print("passwords still in Windows Credential Manager:", len(left), sorted(left)[:15])     # names only
except passvault.Unreadable as e:
    print("Windows Credential Manager couldn't be read in full; found", len(e.found))
session.sign_out()

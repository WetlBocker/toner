# Run directly (python tests/test_sso_config.py). SSO connections (kind "oidc") in the signed directories list: stored, refused when
# insecure, classified by email domain, given a role, and shown on the Accounts page.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\sso%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = _tmp.mkdtemp(prefix="netcheck_appdata_")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import datakey, db, directory, dirsignin, lockdown, oidc, roles, session, ssopresets
db.init()

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1
    else: bad += 1; print("FAIL", name, extra)

PW = "violet staple orbit 42"
datakey.create("Admin", PW)
lockdown.run()
datakey.close()
session.sign_in("Admin", PW)

def sso(i="s1", **kw):
    return {"id": i, "name": "Contoso", "kind": "oidc", "provider": "entra",
            "issuer": ssopresets.issuer_for("entra", "contoso-tenant-id"), "client_id": "app-1", "groups_claim": "groups",
            "id_claim": "oid", "suffixes": ["acme.com"], "groups": {"Admin": ["g-admin"]}, "group_names": {"g-admin": "Admins"},
            "everyone": None, **kw}

def refused(d):
    try:
        roles.set_directories([d])
    except ValueError:
        return True
    return False

def raises(fn):
    try:
        fn()
    except directory.InsecureConfig:
        return True
    return False

roles.set_directories([sso()])
check("an Entra cfg is stored", roles.verified()["directories"][0]["provider"] == "entra")
check("http issuer refused", refused(sso(issuer="http://login.example.com")))
check("empty client id refused", refused(sso(client_id="")))
check("no email domain refused", refused(sso(suffixes=[])))
check("unknown key refused", refused(sso(surprise=1)))
check("an issuer with no host refused", refused(sso(issuer="https://")) and refused(sso(issuer="https:///v2.0"))
      and refused(sso(issuer=None)) and refused(sso(issuer="https://[bad")))
check("an unknown provider refused", refused(sso(provider="azure")) and refused(sso(provider=None)))
check("suffixes must be a non-empty list of non-empty strings", refused(sso(suffixes="acme.com")) and refused(sso(suffixes=[""]))
      and refused(sso(suffixes=["acme.com", 3])) and refused(sso(suffixes=["  "])))
check("group_names must map str to str", refused(sso(group_names=["g"])) and refused(sso(group_names={"g": 1})))
check("everyone must be a role or None", refused(sso(everyone="Owner")) and not refused(sso(everyone="Tech")))
oidc._TEST_ALLOW_HTTP = True
check("http issuer allowed by the test flag", not refused(sso(issuer="http://127.0.0.1:1")))
check("...but still needs a host", refused(sso(issuer="http://")))
oidc._TEST_ALLOW_HTTP = False
AD = {"id": "d1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
      "base_dn": "DC=acme,DC=com", "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc,DC=acme,DC=com",
      "groups": {"Admin": ["CN=Admins,DC=acme,DC=com"]}, "ous": {}, "duo": {"on": False, "host": "", "ikey": ""}}
check("everyone is refused on an AD or LDAP directory", raises(lambda: directory.check_config({**AD, "everyone": "Tech"}))
      and raises(lambda: directory.check_config({**AD, "kind": "ldap", "everyone": None})) and not raises(lambda: directory.check_config(AD)))
check("role_for ignores everyone on a directory that isn't SSO", directory.role_for({**AD, "everyone": "Tech"}, []) is None)
roles.set_directories([sso()])

datakey.add_local("sam@acme.com", PW, "Tech")
r = dirsignin.classify("pat@acme.com")
check("classify picks the SSO cfg by email domain", r[0] == "directory" and r[1]["id"] == "s1" and r[2] == "pat@acme.com", r)
check("a local account with that name still wins", dirsignin.classify("sam@acme.com") == ("local", "sam@acme.com"))

check("role_for: no groups, no everyone -> None", directory.role_for(sso(), []) is None)
check("role_for: everyone gives its role", directory.role_for(sso(everyone="Tech"), []) == "Tech")
check("role_for: a mapped group beats everyone", directory.role_for(sso(everyone="Tech"), ["g-admin"]) == "Admin")

check("issuer_for entra", ssopresets.issuer_for("entra", "contoso-tenant-id") == "https://login.microsoftonline.com/contoso-tenant-id/v2.0")
check("issuer_for others strips a trailing slash", ssopresets.issuer_for("okta", "https://acme.okta.com/") == "https://acme.okta.com")
NOTES = {
    "entra": "In the Entra admin center, register an app for Toner as a public client (mobile and desktop) with the redirect URI http://localhost. Add the groups claim to its ID token, and grant GroupMember.Read.All with admin consent so Toner can list groups.",
    "okta": "In Okta, add an OIDC native app for Toner with the redirect URI http://localhost, and add a groups claim to its ID token.",
    "google": "In Google Cloud, create an OAuth client of type Desktop app for Toner. Google sends no groups, so everyone who signs in gets the role you choose under Roles.",
    "duo": "In Duo, add a Generic OIDC Relying Party for Toner with the redirect URI http://localhost, and send the groups attribute in its ID token.",
    "other": "Register Toner as a native (desktop) app with the redirect URI http://localhost, and add the person's groups to its ID token.",
}
P = ssopresets.PRESETS
check("every preset note is the approved text", {k: v["note"] for k, v in P.items()} == NOTES)
check("preset fields", [P[k]["field"] for k in NOTES] == ["Tenant ID"] + ["Issuer URL"] * 4
      and [P[k]["id_claim"] for k in NOTES] == ["oid", "sub", "sub", "sub", "sub"]
      and P["google"]["groups_claim"] is None and [k for k, v in P.items() if v["lists_groups"]] == ["entra"])
check("labels", [P[k]["label"] for k in NOTES] == ["Entra", "Okta", "Google Workspace", "Duo SSO", "Other"])

from PySide6.QtWidgets import QApplication
app = QApplication([])
from ui.settings_pages import accounts as A
from ui.directorydlg import KINDS
check("KINDS has SSO", ("SSO (OpenID Connect)", "oidc") in KINDS)
page = A.AccountsPage(); page.load(); page.refresh()
check("the Accounts page shows SSO / N/A", [page.idents.item(0, j).text() for j in range(3)] == ["Contoso", "SSO", "N/A"])
page.idents.selectRow(0)
m = page._ident_menu(page.idents.visualRect(page.idents.model().index(0, 0)).center())
check("no Set up 2FA for SSO", [a.text() for a in m.actions() if a.isVisible()] == ["Test login...", "Edit...", "Remove"],
      [(a.text(), a.isVisible()) for a in m.actions()])

print(f"\n{ok} passed, {bad} failed")

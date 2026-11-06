# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database in a temp folder, so nothing on this computer is touched.
# The directory client (core/directory.py) on ldap3's MOCK_SYNC: an AD-shaped tree (nested groups, a disabled user) and an LDAP-shaped
# tree, wrong and empty passwords, the roles, a removed account, the TLS rules, and a closed port that must fail within the timeout.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, socket, uuid
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\dir%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
import ldap3
from core import directory as D

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def raises(exc, fn, *a):
    """The exception's message if fn raised exc, else None."""
    try: fn(*a)
    except exc as e: return str(e) or exc.__name__
    except Exception: return None
    return None

D._STRATEGY = ldap3.MOCK_SYNC
REAL_MAKE_SERVER = D._make_server
BASE = "DC=corp,DC=example"
# fixed GUIDs whose bytes are plain letters: the mock mismatches some random ones (bytes it reads as filter syntax)
G_ALICE, G_BOB, G_BOBBY, G_ZED = (uuid.UUID(bytes_le=(c * 16).encode()) for c in "ABCD")

def tree(entries):
    srv = ldap3.Server("mock", get_info=ldap3.NONE)
    c = ldap3.Connection(srv, client_strategy=ldap3.MOCK_SYNC)
    for dn, attrs in entries: c.strategy.add_entry(dn, attrs)
    c.bind()
    D._make_server = lambda cfg, host, *_: srv
    return srv

# --- AD: alice is in Eng-Team, which is in Network-Admins (nested); Tech-Desk is a separate group; bob is disabled
srv = tree([
    ("CN=Alice A,OU=Users," + BASE, {"objectClass": "user", "userPrincipalName": "Alice@corp.example", "sAMAccountName": "alice", "displayName": "Alice A", "cn": "Alice A",
        "objectGUID": G_ALICE.bytes_le, "userAccountControl": 512, "userPassword": "pw-alice",
        "memberOf": ["CN=Eng-Team,OU=Groups," + BASE, "CN=Tech-Desk,OU=Groups," + BASE]}),
    ("CN=Bob B,OU=Users," + BASE, {"objectClass": "user", "userPrincipalName": "bob@corp.example", "sAMAccountName": "bob", "cn": "Bob B",
        "objectGUID": G_BOB.bytes_le, "userAccountControl": 514, "userPassword": "pw-bob"}),
    ("CN=Eng-Team,OU=Groups," + BASE, {"objectClass": "group", "cn": "Eng-Team", "memberOf": ["CN=Network-Admins,OU=Groups," + BASE]}),
    ("CN=Network-Admins,OU=Groups," + BASE, {"objectClass": "group", "cn": "Network-Admins"}),
    ("CN=Tech-Desk,OU=Groups," + BASE, {"objectClass": "group", "cn": "Tech-Desk"}),
    ("CN=svc,OU=Users," + BASE, {"objectClass": "user", "userPassword": "svc-pw"}),
    # look-alikes: bobby's UPN prefix is bob2, and zed's sAMAccountName is bob2
    ("CN=Bobby,OU=Users," + BASE, {"objectClass": "user", "userPrincipalName": "bob2@corp.example", "sAMAccountName": "bobby", "cn": "Bobby", "objectGUID": G_BOBBY.bytes_le,
        "userAccountControl": 512, "userPassword": "pw-bobby", "memberOf": ["CN=Tech-Desk,OU=Groups," + BASE]}),
    ("CN=Zed,OU=Users," + BASE, {"objectClass": "user", "userPrincipalName": "zed@corp.example", "sAMAccountName": "bob2", "cn": "Zed", "objectGUID": G_ZED.bytes_le,
        "userAccountControl": 512, "userPassword": "pw-zed", "memberOf": ["CN=Network-Admins,OU=Groups," + BASE]}),
    ("CN=Tech-Desk,OU=Other," + BASE, {"objectClass": "group", "cn": "Tech-Desk"}),
    # the configuration naming context's partitions: the domain's crossRef holds its NetBIOS name
    ("CN=CORP,CN=Partitions,CN=Configuration," + BASE, {"objectClass": "crossRef", "cn": "CORP", "nCName": BASE, "nETBIOSName": "CORP"}),
    ("CN=Enterprise Configuration,CN=Partitions,CN=Configuration," + BASE, {"objectClass": "crossRef", "cn": "Enterprise Configuration",
        "nCName": "CN=Configuration," + BASE}),
])
srv.dit["bob2@corp.example"] = srv.dit["CN=Bobby,OU=Users," + BASE]; srv.dit["zed@corp.example"] = srv.dit["CN=Zed,OU=Users," + BASE]
D._who_am_i = lambda conn: "u:CORP\\" + conn.server.dit[conn.user]["sAMAccountName"][0].decode()    # the mock has no Who Am I
for upn, dn in (("alice@corp.example", "CN=Alice A,OU=Users," + BASE), ("bob@corp.example", "CN=Bob B,OU=Users," + BASE)):
    srv.dit[upn] = srv.dit[dn]      # AD binds by UPN; the mock only knows DNs
AD = {"id": "ab12", "name": "Corp", "kind": "ad", "servers": ["dc1.corp.example"], "port": 636, "security": "ldaps", "ca_file": "",
      "base_dn": BASE, "netbios": "CORP", "suffixes": ["corp.example"], "service_dn": "CN=svc,OU=Users," + BASE,
      "groups": {"Admin": ["cn=network-admins,ou=Groups," + BASE.lower()], "Engineer": ["CN=Engineers,OU=Groups," + BASE], "Tech": ["CN=Tech-Desk,OU=Groups," + BASE]}, "duo": {"on": False, "host": "", "ikey": ""}}

print("== Active Directory")
u = D.sign_in(AD, "alice@corp.example", "pw-alice")
check("the UPN form signs in", u.name == "alice@corp.example" and u.display == "Alice A" and u.enabled, u)
check("the GUID is text", u.guid == str(G_ALICE), u.guid)
G = lambda cn: "CN=%s,OU=Groups,%s" % (cn, BASE)
check("groups (as DNs) include the nested one", set(u.groups) == {G("Eng-Team"), G("Network-Admins"), G("Tech-Desk")}, u.groups)
srv.dit["CORP\\alice"] = srv.dit["CN=Alice A,OU=Users," + BASE]      # AD binds DOMAIN\\user as typed
binds = []
class BindSpy(ldap3.Connection):
    def __init__(self, *a, **k): binds.append(k.get("user")); super().__init__(*a, **k)
_real_conn = ldap3.Connection; ldap3.Connection = BindSpy
check("DOMAIN\\user binds as typed, not as user@first-suffix", D.sign_in(AD, "CORP\\alice", "pw-alice").guid == u.guid
      and binds == ["CORP\\alice"], binds)
binds.clear()
check("DOMAIN\\user of another domain is refused before any bind",
      raises(D.BadCredentials, D.sign_in, AD, "OTHER\\alice", "pw-alice") is not None and binds == [], binds)
_wai = D._who_am_i; D._who_am_i = lambda conn: "u:CHILD\\alice"
check("...and Who Am I is still checked", raises(D.BadCredentials, D.sign_in, AD, "CORP\\alice", "pw-alice") is not None)
D._who_am_i = _wai; ldap3.Connection = _real_conn
m = raises(D.BadCredentials, D.sign_in, AD, "alice@corp.example", "nope-nope")
check("a wrong password is BadCredentials, and the message has no password", m is not None and "nope-nope" not in m)
check("an empty password is refused (it would be an anonymous bind)", raises(D.BadCredentials, D.sign_in, AD, "alice@corp.example", "") is not None)
bob = D.sign_in(AD, "bob@corp.example", "pw-bob")
check("a disabled user has enabled False", bob.enabled is False)
check("a user the server shows no groups for has none", bob.groups == ())
f = D.look_up(AD, str(G_ALICE), "svc-pw")
check("look_up finds by GUID", f is not None and f.name == u.name and f.groups == u.groups, f)
check("look_up of a removed GUID is None", D.look_up(AD, str(uuid.uuid4()), "svc-pw") is None)
check("look_up with a wrong service password is BadCredentials", raises(D.BadCredentials, D.look_up, AD, str(G_ALICE), "bad") is not None)
n = D.test(AD, "svc-pw")
check("test counts the groups", n == 4, n)

print("== the NetBIOS name, read from the directory")
D._config_nc = lambda conn: "CN=Configuration," + BASE        # the mock has no rootDSE
check("AD: the domain's crossRef gives its NetBIOS name", D.netbios(dict(AD, netbios=""), "svc-pw") == "CORP")
check("...also when the base DN is an OU in the domain", D.netbios(dict(AD, netbios="", base_dn="OU=Users," + BASE), "svc-pw") == "CORP")
check("...no crossRef for the domain is Unreachable", raises(D.Unreachable, D.netbios, dict(AD, netbios="", base_dn="DC=other,DC=example"),
      "svc-pw") is not None)
check("...a wrong service password is BadCredentials", raises(D.BadCredentials, D.netbios, dict(AD, netbios=""), "bad") is not None)
D._config_nc = lambda conn: None
check("...no configuration naming context is Unreachable", raises(D.Unreachable, D.netbios, dict(AD, netbios=""), "svc-pw") is not None)

print("== look-alike users")
z = D.sign_in(AD, "bob2@corp.example", "pw-bobby")
check("the bound person is read, not a look-alike with the same name part", z.guid == str(G_BOBBY) and z.groups == (G("Tech-Desk"),), z)
check("the other one signs in as themselves", D.sign_in(AD, "zed@corp.example", "pw-zed").guid == str(G_ZED))
check("a name with nothing for the user is BadCredentials", all(raises(D.BadCredentials, D.sign_in, AD, x, "pw") is not None for x in ("", "@x", "CORP\\", "  ")))

print("== resolving group names")
check("a CN resolves to its DN", D.resolve_groups(AD, ["Network-Admins"], "svc-pw") == {"Network-Admins": G("Network-Admins")})
typed = "cn=eng-team,ou=groups," + BASE.lower()
# the mock echoes the requested DN back, a real server answers with the entry's own; so stand in a connection that does
class Echo:
    result = {"result": 0}
    def search(self, base, *a, **k): self.response = [{"type": "searchResEntry", "dn": G("Eng-Team"), "attributes": {}}]
    def unbind(self): pass
_connect = D.connect; D.connect = lambda *a: Echo()
r = D.resolve_groups(AD, [typed], "svc-pw"); D.connect = _connect
check("a typed DN is read back and the server's form is stored, not the typed text", r == {typed: G("Eng-Team")}, r)
check("a CN with an equals sign that is not a DN is searched as a CN", raises(D.NotFound, D.resolve_groups, AD, ["a=b"], "svc-pw") is not None)
check("a CN used twice is Ambiguous", raises(D.Ambiguous, D.resolve_groups, AD, ["Tech-Desk"], "svc-pw") is not None)
check("an unknown CN is NotFound", raises(D.NotFound, D.resolve_groups, AD, ["Nope"], "svc-pw") is not None)
check("a DN that does not exist is NotFound", raises(D.NotFound, D.resolve_groups, AD, ["CN=Nope,OU=Groups," + BASE], "svc-pw") is not None)

print("== Who Am I answers")
for me, want in (("u:CORP\\alice", ("sam", "alice")), ("u:corp\\alice", ("sam", "alice")), ("dn:CN=A,DC=x", ("dn", "CN=A,DC=x"))):
    check("accepted: " + me, D.whoami_target(AD, me) == want)
for me in ("u:CHILD\\alice", "", "u:", "u:CORP\\", "u:\\alice", "x:foo", "CORP\\alice", "dn:"):
    check("refused: %r" % me, raises(D.BadCredentials, D.whoami_target, AD, me) is not None)

print("== referrals")
class Fake:
    def __init__(self, code): self.result = {"result": code}; self.response = []
    def search(self, *a, **k): pass
check("a referral result is Unreachable, never 'not found'", raises(D.Unreachable, D._search, Fake(10), BASE, "(x=1)", []) is not None)
check("any other error result is Unreachable", raises(D.Unreachable, D._search, Fake(50), BASE, "(x=1)", []) is not None)
check("a success with nothing is an empty list", D._search(Fake(0), BASE, "(x=1)", []) == [])
seen = {}
class Spy(ldap3.Connection):
    def __init__(self, *a, **k): seen.update(k); super().__init__(*a, **k)
_real = ldap3.Connection; ldap3.Connection = Spy
D.sign_in(AD, "alice@corp.example", "pw-alice"); ldap3.Connection = _real
check("every connection is made with referrals off", seen.get("auto_referrals") is False, seen)

print("== roles")
check("Admin wins over Tech, DNs compared by case", D.role_for(AD, [G("Tech-Desk"), "CN=NETWORK-ADMINS,OU=Groups,DC=corp,DC=example"]) == "Admin")
check("Tech alone", D.role_for(AD, [G("Tech-Desk")]) == "Tech")
check("escaped look-alike DNs do not match", D.role_for(AD, ["CN=\\54ech-Desk,OU=Groups," + BASE, "CN=Tech-Desk\\20,OU=Groups," + BASE, "CN=\\ Tech-Desk,OU=Groups," + BASE]) is None)
check("a same-CN group in another OU grants nothing", D.role_for(AD, ["CN=Tech-Desk,OU=Other," + BASE]) is None)
check("a bare CN is not a DN and grants nothing", D.role_for(AD, ["Tech-Desk", "Network-Admins"]) is None)
check("no match is None", D.role_for(AD, [G("Other")]) is None and D.role_for(AD, []) is None)
check("only ASCII letters fold: Unicode case look-alikes grant nothing",
      D.role_for(dict(AD, groups={"Admin": ["CN=Straße,DC=x"], "Tech": ["CN=Kiosk,DC=x"]}), ["CN=STRASSE,DC=x", "CN=\u212aiosk,DC=x"]) is None)
check("alice maps to Admin through the nested group", D.role_for(AD, u.groups) == "Admin")

print("== roles from OUs")
def got(fn):
    try: return fn()
    except Exception as e: return e
check("sign_in gives the entry's DN", getattr(u, "dn", None) == "CN=Alice A,OU=Users," + BASE, u)
TD = "CN=Tech-Desk,OU=Groups,DC=acme,DC=com"
OU = dict(AD, groups={"Admin": [], "Engineer": [], "Tech": [TD]}, ous={"Admin": [], "Engineer": [], "Tech": ["OU=IT,DC=acme,DC=com"]})
check("an account in an OU below a mapped OU gets its role", got(lambda: D.role_for(OU, [], "CN=Bob,OU=Ops,OU=IT,DC=acme,DC=com")) == "Tech")
check("...and one right in it", got(lambda: D.role_for(OU, [], "CN=Bob,OU=IT,DC=acme,DC=com")) == "Tech")
check("an OU whose name only starts the same grants nothing", got(lambda: D.role_for(OU, [], "CN=Bob,OU=IT-Old,DC=acme,DC=com")) is None)
check("an escaped comma is not a boundary: CN=x\\,OU=IT,... lives in DC=acme, not in OU=IT",
      got(lambda: D.role_for(OU, [], r"CN=x\,OU=IT,DC=acme,DC=com")) is None)
check("...an escaped backslash then a real comma is one", got(lambda: D.role_for(OU, [], r"CN=x\\,OU=IT,DC=acme,DC=com")) == "Tech")
check("...three backslashes: escaped again", got(lambda: D.role_for(OU, [], r"CN=x\\\,OU=IT,DC=acme,DC=com")) is None)
check("an object named to look like it is in Admins (it is in IT) isn't made Admin",
      got(lambda: D.role_for(dict(OU, ous={"Admin": ["OU=Admins,OU=IT,DC=acme,DC=com"]}), [], r"CN=x\,OU=Admins,OU=IT,DC=acme,DC=com")) is None)
check("the OU itself as a DN grants nothing", got(lambda: D.role_for(OU, [], "OU=IT,DC=acme,DC=com")) is None)
check("ASCII case doesn't matter", got(lambda: D.role_for(OU, [], "cn=bob,ou=ops,ou=it,DC=ACME,dc=com")) == "Tech")
check("...but Unicode case look-alikes grant nothing", got(lambda: D.role_for(dict(OU, ous={"Tech": ["OU=Kiosk,DC=x"]}), [], "CN=a,OU=Kiosk,DC=x")) is None)
UP = dict(OU, ous={"Admin": ["OU=Ops,OU=IT,DC=acme,DC=com"], "Engineer": [], "Tech": []})
check("an OU and a group together: the highest role (OU Admin over group Tech)", got(lambda: D.role_for(UP, [TD], "CN=Bob,OU=Ops,OU=IT,DC=acme,DC=com")) == "Admin")
check("...(group Admin over OU Tech)", got(lambda: D.role_for(dict(OU, groups={"Admin": [TD]}), [TD], "CN=Bob,OU=IT,DC=acme,DC=com")) == "Admin")
check("...and the group alone where the OU doesn't match", got(lambda: D.role_for(UP, [TD], "CN=Bob,OU=IT-Old,DC=acme,DC=com")) == "Tech")
check("no ous key: groups only, as before", got(lambda: D.role_for(AD, [G("Tech-Desk")], "CN=Bob,OU=IT,DC=acme,DC=com")) == "Tech"
      and got(lambda: D.role_for(AD, [], "CN=Alice A,OU=Users," + BASE)) is None)

print("== discovery: the base DN, NetBIOS and DNS domain; the OUs and groups")
AB = "DC=acme,DC=com"
tree([("CN=svc,OU=IT," + AB, {"objectClass": "user", "userPassword": "svc-pw"}),
      ("OU=IT," + AB, {"objectClass": "organizationalUnit", "ou": "IT"}),
      ("OU=Ops,OU=IT," + AB, {"objectClass": "organizationalUnit", "ou": "Ops"}),
      ("OU=IT-Old," + AB, {"objectClass": "organizationalUnit", "ou": "IT-Old"}),
      ("OU=sales," + AB, {"objectClass": "organizationalUnit", "ou": "sales"}),
      ("CN=Ops-Team,OU=IT," + AB, {"objectClass": "group", "cn": "Ops-Team"}),
      ("CN=admins,OU=IT," + AB, {"objectClass": "group", "cn": "admins"}),
      ("CN=Sales,OU=sales," + AB, {"objectClass": "group", "cn": "Sales"}),
      ("CN=ACME,CN=Partitions,CN=Configuration," + AB, {"objectClass": "crossRef", "cn": "ACME", "nCName": AB, "nETBIOSName": "ACME"})])
AC = dict(AD, base_dn="", netbios="", suffixes=[], service_dn="CN=svc,OU=IT," + AB)
class Root:      # a rootDSE as a server answers it (the mock has none)
    def __init__(self, attrs): self.attrs, self.asked = attrs, []
    def search(self, base, flt, search_scope=None, attributes=()): self.asked.append((base, search_scope, list(attributes))); self.response = [{"type": "searchResEntry", "dn": "", "attributes": self.attrs}]
r = Root({"defaultNamingContext": AB, "namingContexts": ["CN=Configuration," + AB, AB]})
check("AD: the base DN is the rootDSE's defaultNamingContext", got(lambda: D._base_dn(r, True)) == AB and r.asked[0][:2] == ("", ldap3.BASE), r.asked)
check("LDAP: the first namingContexts value", got(lambda: D._base_dn(Root({"namingContexts": ["dc=example,dc=org", "o=other"]}), False)) == "dc=example,dc=org")
check("...none said is None", got(lambda: D._base_dn(Root({}), True)) is None)
_base = getattr(D, "_base_dn", None); D._base_dn = lambda conn, ad: AB
D._config_nc = lambda conn: "CN=Configuration," + AB
d = got(lambda: D.discover(AC, "svc-pw"))
check("discover on AD: base DN, NetBIOS ACME, suffix acme.com", d == {"base_dn": AB, "netbios": "ACME", "suffixes": ["acme.com"]}, d)
d = got(lambda: D.discover(dict(AC, kind="ldap"), "svc-pw"))
check("discover on LDAP: no NetBIOS", d == {"base_dn": AB, "netbios": "", "suffixes": ["acme.com"]}, d)
D._config_nc = lambda conn: None
d = got(lambda: D.discover(AC, "svc-pw"))
check("...a NetBIOS name that can't be read is empty (step 5 lets it be typed)", d == {"base_dn": AB, "netbios": "", "suffixes": ["acme.com"]}, d)
def boom(*a, **k): raise ldap3.core.exceptions.LDAPOperationsErrorResult("read refused")
D._config_nc = boom
d = got(lambda: D.discover(AC, "svc-pw"))
check("...also when its read fails with an LDAP error", d == {"base_dn": AB, "netbios": "", "suffixes": ["acme.com"]}, d)
_b = D._base_dn; D._base_dn = boom
check("an LDAP error reading the base DN is Unreachable", raises(D.Unreachable, lambda: D.discover(AC, "svc-pw")) is not None)
D._base_dn = _b
D._base_dn = lambda conn, ad: "OU=People,o=acme"
d = got(lambda: D.discover(dict(AC, kind="ldap"), "svc-pw"))
check("...a base DN with no DC= parts has no suffix", d == {"base_dn": "OU=People,o=acme", "netbios": "", "suffixes": []}, d)
D._base_dn = lambda conn, ad: None
check("no base DN is Unreachable", raises(D.Unreachable, lambda: D.discover(AC, "svc-pw")) is not None)
D._base_dn = lambda conn, ad: AB
check("a wrong service password is BadCredentials", raises(D.BadCredentials, lambda: D.discover(AC, "bad")) is not None)
TC = dict(AC, base_dn=AB)
OUS = ["OU=IT," + AB, "OU=IT-Old," + AB, "OU=Ops,OU=IT," + AB, "OU=sales," + AB]
GRPS = ["CN=admins,OU=IT," + AB, "CN=Ops-Team,OU=IT," + AB, "CN=Sales,OU=sales," + AB]
t = got(lambda: D.tree(TC, "svc-pw"))
check("tree lists OUs and groups as written, sorted ignoring case", t == {"ous": OUS, "groups": GRPS, "more": False}, t)
t = got(lambda: D.tree(TC, "svc-pw", cap=2))
check("...at most cap of each, and more is True", isinstance(t, dict) and len(t["ous"]) == 2 and len(t["groups"]) == 2 and t["more"] is True
      and set(t["ous"]) <= set(OUS) and set(t["groups"]) <= set(GRPS) and t["ous"] == sorted(t["ous"], key=str.lower), t)
t = got(lambda: D.tree(TC, "svc-pw", cap=4))
check("...exactly cap of one kind is not more", isinstance(t, dict) and t["ous"] == OUS and t["more"] is False, t)
t = got(lambda: D.tree(TC, "svc-pw", text="ops"))
check("text: only OUs (by ou) and groups (by cn) containing it", t == {"ous": ["OU=Ops,OU=IT," + AB], "groups": ["CN=Ops-Team,OU=IT," + AB], "more": False}, t)
# the mock reads a filter back unescaped (an escaped * is a wildcard to it), so the filters sent are checked instead
flts = []
class FilterSpy(ldap3.Connection):
    def search(self, base, flt, *a, **k): flts.append(flt); return super().search(base, flt, *a, **k)
_real = ldap3.Connection; ldap3.Connection = FilterSpy
for x, want in (("*", "\\2a"), ("IT)(ou=*", "IT\\29\\28ou=\\2a"), ("\\2a", "\\5c2a")):
    flts.clear(); got(lambda: D.tree(TC, "svc-pw", text=x))
    check("text %r is escaped, never widening the search" % x, flts == ["(&(objectClass=organizationalUnit)(ou=*%s*))" % want,
          "(&(objectClass=group)(cn=*%s*))" % want], flts)
ldap3.Connection = _real
class Refusing(ldap3.Connection):
    def search(self, *a, **k): boom()
ldap3.Connection = Refusing
check("an LDAP error during tree is Unreachable", raises(D.Unreachable, lambda: D.tree(TC, "svc-pw")) is not None)
ldap3.Connection = _real
check("tree with a wrong service password is BadCredentials", raises(D.BadCredentials, lambda: D.tree(TC, "bad")) is not None)
D._base_dn = _base

print("== LDAP")
LB = "dc=example,dc=org"
tree([
    ("uid=carol," + LB, {"objectClass": "inetOrgPerson", "uid": "carol", "cn": "Carol C", "displayName": "Carol C", "entryUUID": "11111111-2222-3333-4444-555555555555", "userPassword": "pw-carol"}),
    ("uid=dave," + LB, {"objectClass": "inetOrgPerson", "uid": "dave", "cn": "Dave D", "entryUUID": "66666666-2222-3333-4444-555555555555", "userPassword": "pw-dave", "nsAccountLock": "true"}),
    ("uid=erin," + LB, {"objectClass": "inetOrgPerson", "uid": "erin", "cn": "Erin E", "entryUUID": "77777777-2222-3333-4444-555555555555", "userPassword": "pw-erin", "pwdAccountLockedTime": "20260101000000Z"}),
    ("cn=Eng,ou=groups," + LB, {"objectClass": "groupOfNames", "cn": "Eng", "member": ["uid=carol," + LB]}),
    ("cn=Admins,ou=groups," + LB, {"objectClass": "groupOfNames", "cn": "Admins", "member": ["cn=Eng,ou=groups," + LB]}),
    ("cn=svc," + LB, {"objectClass": "person", "userPassword": "svc-pw"}),
    ("cn=Posix,ou=groups," + LB, {"objectClass": "posixGroup", "cn": "Posix", "memberUid": ["carol"]}),
    ("cn=NotAGroup," + LB, {"objectClass": "device", "cn": "NotAGroup", "member": ["uid=carol," + LB]}),
])
LD = dict(AD, kind="ldap", base_dn=LB, suffixes=["example.org"], service_dn="cn=svc," + LB, groups={"Admin": ["cn=Admins,ou=groups," + LB], "Engineer": ["cn=Eng,ou=groups," + LB], "Tech": []})
c = D.sign_in(LD, "carol", "pw-carol")
check("LDAP signs in with uid=<user>,<base_dn>", c.name == "carol@example.org" and c.display == "Carol C" and c.enabled and c.guid == "11111111-2222-3333-4444-555555555555", c)
check("LDAP groups: nested, posixGroup by memberUid, only group objects, as DNs", set(c.groups) == {"cn=Eng,ou=groups," + LB, "cn=Admins,ou=groups," + LB, "cn=Posix,ou=groups," + LB}, c.groups)
check("LDAP role", D.role_for(LD, c.groups) == "Admin")
check("user@suffix works on LDAP", D.sign_in(LD, "carol@example.org", "pw-carol").guid == c.guid)
check("nsAccountLock true disables", D.sign_in(LD, "dave", "pw-dave").enabled is False)
check("pwdAccountLockedTime disables", D.sign_in(LD, "erin", "pw-erin").enabled is False)
check("LDAP wrong password", raises(D.BadCredentials, D.sign_in, LD, "carol", "bad") is not None)
f = D.look_up(LD, c.guid, "svc-pw")
check("LDAP look_up by entryUUID", f is not None and f.name == c.name, f)
check("LDAP look_up of a removed one is None", D.look_up(LD, "99999999-2222-3333-4444-555555555555", "svc-pw") is None)
n = D.test(LD, "svc-pw")
check("LDAP test counts the groups", n == 3, n)

print("== the TLS rules")
def passes(cfg):
    try: D.check_config(cfg); return True
    except D.InsecureConfig: return False
check("port 389 with ldaps is refused", not passes(dict(AD, port=389)))
check("no TLS at all is refused", not passes(dict(AD, security="none")))
check("an empty server list is refused", not passes(dict(AD, servers=[])))
check("StartTLS on 389 and LDAPS on 636 pass", passes(dict(AD, security="starttls", port=389)) and passes(AD))
check("connect refuses an insecure config before any network", raises(D.InsecureConfig, D.connect, dict(AD, port=389), "x", "y") is not None)
import inspect; src = inspect.getsource(D)
check("certificates are required, never disabled", "CERT_REQUIRED" in src and "CERT_NONE" not in src)
tls = REAL_MAKE_SERVER(dict(AD, ca_file=""), "h").tls
check("the real server object validates certificates", tls.validate == __import__("ssl").CERT_REQUIRED)

print("== the CA file: signed into the list as ca_sha256, read once at connect")
import builtins, hashlib, pathlib
mock = D._make_server
seen, reads = [], []
def recording(cfg, host, *ca):
    seen.append(REAL_MAKE_SERVER(cfg, host, *ca).tls.ca_certs_data)
    raise OSError("stop before the network")
real_open, real_read_bytes, real_path_open = builtins.open, pathlib.Path.read_bytes, pathlib.Path.open
def counting(real):
    def fn(f, *a, **k):
        if "ca-" in str(f): reads.append(str(f))
        return real(f, *a, **k)
    return fn
def connect_with(cfg):
    seen.clear(); reads.clear()
    D._make_server = recording
    builtins.open, pathlib.Path.read_bytes, pathlib.Path.open = counting(real_open), counting(real_read_bytes), counting(real_path_open)
    try:
        return raises(D.InsecureConfig, D.connect, cfg, "x@corp.example", "pw")
    finally:
        builtins.open, pathlib.Path.read_bytes, pathlib.Path.open = real_open, real_read_bytes, real_path_open
        D._make_server = mock
der, pem = os.path.join(SP, "ca-der.cer"), os.path.join(SP, "ca-pem.pem")
DER = bytes.fromhex("3082") + b"not really DER"
PEM = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
with open(der, "wb") as f: f.write(DER)
with open(pem, "wb") as f: f.write(PEM)
two = dict(AD, servers=["dc1.corp.example", "dc2.corp.example"])
connect_with(dict(two, ca_file=der, ca_sha256=hashlib.sha256(DER).hexdigest()))
check("ldap3.Tls gets the checked bytes as ca_certs_data, for every server", seen == [DER, DER], seen)
check("...read once, not once per server", len(reads) == 1, reads)
connect_with(dict(two, ca_file=pem, ca_sha256=hashlib.sha256(PEM).hexdigest()))
check("a PEM file goes to ldap3.Tls as its text (ssl's cadata takes PEM only as text)", seen == [PEM.decode("ascii")] * 2, seen)
connect_with(dict(AD, ca_file=""))
check("no CA file: the system store (no ca_certs_data)", seen == [None], seen)
for what, cfg in (("a CA file whose contents changed", dict(AD, ca_file=der, ca_sha256=hashlib.sha256(b"other").hexdigest())),
                  ("a CA file with no ca_sha256", dict(AD, ca_file=der)),
                  ("a CA file that can't be read", dict(AD, ca_file=os.path.join(SP, "ca-missing.pem"),
                                                        ca_sha256=hashlib.sha256(DER).hexdigest()))):
    check("%s is refused before any server is made" % what, connect_with(cfg) is not None and seen == [], seen)
check("a CA file whose contents changed is CaChanged (an InsecureConfig), so the sign-in can say so",
      raises(D.CaChanged, D._ca, dict(AD, ca_file=der, ca_sha256=hashlib.sha256(b"other").hexdigest())) is not None
      and issubclass(D.CaChanged, D.InsecureConfig))
check("...a CA file that can't be read is not CaChanged", raises(D.InsecureConfig, D._ca, dict(AD, ca_file=os.path.join(SP, "ca-missing.pem"),
      ca_sha256="x")) is not None and raises(D.CaChanged, D._ca, dict(AD, ca_file=os.path.join(SP, "ca-missing.pem"), ca_sha256="x")) is None)

print("== unreachable (no mock)")
D._STRATEGY = ldap3.SYNC; D._make_server = REAL_MAKE_SERVER
s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
t0 = time.time()
r = raises(D.Unreachable, D.connect, dict(AD, servers=["127.0.0.1"], port=port), "x@corp.example", "pw")
check("a closed port raises Unreachable within the timeout", r is not None and time.time() - t0 < 8, (r, time.time() - t0))

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

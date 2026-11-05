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
G_ALICE, G_BOB, G_BOBBY, G_ZED = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()

def tree(entries):
    srv = ldap3.Server("mock", get_info=ldap3.NONE)
    c = ldap3.Connection(srv, client_strategy=ldap3.MOCK_SYNC)
    for dn, attrs in entries: c.strategy.add_entry(dn, attrs)
    c.bind()
    D._make_server = lambda cfg, host: srv
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
check("DOMAIN\\user converts to the UPN with the first suffix", D.sign_in(AD, "CORP\\alice", "pw-alice").guid == u.guid)
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
check("alice maps to Admin through the nested group", D.role_for(AD, u.groups) == "Admin")

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

print("== unreachable (no mock)")
D._STRATEGY = ldap3.SYNC; D._make_server = REAL_MAKE_SERVER
s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
t0 = time.time()
r = raises(D.Unreachable, D.connect, dict(AD, servers=["127.0.0.1"], port=port), "x@corp.example", "pw")
check("a closed port raises Unreachable within the timeout", r is not None and time.time() - t0 < 8, (r, time.time() - t0))

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

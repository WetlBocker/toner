# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
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
G_ALICE, G_BOB = uuid.uuid4(), uuid.uuid4()

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
])
for upn, dn in (("alice@corp.example", "CN=Alice A,OU=Users," + BASE), ("bob@corp.example", "CN=Bob B,OU=Users," + BASE)):
    srv.dit[upn] = srv.dit[dn]      # AD binds by UPN; the mock only knows DNs
AD = {"id": "ab12", "name": "Corp", "kind": "ad", "servers": ["dc1.corp.example"], "port": 636, "security": "ldaps", "ca_file": "",
      "base_dn": BASE, "netbios": "CORP", "suffixes": ["corp.example"], "service_dn": "CN=svc,OU=Users," + BASE,
      "groups": {"Admin": ["Network-Admins"], "Engineer": ["Engineers"], "Tech": ["Tech-Desk"]}, "duo": {"on": False, "host": "", "ikey": ""}}

print("== Active Directory")
u = D.sign_in(AD, "alice@corp.example", "pw-alice")
check("the UPN form signs in", u.name == "alice@corp.example" and u.display == "Alice A" and u.enabled, u)
check("the GUID is text", u.guid == str(G_ALICE), u.guid)
check("groups include the nested one", set(u.groups) == {"Eng-Team", "Network-Admins", "Tech-Desk"}, u.groups)
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
check("test counts the groups", n == 3, n)

print("== roles")
check("Admin wins over Tech", D.role_for(AD, ["tech-desk", "NETWORK-ADMINS"]) == "Admin")
check("Tech alone", D.role_for(AD, ["Tech-Desk"]) == "Tech")
check("no match is None", D.role_for(AD, ["Other"]) is None and D.role_for(AD, []) is None)
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
])
LD = dict(AD, kind="ldap", base_dn=LB, suffixes=["example.org"], service_dn="cn=svc," + LB, groups={"Admin": ["Admins"], "Engineer": ["Eng"], "Tech": []})
c = D.sign_in(LD, "carol", "pw-carol")
check("LDAP signs in with uid=<user>,<base_dn>", c.name == "carol@example.org" and c.display == "Carol C" and c.enabled and c.guid == "11111111-2222-3333-4444-555555555555", c)
check("LDAP groups, nested", set(c.groups) == {"Eng", "Admins"}, c.groups)
check("LDAP role", D.role_for(LD, c.groups) == "Admin")
check("user@suffix works on LDAP", D.sign_in(LD, "carol@example.org", "pw-carol").guid == c.guid)
check("nsAccountLock true disables", D.sign_in(LD, "dave", "pw-dave").enabled is False)
check("pwdAccountLockedTime disables", D.sign_in(LD, "erin", "pw-erin").enabled is False)
check("LDAP wrong password", raises(D.BadCredentials, D.sign_in, LD, "carol", "bad") is not None)
f = D.look_up(LD, c.guid, "svc-pw")
check("LDAP look_up by entryUUID", f is not None and f.name == c.name, f)
check("LDAP look_up of a removed one is None", D.look_up(LD, "99999999-2222-3333-4444-555555555555", "svc-pw") is None)
n = D.test(LD, "svc-pw")
check("LDAP test counts the groups", n == 2, n)

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

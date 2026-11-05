"""Directory client: binds to Active Directory or LDAP over TLS, reads a person's groups and state, maps groups to roles.
No user-facing text lives here; exception messages are internal and never contain a password."""
import ssl, uuid
from dataclasses import dataclass

import ldap3
from ldap3.core import exceptions as lx
from ldap3.utils.dn import parse_dn

CONNECT_TIMEOUT = 3
RECEIVE_TIMEOUT = 10
ROLE_ORDER = ("Admin", "Engineer", "Tech")      # highest first
_STRATEGY = ldap3.SYNC                           # the tests swap in MOCK_SYNC
_MAX_GROUPS = 1000                               # stops a looping or huge nesting

AD_GROUP = "(objectClass=group)"
LDAP_GROUP = "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))"


class Unreachable(Exception): pass
class BadCredentials(Exception): pass
class InsecureConfig(ValueError): pass


@dataclass(frozen=True)
class User:
    guid: str
    name: str
    display: str
    groups: tuple
    enabled: bool


def check_config(cfg):
    if not cfg.get("servers"):
        raise InsecureConfig("no servers")
    if cfg.get("kind") not in ("ad", "ldap"):
        raise InsecureConfig("unknown kind")
    sec = cfg.get("security")
    if sec not in ("ldaps", "starttls"):
        raise InsecureConfig("TLS is required")
    if sec == "ldaps" and int(cfg.get("port") or 0) == 389:
        raise InsecureConfig("port 389 is not LDAPS")


def _make_server(cfg, host):
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=cfg.get("ca_file") or None)
    return ldap3.Server(host, port=int(cfg["port"]), use_ssl=cfg["security"] == "ldaps", tls=tls,
                        connect_timeout=CONNECT_TIMEOUT, get_info=ldap3.NONE)


def connect(cfg, who, password):
    check_config(cfg)
    if not who or not password:      # an empty password makes a SIMPLE bind anonymous, which "succeeds"
        raise BadCredentials("empty identity or password")
    down = None
    for host in cfg["servers"]:
        try:
            conn = ldap3.Connection(_make_server(cfg, host), user=who, password=password, authentication=ldap3.SIMPLE,
                                    client_strategy=_STRATEGY, receive_timeout=RECEIVE_TIMEOUT, raise_exceptions=True)
            conn.open()
            if cfg["security"] == "starttls":
                conn.start_tls()
            conn.bind()
            return conn
        except (lx.LDAPInvalidCredentialsResult, lx.LDAPBindError, lx.LDAPUserNameIsMandatoryError, lx.LDAPPasswordIsMandatoryError):
            raise BadCredentials("bind refused") from None
        except (lx.LDAPException, OSError):
            down = Unreachable(f"cannot use {host}")
    raise down


def _one(attrs, key, default=None):
    v = attrs.get(key)
    if isinstance(v, (list, tuple)):
        v = v[0] if v else None
    return default if v in (None, "", b"") else v


def _guid_text(v):
    if isinstance(v, (bytes, bytearray)):
        return str(uuid.UUID(bytes_le=bytes(v)))
    return str(v).strip("{}").lower()


def _first_rdn(dn):
    return parse_dn(dn)[0][1]


def _search(conn, base, flt, attrs, scope=ldap3.SUBTREE):
    try:
        conn.search(base, flt, search_scope=scope, attributes=attrs)
    except lx.LDAPNoSuchObjectResult:
        return []
    return [e for e in conn.response or [] if e.get("type", "searchResEntry") == "searchResEntry"]


def _groups(conn, cfg, dn, direct):
    """CNs of every group the entry is in, through nested groups. direct: the entry's own memberOf DNs (AD)."""
    ad = cfg["kind"] == "ad"
    esc = ldap3.utils.conv.escape_filter_chars
    seen, todo = {}, list(direct)
    if not ad:      # LDAP: groups naming the entry as a member
        todo = [e["dn"] for e in _search(conn, cfg["base_dn"], f"(|(member={esc(dn)})(uniqueMember={esc(dn)}))", ["cn"])]
    while todo and len(seen) < _MAX_GROUPS:
        g = todo.pop()
        if g.lower() in seen:
            continue
        seen[g.lower()] = _first_rdn(g)
        if ad:
            for e in _search(conn, g, "(objectClass=*)", ["memberOf"], ldap3.BASE):
                todo += list(e["attributes"].get("memberOf") or [])
        else:
            f = esc(g)
            todo += [e["dn"] for e in _search(conn, cfg["base_dn"], f"(|(member={f})(uniqueMember={f}))", ["cn"])]
    return tuple(sorted(seen.values(), key=str.lower))


def _user_from(conn, cfg, entry):
    a, dn, ad = entry["attributes"], entry["dn"], cfg["kind"] == "ad"
    first = (cfg.get("suffixes") or [""])[0]
    if ad:
        name = str(_one(a, "userPrincipalName") or "").lower()
        guid = _guid_text(_one(a, "objectGUID"))
        enabled = not (int(_one(a, "userAccountControl", 0)) & 2)
    else:
        uid = str(_one(a, "uid") or _first_rdn(dn)).lower()
        name = f"{uid}@{first}" if first else uid
        guid = _guid_text(_one(a, "entryUUID"))
        enabled = str(_one(a, "nsAccountLock", "false")).lower() != "true" and not _one(a, "pwdAccountLockedTime")
    display = str(_one(a, "displayName") or _one(a, "cn") or name)
    return User(guid, name, display, _groups(conn, cfg, dn, a.get("memberOf") or []), enabled)


_AD_ATTRS = ["objectGUID", "userPrincipalName", "displayName", "cn", "userAccountControl", "memberOf"]
_LDAP_ATTRS = ["uid", "entryUUID", "displayName", "cn", "nsAccountLock", "pwdAccountLockedTime"]


def _find(conn, cfg, flt):
    attrs = _AD_ATTRS if cfg["kind"] == "ad" else _LDAP_ATTRS
    found = _search(conn, cfg["base_dn"], flt, attrs)
    return _user_from(conn, cfg, found[0]) if found else None


def _split_login(cfg, login):
    """(bind identity, short user name). AD: DOMAIN\\user becomes user@<first suffix> when there is one, else binds as given.
    LDAP: the DN is built as uid=<user>,<base_dn> (no service account is available at sign-in to search for it)."""
    login = login.strip()
    if "\\" in login:
        short = login.split("\\", 1)[1]
        suffix = (cfg.get("suffixes") or [None])[0]
        who = f"{short}@{suffix}" if suffix else login
    elif "@" in login:
        short, who = login.split("@", 1)[0], login
    else:
        short, who = login, login
    if cfg["kind"] == "ldap":
        who = f"uid={ldap3.utils.dn.escape_rdn(short)},{cfg['base_dn']}"
    return who, short


def sign_in(cfg, login, password, service_password=None):
    """Binds as the person and reads their own entry and groups with that bind. service_password is unused (the vault is sealed)."""
    who, short = _split_login(cfg, login)
    conn = connect(cfg, who, password)
    try:
        esc = ldap3.utils.conv.escape_filter_chars
        if cfg["kind"] == "ad":
            flt = f"(&(objectClass=user)(|(userPrincipalName={esc(who)})(sAMAccountName={esc(short)})))"
        else:
            flt = f"(uid={esc(short)})"
        user = _find(conn, cfg, flt)
    except lx.LDAPException:
        raise Unreachable("read failed") from None
    finally:
        conn.unbind()
    if user is None:
        raise BadCredentials("entry not found")
    return user


def look_up(cfg, guid, service_password):
    conn = connect(cfg, cfg["service_dn"], service_password)
    try:
        if cfg["kind"] == "ad":
            raw = "".join(f"\\{b:02x}" for b in uuid.UUID(guid).bytes_le)
            return _find(conn, cfg, f"(&(objectClass=user)(objectGUID={raw}))")
        return _find(conn, cfg, f"(entryUUID={ldap3.utils.conv.escape_filter_chars(guid)})")
    except lx.LDAPException:
        raise Unreachable("read failed") from None
    finally:
        conn.unbind()


def role_for(cfg, groups):
    have = {g.lower() for g in groups}
    for role in ROLE_ORDER:
        if have & {g.lower() for g in cfg.get("groups", {}).get(role, [])}:
            return role
    return None


def test(cfg, service_password):
    conn = connect(cfg, cfg["service_dn"], service_password)
    try:
        flt = AD_GROUP if cfg["kind"] == "ad" else LDAP_GROUP
        return sum(1 for e in conn.extend.standard.paged_search(cfg["base_dn"], flt, attributes=["cn"], paged_size=500, generator=True)
                   if e.get("type") == "searchResEntry")
    except lx.LDAPException:
        raise Unreachable("read failed") from None
    finally:
        conn.unbind()

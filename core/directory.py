"""Directory client: binds to Active Directory or LDAP over TLS, reads a person's groups and state, maps groups to roles.
No user-facing text lives here; exception messages are internal and never contain a password."""
import hashlib, ssl, uuid
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
class Ambiguous(Exception): pass      # more than one group has that name
class NotFound(Exception): pass       # no group has that name


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


def _ca(cfg):
    """The CA file's contents for ldap3, read once and checked against the SHA-256 signed into the list (roles.set_directories),
    so a changed file is refused, not trusted. No CA file: None (the system store)."""
    if not cfg.get("ca_file"):
        return None
    try:
        with open(cfg["ca_file"], "rb") as f:
            data = f.read()
    except OSError:
        raise InsecureConfig("the CA file can't be read") from None
    if hashlib.sha256(data).hexdigest() != cfg.get("ca_sha256"):
        raise InsecureConfig("the CA file isn't the one signed")
    return data.decode("ascii", "ignore") if b"-----BEGIN" in data else data     # ssl's cadata takes PEM as text, DER as bytes


def _make_server(cfg, host, ca=None):
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_data=ca)
    return ldap3.Server(host, port=int(cfg["port"]), use_ssl=cfg["security"] == "ldaps", tls=tls,
                        connect_timeout=CONNECT_TIMEOUT, get_info=ldap3.NONE)


def connect(cfg, who, password):
    check_config(cfg)
    if not who or not password:      # an empty password makes a SIMPLE bind anonymous, which "succeeds"
        raise BadCredentials("empty identity or password")
    ca = _ca(cfg)
    down = None
    for host in cfg["servers"]:
        conn = None
        try:      # auto_referrals off: ldap3 would follow an ldap:// referral in clear text with the same user and password
            conn = ldap3.Connection(_make_server(cfg, host, ca), user=who, password=password, authentication=ldap3.SIMPLE,
                                    client_strategy=_STRATEGY, receive_timeout=RECEIVE_TIMEOUT, raise_exceptions=True, auto_referrals=False)
            conn.open()
            if cfg["security"] == "starttls" and not (conn.start_tls() and conn.tls_started):
                raise Unreachable(f"StartTLS failed on {host}")
            conn.bind()
            return conn
        except (lx.LDAPInvalidCredentialsResult, lx.LDAPBindError, lx.LDAPUserNameIsMandatoryError, lx.LDAPPasswordIsMandatoryError):
            _close(conn)
            raise BadCredentials("bind refused") from None
        except (lx.LDAPException, OSError, Unreachable):
            _close(conn)
            down = Unreachable(f"cannot use {host}")
    raise down


def _close(conn):
    try:
        if conn is not None: conn.unbind()
    except Exception:
        pass


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
    """The entries found. No such object is an empty list; any other non-success result (a referral, an error) is Unreachable."""
    try:
        conn.search(base, flt, search_scope=scope, attributes=attrs)
    except lx.LDAPNoSuchObjectResult:
        return []
    if (conn.result or {}).get("result", 0) != 0:
        raise Unreachable("search was not answered")
    return [e for e in conn.response or [] if e.get("type", "searchResEntry") == "searchResEntry"]


def _key(dn):
    return str(dn).casefold()      # DNs compared are only ever ones the server wrote; no unescaping, so no two different DNs meet


def _is_dn(text):
    try:
        parse_dn(text)
        return True
    except (lx.LDAPInvalidDnError, ValueError, TypeError):
        return False


def _groups(conn, cfg, dn, direct, uid=None):
    """DNs of every group the entry is in, through nested groups. direct: the entry's own memberOf DNs (AD). uid: for posixGroup memberUid."""
    ad = cfg["kind"] == "ad"
    esc = ldap3.utils.conv.escape_filter_chars

    def parents(d, uid=None):
        f = f"(member={esc(d)})(uniqueMember={esc(d)})" + (f"(memberUid={esc(uid)})" if uid else "")
        return [e["dn"] for e in _search(conn, cfg["base_dn"], f"(&{LDAP_GROUP}(|{f}))", ["cn"])]

    seen, todo = {}, list(direct) if ad else parents(dn, uid)
    while todo and len(seen) < _MAX_GROUPS:
        g = todo.pop()
        key = _key(g)
        if key in seen:
            continue
        seen[key] = g
        if ad:
            for e in _search(conn, g, "(objectClass=*)", ["memberOf"], ldap3.BASE):
                todo += list(e["attributes"].get("memberOf") or [])
        else:
            todo += parents(g)
    return tuple(sorted(seen.values(), key=str.lower))


def _user_from(conn, cfg, entry):
    a, dn, ad = entry["attributes"], entry["dn"], cfg["kind"] == "ad"
    first = (cfg.get("suffixes") or [""])[0]
    uid = None
    if ad:
        name = str(_one(a, "userPrincipalName") or "").lower()
        raw = (entry.get("raw_attributes") or {}).get("objectGUID")
        guid = _guid_text(raw[0] if raw else _one(a, "objectGUID"))
        enabled = not (int(_one(a, "userAccountControl", 0)) & 2)
    else:
        uid = str(_one(a, "uid") or _first_rdn(dn))
        name = f"{uid.lower()}@{first}" if first else uid.lower()
        guid = _guid_text(_one(a, "entryUUID"))
        enabled = str(_one(a, "nsAccountLock", "false")).lower() != "true" and not _one(a, "pwdAccountLockedTime")
    display = str(_one(a, "displayName") or _one(a, "cn") or name)
    return User(guid, name, display, _groups(conn, cfg, dn, a.get("memberOf") or [], uid), enabled)


_AD_ATTRS = ["objectGUID", "userPrincipalName", "displayName", "cn", "userAccountControl", "memberOf"]
_LDAP_ATTRS = ["uid", "entryUUID", "displayName", "cn", "nsAccountLock", "pwdAccountLockedTime"]


def _find(conn, cfg, base, flt, scope=ldap3.SUBTREE, many=BadCredentials):
    """The one user the search finds; None for none; `many` is raised for more than one (never guess which)."""
    found = _search(conn, base, flt, _AD_ATTRS if cfg["kind"] == "ad" else _LDAP_ATTRS, scope)
    if len(found) > 1:
        raise many("more than one entry")
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
    if not short.strip():
        raise BadCredentials("empty user name")
    if cfg["kind"] == "ldap":
        who = f"uid={ldap3.utils.dn.escape_rdn(short)},{cfg['base_dn']}"
    return who, short


def whoami_target(cfg, me):
    """Who Am I answer -> ("dn", DN) or ("sam", name). Only u:DOMAIN\\name with our NetBIOS domain, or dn:..., is accepted."""
    low = me.lower()
    if low.startswith("dn:") and me[3:].strip():
        return "dn", me[3:].strip()
    if low.startswith("u:"):
        dom, sep, sam = me[2:].partition("\\")
        if sep and sam and dom.casefold() == str(cfg.get("netbios") or "").casefold() and dom:
            return "sam", sam
    raise BadCredentials("unexpected identity")


def _who_am_i(conn):
    return conn.extend.standard.who_am_i() or ""


def sign_in(cfg, login, password, service_password=None):
    """Binds as the person and reads their own entry and groups with that bind. service_password is unused (the vault is sealed)."""
    who, short = _split_login(cfg, login)
    conn = connect(cfg, who, password)
    try:
        esc = ldap3.utils.conv.escape_filter_chars
        if cfg["kind"] == "ad":      # ask the server who the bind is, so a look-alike name can't pick another entry
            me = _who_am_i(conn)
            kind, target = whoami_target(cfg, me)
            if kind == "dn":
                user = _find(conn, cfg, target, "(objectClass=user)", ldap3.BASE)
            else:
                user = _find(conn, cfg, cfg["base_dn"], f"(&(objectClass=user)(sAMAccountName={esc(target)}))")
        else:
            user = _find(conn, cfg, who, "(objectClass=*)", ldap3.BASE)
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
            return _find(conn, cfg, cfg["base_dn"], f"(&(objectClass=user)(objectGUID={raw}))", many=Unreachable)
        return _find(conn, cfg, cfg["base_dn"], f"(entryUUID={ldap3.utils.conv.escape_filter_chars(guid)})", many=Unreachable)
    except lx.LDAPException:
        raise Unreachable("read failed") from None
    finally:
        conn.unbind()


def role_for(cfg, groups):
    """The highest role whose group DN is among the person's group DNs (both as the server wrote them; compared by case only)."""
    have = {_key(g) for g in groups}
    for role in ROLE_ORDER:
        if have & {_key(g) for g in cfg.get("groups", {}).get(role, [])}:
            return role
    return None


def resolve_groups(cfg, names, service_password):
    """{name: group DN}. A name is a CN or a DN. A CN is searched under base_dn; a DN is read back. Either way the DN is the server's."""
    conn = connect(cfg, cfg["service_dn"], service_password)
    gf = AD_GROUP if cfg["kind"] == "ad" else LDAP_GROUP
    out = {}
    try:
        for name in names:
            if _is_dn(name):      # a typed DN is read back, and the server's own form is what is stored
                found = _search(conn, name, gf, ["cn"], ldap3.BASE)
                if not found: raise NotFound(name)
                out[name] = found[0]["dn"]
            else:
                found = _search(conn, cfg["base_dn"], f"(&{gf}(cn={ldap3.utils.conv.escape_filter_chars(name)}))", ["cn"])
                if not found: raise NotFound(name)
                if len(found) > 1: raise Ambiguous(name)
                out[name] = found[0]["dn"]
    except lx.LDAPException:
        raise Unreachable("read failed") from None
    finally:
        conn.unbind()
    return out


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

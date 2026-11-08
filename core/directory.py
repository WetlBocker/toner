"""Directory client: binds to Active Directory or LDAP over TLS, reads a person's groups and state, maps groups to roles.
No user-facing text lives here; exception messages are internal and never contain a password."""
import hashlib, ssl, string, uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

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
class CaChanged(InsecureConfig): pass     # the CA file isn't the one signed into the list: an admin saves the directory again


@dataclass(frozen=True)
class User:
    guid: str
    name: str
    display: str
    groups: tuple
    enabled: bool
    dn: str = ""          # the entry's DN as the server wrote it (OU mappings compare against it)


def check_config(cfg):
    if cfg.get("kind") == "oidc":                       # an SSO connection: no servers or LDAP TLS, but https and an email domain
        from core import oidc, ssopresets
        issuer = cfg.get("issuer")
        try:
            parts = urlsplit(issuer) if isinstance(issuer, str) else None
            host = parts and parts.hostname
        except ValueError:
            host = None
        if not host or not (parts.scheme == "https" or (oidc._TEST_ALLOW_HTTP and parts.scheme == "http")):
            raise InsecureConfig("the issuer must be https")
        if cfg.get("provider") not in ssopresets.PRESETS:
            raise InsecureConfig("unknown provider")
        if not cfg.get("client_id"):
            raise InsecureConfig("no client ID")
        sx = cfg.get("suffixes")
        if not (isinstance(sx, list) and sx and all(isinstance(s, str) and s.strip() for s in sx)):
            raise InsecureConfig("no email domain")
        names = cfg.get("group_names", {})
        if not (isinstance(names, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in names.items())):
            raise InsecureConfig("bad group names")
        if cfg.get("everyone") is not None and cfg.get("everyone") not in ROLE_ORDER:
            raise InsecureConfig("bad role for everyone")
        return
    if "everyone" in cfg:                               # a role for everyone is for SSO only: a directory maps its OUs and groups
        raise InsecureConfig("everyone is for SSO only")
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
        raise CaChanged("the CA file isn't the one signed")
    return data.decode("ascii", "ignore") if b"-----BEGIN" in data else data     # ssl's cadata takes PEM as text, DER as bytes


def _make_server(cfg, host, ca=None):
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_data=ca)
    return ldap3.Server(host, port=int(cfg["port"]), use_ssl=cfg["security"] == "ldaps", tls=tls,
                        connect_timeout=CONNECT_TIMEOUT, get_info=ldap3.NONE)


def _open(cfg, host, ca, **credentials):
    """The connection to one server with TLS up (LDAPS, or StartTLS) and the certificate checked; not bound. It is closed again
    if opening fails. auto_referrals off: ldap3 would follow an ldap:// referral in clear text with the same user and password."""
    conn = None
    try:
        conn = ldap3.Connection(_make_server(cfg, host, ca), client_strategy=_STRATEGY, receive_timeout=RECEIVE_TIMEOUT,
                                raise_exceptions=True, auto_referrals=False, **credentials)
        conn.open()
        if cfg["security"] == "starttls" and not (conn.start_tls() and conn.tls_started):
            raise Unreachable(f"StartTLS failed on {host}")
        return conn
    except BaseException:
        _close(conn)
        raise


def reachable(cfg):
    """True if any server completes the TLS handshake (certificate checked as connect does). Never binds, sends no credential."""
    try:
        check_config(cfg)
        ca = _ca(cfg)
    except InsecureConfig:
        return False
    for host in cfg["servers"]:
        try:
            _close(_open(cfg, host, ca))
            return True
        except Exception:
            continue
    return False


def connect(cfg, who, password):
    check_config(cfg)
    if not who or not password:      # an empty password makes a SIMPLE bind anonymous, which "succeeds"
        raise BadCredentials("empty identity or password")
    ca = _ca(cfg)
    down = None
    for host in cfg["servers"]:
        conn = None
        try:
            conn = _open(cfg, host, ca, user=who, password=password, authentication=ldap3.SIMPLE)
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


_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


def _key(dn):
    """DNs compared are only ever ones the server wrote; no unescaping, so no two different DNs meet. Only ASCII letters fold:
    str.casefold would make "STRASSE" match "Straße" and a Kelvin sign match K, which a directory keeps apart."""
    return str(dn).translate(_ASCII_LOWER)


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
    return User(guid, name, display, _groups(conn, cfg, dn, a.get("memberOf") or [], uid), enabled, dn)


_AD_ATTRS = ["objectGUID", "userPrincipalName", "displayName", "cn", "userAccountControl", "memberOf"]
_LDAP_ATTRS = ["uid", "entryUUID", "displayName", "cn", "nsAccountLock", "pwdAccountLockedTime"]


def _find(conn, cfg, base, flt, scope=ldap3.SUBTREE, many=BadCredentials):
    """The one user the search finds; None for none; `many` is raised for more than one (never guess which)."""
    found = _search(conn, base, flt, _AD_ATTRS if cfg["kind"] == "ad" else _LDAP_ATTRS, scope)
    if len(found) > 1:
        raise many("more than one entry")
    return _user_from(conn, cfg, found[0]) if found else None


def _split_login(cfg, login):
    """(bind identity, short user name). AD: DOMAIN\\user binds as typed, and DOMAIN must be the directory's NetBIOS name.
    LDAP: the DN is built as uid=<user>,<base_dn> (no service account is available at sign-in to search for it)."""
    login = login.strip()
    if "\\" in login:
        dom, short = login.split("\\", 1)
        if cfg["kind"] == "ad" and (not dom or dom.casefold() != str(cfg.get("netbios") or "").casefold()):
            raise BadCredentials("another domain")
        who = login
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


def role_for(cfg, groups, dn=""):
    """The highest role whose group DN is among the person's group DNs, or whose OU holds the person's DN (in it or in an OU
    below it). All DNs as the server wrote them; compared by ASCII case only."""
    have, me = {_key(g) for g in groups}, _key(dn)
    for role in ROLE_ORDER:
        if have & {_key(g) for g in cfg.get("groups", {}).get(role, [])}:
            return role
        if me and any(_under(me, _key(ou)) for ou in (cfg.get("ous") or {}).get(role, [])):
            return role
    return cfg.get("everyone") if cfg.get("kind") == "oidc" and cfg.get("everyone") in ROLE_ORDER else None


def _under(me, ou):
    """True when DN `me` (folded) is below OU `ou` (folded): it ends in "," + ou and that comma isn't escaped (an even run of
    backslashes before it): an entry named "x,OU=IT" in the parent is not under OU=IT."""
    if not me.endswith("," + ou):
        return False
    head = me[:-len(ou) - 1]
    return bool(head) and (len(head) - len(head.rstrip("\\"))) % 2 == 0


def _config_nc(conn):
    """The configuration naming context, from the rootDSE (None when the server doesn't say)."""
    conn.search("", "(objectClass=*)", search_scope=ldap3.BASE, attributes=["configurationNamingContext"])
    for e in conn.response or []:
        nc = _one(e.get("attributes") or {}, "configurationNamingContext")
        if nc:
            return str(nc)
    return None


def _domain_dn(base_dn):
    """The domain's DN: base_dn's trailing DC= parts."""
    parts = []
    for attr, value, _ in reversed(parse_dn(base_dn)):
        if attr.lower() != "dc":
            break
        parts.append(f"DC={value}")
    return ",".join(reversed(parts))


def _netbios(conn, base_dn):
    nc, domain = _config_nc(conn), _domain_dn(base_dn)
    if not nc or not domain:
        raise Unreachable("no NetBIOS name found")
    esc = ldap3.utils.conv.escape_filter_chars
    found = _search(conn, "CN=Partitions," + nc, f"(&(objectClass=crossRef)(nCName={esc(domain)}))", ["nETBIOSName"])
    name = _one(found[0]["attributes"], "nETBIOSName") if len(found) == 1 else None
    if not name:
        raise Unreachable("no NetBIOS name found")
    return str(name)


def netbios(cfg, service_password):
    """AD: the domain's NetBIOS name, as the service account reads it: the nETBIOSName of the crossRef in CN=Partitions of the
    configuration naming context whose nCName is the domain's DN. Unreachable when it can't be read."""
    conn = connect(cfg, cfg["service_dn"], service_password)
    try:
        return _netbios(conn, cfg["base_dn"])
    except (lx.LDAPException, ValueError):
        raise Unreachable("read failed") from None
    finally:
        conn.unbind()


def _base_dn(conn, ad):
    """The base DN from the rootDSE: defaultNamingContext on AD, the first namingContexts value on LDAP (None when not said)."""
    attr = "defaultNamingContext" if ad else "namingContexts"
    conn.search("", "(objectClass=*)", search_scope=ldap3.BASE, attributes=[attr])
    for e in conn.response or []:
        v = _one(e.get("attributes") or {}, attr)
        if v:
            return str(v)
    return None


def discover(cfg, service_password):
    """What the Add flow fills in, read as the service account: {"base_dn", "netbios" (AD; "" on LDAP or when it can't be read,
    to be typed), "suffixes" (the DNS domain from the base DN's DC= parts)}. Unreachable when the base DN can't be read."""
    conn = connect(cfg, cfg["service_dn"], service_password)
    try:
        base = _base_dn(conn, cfg["kind"] == "ad")
        if not base:
            raise Unreachable("no base DN found")
        name = ""
        if cfg["kind"] == "ad":
            try:
                name = _netbios(conn, base)
            except (Unreachable, lx.LDAPException):
                pass
        domain = _domain_dn(base)
        dns = ".".join(v for _, v, _ in parse_dn(domain)).lower() if domain else ""
        return {"base_dn": base, "netbios": name, "suffixes": [dns] if dns else []}
    except (lx.LDAPException, ValueError):
        raise Unreachable("read failed") from None
    finally:
        conn.unbind()


def tree(cfg, service_password, cap=5000, text=""):
    """{"ous": [DN], "groups": [DN], "more": bool}: the OUs and groups under base_dn as the server wrote them, sorted ignoring
    case, at most `cap` of each; more when either kind had more. text: only those whose ou (OUs) or cn (groups) contains it."""
    esc = ldap3.utils.conv.escape_filter_chars
    kinds = (("ous", "ou", "(objectClass=organizationalUnit)"), ("groups", "cn", AD_GROUP if cfg["kind"] == "ad" else LDAP_GROUP))
    conn = connect(cfg, cfg["service_dn"], service_password)
    try:
        out = {}
        for kind, attr, flt in kinds:
            if text:
                flt = f"(&{flt}({attr}=*{esc(text)}*))"
            dns = []
            for e in conn.extend.standard.paged_search(cfg["base_dn"], flt, attributes=[attr], paged_size=500, generator=True):
                if e.get("type") == "searchResEntry":
                    dns.append(e["dn"])
                    if len(dns) > cap:
                        break
            out[kind] = dns
    except lx.LDAPException:
        raise Unreachable("read failed") from None
    finally:
        conn.unbind()
    more = any(len(v) > cap for v in out.values())
    return {k: sorted(v, key=str.lower)[:cap] for k, v in out.items()} | {"more": more}


def has_entry(cfg, dn, service_password):
    """True when the service account can read the entry `dn` (a Base DN typed after discovery is checked with it)."""
    conn = connect(cfg, cfg["service_dn"], service_password)
    try:
        return bool(_search(conn, dn, "(objectClass=*)", ["objectClass"], ldap3.BASE))
    except lx.LDAPException:
        raise Unreachable("read failed") from None
    finally:
        conn.unbind()


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

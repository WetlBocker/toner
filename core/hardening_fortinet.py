"""FortiGate hardening rules over a full-configuration backup (Fortinet's hardening guide). FortiOS prints only values that
differ from the default, so a missing line is read as the default. Rules get the parsed tree, not lines."""
from drivers.base import FAIL, WARN

WAN = {"https", "ssh", "http", "telnet", "snmp", "fgfm"}


def _unq(v):
    return v.replace('"', "")


def parse(text):
    """{'system interface': {entry name or None: {setting: value}}, ...}: every `config` section keyed by its own header
    words, its own `set` lines under None, each `edit` under its name. Nested sections are keyed the same way."""
    if not text.lstrip().startswith("#config-version"):
        raise ValueError("not a FortiOS configuration")
    tree, stack = {}, []
    for raw in text.splitlines():
        l = raw.strip()
        if l.startswith("config "):
            stack.append([l[7:], None])
            tree.setdefault(l[7:], {}).setdefault(None, {})
        elif not stack:
            continue
        elif l.startswith("edit "):
            stack[-1][1] = _unq(l[5:])
            tree[stack[-1][0]].setdefault(stack[-1][1], {})
        elif l.startswith(("set ", "unset ")):
            k, _, v = l.partition(" ")[2].partition(" ")
            key, name = stack[-1]
            tree[key].setdefault(name, {})[k] = _unq(v) if l.startswith("set") else ""
        elif l == "next":
            stack[-1][1] = None
        elif l == "end":
            stack.pop()
    return tree


def _entries(doc, section):
    return {k: v for k, v in doc.get(section, {}).items() if k is not None}


def _setting(doc, section, key, default=""):
    return doc.get(section, {}).get(None, {}).get(key, default)


def _n(items, one, many):
    return f"{len(items)} {one if len(items) == 1 else many}"


def _wan(doc):
    return {n for n, s in _entries(doc, "system interface").items() if s.get("role") == "wan" or n.startswith("wan")}


# ---------------------------------------------------------------- test(doc, platform, masked) -> None | reason | ("na", reason)
def wan_admin(doc, plat, masked):
    bad = [f"{n}: set allowaccess {s['allowaccess']}" for n, s in _entries(doc, "system interface").items()
           if n in _wan(doc) and set(s.get("allowaccess", "").split()) & WAN]
    return "; ".join(bad) or None


def telnet_http(doc, plat, masked):
    bad = [f"{n}: set allowaccess {s['allowaccess']}" for n, s in _entries(doc, "system interface").items()
           if set(s.get("allowaccess", "").split()) & {"telnet", "http"}]
    if _setting(doc, "system global", "admin-telnet") == "enable":
        bad.append("set admin-telnet enable")
    return "; ".join(bad) or None


def policy_any(doc, plat, masked):
    wan = _wan(doc) | {"any"}
    bad = [f"policy {n}{' ' + s['name'] if s.get('name') else ''}: accept all from {s['srcintf']}"
           for n, s in _entries(doc, "firewall policy").items()
           if s.get("action") == "accept" and s.get("status", "enable") != "disable" and set(s.get("srcintf", "").split()) & wan
           and "all" in s.get("srcaddr", "").split() and "all" in s.get("dstaddr", "").split() and "ALL" in s.get("service", "").split()]
    return "; ".join(bad) or None


def trusthost(doc, plat, masked):
    admins = _entries(doc, "system admin")
    bad = [n for n, s in admins.items() if not any(k.startswith(("trusthost", "ip6-trusthost")) for k in s)]
    return f"{len(bad)} of {len(admins)} admins without trusted hosts: {', '.join(bad)}" if bad else None


def default_admin(doc, plat, masked):
    return 'account "admin" exists' if "admin" in _entries(doc, "system admin") else None


def idle_timeout(doc, plat, masked):
    v = _setting(doc, "system global", "admintimeout", "5")
    return f"set admintimeout {v}" if v.isdigit() and int(v) > 10 else None


def weak_tls(doc, plat, masked):
    parts = []
    if _setting(doc, "system global", "strong-crypto") == "disable":
        parts.append("set strong-crypto disable")
    if _setting(doc, "system global", "ssl-static-key-ciphers", "enable") != "disable":
        parts.append("ssl-static-key-ciphers is not disabled (enable is the default)")
    return "; ".join(parts) or None


def snmp_v2c(doc, plat, masked):
    on = [n for n, s in _entries(doc, "system snmp community").items() if s.get("status", "enable") != "disable"]
    users = _entries(doc, "system snmp user")
    return f"{_n(on, 'SNMP v1/v2c community', 'SNMP v1/v2c communities')} enabled; {_n(users, 'SNMPv3 user', 'SNMPv3 users')}" if on else None


def syslog(doc, plat, masked):
    s = doc.get("log syslogd setting", {}).get(None, {})
    if s.get("status") != "enable":
        return "config log syslogd setting: status is not enable"
    if s.get("mode", "udp") == "udp":
        return "set mode udp (unencrypted)"
    return "set enc-algorithm disable" if s.get("enc-algorithm") == "disable" else None


def ntp_sync(doc, plat, masked):
    return "set ntpsync disable" if _setting(doc, "system ntp", "ntpsync") == "disable" else None


def password_policy(doc, plat, masked):
    return None if _setting(doc, "system password-policy", "status") == "enable" else "config system password-policy: status is not enable"


def private_data(doc, plat, masked):
    return None if _setting(doc, "system global", "private-data-encryption") == "enable" else "set private-data-encryption enable is not set"


def auto_install(doc, plat, masked):
    bad = [k for k in ("auto-install-config", "auto-install-image") if _setting(doc, "system auto-install", k) != "disable"]
    return f"{' and '.join(bad)} not set to disable" if bad else None


def dos_policy(doc, plat, masked):
    return None if _entries(doc, "firewall DoS-policy") or _entries(doc, "firewall DoS-policy6") else "no DoS policy"


RULES = [
    ("fg wan admin", "Admin access on a WAN interface", FAIL, wan_admin),
    ("fg telnet http", "Telnet or HTTP admin access", FAIL, telnet_http),
    ("fg policy any", "Policy accepting everything from a WAN interface", FAIL, policy_any),
    ("fg trusthost", "Admins without trusted hosts", WARN, trusthost),
    ("fg default admin", 'Default "admin" account present', WARN, default_admin),
    ("fg idle timeout", "Admin idle timeout over 10 minutes", WARN, idle_timeout),
    ("fg weak tls", "Weak TLS settings", WARN, weak_tls),
    ("fg snmp v2c", "SNMP v1/v2c community enabled", WARN, snmp_v2c),
    ("fg syslog", "No syslog server, or syslog unencrypted", WARN, syslog),
    ("fg ntp", "NTP sync off", WARN, ntp_sync),
    ("fg password policy", "Password policy off", WARN, password_policy),
    ("fg private data", "Private data encryption off", WARN, private_data),
    ("fg auto install", "USB auto-install on", WARN, auto_install),
    ("fg dos", "No DoS policy", WARN, dos_policy),
]

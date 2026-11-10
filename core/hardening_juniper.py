"""Junos hardening rules over `show configuration | no-more`, a brace hierarchy. The parse flattens it to the path of every
active statement, with applied groups merged in (`show configuration` does not merge them). Rules get that list."""
import re

from drivers.base import FAIL, WARN

WORDS = re.compile(r'"[^"]*"|[^\s\[\]]+')


def parse(text):
    """[path tuple, ...]: every statement and block as its words from the root, `inactive:` ones and their children left out,
    and each group named by apply-groups copied under the place that applies it. Group names with wildcards are not matched."""
    if not re.search(r"(?m)^\s*(version\s+\S+;|system\s*\{|interfaces\s*\{)", text):
        raise ValueError("not a Junos configuration")
    paths, stack = [], []
    for raw in text.splitlines():
        l = raw.strip()
        if not l or l.startswith(("#", "/*", "*")):
            continue
        if l == "}":
            stack and stack.pop()
            continue
        if l == "password <masked>":      # older stored backups: the masker ate the block's `{`
            l = "password {"
        opens = l.endswith("{")
        l = l.rstrip("{;").strip()
        inactive = l.startswith("inactive:")
        words = tuple(w.strip('"') for w in WORDS.findall(l.removeprefix("inactive:")))
        base, live = stack[-1] if stack else ((), True)
        path, live = base + words, live and not inactive
        if live and words:
            paths.append(path)
        if opens:
            stack.append((path, live))
    groups = {}
    for p in paths:
        if p[0] == "groups" and len(p) > 2:
            groups.setdefault(p[1], []).append(p[2:])
    doc = [p for p in paths if p[0] != "groups" and "apply-groups" not in p]
    for p in paths:
        if "apply-groups" in p and p[0] != "groups":
            i = p.index("apply-groups")
            doc += [p[:i] + rel for name in p[i + 1:] for rel in groups.get(name, [])]
    return doc


def _has(doc, *pre):
    return any(p[:len(pre)] == pre for p in doc)


def _kids(doc, *pre):
    """The words that follow `pre`, in order, once each."""
    return list(dict.fromkeys(p[len(pre)] for p in doc if p[:len(pre)] == pre and len(p) > len(pre)))


def _n(items, one, many):
    return f"{len(items)} {one if len(items) == 1 else many}"


def _delete(found):
    return "; ".join(f"{f}: delete system services {f}" for f in found) or None


# ---------------------------------------------------------------- test(doc, platform, masked) -> None | reason | ("na", reason)
def telnet_http(doc, plat, masked):
    return _delete([f for f, path in (("telnet", ("telnet",)), ("web-management http", ("web-management", "http")))
                    if _has(doc, "system", "services", *path)])


def services(doc, plat, masked):
    return _delete([s for s in ("ftp", "finger", "rlogin", "rsh", "xnm-clear-text") if _has(doc, "system", "services", s)])


def ssh_root(doc, plat, masked):
    return None if _has(doc, "system", "services", "ssh", "root-login", "deny") else "root-login deny is not set: set system services ssh root-login deny"


def lockout(doc, plat, masked):
    return None if _has(doc, "system", "login", "retry-options", "lockout-period") else "retry-options lockout-period is not set: set system login retry-options lockout-period 15"


def idle_timeout(doc, plat, masked):
    # shortcut: with no class defined there is nothing to name, so it passes; the built-in classes cannot be edited anyway
    vals = {c: (_kids(doc, "system", "login", "class", c, "idle-timeout") or [None])[0] for c in _kids(doc, "system", "login", "class")}
    none = not any(vals.values())
    bad = [(c, v) for c, v in vals.items() if (none and v is None) or (v is not None and v.isdigit() and int(v) > 10)]
    return "; ".join(f"class {c}: idle-timeout {v or 'not set'}: set system login class {c} idle-timeout 10" for c, v in bad) or None


def password_length(doc, plat, masked):
    n = (_kids(doc, "system", "login", "password", "minimum-length") or ["6"])[0]
    return f"minimum-length {n}: set system login password minimum-length 15" if n.isdigit() and int(n) < 15 else None


def banner(doc, plat, masked):
    return None if _has(doc, "system", "login", "message") else "no login message: set system login message"


def snmp_community(doc, plat, masked):
    bad = []
    for n in _kids(doc, "snmp", "community"):
        problems = (["name is public or private"] if n.lower() in ("public", "private") else []) \
            + (["authorization read-write"] if _has(doc, "snmp", "community", n, "authorization", "read-write") else [])
        if problems:
            bad.append(f"community {n}: {' and '.join(problems)}: rename it and set authorization read-only under snmp community")
    if not bad and any("<masked>" in n for n in _kids(doc, "snmp", "community")):
        from core.hardening import MASKED          # core.hardening imports this module, so not at the top
        return ("na", f"whether it is public or private cannot be told, {MASKED}")
    return "; ".join(bad) or None


def snmp_clients(doc, plat, masked):
    every = _kids(doc, "snmp", "community")
    bad = [n for n in every if not (_has(doc, "snmp", "community", n, "clients") or _has(doc, "snmp", "community", n, "client-list-name"))]
    return f"{len(bad)} of {len(every)} communities without clients: set snmp community {bad[0]} clients" if bad else None


def snmp_v2c(doc, plat, masked):
    comm = _kids(doc, "snmp", "community")
    users = {n for e in ("local-engine", "remote-engine") for n in _kids(doc, "snmp", "v3", "usm", e, "user")}
    return f"{_n(comm, 'community', 'communities')} (version 1 or 2c); {_n(users, 'SNMPv3 user', 'SNMPv3 users')}: move to snmp v3" if comm else None


def syslog(doc, plat, masked):
    return None if _has(doc, "system", "syslog", "host") else "no syslog host: set system syslog host"


def ntp(doc, plat, masked):
    return None if _has(doc, "system", "ntp", "server") else "no ntp server: set system ntp server"


def ntp_auth(doc, plat, masked):
    if not _has(doc, "system", "ntp", "server"):
        return None
    missing = [k for k in ("authentication-key", "trusted-key") if not _has(doc, "system", "ntp", k)]
    return f"{' and '.join(missing)} not set: set system ntp authentication-key and trusted-key" if missing else None


def lo0_filter(doc, plat, masked):
    # input-list is the same protection as input, so it counts
    ok = any(_has(doc, "interfaces", "lo0", "unit", "0", "family", "inet", "filter", k) for k in ("input", "input-list"))
    return None if ok else "lo0 unit 0: no family inet filter input: set interfaces lo0 unit 0 family inet filter input"


RULES = [
    ("jn telnet http", "Telnet or HTTP management on", FAIL, telnet_http),
    ("jn services", "Legacy services on", WARN, services),
    ("jn ssh root", "Root login over SSH allowed", WARN, ssh_root),
    ("jn lockout", "No lockout after failed logins", WARN, lockout),
    ("jn idle timeout", "Login class without idle timeout", WARN, idle_timeout),
    ("jn password length", "Password minimum under 15", WARN, password_length),
    ("jn banner", "No login banner", WARN, banner),
    ("jn snmp community", "SNMP community public or private, or read-write", FAIL, snmp_community),
    ("jn snmp clients", "SNMP community without clients", WARN, snmp_clients),
    ("jn snmp v2c", "SNMP version 1 or 2c in use", WARN, snmp_v2c),
    ("jn syslog", "No logging host", WARN, syslog),
    ("jn ntp", "No NTP server", WARN, ntp),
    ("jn ntp auth", "NTP not authenticated", WARN, ntp_auth),
    ("jn lo0 filter", "No filter on lo0", WARN, lo0_filter),
]

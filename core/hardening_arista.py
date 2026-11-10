"""Arista EOS hardening rules over `show running-config`, which prints non-default values only. IOS-like, so the line helpers
are core.hardening's (imported inside the functions: core.hardening imports this module)."""
import re

from drivers.base import FAIL, WARN

EOS = re.compile(r"(?m)^(! (device|Command): |service routing protocols model |transceiver qsfp |management (api|ssh|telnet|console|security|xmpp|cvx)\b|daemon \S+)")


def parse(text):
    if not EOS.search(text):
        raise ValueError("not an EOS configuration")
    from core import hardening
    return hardening._lines(text)


def _block(lines, head):
    from core import hardening
    return [b for h, b in hardening._blocks(lines, head) if h.rstrip() == head]


def _first(lines, head, rx):
    """The first group of `rx` among the lines under the `head` block, or None."""
    return next((m.group(1) for b in _block(lines, head) for x in b for m in [re.match(rx, x)] if m), None)


# ---------------------------------------------------------------- test(lines, platform, masked) -> None | reason | ("na", reason)
def telnet(lines, plat, masked):
    return "management telnet is on: set shutdown under management telnet" if any("no shutdown" in b for b in _block(lines, "management telnet")) else None


def http_api(lines, plat, masked):
    on = any("no shutdown" in b and any(re.match(r"protocol http(?!s)\b", x) for x in b) for b in _block(lines, "management api http-commands"))
    return "eAPI over HTTP: remove protocol http under management api http-commands" if on else None


def snmp_community(lines, plat, masked):
    from core import hardening as H
    comm = H._has(lines, r"snmp-server community ")
    bad = [l for l in comm if re.search(r"\bRW\b", l, re.I) or re.match(r"snmp-server community (public|private)\b", l, re.I)]
    if bad:
        return f"{H._q(bad[0])}: change the community and use ro (snmp-server community)"
    if H._masked_snmp(comm):
        return ("na", f"{H._n(comm, 'community', 'communities')}; whether one is public, private or read-write cannot be told, {H.MASKED}")
    return None


def snmp_v2c(lines, plat, masked):
    from core import hardening as H
    got = H.snmp_v2c(lines, plat, masked)
    return got and f"{got}: remove snmp-server community and use snmp-server user v3"


def snmp_acl(lines, plat, masked):
    from core import hardening as H
    comm = H._has(lines, r"snmp-server community ")
    if H._masked_snmp(comm):
        return ("na", f"{H._n(comm, 'community', 'communities')}; whether each has an access list cannot be told, {H.MASKED}")
    bad = [l for l in comm if not re.search(r"\b(ro|rw)\s+\S", l, re.I)]
    return H._of(bad, comm, "without an access list", "add one to snmp-server community") if bad else None


def ssh_acl(lines, plat, masked):
    ok = any(x.startswith("ip access-group ") for b in _block(lines, "management ssh") for x in b)
    return None if ok else "no ip access-group under management ssh: add one"


def idle_timeout(lines, plat, masked):
    out = []
    for what in ("console", "ssh"):
        v = _first(lines, "management " + what, r"idle-timeout (\d+)$")
        if v is None or int(v) == 0 or int(v) > 10:
            out.append(f"management {what}: idle-timeout {v or 'not set'}: set idle-timeout 10")
    return "; ".join(out) or None


def lockout(lines, plat, masked):
    from core import hardening as H
    return None if H._has(lines, r"aaa authentication policy lockout ") else "aaa authentication policy lockout is not set: set aaa authentication policy lockout failure 3 duration 900"


def password_length(lines, plat, masked):
    n = _first(lines, "management security", r"password minimum length (\d+)$")
    return f"password minimum length {n or 'not set'}: set password minimum length 15 under management security" if n is None or int(n) < 15 else None


def banner(lines, plat, masked):
    from core import hardening as H
    return None if H._has(lines, r"banner (login|motd)\b") else "no banner login or banner motd: set one"


def logging_host(lines, plat, masked):
    from core import hardening as H
    return None if H._has(lines, r"logging (vrf \S+ )?host ") else "no logging host: set logging host"


def ntp(lines, plat, masked):
    from core import hardening as H
    return None if H._has(lines, r"ntp server ") else "no ntp server: set ntp server"


def ntp_auth(lines, plat, masked):
    from core import hardening as H
    if not H._has(lines, r"ntp server "):
        return None
    return None if H._has(lines, r"ntp authenticate\b") else "ntp authenticate is not set: set ntp authenticate servers and ntp trusted-key"


def accounting(lines, plat, masked):
    from core import hardening as H
    return None if H._has(lines, r"aaa accounting ") else "no aaa accounting: set aaa accounting commands all default start-stop logging"


RULES = [
    ("ar telnet", "Telnet on", FAIL, telnet),
    ("ar http api", "eAPI over plain HTTP", FAIL, http_api),
    ("ar snmp community", "SNMP community public, private or read-write", FAIL, snmp_community),
    ("ar snmp v2c", "SNMP version 1 or 2c in use", WARN, snmp_v2c),
    ("ar snmp acl", "SNMP community without an access list", WARN, snmp_acl),
    ("ar ssh acl", "SSH without an access list", WARN, ssh_acl),
    ("ar idle timeout", "No idle timeout", WARN, idle_timeout),
    ("ar lockout", "No lockout after failed logins", WARN, lockout),
    ("ar password length", "Password minimum under 15", WARN, password_length),
    ("ar banner", "No login banner", WARN, banner),
    ("ar logging", "No logging host", WARN, logging_host),
    ("ar ntp", "No NTP server", WARN, ntp),
    ("ar ntp auth", "NTP not authenticated", WARN, ntp_auth),
    ("ar accounting", "No AAA accounting", WARN, accounting),
]

"""HPE Aruba hardening rules over `show running-config` on AOS-CX and ArubaOS-Switch (AOS-S, ProCurve). The two differ, so a rule
that could not be confirmed on a platform says it does not apply there. Rules get the config's lines (core.hardening's helpers,
imported inside the functions: core.hardening imports this module)."""
import re

from drivers.base import FAIL, WARN

CX, OS = "aruba_aoscx", "aruba_osswitch"
HPE = re.compile(r"(?m)^(!Version ArubaOS-CX|; .*Configuration Editor|; J[A-Z]?\d{4}\w? )")


def parse(text):
    if not HPE.search(text):
        raise ValueError("not an Aruba configuration")
    from core import hardening
    return hardening._lines(text)


def _plat(lines, plat):
    """The platform: the device's, else read from the header (AOS-CX prints `!Version ArubaOS-CX`)."""
    return plat if plat in (CX, OS) else CX if any(l.startswith("!Version ArubaOS-CX") for l in lines) else OS


def _not_here():
    from core import hardening
    return ("na", hardening.NOT_HERE)


def _has(lines, rx):
    from core import hardening
    return hardening._has(lines, rx)


# ---------------------------------------------------------------- test(lines, platform, masked) -> None | reason | ("na", reason)
def telnet(lines, plat, masked):
    if _plat(lines, plat) == CX:
        return _not_here()
    return None if _has(lines, r"no telnet-server\s*$") else "no telnet-server is not set: set no telnet-server"


def http(lines, plat, masked):
    if _plat(lines, plat) == CX:
        return _not_here()
    return None if _has(lines, r"no web-management(\s+plaintext)?\s*$") else "no web-management plaintext is not set: set web-management ssl and no web-management plaintext"


def snmp_community(lines, plat, masked):
    from core import hardening as H
    comm = H._has(lines, r"snmp-server community ")
    bad = H._has(comm, r'snmp-server community "?(public|private)"?(\s|$)')
    if bad:
        return f"{H._q(bad[0])}: change it (snmp-server community)"
    if H._masked_snmp(comm):
        return ("na", f"{H._n(comm, 'community', 'communities')}; whether one is public or private cannot be told, {H.MASKED}")
    return None


def snmp_v2c(lines, plat, masked):
    from core import hardening as H
    comm = H._has(lines, r"snmp-server community ")
    if not comm or (_plat(lines, plat) == OS and _has(lines, r"snmpv3 only\s*$")):
        return None
    return f"{H._n(comm, 'community', 'communities')}: remove snmp-server community and use SNMPv3 (snmpv3 only on ArubaOS-Switch)"


def lockout(lines, plat, masked):
    if _plat(lines, plat) == OS:
        return None if _has(lines, r"aaa authentication lockout-delay\s+\d") else "aaa authentication lockout-delay is not set: set aaa authentication lockout-delay"
    if _has(lines, r"aaa authentication login \S+ group "):         # remote AAA: the local limit cannot be set
        return ("na", "Remote AAA is in use, so a local lockout cannot be set.")
    return None if _has(lines, r"aaa authentication limit-login-attempts \d+ lockout-time \d+") else "aaa authentication limit-login-attempts is not set: set aaa authentication limit-login-attempts"


def password_length(lines, plat, masked):
    from core import hardening
    cx = _plat(lines, plat) == CX
    setting = "aaa authentication minimum-password-length" if cx else "password minimum-length"
    n = next((int(m.group(1)) for l in lines for m in [re.match(rf"{setting} (\d+)\s*$", l)] if m), None)
    if n is None and "password <masked>" in lines:                # older stored backups: the masker ate the line
        return ("na", f"the minimum length, {hardening.MASKED}")
    return f"{setting} {'not set' if n is None else n}: set {setting} 15" if n is None or n < 15 else None


def timeout(lines, plat, masked):
    if _plat(lines, plat) == OS:
        return _not_here()
    v = next((m.group(1) for l in lines for m in [re.match(r"session-timeout (\d+)\s*$", l)] if m), "30")     # the default is 30
    return f"session-timeout {v}: set session-timeout 10" if int(v) == 0 or int(v) > 10 else None


def banner(lines, plat, masked):
    return None if _has(lines, r"banner (motd|exec)\b") else "no banner motd or banner exec: set one"


def logging_host(lines, plat, masked):
    return None if _has(lines, r"logging (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F]*:[0-9a-fA-F:]+|[\w-]+(\.[\w-]+)+)(\s|$)") else "no logging host: set logging {server}"


def ntp(lines, plat, masked):
    return None if _has(lines, r"s?ntp server\b") else "no ntp server: set ntp server"


def ntp_auth(lines, plat, masked):
    if _plat(lines, plat) == OS:
        return _not_here()
    if not _has(lines, r"ntp server\b"):
        return None
    missing = [w for w, rx in (("ntp authentication", r"ntp authentication(\s+enable)?\s*$"), ("ntp authentication-key", r"ntp authentication-key "))
               if not _has(lines, rx)]
    return f"{' and '.join(missing)} not set: set ntp authentication and ntp authentication-key" if missing else None


def mgmt_acl(lines, plat, masked):
    if _plat(lines, plat) == CX:
        return _not_here()
    return None if _has(lines, r"ip authorized-managers?(\s|$)") else "no ip authorized-manager: add ip authorized-manager lines"


def accounting(lines, plat, masked):
    return None if _has(lines, r"aaa accounting\b") else "no aaa accounting: set aaa accounting"


RULES = [
    ("hp telnet", "Telnet on", FAIL, telnet),
    ("hp http", "HTTP management on", FAIL, http),
    ("hp snmp community", "SNMP community public or private", FAIL, snmp_community),
    ("hp snmp v2c", "SNMP version 1 or 2c in use", WARN, snmp_v2c),
    ("hp lockout", "No lockout after failed logins", WARN, lockout),
    ("hp password length", "Password minimum under 15", WARN, password_length),
    ("hp timeout", "Session timeout over 10 minutes", WARN, timeout),
    ("hp banner", "No login banner", WARN, banner),
    ("hp logging", "No logging host", WARN, logging_host),
    ("hp ntp", "No NTP server", WARN, ntp),
    ("hp ntp auth", "NTP not authenticated", WARN, ntp_auth),
    ("hp mgmt acl", "Management not limited by address", WARN, mgmt_acl),
    ("hp accounting", "No AAA accounting", WARN, accounting),
]

"""Configuration hardening rules for the Scanning section: a device's newest configuration backup, read offline against a rule
list (Cisco first: IOS, IOS XE, NX-OS, ASA), one row per rule with what was found. Stored backups mask passwords and
communities, so the two rules that need the secret itself say so instead of guessing."""
import re

from core import backup, db
from drivers.base import FAIL, NA, OK, WARN, Result

IOS, XE, NXOS, ASA = "cisco_ios", "cisco_xe", "cisco_nxos", "cisco_asa"
ALL = (IOS, XE, NXOS, ASA)
NO_BACKUP = "No configuration backup to read. Configs > Back up now reads one."
NO_RULES = "No hardening rules for this vendor yet."
MASKED = "the stored backup masks it (Settings > Config backups)"
NOT_HERE = "Does not apply to this platform."


def _blocks(lines, start):
    """[(header line, [indented lines under it])] for every line that starts with `start`."""
    out, i = [], 0
    while i < len(lines):
        if lines[i].startswith(start):
            head, body = lines[i], []
            i += 1
            while i < len(lines) and (lines[i].startswith(" ") or lines[i].startswith("\t")):
                body.append(lines[i].strip())
                i += 1
            out.append((head, body))
        else:
            i += 1
    return out


def _has(lines, rx):
    return [l for l in lines if re.match(rx, l, re.I)]


# ---------------------------------------------------------------- the rules: (key, label, severity, platforms, test)
# test(lines, platform, masked) -> None when the rule is kept, else the finding (a short reason) or ("na", reason)
def telnet(lines, plat, masked):
    if plat == ASA:
        hits = _has(lines, r"telnet \d")
        return f"{len(hits)} telnet line{'s' if len(hits) != 1 else ''} allow it: {hits[0]}" if hits else None
    if plat == NXOS:
        return "feature telnet is on" if _has(lines, r"feature telnet$") else None
    bad = []
    for head, body in _blocks(lines, "line vty"):
        ti = [b for b in body if b.startswith("transport input")]
        if not ti:
            bad.append(f"{head} has no transport input (the default allows telnet)")
        elif any(re.search(r"\b(telnet|all)\b", b) for b in ti):
            bad.append(f"{head}: {ti[0]}")
    return "; ".join(bad) or None


def http(lines, plat, masked):
    return "ip http server is on" if _has(lines, r"ip http server$") else None


def snmp_community(lines, plat, masked):
    comm = _has(lines, r"snmp-server community ")
    rw = [l for l in comm if re.search(r"\bRW\b", l, re.I)]
    if rw:
        return f"read-write community: {rw[0]}"
    weak = [l for l in comm if re.match(r"snmp-server community (public|private)\b", l, re.I)]
    if weak:
        return f"well-known community: {weak[0]}"
    if _masked_snmp(comm):
        return ("na", f"{_n(comm, 'community', 'communities')}; whether one is public, private or read-write cannot be told, {MASKED}")
    return None


def _masked_snmp(comm):
    return any("<masked>" in l for l in comm)


def _n(items, one, many):
    return f"{len(items)} {one if len(items) == 1 else many}"


def enable_password(lines, plat, masked):
    if plat == ASA:
        return ("na", NOT_HERE)
    return "enable password is set and enable secret is not" if _has(lines, r"enable password ") and not _has(lines, r"enable secret ") else None


def vty_login(lines, plat, masked):
    if plat == ASA:
        return ("na", NOT_HERE)
    bad = [head for head, body in _blocks(lines, "line vty") if not any(re.match(r"login\b", b) for b in body) or "no login" in body]
    aaa = bool(_has(lines, r"aaa new-model$")) or plat == NXOS
    if bad:
        return f"no login on {', '.join(bad)}" + ("" if aaa else "; aaa new-model is off")
    return None if aaa else "aaa new-model is off"


def type7(lines, plat, masked):
    if plat in (ASA, NXOS):
        return ("na", NOT_HERE)
    weak = _has(lines, r".*\b(password|key) 7 \S")
    if weak:
        return f"type 7 (reversible) secrets: {weak[0].strip()}"
    if not _has(lines, r"service password-encryption$"):
        return "service password-encryption is off"
    return ("na", f"service password-encryption is on; whether type 7 secrets remain cannot be told, {MASKED}") if masked else None


def ssh2(lines, plat, masked):
    if plat == NXOS:
        return ("na", NOT_HERE)
    want = r"ssh version 2$" if plat == ASA else r"ip ssh version 2$"
    return None if _has(lines, want) else ("ssh version 2 is not set" if plat == ASA else "ip ssh version 2 is not set")


def exec_timeout(lines, plat, masked):
    if plat in (ASA, NXOS):
        return ("na", NOT_HERE)
    bad = []
    for head, body in _blocks(lines, "line "):
        if not head.startswith(("line con", "line vty", "line aux")):
            continue
        et = [b for b in body if b.startswith("exec-timeout")]
        if et and re.match(r"exec-timeout 0( 0)?$", et[0]):             # no line at all: the default, 10 minutes
            bad.append(f"{head}: {et[0]} never times out")
    return "; ".join(bad) or None


def banner(lines, plat, masked):
    return None if _has(lines, r"banner (login|motd)\b") else "no banner login or banner motd"


def logging_host(lines, plat, masked):
    rx = {NXOS: r"logging server ", ASA: r"logging host "}.get(plat, r"logging (host |\d)")
    return None if _has(lines, rx) else "no logging host"


def ntp(lines, plat, masked):
    return None if _has(lines, r"ntp server ") else "no ntp server"


def services(lines, plat, masked):
    if plat in (ASA, NXOS):
        return ("na", NOT_HERE)
    bad = []
    if not _has(lines, r"no ip source-route$"):
        bad.append("ip source-route is on (the default)")
    if _has(lines, r"service (tcp|udp)-small-servers$"):
        bad.append("service tcp-small-servers is on")
    if _has(lines, r"ip finger$"):
        bad.append("ip finger is on")
    if [b for _h, body in _blocks(lines, "interface ") for b in body if b == "ip directed-broadcast"]:
        bad.append("ip directed-broadcast is on")
    return "; ".join(bad) or None


def snmp_acl(lines, plat, masked):
    comm = _has(lines, r"snmp-server community ")
    if _masked_snmp(comm):
        return ("na", f"{_n(comm, 'community', 'communities')}; whether each has an access list cannot be told, {MASKED}")
    loose = [l for l in comm if not re.search(r"\b(RO|RW)\s+\S+\s*$", l, re.I)]
    return f"{len(loose)} of {len(comm)} without an access list: {loose[0]}" if loose else None


RULES = [
    ("telnet", "Telnet allowed on VTY lines", FAIL, telnet),
    ("http", "HTTP server on", FAIL, http),
    ("snmp community", "SNMP community public, private or read-write", FAIL, snmp_community),
    ("enable password", "enable password instead of enable secret", FAIL, enable_password),
    ("vty login", "VTY lines without login, or no aaa new-model", FAIL, vty_login),
    ("type 7", "Type 7 passwords, or service password-encryption off", WARN, type7),
    ("ssh version", "SSH not forced to version 2", WARN, ssh2),
    ("exec-timeout", "exec-timeout 0 on console or VTY lines", WARN, exec_timeout),
    ("banner", "No login banner", WARN, banner),
    ("logging", "No logging host", WARN, logging_host),
    ("ntp", "No NTP server", WARN, ntp),
    ("services", "ip source-route, tcp-small-servers, ip finger or directed-broadcast on", WARN, services),
    ("snmp acl", "SNMP community without an access list", WARN, snmp_acl),
]
LABELS = {k: label for k, label, _s, _t in RULES}
PREFIX = "Hardening: "                      # the check name of a rule's row; display.check_name leaves it as written


def rules_off():
    return set(db.get_setting("hardening_off") or [])


def findings(text, platform, off=()):
    """[(rule key, status, message)] for one configuration's text: every rule that is on, in order."""
    text = text or ""
    lines = [l.rstrip() for l in text.replace("\r\n", "\n").split("\n")]
    masked = "<masked>" in text
    plat = platform if platform in ALL else IOS
    out = []
    for key, label, sev, test in RULES:
        if key in off:
            continue
        got = test(lines, plat, masked)
        if got is None:
            out.append((key, OK, "not found"))
        elif isinstance(got, tuple):
            out.append((key, NA, got[1]))
        else:
            out.append((key, sev, got))
    return out


def scan(dev):
    """The hardening rows of one device: one per rule over its newest stored backup, or one row saying why there are none."""
    name, org = dev["name"], dev.get("org")
    row = lambda check, status, message="": Result(name, check, status, "", message, org=org)
    if (dev.get("vendor") or "") != "cisco":
        return [row(PREFIX.rstrip(": "), NA, NO_RULES)]
    off = rules_off()
    if len(off) >= len(RULES):
        return []
    latest = backup.latest(dev.get("key") or name)
    if not latest:
        return [row(PREFIX.rstrip(": "), NA, NO_BACKUP)]
    text = backup.get_text(latest["id"], latest.get("org"))
    taken = (latest.get("taken_at") or "")[:16]
    return [row(PREFIX + LABELS[key], status, f"{message} (backup of {taken})" if status in (WARN, FAIL) and taken else message)
            for key, status, message in findings(text, dev.get("platform") or "", off)]

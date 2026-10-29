"""Configuration hardening rules for the Scanning section: a device's newest configuration backup, read offline against a rule
list, one row per rule with what was found. Cisco (IOS, IOS XE, NX-OS, ASA) lives here; FortiGate and Palo Alto in
hardening_fortinet.py and hardening_paloalto.py. Stored backups mask passwords and communities, so the rules that need
the secret itself say so instead of guessing."""
import re

from core import backup, db
from drivers.base import FAIL, NA, OK, WARN, Result

IOS, XE, NXOS, ASA = "cisco_ios", "cisco_xe", "cisco_nxos", "cisco_asa"
ALL = (IOS, XE, NXOS, ASA)
NO_BACKUP = "No configuration backup to read. Configs > Back up now reads one."
NO_RULES = "No hardening rules for this vendor yet."
UNREADABLE = "The backup could not be read as a {} configuration."
MASKED = "the stored backup masks it (Settings > Config backups)"
NOT_HERE = "Does not apply to this platform."
NOT_SWITCH = "Not a switch configuration."


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


def _n(items, one, many):
    return f"{len(items)} {one if len(items) == 1 else many}"


def _in(body, rx):
    return [b for b in body if re.match(rx, b, re.I)]


def _switch(lines):
    return bool(_has(lines, r"\s*switchport\b"))


def _access_ports(lines):
    return [(h, b) for h, b in _blocks(lines, "interface ") if "switchport mode access" in b]


def _of(bad, every, what, first):
    return f"{len(bad)} of {len(every)} {what}: {first}"


# ---------------------------------------------------------------- the rules: (key, label, severity, test)
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
    if plat == NXOS:
        return ("na", NOT_HERE)
    if plat == ASA:
        ct = _has(lines, r"console timeout (\d+)")
        return None if ct and not ct[0].endswith(" 0") else f"{ct[0] if ct else 'console timeout 0 (the default)'} never times out"
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
    for rx, what in ((r"service (tcp|udp)-small-servers$", "service tcp-small-servers"), (r"ip finger$", "ip finger"),
                     (r"ip bootp server$", "ip bootp server"), (r"service pad$", "service pad"), (r"service config$", "service config")):
        if _has(lines, rx):
            bad.append(f"{what} is on")
    if [b for _h, body in _blocks(lines, "interface ") for b in body if b == "ip directed-broadcast"]:
        bad.append("ip directed-broadcast is on")
    return "; ".join(bad) or None


def snmp_acl(lines, plat, masked):
    comm = _has(lines, r"snmp-server community ")
    if _masked_snmp(comm):
        return ("na", f"{_n(comm, 'community', 'communities')}; whether each has an access list cannot be told, {MASKED}")
    loose = [l for l in comm if not re.search(r"\b(RO|RW)\s+\S+\s*$", l, re.I)]
    return f"{len(loose)} of {len(comm)} without an access list: {loose[0]}" if loose else None


# ---- 1.11.3: the IOS XE hardening guide, the ASA best practices, the Catalyst and switch guides
def access_class(lines, plat, masked):
    if plat == ASA:
        hits = _has(lines, r"(ssh|http) 0\.0\.0\.0 0\.0\.0\.0 ")
        return f"management from anywhere: {hits[0]}" if hits else None
    bad = [head for head, body in _blocks(lines, "line vty") if not _in(body, r"access-class \S+ in\b")]
    return f"no access-class on {', '.join(bad)}" if bad else None


def lockout(lines, plat, masked):
    if plat == NXOS:
        return ("na", NOT_HERE)
    return None if _has(lines, r"aaa local authentication attempts max-fail \d") else "aaa local authentication attempts max-fail is not set"


def accounting(lines, plat, masked):
    return None if _has(lines, r"aaa accounting ") else "no aaa accounting"


def snmp_v2c(lines, plat, masked):
    comm = _has(lines, r"snmp-server community ")
    users = _has(lines, r"snmp-server user .* v3\b")
    return f"{_n(comm, 'community', 'communities')} (version 1 or 2c); {_n(users, 'SNMPv3 user', 'SNMPv3 users')}" if comm else None


def type5(lines, plat, masked):
    if plat in (ASA, NXOS):
        return ("na", NOT_HERE)
    weak = _has(lines, r".*\bsecret 5 \S")
    if weak:
        return f"type 5 (MD5) secrets: {weak[0].strip()}"
    return ("na", f"whether type 5 secrets remain cannot be told, {MASKED}") if masked and _has(lines, r".*\bsecret <masked>") else None


def log_timestamps(lines, plat, masked):
    if plat == NXOS:
        return ("na", NOT_HERE)
    if plat == ASA:
        return None if _has(lines, r"logging timestamp") else "logging timestamp is not set"
    return None if _has(lines, r"service timestamps log datetime") else "service timestamps log datetime is not set"


def smart_install(lines, plat, masked):
    if plat != IOS:
        return ("na", NOT_HERE)
    return None if _has(lines, r"no vstack$") else "no vstack is not set (Smart Install is on by default on IOS switches)"


def icmp_redirects(lines, plat, masked):
    if plat == ASA:
        return ("na", NOT_HERE)
    routed = [(h, b) for h, b in _blocks(lines, "interface ") if _in(b, r"ip address \d") and not h.startswith("interface Loopback")]
    parts = []
    for want in ("no ip redirects",) + (("no ip proxy-arp",) if plat != NXOS else ()):
        bad = [h for h, b in routed if want not in b]
        if bad:
            parts.append(_of(bad, routed, f"routed interfaces without {want}", bad[0]))
    return "; ".join(parts) or None


def routing_auth(lines, plat, masked):
    parts = []
    ifaces = _blocks(lines, "interface ")
    body_all = [b for _h, body in ifaces for b in body]
    for head, body in _blocks(lines, "router bgp"):
        if plat == NXOS:
            peers, pw = _in(body, r"neighbor \S+$"), _in(body, r"password ")
        else:
            peers = {b.split()[1] for b in _in(body, r"neighbor \S+ remote-as ")}
            pw = {b.split()[1] for b in _in(body, r"neighbor \S+ password ")}
            groups = {b.split()[1]: b.split()[3] for b in _in(body, r"neighbor \S+ peer-group \S+$")}
            peers = [p for p in peers if p not in pw and groups.get(p) not in pw]
        miss = max(len(peers) - len(pw), 0) if plat == NXOS else len(peers)
        if miss:
            parts.append(f"{head}: {miss} neighbor{'s' if miss != 1 else ''} without a password")
    auth = {"ospf": r"(ip )?ospf (authentication|message-digest-key)", "eigrp": r"(ip )?authentication (mode|key-chain) eigrp",
            "rip": r"(ip )?rip authentication"}
    for proto, rx in auth.items():
        for head, body in _blocks(lines, f"router {proto}"):
            if not (_in(body_all, rx) or _in(body, r"(area \S+ )?authentication") or _in(body, r"authentication (mode|key-chain)")):
                parts.append(f"{head}: no authentication")
    for head, body in ifaces:
        for fhrp in ("standby", "vrrp", "glbp"):
            groups = {b.split()[1] for b in _in(body, fr"{fhrp} \d+ (ip|address|ipv4)\b")} | ({b.split()[1] for b in _in(body, fr"{fhrp} \d+$")} if plat == NXOS else set())
            bad = [g for g in groups if not _in(body, fr"{fhrp} {g} authentication") and not _in(body, r"authentication ")]
            if bad:
                parts.append(f"{head}: {fhrp} {bad[0]} without authentication")
    return "; ".join(parts) or None


def ntp_auth(lines, plat, masked):
    if not _has(lines, r"ntp server "):
        return None
    missing = [w for w in ("ntp authenticate", "ntp trusted-key") if not _has(lines, w + r"\b")]
    return f"{' and '.join(missing)} not set" if missing else None


def dhcp_snooping(lines, plat, masked):
    if plat == ASA:
        return ("na", NOT_HERE)
    if not _switch(lines):
        return ("na", NOT_SWITCH)
    if plat == NXOS:
        return None if _has(lines, r"feature dhcp$") and _has(lines, r"ip dhcp snooping$") else "feature dhcp with ip dhcp snooping is not set"
    return None if _has(lines, r"ip dhcp snooping$") else "ip dhcp snooping is not set"


def arp_inspection(lines, plat, masked):
    if plat == ASA:
        return ("na", NOT_HERE)
    if not _switch(lines):
        return ("na", NOT_SWITCH)
    return None if _has(lines, r"ip arp inspection vlan ") else "ip arp inspection vlan is not set"


def bpdu_guard(lines, plat, masked):
    if plat == ASA:
        return ("na", NOT_HERE)
    if not _switch(lines):
        return ("na", NOT_SWITCH)
    if _has(lines, r"spanning-tree (portfast|port type edge) bpduguard default$"):
        return None
    acc = _access_ports(lines)
    bad = [h for h, b in acc if "spanning-tree bpduguard enable" not in b]
    return _of(bad, acc, "access ports without bpduguard", bad[0]) if bad else None


def port_security(lines, plat, masked):
    if plat == ASA:
        return ("na", NOT_HERE)
    if not _switch(lines):
        return ("na", NOT_SWITCH)
    acc = _access_ports(lines)
    bad = [h for h, b in acc if "switchport port-security" not in b]
    return _of(bad, acc, "access ports without port security", bad[0]) if bad else None


def vtp(lines, plat, masked):
    if plat == ASA:
        return ("na", NOT_HERE)
    if not _switch(lines):
        return ("na", NOT_SWITCH)
    if plat == NXOS and not _has(lines, r"feature vtp$"):
        return None
    return None if _has(lines, r"vtp mode (transparent|off)$") else "vtp mode transparent or off is not set (server is the default)"


def vlan1(lines, plat, masked):
    if plat == ASA:
        return ("na", NOT_HERE)
    if not _switch(lines):
        return ("na", NOT_SWITCH)
    parts = []
    trunks = [(h, b) for h, b in _blocks(lines, "interface ") if "switchport mode trunk" in b]
    bad = [h for h, b in trunks if not _in(b, r"switchport trunk native vlan (?!1$)\d+$")]
    if bad:
        parts.append(_of(bad, trunks, "trunks with native VLAN 1", bad[0]))
    for h, b in _blocks(lines, "interface Vlan1"):
        if h == "interface Vlan1" and _in(b, r"ip address \S") and "shutdown" not in b:
            parts.append("interface Vlan1 has an address")
    return "; ".join(parts) or None


def acl_any(lines, plat, masked):
    if plat != ASA:
        return ("na", NOT_HERE)
    hits = _has(lines, r"access-list \S+ (extended )?permit ip any[46]? any[46]?\s*$")
    return f"{_n(hits, 'line permits', 'lines permit')} everything: {hits[0]}" if hits else None


def threat_detection(lines, plat, masked):
    if plat != ASA:
        return ("na", NOT_HERE)
    parts = []
    if _has(lines, r"no threat-detection basic-threat$"):
        parts.append("threat-detection basic-threat is off")
    if _has(lines, r"\s*set connection random-sequence-number disable$"):
        parts.append("TCP sequence randomization is off")
    return "; ".join(parts) or None


def log_debug(lines, plat, masked):
    rx = r"logging server \S+ 7\b" if plat == NXOS else r"logging trap (debugging|7)$"
    hits = _has(lines, rx)
    return f"{hits[0]} (level 7)" if hits else None


RULES = [
    ("telnet", "Telnet allowed on VTY lines", FAIL, telnet),
    ("http", "HTTP server on", FAIL, http),
    ("snmp community", "SNMP community public, private or read-write", FAIL, snmp_community),
    ("enable password", "enable password instead of enable secret", FAIL, enable_password),
    ("vty login", "VTY lines without login, or no aaa new-model", FAIL, vty_login),
    ("acl any", "Access list permitting ip any any", FAIL, acl_any),
    ("type 7", "Type 7 passwords, or service password-encryption off", WARN, type7),
    ("type 5", "Type 5 (MD5) secrets", WARN, type5),
    ("ssh version", "SSH not forced to version 2", WARN, ssh2),
    ("exec-timeout", "exec-timeout 0 on console or VTY lines", WARN, exec_timeout),
    ("access-class", "VTY lines without an access-class", WARN, access_class),
    ("lockout", "No lockout after failed logins", WARN, lockout),
    ("accounting", "No AAA accounting", WARN, accounting),
    ("banner", "No login banner", WARN, banner),
    ("logging", "No logging host", WARN, logging_host),
    ("log debug", "Syslog at debugging level", WARN, log_debug),
    ("log timestamps", "Log timestamps off", WARN, log_timestamps),
    ("ntp", "No NTP server", WARN, ntp),
    ("ntp auth", "NTP not authenticated", WARN, ntp_auth),
    ("services", "ip source-route, tcp-small-servers, ip finger or directed-broadcast on", WARN, services),
    ("smart install", "Smart Install not disabled", WARN, smart_install),
    ("snmp acl", "SNMP community without an access list", WARN, snmp_acl),
    ("snmp v2c", "SNMP version 1 or 2c in use", WARN, snmp_v2c),
    ("icmp redirects", "ICMP redirects or proxy ARP on routed interfaces", WARN, icmp_redirects),
    ("routing auth", "Routing protocol without authentication", WARN, routing_auth),
    ("threat detection", "Threat detection or TCP sequence randomization off", WARN, threat_detection),
    ("dhcp snooping", "DHCP snooping off", WARN, dhcp_snooping),
    ("arp inspection", "Dynamic ARP inspection off", WARN, arp_inspection),
    ("bpdu guard", "BPDU guard off on access ports", WARN, bpdu_guard),
    ("port security", "Access ports without port security", WARN, port_security),
    ("vtp", "VTP not transparent or off", WARN, vtp),
    ("vlan 1", "VLAN 1 in use", WARN, vlan1),
]
CISCO = RULES                               # the Cisco list by its own name; RULES below becomes every vendor's


def _lines(text):
    return [l.rstrip() for l in text.replace("\r\n", "\n").split("\n")]


def _groups():
    from core import hardening_fortinet, hardening_paloalto
    return [("cisco", "Cisco (IOS, IOS XE, NX-OS, ASA)", "Cisco", _lines, CISCO),
            ("fortinet", "FortiGate", "FortiOS", hardening_fortinet.parse, hardening_fortinet.RULES),
            ("paloalto", "Palo Alto", "PAN-OS", hardening_paloalto.parse, hardening_paloalto.RULES)]


GROUPS = _groups()                          # (vendor, heading, format name, parse(text) -> doc, rules)
BY_VENDOR = {g[0]: g for g in GROUPS}
RULES = [r for g in GROUPS for r in g[4]]
LABELS = {k: label for k, label, _s, _t in RULES}
PREFIX = "Hardening: "                      # the check name of a rule's row; display.check_name leaves it as written


def rules_off():
    return set(db.get_setting("hardening_off") or [])


def findings(text, platform, off=(), vendor="cisco"):
    """[(rule key, status, message)] for one configuration's text: every rule of the vendor that is on, in order.
    Raises ValueError when the text is not that vendor's configuration format."""
    text = text or ""
    _v, _h, _f, parse, rules = BY_VENDOR[vendor]
    doc = parse(text)
    masked = "<masked>" in text
    plat = platform if platform in ALL else IOS
    out = []
    for key, label, sev, test in rules:
        if key in off:
            continue
        got = test(doc, plat, masked)
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
    group = BY_VENDOR.get(dev.get("vendor") or "")
    if not group:
        return [row(PREFIX.rstrip(": "), NA, NO_RULES)]
    off = rules_off()
    if all(key in off for key, *_ in group[4]):
        return []
    latest = backup.latest(dev.get("key") or name)
    if not latest:
        return [row(PREFIX.rstrip(": "), NA, NO_BACKUP)]
    text = backup.get_text(latest["id"], latest.get("org"))
    taken = (latest.get("taken_at") or "")[:16]
    try:
        found = findings(text, dev.get("platform") or "", off, group[0])
    except ValueError:
        return [row(PREFIX.rstrip(": "), NA, UNREADABLE.format(group[2]))]
    return [row(PREFIX + LABELS[key], status, f"{message} (backup of {taken})" if status in (WARN, FAIL) and taken else message)
            for key, status, message in found]

"""Palo Alto hardening rules over a PAN-OS XML export (Palo Alto's administrative-access best practices). Rules get the
parsed document root. A masked backup holds `<masked>` inside elements, which is not XML, so it is escaped first."""
import xml.etree.ElementTree as ET

from drivers.base import FAIL, WARN


def parse(text):
    try:
        root = ET.fromstring(text.replace("<masked>", "&lt;masked&gt;"))
    except ET.ParseError as e:
        raise ValueError(f"not PAN-OS XML: {e}")
    if root.tag != "config":
        raise ValueError("not a PAN-OS configuration")
    return root


def _text(root, path):
    el = root.find(path)
    return (el.text or "").strip() if el is not None else None


def _profiles(root):
    return root.findall(".//network/profiles/interface-management-profile/entry")


def _yes(el, tag):
    return el is not None and (el.findtext(tag) or "").strip() == "yes"


# ---------------------------------------------------------------- test(root, platform, masked) -> None | reason | ("na", reason)
def telnet_http(root, plat, masked):
    parts = []
    svc = root.find(".//deviceconfig/system/service")
    for tag in ("disable-telnet", "disable-http"):
        if svc is not None and (svc.findtext(tag) or "").strip() == "no":
            parts.append(f"{tag} no")
    for p in _profiles(root):
        on = [t for t in ("telnet", "http") if _yes(p, t)]
        if on:
            parts.append(f"interface management profile {p.get('name')}: {' and '.join(on)} yes")
    return "; ".join(parts) or None


def permitted_ip(root, plat, masked):
    parts = []
    if not root.findall(".//deviceconfig/system/permitted-ip/entry"):
        parts.append("no permitted-ip on the management interface")
    for p in _profiles(root):
        if (_yes(p, "https") or _yes(p, "ssh")) and not p.findall("permitted-ip/entry"):
            parts.append(f"interface management profile {p.get('name')} allows https or ssh from anywhere")
    return "; ".join(parts) or None


def rule_any(root, plat, masked):
    bad = []
    for r in root.findall(".//rulebase/security/rules/entry"):
        members = {t: [m.text for m in r.findall(f"{t}/member")] for t in ("from", "to", "source", "destination", "application", "service")}
        if all(v == ["any"] for v in members.values()) and (r.findtext("action") or "").strip() == "allow" and (r.findtext("disabled") or "").strip() != "yes":
            bad.append(f"rule {r.get('name')}: any to any, allow")
    return "; ".join(bad) or None


def default_admin(root, plat, masked):
    return 'account "admin" exists' if root.find(".//mgt-config/users/entry[@name='admin']") is not None else None


def lockout(root, plat, masked):
    fa = _text(root, ".//deviceconfig/setting/management/admin-lockout/failed-attempts") or "0"
    lt = _text(root, ".//deviceconfig/setting/management/admin-lockout/lockout-time") or "0"
    if fa == "0":
        return "admin-lockout failed-attempts is 0 or not set"
    return "admin-lockout lockout-time is 0" if lt == "0" else None


def idle_timeout(root, plat, masked):
    return "idle-timeout 0 (never)" if _text(root, ".//deviceconfig/setting/management/idle-timeout") == "0" else None


def password_complexity(root, plat, masked):
    return None if _text(root, ".//mgt-config/password-complexity/enabled") == "yes" else "password-complexity is not enabled"


def tls(root, plat, masked):
    name = _text(root, ".//deviceconfig/system/ssl-tls-service-profile")
    if not name:
        return "no SSL/TLS service profile on the management interface (TLS 1.0 allowed)"
    v = _text(root, f".//ssl-tls-service-profile/entry[@name='{name}']/protocol-settings/min-version") or "tls1-0"
    return f"profile {name}: min-version {v}" if v in ("tls1-0", "tls1-1") else None


def log_forwarding(root, plat, masked):
    syslog = root.findall(".//log-settings/system//send-syslog/member")
    panorama = [e for e in root.findall(".//deviceconfig/system//panorama-server") if (e.text or "").strip()]
    return None if syslog or panorama else "system logs: no syslog server profile and no Panorama server"


def ntp(root, plat, masked):
    servers = [e for e in root.findall(".//deviceconfig/system/ntp-servers//ntp-server-address") if (e.text or "").strip()]
    return None if servers else "no ntp-servers"


def snmp_v2c(root, plat, masked):
    return "snmp-setting version v2c" if root.find(".//deviceconfig/system/snmp-setting/access-setting/version/v2c") is not None else None

def idle_long(root, plat, masked):
    n = _text(root, ".//deviceconfig/setting/management/idle-timeout") or "60"
    return f"idle-timeout {n}: set Idle Timeout to 10 or fewer (Device > Setup > Management > Authentication Settings)" if n.isdigit() and int(n) > 10 else None


def _complexity(root):
    return _text(root, ".//mgt-config/password-complexity/enabled") == "yes"


def password_length(root, plat, masked):
    n = _text(root, ".//mgt-config/password-complexity/minimum-length") or "0"
    if _complexity(root) and n.isdigit() and int(n) < 15:
        return f"minimum-length {n}: set Minimum Length to 15 (Device > Setup > Management > Minimum Password Complexity)"


def password_chars(root, plat, masked):
    off = [k for k in ("minimum-uppercase-letters", "minimum-lowercase-letters", "minimum-numeric-letters", "minimum-special-characters")
           if (_text(root, f".//mgt-config/password-complexity/{k}") or "0") in ("0", "")]
    return f"{', '.join(off)} 0: set Minimum Uppercase, Lowercase, Numeric and Special to 1 (Device > Setup > Management > Minimum Password Complexity)" if off else None


def banner(root, plat, masked):
    return None if _text(root, ".//deviceconfig/system/login-banner") else "no login-banner: set Login Banner (Device > Setup > Management > General Settings)"


def ntp_auth(root, plat, masked):
    bad = []
    for tag in ("primary-ntp-server", "secondary-ntp-server"):
        s = root.find(f".//deviceconfig/system/ntp-servers/{tag}")
        if s is not None and (s.findtext("ntp-server-address") or "").strip():
            a = s.find("authentication-type")
            if a is None or (a.find("symmetric-key") is None and a.find("autokey") is None):
                bad.append(tag)
    return f"{', '.join(bad)} authentication-type none: set Symmetric Key or Autokey (Device > Setup > Services)" if bad else None


def ntp_second(root, plat, masked):
    return None if _text(root, ".//deviceconfig/system/ntp-servers/secondary-ntp-server/ntp-server-address") else "no secondary-ntp-server: set Secondary NTP Server (Device > Setup > Services)"


def config_log(root, plat, masked):
    syslog = root.findall(".//log-settings/config//send-syslog/member")
    panorama = [e for e in root.findall(".//deviceconfig/system//panorama-server") if (e.text or "").strip()]
    return None if syslog or panorama else "config logs: no syslog server profile: set one (Device > Log Settings > Configuration)"


def snmp_trap(root, plat, masked):
    # shortcut: both the log-settings path and the server-profile path are read, as no real export was at hand to tell which
    bad = [f"trap profile {e.get('name')}: version v2c: set Version to V3 (Device > Server Profiles > SNMP Trap)"
           for tag in ("snmptrap", "snmp-trap") for e in root.findall(f".//{tag}/entry") if e.find("version/v2c") is not None]
    return "; ".join(bad) or None


def ldap_ssl(root, plat, masked):
    bad = [f"LDAP profile {e.get('name')}: ssl no: tick Require SSL/TLS (Device > Server Profiles > LDAP)"
           for e in root.findall(".//server-profile/ldap/entry") if (e.findtext("ssl") or "").strip() == "no"]
    return "; ".join(bad) or None


def syslog_udp(root, plat, masked):
    bad = [f"syslog profile {p.get('name')}: transport UDP: set Transport to SSL (Device > Server Profiles > Syslog)"
           for p in root.findall(".//syslog/entry")
           if any((s.findtext("transport") or "UDP").strip().upper() == "UDP" for s in p.findall("server/entry"))]
    return "; ".join(bad) or None


RULES = [
    ("pa telnet http", "Telnet or HTTP management on", FAIL, telnet_http),
    ("pa rule any", "Rule allowing everything", FAIL, rule_any),
    ("pa permitted ip", "Management with no permitted IPs", WARN, permitted_ip),
    ("pa default admin", 'Default "admin" account present', WARN, default_admin),
    ("pa lockout", "No admin lockout", WARN, lockout),
    ("pa idle timeout", "Idle timeout never", WARN, idle_timeout),
    ("pa password complexity", "Password complexity off", WARN, password_complexity),
    ("pa tls", "TLS below 1.2 on the web UI", WARN, tls),
    ("pa log forwarding", "System logs not forwarded", WARN, log_forwarding),
    ("pa ntp", "No NTP server", WARN, ntp),
    ("pa snmp v2c", "SNMP v2c in use", WARN, snmp_v2c),
    ("pa idle long", "Idle timeout over 10 minutes", WARN, idle_long),
    ("pa password length", "Password minimum under 15", WARN, password_length),
    ("pa password chars", "Password character rules off", WARN, password_chars),
    ("pa banner", "No login banner", WARN, banner),
    ("pa ntp auth", "NTP not authenticated", WARN, ntp_auth),
    ("pa ntp second", "Only one NTP server", WARN, ntp_second),
    ("pa config log", "Config logs not forwarded", WARN, config_log),
    ("pa snmp trap", "SNMP traps on v2c", WARN, snmp_trap),
    ("pa ldap ssl", "LDAP without SSL", WARN, ldap_ssl),
    ("pa syslog udp", "Syslog over UDP", WARN, syslog_udp),
]

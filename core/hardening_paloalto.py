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
]

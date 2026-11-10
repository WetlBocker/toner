"""The Windows settings snapshot: the registry values, security policy keys and audit settings the hardening rules read
(docs/superpowers/plans/2026-11-09-hardening-rules.md, Windows). Both collectors send it as the report's `hardening` part:

    {"v": 1, "reg": {name: value or null}, "policy": {key: number}, "audit": {guid: setting}}

A `reg` value that is set keeps its value, one that is not set (read fine, absent) is null, and one that could not be read is
left out. This file is the one list: the PowerShell script (core/winmon.py) is generated from REG, and
agent/internal/collect/windows_settings.go keeps a copy that tests/test_winsettings.py checks."""
import json

LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"
SVC = r"SYSTEM\CurrentControlSet\Services"
TS = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
SCH = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

# (name, key path under HKLM, value name). Every value is a DWORD.
REG = [
    ("Smb1Server", SVC + r"\LanmanServer\Parameters", "SMB1"),
    ("Smb1ClientStart", SVC + r"\mrxsmb10", "Start"),
    ("SmbServerSigning", SVC + r"\LanManServer\Parameters", "RequireSecuritySignature"),
    ("SmbClientSigning", SVC + r"\LanmanWorkstation\Parameters", "RequireSecuritySignature"),
    ("LlmnrMulticast", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast"),
    ("LmCompatibilityLevel", LSA, "LmCompatibilityLevel"),
    ("RunAsPPL", LSA, "RunAsPPL"),
    ("WDigestLogonCredential", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential"),
    ("CredGuardPolicy", r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "LsaCfgFlags"),
    ("CredGuardLsa", LSA, "LsaCfgFlags"),
    ("RdpNlaPolicy", r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "UserAuthentication"),
    ("RdpNlaTcp", TS + r"\WinStations\RDP-Tcp", "UserAuthentication"),
    ("RdpDenyConnections", TS, "fDenyTSConnections"),
    ("EnableLUA", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"),
    ("Tls10Server", SCH + r"\TLS 1.0\Server", "Enabled"),
    ("Tls11Server", SCH + r"\TLS 1.1\Server", "Enabled"),
]

# The secedit keys that are kept. Never an account name (NewAdministratorName, NewGuestName) or anything else in that file.
POLICY = ["MinimumPasswordLength", "PasswordComplexity", "PasswordHistorySize", "ClearTextPassword",
          "LockoutBadCount", "LockoutDuration", "ResetLockoutCount", "EnableGuestAccount"]

_SUFFIX = "-69AE-11D9-BED3-505054503030}"
# Audit subcategory GUIDs the logon and change auditing rules read (uppercase, with braces).
AUDIT = {"{0CCE" + h + _SUFFIX for h in ("923F", "9215", "9216", "921B", "9217", "9235", "9237", "922F", "9228", "922B", "9210", "9211", "9212")}

MAX_BYTES = 64 * 1024


def _number(v):
    return isinstance(v, int) and not isinstance(v, bool) and abs(v) < 2 ** 63


def clean(raw):
    """What of a report's `hardening` part is kept, or None when it is not a version 1 snapshot or is over 64 KB. Only the known
    names survive and only numbers (audit: short text), so nothing else a computer sends is stored. A null `reg` value stays.
    A dict that also carries the report's firewall, defender, joined and build keeps those when they are well formed."""
    if not isinstance(raw, dict) or raw.get("v") != 1:
        return None
    try:
        if len(json.dumps(raw)) > MAX_BYTES:
            return None
    except (TypeError, ValueError):
        return None
    reg, policy, audit = raw.get("reg"), raw.get("policy"), raw.get("audit")
    reg, policy, audit = (x if isinstance(x, dict) else {} for x in (reg, policy, audit))
    out = {"v": 1,
           "reg": {n: reg[n] for n, _p, _v in REG if n in reg and (reg[n] is None or _number(reg[n]))},
           "policy": {k: policy[k] for k in POLICY if _number(policy.get(k))},
           "audit": {}}
    for guid, setting in audit.items():
        if isinstance(guid, str) and guid.upper() in AUDIT and isinstance(setting, str) and len(setting) <= 64:
            out["audit"][guid.upper()] = setting
    fw = raw.get("firewall")
    if isinstance(fw, list):
        out["firewall"] = [{"name": p["name"][:40], "on": p["on"]} for p in fw
                           if isinstance(p, dict) and isinstance(p.get("name"), str) and isinstance(p.get("on"), bool)]
    df = raw.get("defender")
    if isinstance(df, dict):
        out["defender"] = {k: df[k] for k in ("enabled", "realtime") if isinstance(df.get(k), bool)}
        if isinstance(df.get("mode"), str):
            out["defender"]["mode"] = df["mode"][:40]
    if isinstance(raw.get("joined"), bool):
        out["joined"] = raw["joined"]
    if isinstance(raw.get("build"), str):
        out["build"] = raw["build"][:40]
    return out

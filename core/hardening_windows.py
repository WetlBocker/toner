"""Windows hardening rules over the settings snapshot a Windows agent reports (core/winsettings.py), not a configuration backup.
A `reg` value that is null was read and is not set (the rule uses Windows' default); a name that is left out could not be read,
and the rule answers N/A, never a pass. Rules get the snapshot dict (core.hardening is imported inside the functions: it
imports this module)."""
import json
import re

from drivers.base import FAIL, WARN

UNREAD = object()
KEEP = 26100                    # Windows 11 24H2 and Server 2025: signing is required and TLS 1.0 and 1.1 are off when nothing is set


def parse(text):
    try:
        doc = json.loads(text)
    except ValueError:
        raise ValueError("not a Windows settings snapshot")
    if not isinstance(doc, dict):
        raise ValueError("not a Windows settings snapshot")
    return doc


def _na(reason=None):
    from core import hardening
    return ("na", reason or hardening.UNREAD_SETTING)


def _get(o, part, key):
    d = o.get(part)
    return d[key] if isinstance(d, dict) and key in d else UNREAD


def _reg(o, name):
    return _get(o, "reg", name)


def _build(o):
    m = re.match(r"\s*(\d+)", str(o.get("build") or ""))
    return int(m.group(1)) if m else None


def _out(bad, unread, message):
    """The finding when something is wrong, N/A when nothing is wrong but something could not be read, else None."""
    return message if bad else _na() if unread else None


# ---------------------------------------------------------------- test(snapshot, platform, masked) -> None | reason | ("na", reason)
def smb1(o, plat, masked):
    start, server = _reg(o, "Smb1ClientStart"), _reg(o, "Smb1Server")
    if start is UNREAD:
        return _na()
    if start is not None and start != 4:
        return "SMBv1 is on: remove the FS-SMB1 feature, or set LanmanServer\\Parameters\\SMB1 to 0 and mrxsmb10\\Start to 4"
    gone = start is None                                         # mrxsmb10 is gone: the feature was removed, so an unset server value is not on; one set to on still is
    return _out((server is None and not gone) or (server is not None and server is not UNREAD and server != 0), server is UNREAD,
                "SMBv1 is on: remove the FS-SMB1 feature, or set LanmanServer\\Parameters\\SMB1 to 0 and mrxsmb10\\Start to 4")


def smb_signing(o, plat, masked):
    bad, unread, build = [], False, _build(o)
    for who, name in (("server", "SmbServerSigning"), ("client", "SmbClientSigning")):
        v = _reg(o, name)
        if v is None and build is None or v is UNREAD:
            unread = True
        elif (v == 0) if v is not None else build < KEEP:
            bad.append(who)
    return _out(bad, unread, f"RequireSecuritySignature is off on {', '.join(bad)}: set Microsoft network {', '.join(bad)}: Digitally sign communications (always) to Enabled")


def llmnr(o, plat, masked):
    v = _reg(o, "LlmnrMulticast")
    return _na() if v is UNREAD else "EnableMulticast is not 0: set Turn off multicast name resolution to Enabled (DNS Client policy)" if v != 0 else None


def ntlm(o, plat, masked):
    v = _reg(o, "LmCompatibilityLevel")
    if v is UNREAD:
        return _na()
    v = 3 if v is None else v
    return f"LmCompatibilityLevel {v}: set Network security: LAN Manager authentication level to Send NTLMv2 response only. Refuse LM & NTLM (5)" if v < 5 else None


def lsa_protection(o, plat, masked):
    v = _reg(o, "RunAsPPL")
    if v is UNREAD:
        return _na()
    return None if v in (1, 2) else f"RunAsPPL is {'not set' if v is None else v}: set it to 1 under Lsa"


def wdigest(o, plat, masked):
    v = _reg(o, "WDigestLogonCredential")
    return _na() if v is UNREAD else "UseLogonCredential is 1: set it to 0 (SecurityProviders\\WDigest)" if v == 1 else None


def credential_guard(o, plat, masked):
    from core import hardening
    dc, joined = o.get("dc"), o.get("joined")
    if dc is True or joined is False:
        return ("na", hardening.NOT_HERE)
    pol, lsa = _reg(o, "CredGuardPolicy"), _reg(o, "CredGuardLsa")
    if dc is None or joined is None:
        return _na()
    if pol in (1, 2) or lsa in (1, 2):
        return None
    if pol is UNREAD or lsa is UNREAD:
        return _na()
    return f"LsaCfgFlags is {pol if pol is not None else lsa if lsa is not None else 'not set'}: turn on Credential Guard Configuration (Device Guard policy)"


def firewall(o, plat, masked):
    fw = o.get("firewall")
    if not isinstance(fw, list) or not fw:
        return _na()
    off = [p["name"] for p in fw if not p.get("on")]
    return f"{', '.join(off)} off: turn on Windows Defender Firewall for those profiles" if off else None


def rdp_nla(o, plat, masked):
    pol, tcp, deny = _reg(o, "RdpNlaPolicy"), _reg(o, "RdpNlaTcp"), _reg(o, "RdpDenyConnections")
    if pol is UNREAD or (pol is None and tcp is UNREAD):
        return _na()
    on = (pol if pol is not None else 1 if tcp is None else tcp) != 0         # nothing set: NLA is the default
    if on or deny == 1:
        return None
    return _na() if deny is UNREAD else "UserAuthentication is off on RDP-Tcp: set Require user authentication for remote connections by using Network Level Authentication to Enabled"


def uac(o, plat, masked):
    v = _reg(o, "EnableLUA")
    return _na() if v is UNREAD else "EnableLUA is 0: set User Account Control: Run all administrators in Admin Approval Mode to Enabled" if v == 0 else None


def guest(o, plat, masked):
    v = _get(o, "policy", "EnableGuestAccount")
    return _na() if v is UNREAD else "Guest is enabled: set Accounts: Guest account status to Disabled" if v == 1 else None


def _policy(o, checks):
    """checks: (key, text for a bad value or None). The settings that are wrong, and whether any could not be read."""
    bad, unread = [], False
    for key, wrong in checks:
        v = _get(o, "policy", key)
        if v is UNREAD:
            unread = True
        elif wrong(v):
            bad.append(f"{key} {v}")
    return bad, unread


def password(o, plat, masked):
    bad, unread = _policy(o, (("MinimumPasswordLength", lambda v: v < 14), ("PasswordComplexity", lambda v: v == 0), ("PasswordHistorySize", lambda v: v < 24)))
    return _out(bad, unread, f"{', '.join(bad)}: set Account Policies > Password Policy to length 14, complexity on and history 24")


def reversible(o, plat, masked):
    v = _get(o, "policy", "ClearTextPassword")
    return _na() if v is UNREAD else "ClearTextPassword is 1: set Store passwords using reversible encryption to Disabled" if v == 1 else None


def lockout(o, plat, masked):
    bad, unread = _policy(o, (("LockoutBadCount", lambda v: v == 0 or v > 3), ("LockoutDuration", lambda v: 0 <= v < 15), ("ResetLockoutCount", lambda v: v < 15)))
    return _out(bad, unread, f"{', '.join(bad)}: set Account Lockout Policy to 3 attempts or fewer, with duration and reset at 15 minutes or more")


_S, _F, _SF = {"success"}, {"failure"}, {"success", "failure"}
_SUFFIX = "-69AE-11D9-BED3-505054503030}"
# (subcategory, GUID, what it must audit)
AUDIT_LOGON = [("Credential Validation", "923F", _SF), ("Logon", "9215", _SF), ("Logoff", "9216", _S), ("Special Logon", "921B", _S), ("Account Lockout", "9217", _F)]
AUDIT_CHANGES = [("User Account Management", "9235", _SF), ("Security Group Management", "9237", _S), ("Audit Policy Change", "922F", _SF),
                 ("Sensitive Privilege Use", "9228", _SF), ("Process Creation", "922B", _S), ("Security State Change", "9210", _S),
                 ("Security System Extension", "9211", _S), ("System Integrity", "9212", _SF)]
_SETTINGS = {"no auditing": set(), "success": _S, "failure": _F, "success and failure": _SF}      # auditpol's English text only


def _audit(o, subs, message):
    bad, unread = [], False
    for name, h, need in subs:
        got = _SETTINGS.get(str(_get(o, "audit", "{0CCE" + h + _SUFFIX)).strip().lower())
        if got is None:                                            # not read, or text on a non-English Windows
            unread = True
        elif not need <= got:
            bad.append(name)
    return _out(bad, unread, f"{', '.join(bad)}: {message}")


def audit_logon(o, plat, masked):
    return _audit(o, AUDIT_LOGON, "set Advanced Audit Policy for Logon/Logoff and Account Logon to the needed Success or Failure")


def audit_changes(o, plat, masked):
    return _audit(o, AUDIT_CHANGES, "set Advanced Audit Policy for Account Management, Policy Change, Privilege Use, Detailed Tracking and System to the needed Success or Failure")


def defender(o, plat, masked):
    d = o.get("defender")
    if not isinstance(d, dict) or "realtime" not in d:
        return _na()
    if d["realtime"]:
        return None
    if "mode" not in d:
        return _na()
    mode = str(d["mode"]).strip().lower()
    if "passive" in mode:                                                     # another antivirus has Defender passive
        return None
    if mode != "normal":                                                      # empty or unknown: not a pass
        return _na()
    return "Real-time protection off: turn on Microsoft Defender real-time protection"


def tls(o, plat, masked):
    bad, unread, build = [], False, _build(o)
    for ver, name in (("TLS 1.0", "Tls10Server"), ("TLS 1.1", "Tls11Server")):
        v = _reg(o, name)
        if v is None and build is None or v is UNREAD:
            unread = True
        elif (v != 0) if v is not None else build < KEEP:               # a DWORD of 2^31 or more can read negative
            bad.append(ver)
    return _out(bad, unread, f"{', '.join(bad)} on: set Enabled to 0 under " + " and ".join(f"SCHANNEL\\Protocols\\{v}\\Server" for v in bad))


RULES = [
    ("win smb1", "SMBv1 on", FAIL, smb1),
    ("win smb signing", "SMB signing not required", WARN, smb_signing),
    ("win llmnr", "LLMNR on", WARN, llmnr),
    ("win ntlm", "LAN Manager level below 5", FAIL, ntlm),
    ("win lsa protection", "LSA protection off", WARN, lsa_protection),
    ("win wdigest", "WDigest stores credentials", FAIL, wdigest),
    ("win credential guard", "Credential Guard off", WARN, credential_guard),
    ("win firewall", "Windows Firewall off", FAIL, firewall),
    ("win rdp nla", "RDP without network-level authentication", WARN, rdp_nla),
    ("win uac", "UAC off", FAIL, uac),
    ("win guest", "Guest account enabled", FAIL, guest),
    ("win password", "Password policy weak", WARN, password),
    ("win reversible", "Reversible password encryption on", FAIL, reversible),
    ("win lockout", "Account lockout weak", WARN, lockout),
    ("win audit logon", "Logon auditing incomplete", WARN, audit_logon),
    ("win audit changes", "Change auditing incomplete", WARN, audit_changes),
    ("win defender", "Defender real-time protection off", FAIL, defender),
    ("win tls", "TLS 1.0 or 1.1 on", WARN, tls),
]

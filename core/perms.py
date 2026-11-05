"""The permission catalogue: what an Admin can switch on or off for Engineers and Techs, and each role's defaults.
Import nothing from ui/ (core is imported headless by the CLI). Admin is fixed at everything and isn't listed.
The checks (allowed, require, is_admin) ask core/roles, which imports this module only inside its functions."""
from core import datakey, roles, session

REASON = "Your role doesn't allow this. Ask an admin."


class Denied(PermissionError):
    def __init__(self, msg=REASON):
        super().__init__(msg)


TOOLS = [("tool:command-runner", "Command Runner"), ("tool:api-tester", "API Tester"),
         ("tool:ping", "Ping / Traceroute / DNS"), ("tool:live-ping", "Live Ping"), ("tool:path-monitor", "Path Monitor (MTR)"),
         ("tool:port-scanner", "Port Scanner"), ("tool:iperf", "Throughput (iperf3)"),
         ("tool:find-devices", "Find Devices"), ("tool:topology", "Topology"), ("tool:wifi", "Wi-Fi Scanner"),
         ("tool:snmp", "SNMP"), ("tool:syslog", "Syslog and Traps"),
         ("tool:firmware", "Firmware Transfer"), ("tool:tftp", "TFTP Server"), ("tool:sftp", "SFTP / SCP Server"),
         ("tool:ftp", "FTP Server"), ("tool:scp", "SCP"), ("tool:copy-files", "Copy Files"),
         ("tool:tls", "TLS Certificates"), ("tool:openssl", "OpenSSL"), ("tool:ssh-keys", "SSH Keys"),
         ("tool:playbook-editor", "Playbook Editor"), ("tool:mac-lookup", "MAC OUI Lookup"), ("tool:wol", "Wake-on-LAN"),
         ("tool:subnet", "Subnet Calculator"),
         ("tool:sessions", "Sessions (SSH, Telnet, serial)"), ("tool:rdp", "Remote desktop (RDP)"), ("tool:automation", "Automation (Ansible)")]

# Every Settings page except "Accounts and sign-in" (admin only).
SETTINGS_PAGES = ["General", "Thresholds", "Checks", "Scanning", "Maintenance", "Connections", "Proxy", "Credentials", "Agents", "Demarc",
                  "Notifications", "Reports", "Config backups", "Ansible", "AI", "Appearance", "Terminal", "Security", "Audit log",
                  "Data and logs", "Organizations"]
SETTINGS = [("settings:" + t, t) for t in SETTINGS_PAGES]

PERMISSIONS = [("push", "Push changes to devices"), ("unmasked", "See passwords in config backups"), ("ai", "AI assistant")] + TOOLS + SETTINGS

DEFAULTS = {"Engineer": {k: True for k, _ in PERMISSIONS},
            "Tech": {k: not (k in ("push", "unmasked") or (k.startswith("settings:") and k not in ("settings:Appearance", "settings:Terminal")))
                     for k, _ in PERMISSIONS}}


def allowed(key):
    """With sign-in off, everything; signed out, nothing; else what the signed-in person's role allows (a keys file deleted
    while someone is signed in is roles' "tampered", not sign-in off)."""
    if session.state() == "signed_out":
        return not datakey.exists()
    return roles.permissions(roles.role_of(datakey.signed_in_name()))[key]


def require(key):
    if not allowed(key):
        raise Denied()


def is_admin():
    if session.state() == "signed_out":
        return not datakey.exists()
    return roles.role_of(datakey.signed_in_name()) == "Admin"

"""Tools > File transfer > Firmware Transfer: put a firmware image on Cisco devices (IOS, IOS XE, NX-OS, ASA).

Each device pulls its image itself from a source server: Toner's own FTP, SFTP / SCP or TFTP server, or another FTP, SFTP or
SCP server. Toner lists the source's folder from here so the technician picks from what is really there. Nothing in this
module reloads a device, ever.

Sources are plain dicts:
    {"own": bool, "proto": "ftp"|"sftp"|"scp"|"tftp", "host", "port", "user", "password", "folder", "anonymous": bool}
For Toner's own server, "host" is this computer's address as the devices see it and "folder" is the server's folder on disk.
"""
import ftplib
import os
import re
import socket
import stat
import time
from datetime import datetime

from core import db, vendors

# ---------------------------------------------------------------- which devices, and what their copy command can fetch from
PLATFORMS = ("cisco_ios", "cisco_xe", "cisco_nxos", "cisco_asa")
PLATFORM_NAMES = dict(vendors.VENDORS["cisco"]["platforms"])          # cisco_xe -> 'IOS XE'
# the copy clients each platform has (IOS and ASA have no SFTP client)
CLIENTS = {"cisco_ios": ("ftp", "scp", "tftp"), "cisco_xe": ("ftp", "sftp", "scp", "tftp"),
           "cisco_nxos": ("ftp", "sftp", "scp", "tftp"), "cisco_asa": ("ftp", "scp", "tftp")}
PROTO_NAMES = {"ftp": "FTP", "sftp": "SFTP", "scp": "SCP", "tftp": "TFTP"}
DEFAULT_PORTS = {"ftp": 21, "sftp": 22, "scp": 22, "tftp": 69}
OTHER_PROTOS = ("ftp", "sftp", "scp")                                # what "Another server" offers
SETTING = "firmware_source"                                           # the remembered server, per organization
SECRET = "firmware-source"                                            # its password, in the vault under the organization's prefix
NOT_CISCO = "Not a Cisco device ({vendor}). The wizard handles Cisco IOS, IOS XE, NX-OS and ASA."


def platform_of(dev):
    """The device's Cisco platform (a Cisco device with none set is IOS, as everywhere in Toner), or '' for any other device."""
    if dev.get("vendor") != "cisco":
        return ""
    p = dev.get("platform") or "cisco_ios"
    return p if p in PLATFORMS else ""


def eligible(dev):
    """(True, '') for a device the wizard can work on; (False, the reason shown beside it) for any other."""
    if platform_of(dev):
        return True, ""
    from core import display
    return False, NOT_CISCO.format(vendor=display.vendor_name(dev.get("vendor") or "") or "no vendor set")


def can_fetch(platform, proto):
    return proto in CLIENTS.get(platform, ())


# ---------------------------------------------------------------- sizes and names as people read them
def human_size(n):
    """'512 bytes', '24 KB', '437 MB', '1.1 GB'."""
    if n is None:
        return ""
    for unit in ("bytes", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def proto_label(src):
    """'FTP' for another server, "Toner's FTP server" for Toner's own."""
    name = PROTO_NAMES[src["proto"]]
    return f"Toner's {name} server" if src.get("own") else name


def summary(src, files):
    """The line under the list once it has been read."""
    folder = src.get("folder") or "/"
    if not files:
        return f"No files in {folder}. Put the images there and click Test and list files again."
    n = len(files)
    return f"{n} file{'s' if n != 1 else ''} in {folder} on {src['host']} ({proto_label(src)})."


# ---------------------------------------------------------------- Toner's own servers
NONE_RUNNING = "None of Toner's file servers is running. Start one on the TFTP, SFTP / SCP or FTP Server page."


def own_choices(servers):
    """The protocols Toner is serving now, for the drop-down: [(shown text, proto, server)]. `servers` is {'ftp': FtpServer or None,
    'sftp': SftpServer or None, 'tftp': TftpServer or None}. The SFTP server is offered twice: as SFTP and as SCP."""
    out = []
    for proto, key, label in (("ftp", "ftp", "FTP server"), ("sftp", "sftp", "SFTP server"),
                              ("scp", "sftp", "SCP (the SFTP / SCP server)"), ("tftp", "tftp", "TFTP server")):
        srv = servers.get(key)
        if srv is not None and srv.running:
            out.append((f"{label}: folder {srv.root}, port {srv.port}", proto, srv))
    return out


def own_source(proto, srv, address):
    """The source dict for one of Toner's own servers. The devices sign in with the server's own login."""
    return {"own": True, "proto": proto, "host": address, "port": srv.port, "user": getattr(srv, "username", ""),
            "password": getattr(srv, "password", ""), "folder": srv.root, "anonymous": False}


def addresses():
    """This computer's addresses, for "as the devices see it"."""
    from core import fileserver
    return fileserver.local_addresses() or ["127.0.0.1"]


# ---------------------------------------------------------------- listing the source's folder
class SourceError(Exception):
    """A listing failed; the text is the line shown to the technician."""


def _connect_failed(src, e):
    reason = str(e).strip() or type(e).__name__
    if isinstance(e, socket.timeout) or "timed out" in reason.lower():
        reason = "no answer (timed out)"
    return SourceError(f"Could not connect to {src['host']} port {src['port']}: {reason}.")


REFUSED = "The server refused the user name or password."


def _no_folder(src):
    return SourceError(f"The folder {src.get('folder') or '/'} was not found on the server.")


def list_files(src, timeout=15):
    """The files (not folders) in the source's folder: [{'name', 'size', 'modified' (datetime or None)}], by name.
    Raises SourceError with the line to show."""
    if src.get("own"):
        files = _list_local(src)
    elif src["proto"] == "ftp":
        files = _list_ftp(src, timeout)
    else:
        files = _list_ssh(src, timeout)
    return sorted(files, key=lambda f: f["name"].lower())


def _list_local(src):
    """Toner's own server: its folder on this computer, as the server shows it (no unfinished uploads)."""
    from core import fileserver
    folder = src["folder"]
    try:
        names = os.listdir(folder)
    except OSError:
        raise _no_folder(src) from None
    out = []
    for n in names:
        if n.lower().endswith(fileserver.PART):
            continue
        try:
            st = os.stat(os.path.join(folder, n))
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode):
            out.append({"name": n, "size": st.st_size, "modified": datetime.fromtimestamp(st.st_mtime)})
    return out


def _list_ftp(src, timeout):
    c = ftplib.FTP()
    try:
        try:
            c.connect(src["host"], int(src["port"] or 21), timeout=timeout)
        except (OSError, EOFError) as e:
            raise _connect_failed(src, e) from None
        try:
            if src.get("anonymous"):
                c.login()                                   # user 'anonymous', as every FTP client does it
            else:
                c.login(src.get("user") or "", src.get("password") or "")
        except ftplib.error_perm:
            raise SourceError(REFUSED) from None
        except (OSError, EOFError, ftplib.Error) as e:
            raise _connect_failed(src, e) from None
        try:
            c.cwd(src.get("folder") or "/")
        except ftplib.error_perm:
            raise _no_folder(src) from None
        try:
            return _ftp_mlsd(c)
        except ftplib.error_perm:                           # an older server without MLSD: read LIST instead
            return _ftp_list(c)
        except (OSError, EOFError, ftplib.Error) as e:
            raise _connect_failed(src, e) from None
    finally:
        try:
            c.quit()
        except Exception:
            c.close()


def _ftp_mlsd(c):
    out = []
    for name, facts in c.mlsd(facts=["type", "size", "modify"]):
        if facts.get("type", "file").lower() != "file":
            continue
        modified = None
        if facts.get("modify"):
            try:
                modified = datetime.strptime(facts["modify"][:14], "%Y%m%d%H%M%S")
            except ValueError:
                pass
        out.append({"name": name, "size": int(facts["size"]) if facts.get("size", "").isdigit() else None, "modified": modified})
    return out


_LS = re.compile(r"^(?P<kind>[-dlbcps])[rwxsStT-]{9}\S*\s+\d+\s+\S+\s+\S+\s+(?P<size>\d+)\s+"
                 r"(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<when>\d{1,2}:\d{2}|\d{4})\s+(?P<name>.+)$")


def parse_ls(lines):
    """Files from `ls -l` / FTP LIST lines (the Unix form every server prints). Folders and links are left out."""
    out = []
    now = datetime.now()
    for line in lines:
        m = _LS.match(line.rstrip("\r\n"))
        if not m or m.group("kind") != "-":
            continue
        modified = None
        try:
            if ":" in m.group("when"):
                modified = datetime.strptime(f"{m.group('month')} {m.group('day')} {now.year} {m.group('when')}", "%b %d %Y %H:%M")
                if modified > now:                          # ls leaves the year out for the last six months
                    modified = modified.replace(year=now.year - 1)
            else:
                modified = datetime.strptime(f"{m.group('month')} {m.group('day')} {m.group('when')}", "%b %d %Y")
        except ValueError:
            pass
        out.append({"name": m.group("name"), "size": int(m.group("size")), "modified": modified})
    return out


def _ftp_list(c):
    lines = []
    c.retrlines("LIST", lines.append)
    return parse_ls(lines)


def _list_ssh(src, timeout):
    """SFTP, and SCP servers: over SFTP on the same login; an SCP server without SFTP is asked for `ls -l` instead."""
    import paramiko
    from core import nettools
    client = paramiko.SSHClient()
    nettools.configure_hostkeys(client, db.get_setting("hostkey_mode"))
    try:
        try:
            client.connect(src["host"], port=int(src["port"] or 22), username=src.get("user") or "", password=src.get("password") or "",
                           timeout=timeout, banner_timeout=timeout, auth_timeout=timeout, allow_agent=False, look_for_keys=False)
        except paramiko.AuthenticationException:
            raise SourceError(REFUSED) from None
        except (OSError, EOFError, paramiko.SSHException) as e:
            raise _connect_failed(src, e) from None
        folder = src.get("folder") or "/"
        try:
            sftp = client.open_sftp()
        except (OSError, EOFError, paramiko.SSHException) as e:
            if src["proto"] != "scp":
                raise _connect_failed(src, e) from None
            return _ls_over_exec(client, src, timeout)
        try:
            entries = sftp.listdir_attr(folder)
        except FileNotFoundError:
            raise _no_folder(src) from None
        except OSError as e:
            if getattr(e, "errno", None) == 2 or "no such file" in str(e).lower():
                raise _no_folder(src) from None
            raise _connect_failed(src, e) from None
        finally:
            sftp.close()
        return [{"name": a.filename, "size": a.st_size, "modified": datetime.fromtimestamp(a.st_mtime) if a.st_mtime else None}
                for a in entries if a.st_mode is not None and stat.S_ISREG(a.st_mode)]
    finally:
        client.close()


def _ls_over_exec(client, src, timeout):
    from core.scp import quote
    folder = src.get("folder") or "/"
    try:
        chan = client.get_transport().open_session(timeout=timeout)
        chan.settimeout(timeout)
        chan.exec_command(f"ls -l {quote(folder)}")
        out, deadline = b"", time.time() + timeout
        while time.time() < deadline:
            chunk = chan.recv(65536)
            if not chunk:
                break
            out += chunk
        code = chan.recv_exit_status() if chan.exit_status_ready() else 0
        chan.close()
    except (OSError, EOFError) as e:
        raise _connect_failed(src, e) from None
    text = out.decode("utf-8", "replace")
    if code != 0 and not text.strip():
        raise _no_folder(src)
    return parse_ls(text.splitlines())


# ---------------------------------------------------------------- remembering the other server, per organization
def saved():
    """The remembered server for the organization being looked at, with its password from the vault, or None."""
    data = db.get_setting(SETTING) or {}
    if not data.get("host"):
        return None
    out = {"own": False, "proto": data.get("proto", "ftp"), "host": data["host"], "port": int(data.get("port") or 0),
           "user": data.get("user", ""), "folder": data.get("folder", ""), "anonymous": bool(data.get("anonymous")), "password": ""}
    try:
        import keyring
        out["password"] = keyring.get_password(db.SERVICE, db.qualify(SECRET)) or ""
    except Exception:
        pass
    return out


def remember(src):
    """Keep another server and its login for this organization: the password in the vault, the rest in its settings."""
    db.set_setting(SETTING, {k: src.get(k) for k in ("proto", "host", "port", "user", "folder", "anonymous")})
    if src.get("password") and not src.get("anonymous"):
        db.set_secret(db.qualify(SECRET), src["password"])
    else:
        db.delete_secret(db.qualify(SECRET))


def forget():
    db.set_setting(SETTING, {})
    db.delete_secret(db.qualify(SECRET))


# ---------------------------------------------------------------- never showing a password
def mask(text, secrets):
    """`text` with every secret replaced by ****, and the password in any 'scheme://user:password@' replaced too."""
    out = str(text)
    for s in sorted({s for s in secrets if s}, key=len, reverse=True):
        out = out.replace(s, "****")
    return re.sub(r"(\b(?:ftp|sftp|scp|tftp)://[^:/@\s]*:)[^@\s]*@", r"\1****@", out)

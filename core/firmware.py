"""Tools > File transfer > Firmware Transfer: put a firmware image on Cisco devices (IOS, IOS XE, NX-OS, ASA).

Each device pulls its image itself from a source server: Toner's own FTP, SFTP / SCP or TFTP server, or another FTP, SFTP,
SCP, TFTP, HTTP or HTTPS server. Toner lists the source's folder from here so the technician picks from what is really there;
TFTP and HTTP(S) cannot list, so there the technician types the file names and Toner checks each one. Nothing in this module
reloads a device, ever.

Sources are plain dicts:
    {"own": bool, "proto": "ftp"|"sftp"|"scp"|"tftp"|"http"|"https", "host", "port", "user", "password", "folder",
     "anonymous": bool, "files": [typed names, for tftp/http/https], "insecure": bool (https: Toner's own check skips the certificate)}
For Toner's own server, "host" is this computer's address as the devices see it and "folder" is the server's folder on disk.
"""
import ftplib
import io
import os
import re
import socket
import stat
import threading
import time
from datetime import datetime

from core import db, vendors

# ---------------------------------------------------------------- which devices, and what their copy command can fetch from
PLATFORMS = ("cisco_ios", "cisco_xe", "cisco_nxos", "cisco_asa")
PLATFORM_NAMES = dict(vendors.VENDORS["cisco"]["platforms"])          # cisco_xe -> 'IOS XE'
# the copy clients each platform has (IOS and ASA have no SFTP client)
CLIENTS = {"cisco_ios": ("ftp", "scp", "tftp", "http", "https"), "cisco_xe": ("ftp", "sftp", "scp", "tftp", "http", "https"),
           "cisco_nxos": ("ftp", "sftp", "scp", "tftp", "http", "https"), "cisco_asa": ("ftp", "scp", "tftp", "http", "https")}
PROTO_NAMES = {"ftp": "FTP", "sftp": "SFTP", "scp": "SCP", "tftp": "TFTP", "http": "HTTP", "https": "HTTPS"}
DEFAULT_PORTS = {"ftp": 21, "sftp": 22, "scp": 22, "tftp": 69, "http": 80, "https": 443}
OTHER_PROTOS = ("ftp", "sftp", "scp", "tftp", "http", "https")      # what "Another server" offers
NAMED = ("tftp", "http", "https")                                     # cannot list a folder: the file names are typed, each checked
NOT_FOUND = "{name} was not found on the server."
NO_SIZE = "The server did not give the size of {name}; Fits is not checked for it."
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
    line = f"{n} file{'s' if n != 1 else ''} in {folder} on {src['host']} ({proto_label(src)})."
    return " ".join([line] + [NO_SIZE.format(name=f["name"]) for f in files if "size" in f and f["size"] is None])


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
NO_SFTP = ("Signed in to {host}, but the server did not start SFTP for this account. Check that the account is allowed to use SFTP "
           "(not only FTP) and has a home folder.")


def _no_folder(src):
    return SourceError(f"The folder {src.get('folder') or '/'} was not found on the server.")


def list_files(src, timeout=15):
    """The files (not folders) in the source's folder: [{'name', 'size', 'modified' (datetime or None)}], by name.
    Raises SourceError with the line to show."""
    if src.get("own"):
        files = _list_local(src)
    elif src["proto"] in NAMED:
        files = _check_named(src, timeout)
    elif src["proto"] == "ftp":
        files = _list_ftp(src, timeout)
    else:
        files = _list_ssh(src, timeout)
    return sorted(files, key=lambda f: f["name"].lower())


def _check_named(src, timeout):
    """TFTP, HTTP and HTTPS cannot list a folder, so each typed name (src['files']) is asked for: HTTP(S) with a HEAD request
    (the size from its Content-Length), TFTP with a read request that asks for the size (tsize) and is cancelled straight away.
    A size the server does not give is None."""
    folder = (src.get("folder") or "").strip("/")
    out = []
    for name in src.get("files") or []:
        path = f"{folder}/{name}" if folder else name
        size = _http_size(src, path, name, timeout) if src["proto"] in ("http", "https") else _tftp_size(src, path, name, timeout)
        out.append({"name": name, "size": size, "modified": None})
    return out


def _http_size(src, path, name, timeout):
    import requests
    url = f"{src['proto']}://{src['host']}:{src['port']}/{path}"
    auth = (src["user"], src.get("password") or "") if src.get("user") else None
    try:
        r = requests.head(url, auth=auth, timeout=timeout, verify=not src.get("insecure"), allow_redirects=True)
    except requests.exceptions.SSLError:
        raise _connect_failed(src, ValueError("the certificate was not accepted (self-signed?)")) from None
    except requests.RequestException as e:
        raise _connect_failed(src, getattr(e, "__context__", None) or e) from None
    if r.status_code == 404:
        raise SourceError(NOT_FOUND.format(name=name))
    if r.status_code in (401, 403):
        raise SourceError(REFUSED)
    if r.status_code >= 400:
        raise SourceError(f"The server answered {r.status_code} {r.reason} for {name}.")
    length = r.headers.get("Content-Length", "")
    return int(length) if length.isdigit() else None


def _tftp_size(src, path, name, timeout):
    """A read request with the tsize option (RFC 2349): the server answers with the size (OACK), or starts sending without
    one, or says the file is not there. Toner cancels at once, so nothing is downloaded."""
    import struct
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(struct.pack("!H", 1) + path.encode() + b"\0octet\0tsize\x000\0", (src["host"], int(src["port"] or 69)))
        try:
            pkt, addr = s.recvfrom(70000)
        except OSError as e:
            raise _connect_failed(src, e) from None
        op = struct.unpack("!H", pkt[:2])[0]
        s.sendto(struct.pack("!HH", 5, 0) + b"size only\0", addr)
        if op == 5:
            code, words = struct.unpack("!H", pkt[2:4])[0], pkt[4:].rstrip(b"\0").decode(errors="replace")
            raise SourceError(NOT_FOUND.format(name=name) if code == 1 else f"The server refused {name}: {words}.")
        if op == 6:
            fields = pkt[2:].split(b"\0")
            opts = dict(zip(fields[0::2], fields[1::2]))
            return int(opts[b"tsize"]) if opts.get(b"tsize", b"").isdigit() else None
        return None
    finally:
        s.close()


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
                raise SourceError(NO_SFTP.format(host=src["host"])) from None     # the login worked; the server refused the SFTP channel
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
           "user": data.get("user", ""), "folder": data.get("folder", ""), "anonymous": bool(data.get("anonymous")), "password": "",
           "files": list(data.get("files") or []), "insecure": bool(data.get("insecure"))}
    try:
        import keyring
        out["password"] = keyring.get_password(db.SERVICE, db.qualify(SECRET)) or ""
    except Exception:
        pass
    return out


def remember(src):
    """Keep another server and its login for this organization: the password in the vault, the rest in its settings."""
    db.set_setting(SETTING, {k: src.get(k) for k in ("proto", "host", "port", "user", "folder", "anonymous", "files", "insecure")})
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
    return re.sub(r"(\b(?:ftp|sftp|scp|tftp|https?)://[^:/@\s]*:)[^@\s]*@", r"\1****@", out)


# ================================================================ reading the devices (step 3: Check devices)
CHECK_WORKERS, TRANSFER_WORKERS = 8, 4                 # all selected devices at once, up to these (transfers: bandwidth)
MAIN_FS = {"cisco_ios": "flash:", "cisco_xe": "flash:", "cisco_nxos": "bootflash:", "cisco_asa": "disk0:"}
NO_LOGIN = "No user name or password: set one on the device or its profile."
NO_CLIENT = "{platform} has no SFTP client: use FTP, SCP or TFTP."
NO_ENABLE = "Could not enter enable mode. Add the enable password to the device or its credential profile."


def member_fs(platform, n):
    """Stack member n's flash: flash-2: on IOS XE, flash2: on classic IOS (3750, 2960-X stacks)."""
    return MAIN_FS[platform] if n == 1 else (f"flash-{n}:" if platform == "cisco_xe" else f"flash{n}:")


def parse_version(platform, text):
    """{'version', 'image' (the file it booted, without the file system), 'mode' ('INSTALL', 'BUNDLE' or '')} from `show version`.
    IOS XE prints the mode in up to two places: the table of switches ("Switch Ports Model SW Version SW Image Mode", one row
    per stack member, the active one marked *) and, on some releases only, a line "Installation mode is INSTALL". Catalyst 9000
    software prints the table alone, so the table is read first and the line second; a stack reports its active switch's row.
    When neither is there the mode is '' and collect() falls back on the booted file's name and `show install summary`."""
    t = text or ""
    if platform == "cisco_nxos":
        v = re.search(r"NXOS:\s*version\s+(\S+)", t) or re.search(r"system:\s*version\s+(\S+)", t)
        img = re.search(r"NXOS image file is:\s*(\S+)", t) or re.search(r"system image file is:\s*(\S+)", t)
    elif platform == "cisco_asa":
        v = re.search(r"Adaptive Security Appliance Software Version\s+(\S+)", t)
        img = re.search(r'System image file is "([^"]+)"', t)
    else:
        v = re.search(r"Cisco IOS XE Software, Version\s+(\S+)", t) or re.search(r"\bVersion\s+([^\s,]+)", t)
        img = re.search(r'System image file is "([^"]+)"', t)
    mode = ""
    if platform == "cisco_xe":
        m = re.search(r"Installation mode is\s+(INSTALL|BUNDLE)\b", t, re.I)
        mode = xe_mode_table(t) or (m.group(1).upper() if m else "")
    return {"version": v.group(1) if v else "", "image": file_name(img.group(1)) if img else "", "mode": mode}


def read_software(platform, run):
    """{'version', 'image', 'mode'} from a signed-in Cisco device: `show version` through parse_version and, for IOS XE software
    whose show version does not say the mode, the booted file's name, then `show install summary`. `run(command)` returns the
    text. The health checks (drivers/cisco.py) and the wizard's Check devices (collect) read it the same way."""
    out = parse_version(platform, run("show version"))
    if platform == "cisco_xe" and not out["mode"]:         # show version said neither: the booted file's name, then install's own view
        out["mode"] = xe_mode_of_image(out["image"]) or parse_install_summary(run("show install summary"))
    return out


_XE_ROW = re.compile(r"^\s*(\*?)\s*\d+\s+\d+\s+\S+\s+\S+\s+\S+(.*)$")       # [*] switch, ports, model, version, image, [mode]


def _mode_word(text):
    m = re.search(r"\b(INSTALL|BUNDLE)\b", text or "", re.I)
    return m.group(1).upper() if m else ""


def xe_mode_table(text):
    """The mode from `show version`'s table of switches, as Catalyst 3850 and 9000 software prints it:
        Switch Ports Model              SW Version        SW Image              Mode
        ------ ----- -----              ----------        ----------            ----
        *    1 41    C9300-24P          17.09.04a         CAT9K_IOSXE           INSTALL
             2 41    C9300-24P          17.09.04a         CAT9K_IOSXE           INSTALL
    The active switch's row (marked *) counts, else the first row. A narrow terminal can wrap a row's last column onto the next
    line; that line is read as part of the row. '' when there is no such table."""
    rows = []                                               # [active, mode] per switch
    in_table = False
    for line in (text or "").splitlines():
        if re.match(r"^\s*Switch\s+Ports\s+Model\b.*\bMode\b", line, re.I):
            in_table, rows = True, []
            continue
        if not in_table:
            continue
        if not line.strip():
            if rows:
                break
            continue
        if line.lstrip().startswith("-"):
            continue
        m = _XE_ROW.match(line)
        if m:
            rows.append([m.group(1) == "*", _mode_word(m.group(2))])
        elif rows and not rows[-1][1] and _mode_word(line) and len(line.split()) == 1:
            rows[-1][1] = _mode_word(line)                  # the Mode column, wrapped onto its own line
        else:
            break
    if not rows:                                            # a table with another heading: any row that ends in the mode
        for line in (text or "").splitlines():
            m = _XE_ROW.match(line)
            if m and re.fullmatch(r"\s*(INSTALL|BUNDLE)\s*", m.group(2), re.I):
                rows.append([m.group(1) == "*", _mode_word(m.group(2))])
    for active, mode in rows:
        if active and mode:
            return mode
    return next((mode for _active, mode in rows if mode), "")


def xe_mode_of_image(image):
    """The mode an IOS XE device must be in from the file it booted: INSTALL mode always boots packages.conf, BUNDLE mode a .bin.
    '' when the name says neither."""
    name = (image or "").lower()
    if name == "packages.conf":
        return "INSTALL"
    if name.endswith(".bin"):
        return "BUNDLE"
    return ""


def parse_install_summary(text):
    """The mode from `show install summary`, for IOS XE software whose `show version` does not say: 'INSTALL' when the running
    image is listed as an installed package ("IMG   C    17.06.05.0.5797", activated and committed, or U while uncommitted),
    'BUNDLE' when the device answers that it is not in INSTALL mode, else ''."""
    t = text or ""
    if re.search(r"not in INSTALL mode", t, re.I):
        return "BUNDLE"
    if re.search(r"Installed Package\(s\) Information", t) and re.search(r"^\s*IMG\s+[CU]\s+\S+", t, re.M):
        return "INSTALL"
    return ""


def file_name(path):
    """'flash:/x.bin', 'bootflash:///x.bin', 'disk0:/x.bin', 'flash:x.bin' -> 'x.bin'."""
    return re.sub(r"^[\w-]+:/*", "", str(path or "")).strip()


_DIR_IOS = re.compile(r"^\s*\d+\s+[-drwx]{4,}\s+(\d+)\s+.*?\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{2}:?\d{2})?\s+(\S.*)$")
_DIR_ASA = re.compile(r"^\s*\d+\s+[-drwx]{4,}\s+(\d+)\s+\d{2}:\d{2}:\d{2}\s+\w{3}\s+\d{1,2}\s+\d{4}\s+(\S.*)$")
_DIR_NX = re.compile(r"^\s*(\d+)\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+(\S.*)$")


def parse_dir(text):
    """`dir flash:` (IOS, IOS XE), `dir disk0:` (ASA) or `dir bootflash:` (NX-OS): {'files': {name: size}, 'total', 'free'}; None when
    the totals are not there. Folders (a 'd' flag, or a name ending in /) are left out."""
    t = text or ""
    m = re.search(r"(\d+)\s+bytes total\s*\((\d+)\s+bytes free[^)]*\)", t)     # an ASA adds '/94% free' inside the brackets
    if m:
        total, free = int(m.group(1)), int(m.group(2))
    else:
        tot, fr = re.search(r"^\s*(\d+)\s+bytes total", t, re.M), re.search(r"^\s*(\d+)\s+bytes free", t, re.M)
        if not (tot and fr):
            return None
        total, free = int(tot.group(1)), int(fr.group(1))
    files = {}
    for line in t.splitlines():
        if re.search(r"\s+d[-rwx]{3,}\s", line):
            continue
        hit = _DIR_ASA.match(line) or _DIR_IOS.match(line) or _DIR_NX.match(line)
        if hit and not hit.group(2).endswith("/"):
            files[hit.group(2).strip()] = int(hit.group(1))
    return {"files": files, "total": total, "free": free}


def parse_boot(platform, text):
    """The image files the boot statement or variable names: `show boot` (IOS, IOS XE, NX-OS) or `show running-config boot` (ASA).
    Only the file names, without the file system ('packages.conf' on IOS XE in INSTALL mode). IOS XE prints the current boot
    variable and the one for the next reload; both count (a file set for the next reload must never be offered for deleting)."""
    t = text or ""
    if platform == "cisco_asa":
        paths = re.findall(r"^\s*boot system\s+(\S+)", t, re.M)
    elif platform == "cisco_nxos":
        paths = [p for line in re.findall(r"NXOS variable\s*=\s*(\S+)", t) for p in line.split(";")]
    elif platform == "cisco_xe":
        paths = [p for line in re.findall(r"BOOT variable\s*=\s*([^\r\n]*)", t) for p in line.split(";")]
    else:
        m = re.search(r"BOOT path-list\s*:\s*([^\r\n]*)", t) or re.search(r"BOOT variable\s*=\s*([^\r\n]*)", t)
        paths = (m.group(1) if m else "").split(";")
    out = []
    for p in paths:
        p = p.strip().strip(",")
        if p and file_name(p) not in out:
            out.append(file_name(p))
    return out


def ping_ok(text):
    """IOS / ASA 'Success rate is 100 percent' or NX-OS '5 packets received': True when any answer came back."""
    t = text or ""
    m = re.search(r"Success rate is (\d+) percent", t)
    if m:
        return int(m.group(1)) > 0
    m = re.search(r"(\d+) packets received", t)
    return bool(m and int(m.group(1)) > 0)


# ---------------------------------------------------------------- signing in, and the wizard's session log
def has_login(dev):
    from core import profiles
    return bool(profiles.username(dev) and profiles.secret(dev, "main"))


def connect(dev, log=None, opts=None):
    """A netmiko connection to the device the way the checks and the Command Runner make one: its login and credential profile,
    its jump host or proxy, its SSH host key checked per Settings > Security. Use as a context manager."""
    from core import profiles
    from drivers import DRIVERS
    dev = profiles.resolve(dev)
    drv = DRIVERS["cisco"](dev, {}, opts or db.runtime_options())
    drv.plat = platform_of(dev)
    drv.session_log = log
    return drv.connect()


def log_path(dev):
    from core import sessionlog
    safe = re.sub(r"[^\w.-]+", "_", dev["name"])[:60]
    return sessionlog.log_dir() / f"firmware-{safe}.log"


def save_log(dev, buf, secrets, append=True):
    """Write what was sent and received to firmware-<device>.log in the SSH logs folder, every password masked. The first step
    of a run replaces the file; the later steps add to it."""
    data = buf.getvalue().decode("utf-8", "replace") if buf is not None else ""
    if not data:
        return None
    try:
        path = log_path(dev)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a" if append else "w", encoding="utf-8") as fh:
            fh.write(mask(data, secrets))
        return path
    except OSError:
        return None


def plain_error(e, secrets=()):
    """An exception as one line for the page, any password masked."""
    text = " ".join(str(e).split()) or type(e).__name__
    return mask(text[:240], secrets)


def _prompt_re(c):
    from core.netconn import any_mode
    return any_mode(c) or r"[>#]\s*$"


def _read_until(c, pattern, seconds):
    """Read the channel until `pattern` matches what came back (or the time is up). Returns what was read."""
    seen, end = "", time.time() + seconds
    while time.time() < end:
        seen += c.read_channel()
        if re.search(pattern, seen):
            return seen
        time.sleep(0.1)
    return seen


def port_open(c, host, port, seconds=40):
    """IOS and IOS XE: `telnet <host> <port>` from the device. True when it opens (Toner then leaves it with Ctrl-^ x and
    `disconnect`), False when it is refused or times out."""
    prompt = _prompt_re(c)
    c.write_channel(f"telnet {host} {port}{c.RETURN}")
    seen, end = "", time.time() + seconds
    while time.time() < end:
        seen += c.read_channel()
        if re.search(r"\bOpen\b", seen):
            c.write_channel("\x1e")
            time.sleep(0.3)
            c.write_channel("x")
            _read_until(c, prompt, 10)
            c.write_channel("disconnect" + c.RETURN)
            if re.search(r"\[confirm\]", _read_until(c, r"\[confirm\]|" + prompt, 10)):
                c.write_channel(c.RETURN)
                _read_until(c, prompt, 10)
            return True
        tail = seen.split("\n", 1)[1] if "\n" in seen else ""   # what came after the command's own echo
        if re.search(prompt, tail):                         # the prompt is back without 'Open': refused, timed out, unknown host
            return False
        time.sleep(0.1)
    c.write_channel("\x1e")                                 # still trying: give up on it and get the prompt back
    time.sleep(0.3)
    c.write_channel("x")
    _read_until(c, prompt, 10)
    return False


# ---------------------------------------------------------------- step 3: what each device has, and whether it can take part
def collect(dev, src, vrf="management", opts=None, append_log=False):
    """Sign in and read the device: version, mode, free space on every flash (every stack member), the boot statement, and
    whether the source answers ping and its port from the device itself. Changes nothing. Returns
    {'key', 'name', 'host', 'platform', 'version', 'mode', 'image', 'boot': [files], 'flashes': [{'member', 'role', 'state',
    'fs', 'total', 'free', 'files': {name: size}}], 'ping', 'port' (True/False/None), 'note', 'held' (the reason, or ''), 'dev'}."""
    plat = platform_of(dev)
    out = {"key": dev.get("key") or dev["name"], "name": dev["name"], "host": dev.get("host", ""), "platform": plat, "version": "",
           "mode": "", "image": "", "boot": [], "flashes": [], "ping": None, "port": None, "note": "", "held": "", "dev": dev}
    secrets = [src.get("password") or ""]
    if not can_fetch(plat, src["proto"]):
        out["held"] = NO_CLIENT.format(platform=PLATFORM_NAMES[plat])
        return out
    if not has_login(dev):
        out["held"] = NO_LOGIN
        return out
    from core import profiles
    secrets.append(profiles.secret(dev, "main") or "")
    log = io.BytesIO()
    try:
        with connect(dev, log, opts) as c:
            c.enable()                                      # a no-op when the login is privileged already
            prompt = _prompt_re(c)

            def run(cmd, t=60):
                return c.send_command(cmd, read_timeout=t, expect_string=prompt)
            out.update(read_software(plat, run))
            members = []
            if plat in ("cisco_ios", "cisco_xe"):
                from drivers import clichecks
                members = clichecks.stack_members(run("show switch"))
            if len(members) < 2:
                members = [("1", "", "Ready")]
            for n, role, state in members:
                fs = member_fs(plat, int(n))
                listing = parse_dir(run(f"dir {fs}"))
                if listing is None:
                    out["held"] = out["held"] or f"Could not read the free space from 'dir {fs}'."
                    listing = {"files": {}, "total": None, "free": None}
                out["flashes"].append({"member": int(n), "role": role, "state": state, "fs": fs, **listing})
            out["boot"] = parse_boot(plat, run("show running-config boot" if plat == "cisco_asa" else "show boot"))
            host, port = src["host"], int(src["port"])
            out["ping"] = ping_ok(run(f"ping {host} vrf {vrf}" if plat == "cisco_nxos" else f"ping {host}", 60))
            if out["ping"]:
                if src["proto"] == "tftp":
                    out["note"] = f"Port {port} not checked (TFTP is UDP)"
                elif plat in ("cisco_nxos", "cisco_asa"):
                    out["note"] = f"Port {port} not checked (ping only)"
                else:
                    out["port"] = port_open(c, host, port)
    except Exception as e:                                  # noqa: BLE001  (the reason is shown beside the device)
        # netmiko says "enable mode" when `enable` was refused (the ASA's runs while signing in: see netconn.AsaSSH.enable)
        out["held"] = NO_ENABLE if "enable mode" in str(e) else f"Could not sign in: {plain_error(e, secrets)}"
    finally:
        save_log(dev, log, secrets, append=append_log)
    if out["version"]:                                      # the device record keeps what was read (see db.set_software)
        try:
            db.set_software(dev, out)
        except Exception:
            from core import quiet
            quiet.ignored()
    if not out["held"]:
        bad = [f for f in out["flashes"] if f["state"].strip().lower() != "ready"]
        if bad:
            out["held"] = f"Stack member {bad[0]['member']} is not Ready ({bad[0]['state']})."
        elif out["ping"] is False:
            out["held"] = f"Cannot reach {src['host']} from the device (ping failed)."
        elif out["port"] is False:
            out["held"] = f"Reaches {src['host']}, but port {src['port']} is closed."
    return out


def collect_many(devices, src, vrf="management", on_result=None, cancel=None, opts=None):
    """collect() for every device, up to CHECK_WORKERS at once, each in its own organization's file. Results in the order given."""
    from concurrent.futures import ThreadPoolExecutor

    def one(d):
        if cancel is not None and cancel.is_set():
            return None
        with db.within(d.get("org")):
            r = collect(d, src, vrf, opts)
        if on_result:
            on_result(r)
        return r
    with ThreadPoolExecutor(max_workers=max(1, min(CHECK_WORKERS, len(devices)))) as pool:
        return [r for r in pool.map(one, devices) if r is not None]


# ================================================================ step 4: Clean up
IMAGE_EXT = (".bin", ".spa", ".pkg", ".tar")
DELETE_WARNING = ("These files are deleted now and cannot be recovered. The running image and the files in the boot statement are not "
                  "touched. Nothing is reloaded.")


def file_note(r, name):
    """(note, tickable, pre-ticked) for one file on a device read by collect(). The running image and the boot statement's files
    can never be ticked; ASDM images are kept unless ticked; other image files are old images, ticked."""
    low = name.lower()
    if low == (r.get("image") or "").lower():
        return "running image", False, False
    if low in {b.lower() for b in r.get("boot") or []}:
        return "in boot statement", False, False
    if r["platform"] == "cisco_asa" and low.startswith("asdm"):
        return "ASDM image", True, False
    if low.endswith(IMAGE_EXT):
        return "old image", True, True
    return "", True, False


def cleanup_plan(r):
    """What the Clean up step shows for one device: {'install': True} on IOS XE in INSTALL mode, else
    {'install': False, 'flashes': [{'fs', 'member', 'free', 'total', 'files': [{'name', 'size', 'note', 'tickable', 'ticked'}]}]}."""
    if r["platform"] == "cisco_xe" and r.get("mode") == "INSTALL":
        return {"install": True, "flashes": []}
    out = []
    for f in r["flashes"]:
        files = []
        for name, size in sorted(f["files"].items(), key=lambda kv: kv[0].lower()):
            note, tickable, ticked = file_note(r, name)
            files.append({"name": name, "size": size, "note": note, "tickable": tickable, "ticked": ticked})
        out.append({"fs": f["fs"], "member": f["member"], "free": f["free"], "total": f["total"], "files": files})
    return {"install": False, "flashes": out}


def space_line(fs, free, total):
    """'flash: 1.2 GB free of 11.0 GB'."""
    if free is None or total is None:
        return fs
    return f"{fs} {human_size(free)} free of {human_size(total)}"


def delete_command(platform, fs, name):
    """The platform's delete that asks nothing: delete /force (IOS, IOS XE), ... no-prompt (NX-OS), delete /noconfirm (ASA)."""
    if platform == "cisco_nxos":
        return f"delete {fs}{name} no-prompt"
    if platform == "cisco_asa":
        return f"delete /noconfirm {fs}/{name}"
    return f"delete /force {fs}{name}"


def confirm_text(chosen):
    """(title, body) of the one confirmation before anything is deleted. `chosen`: [(result, {'install': bool, 'files': [(fs, name, size)]})]
    for the devices with something ticked, in page order."""
    n = len(chosen)
    lines = []
    for r, pick in chosen:
        lines.append(f"{r['name']} ({r['host']})")
        if pick.get("install"):
            lines.append("    install remove inactive")
        for fs, name, size in pick.get("files", []):
            lines.append(f"    {fs}{'/' if r['platform'] == 'cisco_asa' else ''}{name}  {human_size(size)}")
    return f"Delete files on {n} device{'s' if n != 1 else ''}?", "\n".join(lines) + "\n\n" + DELETE_WARNING


def _install_remove(c, prompt):
    """install remove inactive, answering its y/n question with y. Returns (ok, the device's last words)."""
    out = c.send_command("install remove inactive", expect_string=r"\[y/n\]|" + prompt, read_timeout=900)
    if re.search(r"\[y/n\]", out):
        out += c.send_command("y", expect_string=prompt, read_timeout=1800, cmd_verify=False)
    ok = "SUCCESS" in out and "FAILED" not in out
    last = next((l.strip() for l in reversed(out.splitlines()) if l.strip() and ("SUCCESS" in l or "FAILED" in l or "%" in l)), "")
    return ok, last


def cleanup(dev, r, pick, src_password="", on_item=None, opts=None):
    """Delete what was ticked on one device (and only that), then read the free space again. `pick`: {'install': bool, 'files':
    [(fs, name, size)]}. on_item(item, status) as each one goes: item is 'install' or (fs, name); status 'Deleting...', 'Deleted' or
    'Failed: <reason>'. Every deletion is in the audit log. Returns {fs: free bytes} read afterwards."""
    from core import audit, profiles
    report = on_item or (lambda *_a: None)
    secrets = [src_password, profiles.secret(dev, "main") or ""]
    plat = platform_of(dev)
    free = {}
    log = io.BytesIO()
    items = (["install"] if pick.get("install") else []) + [(fs, name) for fs, name, _s in pick.get("files", [])]
    sizes = {(fs, name): size for fs, name, size in pick.get("files", [])}
    try:
        with connect(dev, log, opts) as c:
            try:
                c.enable()
            except Exception:                               # noqa: BLE001
                pass
            prompt = _prompt_re(c)
            for item in items:
                report(item, "Deleting...")
                if item == "install":
                    ok, last = _install_remove(c, prompt)
                    if ok:
                        audit.log("firmware install remove inactive", f"{dev['name']}: done")
                        report(item, "Deleted")
                    else:
                        audit.log("firmware failed", f"{dev['name']}: install remove inactive: {mask(last, secrets)}")
                        report(item, f"Failed: {mask(last, secrets) or 'install remove inactive did not finish'}")
                    continue
                fs, name = item
                out = c.send_command(delete_command(plat, fs, name), expect_string=prompt, read_timeout=120)
                gone = name not in ((parse_dir(c.send_command(f"dir {fs}", expect_string=prompt, read_timeout=60)) or {}).get("files") or {})
                where = f"{fs}{'/' if plat == 'cisco_asa' else ''}{name}"
                if gone:
                    audit.log("firmware delete", f"{dev['name']}: {where} ({human_size(sizes[item])})")
                    report(item, "Deleted")
                else:
                    why = next((l.strip() for l in out.splitlines() if "%" in l or "rror" in l), "") or "the file is still there"
                    audit.log("firmware failed", f"{dev['name']}: delete {where}: {mask(why, secrets)}")
                    report(item, f"Failed: {mask(why, secrets)}")
            for f in r["flashes"]:
                listing = parse_dir(c.send_command(f"dir {f['fs']}", expect_string=prompt, read_timeout=60))
                if listing is not None:
                    free[f["fs"]] = listing["free"]
                    f.update(listing)                        # the Images step works from what is there now
    except Exception as e:                                  # noqa: BLE001
        why = plain_error(e, secrets)
        audit.log("firmware failed", f"{dev['name']}: clean up: {why}")
        for item in items:
            report(item, f"Failed: {why}")
    finally:
        save_log(dev, log, secrets)
    return free


# ================================================================ step 5: Images
MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def free_text(r):
    """'1.2 GB' for one flash, 'switch 1: 1.2 GB, switch 2: 1.1 GB' for a stack."""
    if len(r["flashes"]) == 1:
        return human_size(r["flashes"][0]["free"])
    return ", ".join(f"switch {f['member']}: {human_size(f['free'])}" for f in r["flashes"])


def room_for(r, name, size):
    """[(where, free)] for each flash the image does not fit on: 'switch 2' on a stack, the file system otherwise. A file of
    the same name already there is replaced, so its size counts as free."""
    out = []
    for f in r["flashes"]:
        if f["free"] is None or size is None:
            continue
        free = f["free"] + (f["files"].get(name) or 0)
        if size > free:
            out.append((f"switch {f['member']}" if len(r["flashes"]) > 1 else f["fs"], free))
    return out


def image_problems(rows):
    """The lines under the Images table: [(text, blocks Next)]. `rows`: [(result, file dict or None, typed hash)]."""
    out = []
    for r, f, typed in rows:
        if f is None:
            continue
        h = (typed or "").strip()
        if not h:
            out.append((f"{r['name']}: an image is chosen but no MD5 hash is typed.", True))
        elif not MD5_RE.match(h):
            out.append((f"{r['name']}: the MD5 hash must be 32 hexadecimal characters.", True))
        for where, free in room_for(r, f["name"], f["size"]):
            out.append((f"{r['name']}: {f['name']} ({human_size(f['size'])}) does not fit on {where} ({human_size(free)} free). "
                        "Clean up first, or skip the device.", False))
    if not any(f is not None for _r, f, _t in rows):
        out.append(("No device has an image chosen.", True))
    return out


TRANSFER_STEPS = ("For each device Toner copies the image, checks its MD5, puts it on every stack member and checks it there, then:\n"
                  "• IOS XE in INSTALL mode: install add only.\n"
                  "• IOS XE in BUNDLE mode and IOS: sets the boot statement and saves the configuration.\n"
                  "• NX-OS: sets the boot variable and saves the configuration.\n"
                  "• ASA: replaces the boot system line and saves the configuration.\n"
                  "Nothing is reloaded. Up to 4 devices copy at once.")


def source_shown(src):
    """The server as the confirmation shows it, never with its password: 'sftp://toner@10.0.0.5', 'ftp://toner@10.0.0.5:2121',
    'tftp://10.0.0.5' (a port only when it is not the protocol's usual one)."""
    user = "" if src["proto"] == "tftp" or src.get("anonymous") else (src.get("user") or "")
    port = "" if int(src["port"]) == DEFAULT_PORTS[src["proto"]] else f":{src['port']}"
    return f"{src['proto']}://{user + '@' if user else ''}{src['host']}{port}"


def transfer_text(chosen, src):
    """(title, body) of the confirmation before copying. `chosen`: [(result, file dict)]."""
    n = len(chosen)
    lines = [f"{r['name']} ({r['host']}): {f['name']}, {human_size(f['size'])}, from {source_shown(src)}" for r, f in chosen]
    return f"Transfer images to {n} device{'s' if n != 1 else ''}?", "\n".join(lines) + "\n\n" + TRANSFER_STEPS


# ================================================================ step 6: Transfer
POLL_SECONDS = 3.0                 # how often the second session reads the file's size while it copies
COPY_TIMEOUT = 3600                # the copy itself may take this long (a large image over a slow link)
MD5_TIMEOUT = 900                  # verify /md5 reads the whole image


def copy_url(src, name):
    """The URL the device pulls `name` from, with the login in it (it is masked everywhere it could be shown)."""
    proto = src["proto"]
    port = "" if int(src["port"]) == DEFAULT_PORTS[proto] else f":{src['port']}"
    folder = "" if src.get("own") else (src.get("folder") or "").strip("/")
    path = f"{folder}/{name}" if folder else name
    if proto == "tftp" or not (src.get("user") or src.get("anonymous")):     # TFTP has no login; HTTP(S) may have none
        login = ""
    elif src.get("anonymous"):
        login = "anonymous:anonymous@"
    else:
        login = f"{src.get('user') or ''}:{src.get('password') or ''}@"
    return f"{proto}://{login}{src['host']}{port}/{path}"


def target_path(platform, fs, name):
    """'flash:x.bin', 'bootflash:x.bin', 'disk0:/x.bin'."""
    return f"{fs}/{name}" if platform == "cisco_asa" else f"{fs}{name}"


def cant_reach_hint(words, src):
    """What to add when the device's words say it could not open a connection to the server (Toner itself listed the server
    from this computer, so the server is up): where to look. '' for any other failure."""
    if not re.search(r"Resource temporarily unavailable|Timed out|refused|unreachable", words, re.I):
        return ""
    return (f" The device could not connect to {src['host']} port {src['port']}; Toner could, from this computer. Check the server's "
            f"firewall from the device's side{' and, for FTP, its passive-mode settings' if src['proto'] == 'ftp' else ''}.")


def copy_command(platform, url, name, vrf):
    """IOS and IOS XE copy to flash: (and answer the file name question); NX-OS needs the VRF; ASA asks nothing with /noconfirm."""
    if platform == "cisco_nxos":
        return f"copy {url} bootflash: vrf {vrf}"
    if platform == "cisco_asa":
        return f"copy /noconfirm {url} disk0:/{name}"
    return f"copy {url} flash:"


def _answering(c, command, prompt, timeout):
    """Send a command that may ask 'Destination filename [x]?' or '[confirm]', answering each with Enter, until the prompt is back."""
    asks = r"Destination filename \[[^\]]*\]\?|\[confirm\]|[Oo]ver ?write\?.*$"
    out = c.send_command(command, expect_string=asks + "|" + prompt, read_timeout=timeout)
    for _ in range(4):
        if not re.search(asks, out.splitlines()[-1] if out.strip() else ""):
            break
        out += c.send_command(c.RETURN, expect_string=asks + "|" + prompt, read_timeout=timeout, cmd_verify=False)
    return out


def device_md5(c, platform, path, typed, prompt):
    """(matches, what the device computed or '', its words when it could not)."""
    if platform == "cisco_nxos":
        out = c.send_command(f"show file {path} md5sum", expect_string=prompt, read_timeout=MD5_TIMEOUT)
    else:
        out = c.send_command(f"verify /md5 {path} {typed}", expect_string=prompt, read_timeout=MD5_TIMEOUT)
    m = re.search(r"Computed signature\s*=\s*([0-9a-fA-F]{32})", out) or re.search(r"=\s*([0-9a-fA-F]{32})", out) \
        or re.search(r"^\s*([0-9a-fA-F]{32})\s*$", out, re.M)
    got = m.group(1).lower() if m else ""
    if not got:
        return False, "", next((l.strip() for l in out.splitlines() if "%" in l), out.strip()[:120])
    return got == typed.lower() and "%Error" not in out, got, ""


def _poll_size(dev, path, name, total, on_progress, done, poll, opts):
    """The second session: read the file's size on flash while the copy runs, and report it against the server's size."""
    try:
        with connect(dev, None, opts) as c:
            prompt = _prompt_re(c)
            while not done.wait(poll):
                listing = parse_dir(c.send_command(f"dir {path}", expect_string=prompt, read_timeout=60)) or {}
                size = (listing.get("files") or {}).get(name)
                if size is not None:
                    on_progress(size if total is None else min(size, total), total)
    except Exception:                                       # noqa: BLE001  (progress is a help; the copy itself decides)
        pass


def transfer(dev, r, choice, src, vrf="management", on_step=None, cancel=None, poll=None, opts=None, then=None):
    """Copy the chosen image onto one device, check its MD5, put it on every stack member and check it there.
    choice: {'name', 'size' (from the server), 'md5' (typed)}. on_step(step, (done, total) or None, detail).
    then(c, prompt, report): the step after a verified copy (the boot statement or install add), or None.
    Returns {'ok', 'stopped', 'detail'}."""
    from core import audit, profiles
    say = on_step or (lambda *_a: None)
    plat, name, size, typed = platform_of(dev), choice["name"], choice["size"], choice["md5"].strip().lower()
    secrets = [src.get("password") or "", profiles.secret(dev, "main") or ""]
    url = copy_url(src, name)
    shown = f"{source_shown(src)}/{url.split('/', 3)[3]}"
    fs = r["flashes"][0]["fs"]
    path = target_path(plat, fs, name)
    log = io.BytesIO()

    def fail(detail):
        audit.log("firmware failed", f"{dev['name']}: {mask(detail, secrets)}")
        say("Failed", None, mask(detail, secrets))
        return {"ok": False, "stopped": False, "detail": mask(detail, secrets)}

    if cancel is not None and cancel.is_set():
        say("Not started (stopped)", None, "")
        return {"ok": False, "stopped": True, "detail": ""}
    signed_in = False
    try:
        with connect(dev, log, opts) as c:
            signed_in = True
            try:
                c.enable()
            except Exception:                               # noqa: BLE001
                pass
            prompt = _prompt_re(c)
            say("Copying", (0, size), "")
            done = threading.Event()
            watcher = threading.Thread(target=_poll_size, args=(dev, path, name, size, lambda d, t: say("Copying", (d, t), ""), done,
                                                                 POLL_SECONDS if poll is None else poll, opts), daemon=True)
            watcher.start()
            try:
                out = _answering(c, copy_command(plat, url, name, vrf), prompt, COPY_TIMEOUT)
            finally:
                done.set()
                watcher.join(10)
            listing = parse_dir(c.send_command(f"dir {path}", expect_string=prompt, read_timeout=60)) or {}
            got = (listing.get("files") or {}).get(name)
            if size is None and got:                        # the server gave no size (TFTP without tsize): the device's copy decides
                size = got
            if re.search(r"%\s*Error|Error opening|Invalid input", out, re.I) and got != size:
                words = next((l.strip() for l in out.splitlines() if re.search(r"%\s*Error|Error opening|Invalid", l, re.I)), "")
                return fail(f"The copy failed: {mask(words, secrets)}.{cant_reach_hint(words, src)}")
            if got != size:
                return fail(f"The copy stopped at {human_size(got or 0)} of {human_size(size)}.")
            say("Copying", (size, size), "")
            say("Checking MD5", None, "")
            ok, computed, words = device_md5(c, plat, path, typed, prompt)
            if not ok:
                if computed:
                    return fail(f"MD5 differs: the device computed {computed} and you typed {typed}. The file was left on flash; "
                                "nothing else was changed on this device.")
                return fail(f"The MD5 could not be read: {words}")
            audit.log("firmware copy", f"{dev['name']}: {name} from {shown}, {human_size(size)}, MD5 verified")
            if cancel is not None and cancel.is_set():
                say("Stopped", None, "Stopped after the copy (MD5 verified). Nothing else was changed on this device.")
                return {"ok": False, "stopped": True, "detail": "Stopped after the copy (MD5 verified). Nothing else was changed on this device."}
            for f in r["flashes"][1:]:
                n = f["member"]
                say(f"Copying to switch {n}", None, "")
                member_path = target_path(plat, f["fs"], name)
                out = _answering(c, f"copy {path} {member_path}", prompt, COPY_TIMEOUT)
                there = (parse_dir(c.send_command(f"dir {member_path}", expect_string=prompt, read_timeout=60)) or {}).get("files", {}).get(name)
                if there != size:
                    words = next((l.strip() for l in out.splitlines() if "%" in l), "") or f"switch {n} has {human_size(there or 0)} of {human_size(size)}"
                    return fail(f"The copy failed: {words}.")
                say(f"Checking MD5 on switch {n}", None, "")
                ok, computed, words = device_md5(c, plat, member_path, typed, prompt)
                if not ok:
                    return fail(f"MD5 differs on switch {n}: the device computed {computed or '(nothing)'} and you typed {typed}. "
                                "The file was left on flash; nothing else was changed on this device.")
                audit.log("firmware stack copy", f"{dev['name']}: {name} to switch {n}, MD5 verified")
            if then is not None:
                result = then(c, prompt, lambda step, detail="": say(step, None, detail))
                if isinstance(result, dict):
                    return staged(dev, result, say, secrets)
                if result is not True:
                    return fail(result)
            say("Done", None, "")
            return {"ok": True, "stopped": False, "detail": ""}
    except Exception as e:                                  # noqa: BLE001
        if not signed_in:
            return fail(f"Could not sign in: {plain_error(e, secrets)}")
        return fail(f"The copy failed: {plain_error(e, secrets)}.")
    finally:
        save_log(dev, log, secrets)


# ================================================================ after a verified copy: the boot statement, or install add
INSTALL_TIMEOUT = 1800             # install add unpacks and checks the image on every member
INSTALL_NOTE = ("IOS XE INSTALL mode: the image is added, not activated; run install activate and install commit in the maintenance "
                "window (that reloads). Other devices boot the new image at their next reload.")


UNSAVED = re.compile(r"System configuration has been modified", re.I)
VERIFY = "Verify"
STAGING_FAILED = "Staging failed"
UNSAVED_DETAIL = "Unsaved configuration changes stopped install add. The image is on flash (MD5 verified)."
STAGING_DETAIL = "The image is on flash (MD5 verified), but install add failed: {words}"


def staged(dev, result, say, secrets=()):
    """transfer()'s answer when the image is verified on flash but install add did not take: Verify (unsaved configuration, with
    the pending lines) or Staging failed."""
    from core import audit
    detail = mask(result["detail"], secrets)
    audit.log("firmware failed", f"{dev['name']}: {detail}")
    say(result["step"], None, detail)
    return {"ok": False, "stopped": False, "staged": True, "detail": detail, "pending": result.get("pending")}


def pending_changes(c, prompt, secrets=()):
    """What a save would write: the unified diff from the startup to the running configuration, passwords masked and the
    lines that only carry a time (or the startup's 'Using n out of m bytes') left out."""
    from core import backup

    def read(cmd):
        text = c.send_command(cmd, expect_string=prompt, read_timeout=300)
        text = "\n".join(l for l in text.splitlines() if not re.match(r"^\s*Using \d+ out of \d+ bytes", l))
        return mask(backup.clean(text, mask=True), secrets)
    try:
        start, run = read("show startup-config"), read("show running-config")
    except Exception:                                       # noqa: BLE001  shortcut: an unreadable config shows as no lines
        return []
    return backup.diff_lines(start, run, "startup-config", "running-config")[0]


def _install_add(dev, c, prompt, report, fs, name, secrets):
    """install add on IOS XE in INSTALL mode. True, or a staging result: Verify when unsaved changes stop it, else Staging failed."""
    from core import audit
    report("Running install add (this can take several minutes)")
    out = c.send_command(f"install add file {fs}{name}", expect_string=prompt, read_timeout=INSTALL_TIMEOUT)
    if "SUCCESS" in out and "FAILED" not in out:
        audit.log("firmware install add", f"{dev['name']}: {fs}{name}")
        return True
    if UNSAVED.search(out):
        return {"step": VERIFY, "detail": UNSAVED_DETAIL, "pending": pending_changes(c, prompt, secrets)}
    return {"step": STAGING_FAILED, "detail": STAGING_DETAIL.format(words=mask(_words(out), secrets))}


def save_and_install(dev, r, name, secrets=(), on_step=None, opts=None):
    """After Verify was approved: sign in again, save the configuration (write memory, checked for [OK]) and run install add once
    more. Returns transfer()'s shape: {'ok', 'stopped', 'staged', 'detail', 'pending'}. Nothing here reloads or activates."""
    from core import audit
    say = on_step or (lambda *_a: None)
    fs = r["flashes"][0]["fs"]
    log = io.BytesIO()
    report = lambda step, detail="": say(step, None, detail)
    try:
        with connect(dev, log, opts) as c:
            try:
                c.enable()
            except Exception:                               # noqa: BLE001
                pass
            prompt = _prompt_re(c)
            report("Saving configuration")
            out = c.send_command("write memory", expect_string=prompt, read_timeout=600)
            if not re.search(r"\[OK\]|Copy complete", out):
                return staged(dev, {"step": STAGING_FAILED, "detail": f"The configuration was not saved: {mask(_words(out), secrets)}"}, say, secrets)
            audit.log("firmware config saved", f"{dev['name']}: write memory before install add")
            result = _install_add(dev, c, prompt, report, fs, name, secrets)
            if result is True:
                say("Done", None, "")
                return {"ok": True, "stopped": False, "detail": ""}
            return staged(dev, result, say, secrets)
    except Exception as e:                                  # noqa: BLE001
        return staged(dev, {"step": STAGING_FAILED, "detail": f"Could not sign in: {plain_error(e, secrets)}"}, say, secrets)
    finally:
        save_log(dev, log, secrets)


def _words(out, pattern=r"FAILED|%|rror"):
    """The device's line that says what went wrong."""
    return next((l.strip() for l in reversed((out or "").splitlines()) if re.search(pattern, l)), (out or "").strip()[-160:])


def boot_lines(r, name, current_paths=()):
    """The configuration lines that point the device at the new image (never a reload). `current_paths`: an ASA's boot system
    lines as the device prints them, to remove."""
    plat, fs = r["platform"], r["flashes"][0]["fs"]
    if plat == "cisco_nxos":
        return [f"boot nxos {fs}{name}"]
    if plat == "cisco_asa":
        # An ASA boots the first boot system line and adds new lines at the end. So: take them all out, put the new image first,
        # then the others back in their order, except the line for the image it runs now (the old one, which goes).
        running = (r.get("image") or "").lower()
        others = [p for p in current_paths if file_name(p).lower() not in (running, name.lower())]
        return [f"no boot system {p}" for p in current_paths] + [f"boot system {fs}/{name}"] + [f"boot system {p}" for p in others]
    stack = len(r["flashes"]) > 1
    return ["no boot system", f"boot system switch all {fs}{name}" if stack else f"boot system {fs}{name}"]


def after_copy(dev, r, name, secrets=()):
    """The step after a verified copy, for transfer(then=...): install add on IOS XE in INSTALL mode, else set the boot statement
    or variable and save the configuration, checked by reading it back. Returns True, the line saying what went wrong, or for
    install add a staging result (see _install_add).
    Every change has its audit line. Nothing here reloads, activates or commits."""
    from core import audit
    plat, fs = r["platform"], r["flashes"][0]["fs"]

    def then(c, prompt, report):
        if plat == "cisco_xe" and r.get("mode") == "INSTALL":
            return _install_add(dev, c, prompt, report, fs, name, secrets)
        current = []
        if plat == "cisco_asa":
            current = re.findall(r"^\s*boot system\s+(\S+)", c.send_command("show running-config boot", expect_string=prompt, read_timeout=60), re.M)
        lines = boot_lines(r, name, current)
        report("Setting boot statement")
        out = c.send_config_set(lines, read_timeout=600)
        if re.search(r"%\s*(Invalid|Error|Incomplete)|Invalid input", out):
            return f"The boot statement did not take: {mask(_words(out), secrets)}"
        report("Saving configuration")
        save = "copy running-config startup-config" if plat == "cisco_nxos" else "write memory"
        out = c.send_command(save, expect_string=prompt, read_timeout=600)
        if not re.search(r"\[OK\]|Copy complete", out):
            return f"The configuration was not saved: {mask(_words(out), secrets)}"
        shown = c.send_command("show running-config boot" if plat == "cisco_asa" else "show boot", expect_string=prompt, read_timeout=60)
        now = parse_boot(plat, shown)
        took = now[:1] == [name] if plat == "cisco_asa" else name in now      # an ASA boots the first boot system line
        if not took:
            return f"The boot statement did not take: show boot says {', '.join(now) or 'nothing'}."
        new_line = next(l for l in lines if not l.startswith("no ") and file_name(l.split()[-1]) == name)
        audit.log("firmware boot", f"{dev['name']}: {new_line}, saved")
        return True
    return then


def summary_text(rows, status, note):
    """What Copy summary puts on the clipboard: one line per device, then the line under the table. `rows`: [(device, address, step, detail)]."""
    lines = [f"{name} ({host}): {step}" + (f" - {detail}" if detail else "") for name, host, step, detail in rows]
    return "\n".join(lines + ["", status] + ([note] if note else []))

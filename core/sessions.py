"""Saved connection sessions: SSH, Telnet, Remote Desktop (RDP) and Serial. A session is a name plus how to connect, kept
so it can be opened again with a double-click. SSH sessions can keep their password in Toner's vault; the rest of a
session is stored in the database. RDP sessions run in a tab (Windows' Remote Desktop control, hosted by Toner) or start Windows' own client (mstsc) with a generated .rdp
file, so Windows asks for the password. The others open in a terminal tab inside Toner."""
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime

import keyring

from core import db, nettools
from core.folders import FolderTree

KINDS = [("ssh", "SSH", 22, "Encrypted command line to a switch, router, firewall or server."),
         ("telnet", "Telnet", 23, "Plain-text command line. Not encrypted: use it only on networks you trust."),
         ("rdp", "Remote Desktop (RDP)", 3389, "Windows' Remote Desktop client, as a tab inside Toner (or in its own window, see Settings > Terminal)."
          if sys.platform == "win32" else "Remote Desktop through FreeRDP, in its own window."),
         ("vnc", "VNC", 5900, "A remote screen through a VNC viewer. The viewer asks for the password."),
         ("serial", "Serial", 0, "A console cable on a COM port (or a network serial server).")]
NAMES = {k: label for k, label, _, _ in KINDS}
DEFAULT_PORT = {k: p for k, _, p, _ in KINDS}
BAUDS = [300, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]
PARITY = [("None", "N"), ("Even", "E"), ("Odd", "O"), ("Mark", "M"), ("Space", "S")]
FLOW = [("None", "none"), ("XON/XOFF (software)", "xonxoff"), ("RTS/CTS (hardware)", "rtscts")]
DEFAULTS = {
    "ssh": {"paging": True, "remember": False},
    "telnet": {},
    "rdp": {"fullscreen": False, "width": 1280, "height": 800, "clipboard": True, "drives": False, "printers": False,
            "admin": False, "gateway": "", "client": ""},          # client: "windows" or "freerdp" ("" = this system's own)
    "vnc": {"fullscreen": False, "viewonly": False},
    "serial": {"baud": 9600, "bytesize": 8, "parity": "N", "stopbits": 1, "flow": "none"},
}
FIELDS = ["name", "kind", "folder_id", "host", "port", "username", "device", "options"]
_SERIAL_URL = re.compile(r"^(COM\d+|loop://.*|socket://[^\s:]+:\d+.*|rfc2217://[^\s:]+:\d+.*|/dev/\S+)$", re.I)


FOLDERS = FolderTree("session_folders", "sessions")
list_folders, folder_paths, folder_descendants = FOLDERS.list, FOLDERS.paths, FOLDERS.descendants
create_folder, rename_folder, move_folder, delete_folder = FOLDERS.create, FOLDERS.rename, FOLDERS.move, FOLDERS.delete
move_sessions, ensure_folder_path = FOLDERS.move_members, FOLDERS.ensure_path


def secret_name(session_id):
    return db.qualify(f"session:{session_id}")


# ---------------------------------------------------------------- storage
def _sessions_here():
    with db.connect() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM sessions ORDER BY name COLLATE NOCASE")]
    for r in rows:
        r["options"] = _options(r)
    return rows


def list_sessions():
    """The sessions of the view, each with 'org' (the file it is kept in): an organization's own plus Global's Shared ones, or in
    Global every organization's."""
    rows = db.gather(_sessions_here)
    if len({r["org"] for r in rows}) > 1:
        rows.sort(key=lambda r: r["name"].lower())
    return rows


def _options(row):
    try:
        given = json.loads(row.get("options") or "{}") if isinstance(row.get("options"), str) else (row.get("options") or {})
    except ValueError:
        given = {}
    return {**DEFAULTS.get(row.get("kind"), {}), **(given if isinstance(given, dict) else {})}


def get(session_id, org=None):
    """One saved session (from `org`'s file; None: the one being written to)."""
    with db.within(org):
        found = next((s for s in _sessions_here() if s["id"] == session_id), None)
        if found:
            found["org"] = db.target()
    return found


def path_of(session):
    """'Chicago/Core' for a session in that folder, '' at the top level."""
    return folder_paths().get(session.get("folder_id"), "")


def validate(s):
    """Raises ValueError with a message that says what to fix."""
    kind = s.get("kind")
    if kind not in NAMES:
        raise ValueError("Choose a session type.")
    if not (s.get("name") or "").strip():
        raise ValueError("Give the session a name so it can be found again.")
    o = {**DEFAULTS[kind], **(s.get("options") or {})}
    if kind in ("ssh", "telnet", "rdp", "vnc"):
        nettools.check_host(s.get("host"))
        port = int(s.get("port") or DEFAULT_PORT[kind])
        if not 1 <= port <= 65535:
            raise ValueError("The port must be between 1 and 65535.")
    if kind == "ssh" and not (s.get("username") or "").strip() and not s.get("device"):
        raise ValueError("Enter the user name for this device.")
    if kind == "rdp":
        if o["fullscreen"] is False and not (320 <= int(o["width"]) <= 8192 and 200 <= int(o["height"]) <= 8192):
            raise ValueError("The window size must be between 320 x 200 and 8192 x 8192.")
    if kind == "serial":
        port = (s.get("host") or "").strip()
        if not port:
            raise ValueError("Choose the serial port, for example COM3.")
        if not _SERIAL_URL.match(port):
            raise ValueError(f"'{port}' is not a COM port (COM3) or a serial URL (socket://host:port, rfc2217://host:port).")
        if int(o["baud"]) not in range(50, 4_000_001):
            raise ValueError("Enter a baud rate such as 9600 or 115200.")
        if int(o["bytesize"]) not in (5, 6, 7, 8) or o["parity"] not in "NEOMS" or float(o["stopbits"]) not in (1, 1.5, 2) \
                or o["flow"] not in ("none", "xonxoff", "rtscts"):
            raise ValueError("One of the serial settings is not valid.")
    return (s["name"]).strip()


def save(s):
    """Insert or update, in the session's own organization's file (s['org']; Shared ones in Global's). Returns the id.
    Raises ValueError (bad input)."""
    with db.within(s.get("org")):
        return _save(s)


def _save(s):
    name = validate(s)
    row = {k: s.get(k) for k in FIELDS}
    row["shared"] = 1 if s.get("shared") and db.target() == db.GLOBAL else 0
    known = {f["id"] for f in list_folders()}
    row.update(name=name, folder_id=s.get("folder_id") if s.get("folder_id") in known else None, host=(s.get("host") or "").strip(),
               port=int(s.get("port") or (0 if s["kind"] == "serial" else DEFAULT_PORT[s["kind"]])),
               username=(s.get("username") or "").strip(), device=s.get("device") or "",
               options=json.dumps({**DEFAULTS[s["kind"]], **(s.get("options") or {})}))
    with db.connect() as c:
        clash = c.execute("SELECT id FROM sessions WHERE name=? COLLATE NOCASE AND folder_id IS ? AND id IS NOT ?",
                          (name, row["folder_id"], s.get("id"))).fetchone()
        if clash:
            where = folder_paths().get(row["folder_id"])
            raise ValueError(f"A session named '{name}' already exists" + (f" in {where}." if where else " at the top level."))
        cols = FIELDS + ["shared"]
        if s.get("id"):
            c.execute("UPDATE sessions SET " + ", ".join(f"{k}=?" for k in cols) + " WHERE id=?",
                      [row[k] for k in cols] + [s["id"]])
            return s["id"]
        return c.execute(f"INSERT INTO sessions ({','.join(cols)}, created) VALUES ({','.join('?' * len(cols))}, ?)",
                         [row[k] for k in cols] + [_now()]).lastrowid


def delete(session_id, org=None):
    with db.within(org):
        with db.connect() as c:
            c.execute("DELETE FROM sessions WHERE id=?", (session_id,))
        forget_password(session_id)


def duplicate(session_id, org=None):
    with db.within(org):
        return _duplicate(session_id)


def _duplicate(session_id):
    s = get(session_id)
    if not s:
        return None
    new = {**s, "id": None}
    base = f"{s['name']} (copy)"
    names = {x["name"].lower() for x in _sessions_here() if x["folder_id"] == s["folder_id"]}
    n, name = 2, base
    while name.lower() in names:
        name, n = f"{s['name']} (copy {n})", n + 1
    new["name"] = name
    new_id = save(new)
    pw = password(session_id)
    if pw:
        set_password(new_id, pw)
    return new_id


def touch(session_id, org=None):
    with db.within(org), db.connect() as c:
        c.execute("UPDATE sessions SET last_used=? WHERE id=?", (_now(), session_id))


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- the saved password (SSH only)
def password(session_id, org=None):
    try:
        with db.within(org):
            return keyring.get_password(db.SERVICE, secret_name(session_id)) or ""
    except Exception:
        return ""


def set_password(session_id, value, org=None):
    with db.within(org):
        db.set_secret(secret_name(session_id), value)


def forget_password(session_id, org=None):
    with db.within(org):
        db.delete_secret(secret_name(session_id))


# ---------------------------------------------------------------- Remote Desktop
def rdp_file_text(s):
    """The contents of a .rdp file for this session. It never holds a password: Windows asks for it."""
    o = {**DEFAULTS["rdp"], **(s.get("options") or {})}
    port = int(s.get("port") or 3389)
    lines = [f"full address:s:{s['host']}" + (f":{port}" if port != 3389 else ""),
             f"screen mode id:i:{2 if o['fullscreen'] else 1}", "use multimon:i:0", "session bpp:i:32",
             f"redirectclipboard:i:{int(bool(o['clipboard']))}", f"redirectprinters:i:{int(bool(o['printers']))}",
             "authentication level:i:2", "enablecredsspsupport:i:1", "prompt for credentials:i:0"]
    if not o["fullscreen"]:
        lines += [f"desktopwidth:i:{int(o['width'])}", f"desktopheight:i:{int(o['height'])}"]
    if s.get("username"):
        lines.append(f"username:s:{s['username']}")
    if o["drives"]:
        lines.append("drivestoredirect:s:*")
    if o["admin"]:
        lines.append("administrative session:i:1")
    if (o.get("gateway") or "").strip():
        lines += [f"gatewayhostname:s:{o['gateway'].strip()}", "gatewayusagemethod:i:1", "gatewaycredentialssource:i:4"]
    return "\r\n".join(lines) + "\r\n"


def rdp_for_device(dev):
    """A Remote Desktop session for an inventory device (a Windows computer)."""
    from core import winmon
    return {"name": dev["name"], "host": dev["host"], "port": 3389,
            "username": dev.get("username") if winmon.transport(dev) == "winrm" else "", "options": {}}


def find_mstsc():
    return shutil.which("mstsc")


FREERDP = ("xfreerdp3", "xfreerdp", "sdl-freerdp3", "sdl-freerdp", "wlfreerdp3", "wlfreerdp")


WINDOWS_FREERDP = ("sdl3-freerdp", "sdl-freerdp3", "sdl-freerdp", "wfreerdp")


def find_freerdp():
    """FreeRDP's client: on PATH, or (Windows) where its installer puts it. None when it is not installed."""
    from core.platforms import WINDOWS
    names = WINDOWS_FREERDP if WINDOWS else FREERDP
    found = next((p for p in (shutil.which(n) for n in names) if p), None)
    if found or not WINDOWS:
        return found
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        for n in names:
            cand = os.path.join(base or "", "FreeRDP", n + ".exe")
            if base and os.path.isfile(cand):
                return cand
    return None


def rdp_client(s=None):
    """'windows' (Windows' own Remote Desktop: the tab or mstsc) or 'freerdp'. Only Windows has a choice (the session's Client);
    Linux uses FreeRDP; macOS gives the .rdp file to Microsoft's Windows App."""
    from core.platforms import MAC, WINDOWS
    if MAC:
        return "mac"
    if not WINDOWS:
        return "freerdp"
    chosen = ((s or {}).get("options") or {}).get("client") or "windows"
    return chosen if chosen in ("windows", "freerdp") else "windows"


def find_rdp_client(s=None):
    """The Remote Desktop client for a session: mstsc, FreeRDP, or `open` on macOS. None when there is none."""
    kind = rdp_client(s)
    if kind == "windows":
        return find_mstsc()
    if kind == "mac":
        return shutil.which("open")
    return find_freerdp()


def asks_for_password(s=None):
    """True when Toner must ask for the password itself: FreeRDP's X11 and Wayland clients have no window of their own to ask
    in (its SDL client and its Windows client do)."""
    if rdp_client(s) != "freerdp":
        return False
    exe = os.path.basename(find_freerdp() or "")
    return exe.startswith(("xfreerdp", "wlfreerdp"))


def freerdp_args(s, exe=""):
    """FreeRDP's arguments for a session (never the password: that goes to it on standard input)."""
    o = {**DEFAULTS["rdp"], **(s.get("options") or {})}
    domain, user = split_user(s.get("username"))
    args = [f"/v:{s['host']}:{int(s.get('port') or 3389)}", "/cert:tofu"]          # a new server's certificate: trust on first use
    if user:
        args.append(f"/u:{user}")
    if domain:
        args.append(f"/d:{domain}")
    args += ["/f"] if o["fullscreen"] else [f"/size:{int(o['width'])}x{int(o['height'])}"]
    args.append("+clipboard" if o["clipboard"] else "-clipboard")
    if o["drives"]:
        args.append(f"/drive:home,{os.path.expanduser('~')}")
    if o["printers"]:
        args.append("/printer")
    if o["admin"]:
        args.append("/admin")
    if (o.get("gateway") or "").strip():
        three = "3" in os.path.basename(exe or "")
        args.append(f"/gateway:g:{o['gateway'].strip()}" if three else f"/g:{o['gateway'].strip()}")
    return args


def rdp_path(s):
    d = db.base_path().parent / "rdp"
    d.mkdir(parents=True, exist_ok=True)
    return d / (re.sub(r"[^A-Za-z0-9._-]", "_", s.get("name") or s["host"])[:60] + ".rdp")


def launch_rdp(s, password=None):
    """Start Remote Desktop in a client of its own. Returns the .rdp file's path (mstsc, macOS) or None (FreeRDP, which is given
    the session on its command line and, where Toner asked for it, the password on standard input). Raises OSError when there
    is no client."""
    from core.platforms import WINDOWS
    client = rdp_client(s)
    exe = find_rdp_client(s)
    if not exe:
        raise OSError("Windows' Remote Desktop client (mstsc.exe) was not found on this computer." if client == "windows" else
                      "FreeRDP was not found. Install it from freerdp.com, or choose Windows Remote Desktop as the Client."
                      if client == "freerdp" and WINDOWS else
                      "No Remote Desktop client was found. Install FreeRDP (for example: sudo apt install freerdp3-x11), "
                      "then try again." if client == "freerdp" else
                      "No Remote Desktop client was found. Install Microsoft's Windows App from the App Store, then try again.")
    if client == "freerdp":
        args = [exe] + freerdp_args(s, exe) + (["/from-stdin:force"] if password is not None else [])
        p = subprocess.Popen(args, close_fds=True, stdin=subprocess.PIPE if password is not None else subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
        if password is not None:
            try:
                p.stdin.write(password + "\n")
                p.stdin.close()
            except OSError:
                pass
        return None
    path = rdp_path(s)
    path.write_text(rdp_file_text(s), encoding="utf-8")
    subprocess.Popen([exe, str(path)], close_fds=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return path


# ---------------------------------------------------------------- Remote Desktop inside Toner
PROG_ID = "MsTscAx.MsTscAx"          # Windows' Remote Desktop ActiveX control (mstscax.dll), the same client mstsc.exe uses


def embedded_available():
    """True when Windows has the Remote Desktop control and Qt can host it, so a session can run inside Toner."""
    if sys.platform != "win32":
        return False
    try:
        import winreg
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, PROG_ID))
        from PySide6 import QtAxContainer          # noqa: F401
    except (ImportError, OSError):
        return False
    return True


def use_embedded(s=None):
    """Settings > Terminal > Remote Desktop: inside Toner (the default) when that is possible, and the session's Client is
    Windows Remote Desktop."""
    return bool(db.get_setting("rdp_embedded")) and embedded_available() and rdp_client(s) == "windows"


# ---------------------------------------------------------------- VNC
# Linux viewers in the order they are tried; TigerVNC's takes 'host::port', -FullScreen and -ViewOnly.
VNC_VIEWERS = ("vncviewer", "xtigervncviewer", "tigervnc", "xtightvncviewer", "gvncviewer", "remmina", "krdc")
WINDOWS_VNC = (("TigerVNC", ("vncviewer64.exe", "vncviewer.exe")), ("RealVNC", ("vncviewer.exe",)),
               ("RealVNC\\VNC Viewer", ("vncviewer.exe",)), ("TightVNC", ("tvnviewer.exe",)), ("uvnc bvba\\UltraVNC", ("vncviewer.exe",)))


def find_vnc_viewer():
    """A VNC viewer: on Linux the first of VNC_VIEWERS on PATH; on Windows TigerVNC, RealVNC, TightVNC or UltraVNC where they
    install (or on PATH); on macOS `open` (its built-in Screen Sharing takes vnc:// addresses). None when there is none."""
    from core.platforms import MAC, WINDOWS
    if MAC:
        return shutil.which("open")
    if not WINDOWS:
        return next((p for p in (shutil.which(n) for n in VNC_VIEWERS) if p), None)
    found = shutil.which("vncviewer") or shutil.which("tvnviewer")
    if found:
        return found
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        for folder, names in WINDOWS_VNC:
            for n in names:
                cand = os.path.join(base or "", folder, n)
                if base and os.path.isfile(cand):
                    return cand
    return None


def vnc_args(s, exe):
    """The viewer's command line for a session (never a password: the viewer asks for it)."""
    o = {**DEFAULTS["vnc"], **(s.get("options") or {})}
    host, port = s["host"], int(s.get("port") or 5900)
    name = re.split(r"[\\/]", exe)[-1].lower()                 # (a Windows path is split the same way on any system)
    if name == "open":                                              # macOS Screen Sharing
        return [exe, f"vnc://{host}:{port}"]
    if name in ("remmina",):
        return [exe, "-c", f"vnc://{host}:{port}"]
    if name in ("krdc", "gvncviewer"):
        return [exe, f"{host}:{port}" if name == "krdc" else f"{host}:{port - 5900 if 5900 <= port < 6000 else port}"]
    if name.startswith("tvnviewer"):                                # TightVNC for Windows
        return [exe, f"-host={host}", f"-port={port}"] + (["-viewonly=yes"] if o["viewonly"] else [])
    args = [exe]                                                    # TigerVNC, RealVNC, UltraVNC and the like
    if o["fullscreen"]:
        args.append("-FullScreen")
    if o["viewonly"]:
        args.append("-ViewOnly")
    return args + [f"{host}::{port}"]


def launch_vnc(s):
    """Open a VNC session in the viewer. Raises OSError when there is none."""
    from core.platforms import MAC, WINDOWS
    exe = find_vnc_viewer()
    if not exe:
        raise OSError("No VNC viewer was found. Install TigerVNC from tigervnc.org, then try again." if WINDOWS else
                      "No VNC viewer was found. Install TigerVNC (for example: sudo apt install tigervnc-viewer), then try again."
                      if not MAC else "macOS could not open its Screen Sharing.")
    subprocess.Popen(vnc_args(s, exe), close_fds=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def split_user(username):
    """(domain, user) for a name written domain-slash-user; ('', name) for user@domain or a plain name. The control takes the domain separately."""
    u = (username or "").strip()
    if "\\" in u:
        dom, _, name = u.partition("\\")
        return dom, name
    return "", u


def rdp_settings(s, width=0, height=0):
    """What the embedded client is given for a session. `width` and `height` are the room in the tab, used when the session is
    set to fill the window (otherwise its own size is used)."""
    o = {**DEFAULTS["rdp"], **(s.get("options") or {})}
    domain, user = split_user(s.get("username"))
    fit = bool(o["fullscreen"]) and width >= 320 and height >= 240
    return {"server": s["host"], "port": int(s.get("port") or 3389), "username": user, "domain": domain, "fit": fit,
            "width": int(width) if fit else int(o["width"]), "height": int(height) if fit else int(o["height"]),
            "clipboard": bool(o["clipboard"]), "drives": bool(o["drives"]), "printers": bool(o["printers"]),
            "admin": bool(o["admin"]), "gateway": (o.get("gateway") or "").strip()}

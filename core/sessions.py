"""Saved connection sessions: SSH, Telnet, Remote Desktop (RDP) and Serial. A session is a name plus how to connect, kept
so it can be opened again with a double-click. SSH sessions can keep their password in Credential Manager; the rest of a
session is stored in the database. RDP sessions start Windows' own Remote Desktop client (mstsc) with a generated .rdp
file, so Windows asks for the password. The others open in a terminal tab inside Toner."""
import json
import os
import re
import shutil
import subprocess
from datetime import datetime

import keyring

from core import db, nettools
from core.folders import FolderTree

KINDS = [("ssh", "SSH", 22, "Encrypted command line to a switch, router, firewall or server."),
         ("telnet", "Telnet", 23, "Plain-text command line. Not encrypted: use it only on networks you trust."),
         ("rdp", "Remote Desktop (RDP)", 3389, "Windows' own Remote Desktop client, started with these settings."),
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
            "admin": False, "gateway": ""},
    "serial": {"baud": 9600, "bytesize": 8, "parity": "N", "stopbits": 1, "flow": "none"},
}
FIELDS = ["name", "kind", "folder_id", "host", "port", "username", "device", "options"]
_SERIAL_URL = re.compile(r"^(COM\d+|loop://.*|socket://[^\s:]+:\d+.*|rfc2217://[^\s:]+:\d+.*|/dev/\S+)$", re.I)


FOLDERS = FolderTree("session_folders", "sessions")
list_folders, folder_paths, folder_descendants = FOLDERS.list, FOLDERS.paths, FOLDERS.descendants
create_folder, rename_folder, move_folder, delete_folder = FOLDERS.create, FOLDERS.rename, FOLDERS.move, FOLDERS.delete
move_sessions, ensure_folder_path = FOLDERS.move_members, FOLDERS.ensure_path


def secret_name(session_id):
    return f"session:{session_id}"


# ---------------------------------------------------------------- storage
def list_sessions():
    with db.connect() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM sessions ORDER BY name COLLATE NOCASE")]
    for r in rows:
        r["options"] = _options(r)
    return rows


def _options(row):
    try:
        given = json.loads(row.get("options") or "{}") if isinstance(row.get("options"), str) else (row.get("options") or {})
    except ValueError:
        given = {}
    return {**DEFAULTS.get(row.get("kind"), {}), **(given if isinstance(given, dict) else {})}


def get(session_id):
    return next((s for s in list_sessions() if s["id"] == session_id), None)


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
    if kind in ("ssh", "telnet", "rdp"):
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
    """Insert or update. Returns the id. Raises ValueError (bad input) or KeyError-free."""
    name = validate(s)
    row = {k: s.get(k) for k in FIELDS}
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
        if s.get("id"):
            c.execute("UPDATE sessions SET " + ", ".join(f"{k}=?" for k in FIELDS) + " WHERE id=?",
                      [row[k] for k in FIELDS] + [s["id"]])
            return s["id"]
        return c.execute(f"INSERT INTO sessions ({','.join(FIELDS)}, created) VALUES ({','.join('?' * len(FIELDS))}, ?)",
                         [row[k] for k in FIELDS] + [_now()]).lastrowid


def delete(session_id):
    with db.connect() as c:
        c.execute("DELETE FROM sessions WHERE id=?", (session_id,))
    forget_password(session_id)


def duplicate(session_id):
    s = get(session_id)
    if not s:
        return None
    new = {**s, "id": None}
    base = f"{s['name']} (copy)"
    names = {x["name"].lower() for x in list_sessions() if x["folder_id"] == s["folder_id"]}
    n, name = 2, base
    while name.lower() in names:
        name, n = f"{s['name']} (copy {n})", n + 1
    new["name"] = name
    new_id = save(new)
    pw = password(session_id)
    if pw:
        set_password(new_id, pw)
    return new_id


def touch(session_id):
    with db.connect() as c:
        c.execute("UPDATE sessions SET last_used=? WHERE id=?", (_now(), session_id))


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- the saved password (SSH only)
def password(session_id):
    try:
        return keyring.get_password(db.SERVICE, secret_name(session_id)) or ""
    except Exception:
        return ""


def set_password(session_id, value):
    db.set_secret(secret_name(session_id), value)


def forget_password(session_id):
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


def find_mstsc():
    return shutil.which("mstsc")


def rdp_path(s):
    d = db.db_path().parent / "rdp"
    d.mkdir(parents=True, exist_ok=True)
    return d / (re.sub(r"[^A-Za-z0-9._-]", "_", s.get("name") or s["host"])[:60] + ".rdp")


def launch_rdp(s):
    """Write the .rdp file and start Remote Desktop. Returns the file's path. Raises OSError if Windows has no client."""
    exe = find_mstsc()
    if not exe:
        raise OSError("Windows' Remote Desktop client (mstsc.exe) was not found on this computer.")
    path = rdp_path(s)
    path.write_text(rdp_file_text(s), encoding="utf-8")
    subprocess.Popen([exe, str(path)], close_fds=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return path

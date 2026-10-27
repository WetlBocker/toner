"""Sessions from other terminal programs: MobaXterm (.mobaconf export, and its "Stored Passwords" text export), PuTTY (a .reg
export of its sessions, or the sessions on this computer) and SecureCRT (its XML export, or its Sessions folder of .ini files).

Each reader returns a Found: the sessions (kind, name, folder path, host, port, user name, options) and what was skipped and
why. Folders keep their structure; for MobaXterm the root folder every bookmark shares (such as "My Sessions") is left out.
Nothing here writes anything until save() is called. Passwords go only to Toner's vault (sessions.set_password)."""
import os
import re
import sqlite3
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import unquote

from core import sessions

SESSION_FILTER = "MobaXterm sessions (*.mobaconf);;PuTTY sessions (*.reg);;SecureCRT sessions (*.xml *.ini)"
EXTENSIONS = (".mobaconf", ".reg", ".xml", ".ini")
SKIPPED_NAMES = {"browser": "browser", "vnc": "VNC", "ftp": "FTP", "sftp": "SFTP", "rlogin": "rlogin", "raw": "raw TCP",
                 "other": "other"}


@dataclass
class Found:
    source: str
    items: list = field(default_factory=list)       # {'kind','name','folder':[parts],'host','port','username','options'}
    skipped: Counter = field(default_factory=Counter)  # kind word -> count of sessions Toner has no type for

    def counts(self):
        return Counter(i["kind"] for i in self.items)

    def folders(self):
        return {tuple(i["folder"]) for i in self.items if i["folder"]}


def is_session_file(path):
    return os.path.splitext(path or "")[1].lower() in EXTENSIONS


def read_text(path):
    raw = open(path, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("cp1252", "replace")


def _folder_part(name):
    """A folder name Toner accepts: no / or \\ inside it."""
    return re.sub(r"[\\/]+", "-", (name or "").strip()).strip() or "-"


def load(path):
    """The sessions in an exported file, whichever program wrote it. Raises ValueError when it is not one Toner reads."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".mobaconf":
        return mobaxterm(read_text(path))
    if ext == ".reg":
        return putty_reg(read_text(path))
    if ext == ".xml":
        return securecrt_xml(read_text(path))
    if ext == ".ini":
        return securecrt_folder(_sessions_root(path))
    raise ValueError("This is not a MobaXterm, PuTTY or SecureCRT export.")


# ---------------------------------------------------------------- MobaXterm
# A bookmark line is  Name=#<type>#<icon>%field%field...#...  ; fields 1-3 are host, port and user name.
MOBA_TYPES = {"109": "ssh", "98": "telnet", "91": "rdp", "313": "browser", "128": "vnc", "130": "ftp", "140": "sftp"}
MOBA_ESCAPES = {"__PTVIRG__": ";", "__DIEZE__": "#", "__PERCENT__": "%", "__DBLQUO__": '"', "__PIPE__": "|"}


def _moba(text):
    for k, v in MOBA_ESCAPES.items():
        text = text.replace(k, v)
    return text


def mobaxterm(text):
    found = Found("MobaXterm")
    raw, folder = [], None
    for line in text.splitlines():
        m = re.match(r"^\[(Bookmarks(?:_\d+)?)\]\s*$", line)
        if m:
            folder = []
            continue
        if re.match(r"^\[.+\]\s*$", line):
            folder = None                               # [Misc], [ImportExportSpecials] and the like
            continue
        if folder is None or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == "SubRep":
            folder = [_folder_part(_moba(p)) for p in value.split("\\") if p.strip()]
            continue
        if key == "ImgNum":
            continue
        t = re.match(r"^\s*#(\d+)#\d+%(.*)$", value)             # some versions write 'name= #109#...'
        if not t:
            continue
        kind = MOBA_TYPES.get(t.group(1), "other")
        fields = t.group(2).split("#", 1)[0].split("%")
        if kind not in ("ssh", "telnet", "rdp", "vnc"):
            found.skipped[kind] += 1
            continue
        host, port, user = (_moba(fields[i]) if len(fields) > i else "" for i in (0, 1, 2))
        raw.append({"kind": kind, "name": _moba(key).strip(), "folder": list(folder), "host": host.strip(),
                    "port": int(port) if port.strip().isdigit() else sessions.DEFAULT_PORT[kind], "username": user.strip(), "options": {}})
    # the root folder every bookmark shares ("My Sessions") is left out, so its folders are the top level
    if raw and all(r["folder"] for r in raw) and len({r["folder"][0].lower() for r in raw}) == 1:
        for r in raw:
            r["folder"] = r["folder"][1:]
    found.items = raw
    return found


def mobaxterm_passwords(text):
    """MobaXterm's "Stored Passwords" export: lines 'ssh22:user@host = password' or 'user@host = password'.
    Returns {(protocol, port, user, host): password}; protocol and port are '' on the lines without them."""
    out = {}
    for line in text.splitlines():
        if " = " not in line:
            continue
        left, pw = line.split(" = ", 1)
        m = re.match(r"^([A-Za-z]+)(\d*):(.+)$", left.strip())
        proto, port, who = (m.group(1).lower(), m.group(2), m.group(3)) if m else ("", "", left.strip())
        if "@" not in who:
            continue
        user, host = who.rsplit("@", 1)
        out[(proto, port, user.lower(), host.lower())] = pw
    return out


def password_for(item, stored):
    """The stored password for an SSH session: the one for its port, else the one without a protocol."""
    if item["kind"] != "ssh" or not item.get("username"):
        return ""
    user, host = item["username"].lower(), item["host"].lower()
    return stored.get(("ssh", str(item["port"]), user, host)) or stored.get(("", "", user, host)) or ""


# ---------------------------------------------------------------- PuTTY
PUTTY_KEY = r"Software\SimonTatham\PuTTY\Sessions"


def _putty_item(name, values, found):
    proto = str(values.get("Protocol") or "ssh").lower()
    if proto not in ("ssh", "telnet", "serial"):
        found.skipped[proto if proto in SKIPPED_NAMES else "other"] += 1
        return
    if proto == "serial":
        line = str(values.get("SerialLine") or "").strip()
        if not line:
            return
        return {"kind": "serial", "name": name, "folder": [], "host": line, "port": 0, "username": "",
                "options": {"baud": int(values.get("SerialSpeed") or 9600)}}
    host = str(values.get("HostName") or "").strip()
    if not host:
        return                                          # Default Settings, or a session with no address
    if "@" in host and not values.get("UserName"):
        values["UserName"], host = host.rsplit("@", 1)
    return {"kind": proto, "name": name, "folder": [], "host": host, "port": int(values.get("PortNumber") or sessions.DEFAULT_PORT[proto]),
            "username": str(values.get("UserName") or "").strip(), "options": {}}


def putty_reg(text):
    """A .reg export of HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions."""
    found, current, values = Found("PuTTY"), None, {}

    def flush():
        if current is not None:
            item = _putty_item(current, values, found)
            if item:
                found.items.append(item)
    for line in text.splitlines():
        m = re.match(r"^\[HKEY_[^\]]*\\SimonTatham\\PuTTY\\Sessions\\([^\\\]]+)\]\s*$", line)
        if m:
            flush()
            current, values = unquote(m.group(1)), {}
            continue
        if line.startswith("["):
            flush()
            current = None
            continue
        v = re.match(r'^"([^"]+)"=(?:"((?:[^"\\]|\\.)*)"|dword:([0-9a-fA-F]{8}))\s*$', line)
        if v and current is not None:
            values[v.group(1)] = int(v.group(3), 16) if v.group(3) else v.group(2).replace('\\"', '"').replace("\\\\", "\\")
    flush()
    return found


def putty_here():
    """The PuTTY sessions saved on this computer: the signed-in user's registry on Windows, ~/.putty/sessions elsewhere."""
    found = Found("PuTTY")
    try:
        import winreg
    except ImportError:
        return putty_files(os.path.join(os.path.expanduser("~"), ".putty", "sessions"), found)
    try:
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, PUTTY_KEY)
    except OSError:
        return found
    with root:
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            values = {}
            try:
                with winreg.OpenKey(root, sub) as k:
                    j = 0
                    while True:
                        try:
                            n, v, _t = winreg.EnumValue(k, j)
                        except OSError:
                            break
                        values[n] = v
                        j += 1
            except OSError:
                continue
            item = _putty_item(unquote(sub), values, found)
            if item:
                found.items.append(item)
    return found


def putty_files(folder, found=None):
    """PuTTY on Linux and macOS: one file per session, named like the registry keys (percent-encoded), 'Key=Value' lines."""
    found = found or Found("PuTTY")
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return found
    for fname in names:
        values = {}
        try:
            text = read_text(os.path.join(folder, fname))
        except OSError:
            continue
        for line in text.splitlines():
            key, sep, val = line.partition("=")
            if sep:
                values[key.strip()] = int(val) if val.strip().isdigit() else val
        item = _putty_item(unquote(fname), values, found)
        if item:
            found.items.append(item)
    return found


# ---------------------------------------------------------------- SecureCRT
CRT_PROTOCOLS = {"ssh2": "ssh", "ssh1": "ssh", "telnet": "telnet", "serial": "serial", "rdp": "rdp", "rlogin": "rlogin", "raw": "raw"}


def _crt_item(name, folder, v, found):
    proto = CRT_PROTOCOLS.get(str(v.get("Protocol Name") or "").strip().lower(), "other")
    if proto not in ("ssh", "telnet", "serial"):
        found.skipped[proto] += 1
        return
    if proto == "serial":
        port = str(v.get("Com Port") or "").strip()
        return {"kind": "serial", "name": name, "folder": folder, "host": port, "port": 0, "username": "",
                "options": {"baud": int(v.get("Baud Rate") or 9600)}} if port else None
    host = str(v.get("Hostname") or "").strip()
    if not host:
        return
    port = v.get("[SSH2] Port") if proto == "ssh" else v.get("Port")
    return {"kind": proto, "name": name, "folder": folder, "host": host, "port": int(port or sessions.DEFAULT_PORT[proto]),
            "username": str(v.get("Username") or "").strip(), "options": {}}


def securecrt_xml(text):
    """SecureCRT's File > Export Settings (XML): <key name="Sessions"> holds folders (keys) and sessions (keys with a protocol)."""
    found = Found("SecureCRT")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise ValueError(f"The XML could not be read: {e}") from None
    top = next((k for k in root.iter("key") if k.get("name") == "Sessions"), None)
    if top is None:
        raise ValueError("This XML file has no SecureCRT sessions in it.")

    def walk(key, folder):
        for child in key.findall("key"):
            name = child.get("name") or ""
            values = {e.get("name"): (int(e.text or 0) if e.tag == "dword" else (e.text or "")) for e in child if e.tag in ("string", "dword")}
            if "Protocol Name" in values or "Hostname" in values:
                if name.lower() != "default":
                    item = _crt_item(name, folder, values, found)
                    if item:
                        found.items.append(item)
            else:
                walk(child, folder + [_folder_part(name)])
    walk(top, [])
    return found


def _sessions_root(path):
    """The SecureCRT Sessions folder an .ini file is in (its whole tree is read), else that file's own folder."""
    d = os.path.dirname(os.path.abspath(path))
    probe = d
    while True:
        if os.path.basename(probe).lower() == "sessions":
            return probe
        parent = os.path.dirname(probe)
        if parent == probe:
            return d
        probe = parent


def securecrt_folder(folder):
    """SecureCRT's Sessions folder: one .ini file per session, folders as directories."""
    found = Found("SecureCRT")
    for dirpath, dirs, files in os.walk(folder):
        dirs.sort()
        rel = os.path.relpath(dirpath, folder)
        parts = [] if rel == "." else [_folder_part(p) for p in rel.split(os.sep)]
        for f in sorted(files):
            if not f.lower().endswith(".ini") or f.startswith("__") or f.lower() == "default.ini":
                continue
            values = {}
            for line in read_text(os.path.join(dirpath, f)).splitlines():
                m = re.match(r'^([SD]):"([^"]+)"=(.*)$', line.strip())
                if m:
                    values[m.group(2)] = int(m.group(3), 16) if m.group(1) == "D" and re.fullmatch(r"[0-9a-fA-F]+", m.group(3)) else m.group(3)
            item = _crt_item(f[:-4], parts, values, found)
            if item:
                found.items.append(item)
    return found


# ---------------------------------------------------------------- saving
def _key(kind, host, port, user, folder_id):
    return (kind, (host or "").lower(), int(port or 0), (user or "").lower(), folder_id)


def save(found, passwords=None):
    """Add the sessions to Toner, folders and all. Sessions already there (same type, host, port and user name in the same
    folder) are skipped, except that one without a saved password gets it from `passwords` (importing the passwords again
    fills in the ones an earlier import could not save). Returns {'added', 'existing', 'folders', 'passwords', 'bad': [reasons],
    'ids': [the ids of the sessions added, for link_devices]}. The vault is written once, at the end."""
    from core import passvault
    with passvault.batch():
        return _save(found, passwords)


def _save(found, passwords):
    before = {f["id"] for f in sessions.list_folders()}
    here = {_key(s["kind"], s["host"], s["port"], s["username"], s["folder_id"]): s for s in sessions._sessions_here()}
    known = set(here)
    names = {(s["name"].lower(), s["folder_id"]) for s in sessions._sessions_here()}
    folder_ids, out = {}, {"added": 0, "existing": 0, "folders": 0, "passwords": 0, "bad": [], "ids": []}
    for item in found.items:
        path = tuple(item["folder"])
        try:
            if path not in folder_ids:
                folder_ids[path] = sessions.ensure_folder_path("/".join(path)) if path else None
            fid = folder_ids[path]
        except ValueError as e:
            out["bad"].append(f"{'/'.join(path)}/{item['name']}: {e}")
            continue
        k = _key(item["kind"], item["host"], item["port"], item["username"], fid)
        if k in known:
            out["existing"] += 1
            old = here.get(k)
            pw = password_for(item, passwords or {})
            if old and pw and not sessions.password(old["id"]):
                sessions.set_password(old["id"], pw)
                if not old["options"].get("remember"):
                    sessions.save({**old, "options": {**old["options"], "remember": True}})
                out["passwords"] += 1
            continue
        name, n = item["name"] or item["host"], 2
        while (name.lower(), fid) in names:
            name, n = f"{item['name']} ({n})", n + 1
        pw = password_for(item, passwords or {})
        options = {**item.get("options", {}), **({"remember": True} if pw else {})}
        try:
            sid = sessions.save({"kind": item["kind"], "name": name, "folder_id": fid, "host": item["host"], "port": item["port"],
                                 "username": item["username"], "options": options})
        except ValueError as e:
            out["bad"].append(f"{name}: {e}")
            continue
        known.add(k)
        names.add((name.lower(), fid))
        out["added"] += 1
        out["ids"].append(sid)
        if pw:
            sessions.set_password(sid, pw)
            out["passwords"] += 1
    out["folders"] = len({f["id"] for f in sessions.list_folders()} - before)
    return out


# ---------------------------------------------------------------- the new sessions and the devices with their names
LINKABLE_KINDS = ("ssh", "telnet", "rdp", "vnc")      # the kinds whose editor offers an inventory device


def _count(n):
    return {2: "two", 3: "three"}.get(n, str(n))


def link_devices(session_ids):
    """Point each of these sessions (just added, in the organization being written to) at the inventory device with the same
    name, capitals aside, among the devices the session editor offers there (the organization's own plus Global's Shared ones;
    in Global, every organization's). A session that already has a device keeps it. Two devices with that name, or two of these
    sessions sharing a name, link nothing, with the reason. Returns {'linked', 'unlinked': [reasons]}."""
    from core import db
    out = {"linked": 0, "unlinked": []}
    wanted = {int(i) for i in session_ids or ()}
    if not wanted:
        return out
    devices = {}
    for d in db.list_devices():
        devices.setdefault(d["name"].strip().lower(), []).append(d["name"])
    mine = [s for s in sessions._sessions_here() if s["id"] in wanted and s["kind"] in LINKABLE_KINDS and not s.get("device")]
    shared_names = Counter(s["name"].strip().lower() for s in mine)
    said = set()
    with db.connect() as c:
        for s in mine:
            key = s["name"].strip().lower()
            found = devices.get(key)
            if not found:
                continue
            if len(found) > 1 or shared_names[key] > 1:
                if key not in said:
                    said.add(key)
                    out["unlinked"].append(f"{s['name']}: {_count(len(found))} inventory devices have this name." if len(found) > 1
                                           else f"{s['name']}: {_count(shared_names[key])} imported sessions have this name.")
                continue
            c.execute("UPDATE sessions SET device=? WHERE id=?", (found[0], s["id"]))
            out["linked"] += 1
    return out


# ---------------------------------------------------------------- the same entries as devices to monitor
DEVICE_KINDS = ("ssh", "telnet", "rdp")       # VNC stays a session only


def device_items(found):
    """The entries that can also be devices, as [(index in found.items, item)]: SSH, Telnet and Remote Desktop with a usable
    address (an invalid one is skipped, as it is for the session)."""
    from core import nettools
    out = []
    for i, item in enumerate(found.items):
        if item["kind"] not in DEVICE_KINDS:
            continue
        try:
            nettools.check_host(item["host"])
        except ValueError:
            continue
        out.append((i, item))
    return out


def first_vendor(item):
    """What the vendor window starts with: Windows for a Remote Desktop session, else none (MobaXterm doesn't say)."""
    return "windows" if item["kind"] == "rdp" else ""


def device_password(item, stored):
    """The stored password for an entry, for its device: its protocol and port ('ssh22:'), its protocol alone ('rdp:'), else
    the line without a protocol."""
    if not item.get("username"):
        return ""
    user, host = item["username"].lower(), item["host"].lower()
    return (stored.get((item["kind"], str(item["port"]), user, host)) or stored.get((item["kind"], "", user, host))
            or stored.get(("", "", user, host)) or "")


def add_devices(items, passwords=None):
    """Add entries to the device list of the organization being written to, in their folders. Each item is a session entry plus
    'vendor' ('' = none yet: added anyway, to choose later) and optionally 'platform'. A device already there at the same
    address is skipped. Returns {'added', 'existing', 'no_vendor', 'bad': [reasons]}."""
    from core import db, nettools, vendors
    from core.passvault import batch
    out = {"added": 0, "existing": 0, "no_vendor": 0, "bad": []}
    here = db._devices_here()
    hosts = {(d.get("host") or "").lower() for d in here}
    names = {d["name"].lower() for d in here}
    with batch():
        for item in items:
            try:
                host = nettools.check_host(item["host"])
            except ValueError:
                continue                                             # skipped as a session already, with its reason
            if host.lower() in hosts:
                out["existing"] += 1
                continue
            vendor = item.get("vendor") or ""
            platform = item.get("platform") or ("winrm" if vendor == "windows" else vendors.default_platform(vendor))
            port = int(item.get("port") or 0)
            if item["kind"] != "ssh" or not vendor or vendors.get(vendor).get("kind") != "ssh" or port == 22:
                port = 0                                             # the vendor's own port (Telnet and RDP ports are not how Toner monitors)
            base = (item.get("name") or host).strip()
            name, n = base, 2
            while name.lower() in names:
                name, n = f"{base} ({n})", n + 1
            dev = {"name": name, "vendor": vendor, "host": host, "port": port, "platform": platform,
                   "username": (item.get("username") or "").strip(), "site": "default", "verify_ssl": 0, "ha_expected": 0,
                   "enabled": 1, "location": "", "details": "", "folder_id": None}
            try:
                if item.get("folder"):
                    dev["folder_id"] = db.ensure_folder_path("/".join(item["folder"]))
                db.save_device(dev)
            except (ValueError, sqlite3.IntegrityError) as e:
                out["bad"].append(f"{name}: {e}")
                continue
            pw = device_password(item, passwords or {})
            if pw:
                db.set_secret(db.secret_name(name), pw)
            hosts.add(host.lower())
            names.add(name.lower())
            out["added"] += 1
            out["no_vendor"] += 0 if vendor else 1
    return out

"""SQLite storage: device inventory, settings, run history."""
import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import keyring

from core import display, paths
from core import quiet

SERVICE = "netcheck"
DEFAULT_THRESHOLDS = {
    "cpu":          {"warn": 70, "fail": 90},
    "memory":       {"warn": 80, "fail": 90},
    "channel_util": {"warn": 60, "fail": 80},       # UniFi radios, %
    "temperature":  {"warn": 70, "fail": 85},       # degrees C
    "port_errors":  {"warn": 100, "fail": 10000},   # rx+tx errors on up ports (see counter_mode)
    "uptime":       {"warn": 1, "fail": 0},         # hours; LOWER is worse (recent reboot). 0 = off
    "sessions":     {"warn": 70, "fail": 90},       # Palo Alto session table, % of maximum
    "disk":         {"warn": 80, "fail": 90},       # SNMP storage, % used
    "utilization":  {"warn": 70, "fail": 90},       # busiest SNMP interface, % of its speed
    "wifi_signal":  {"warn": 50, "fail": 30},       # this PC's Wi-Fi signal, %; LOWER is worse
    "win_events":   {"warn": 25, "fail": 250},      # Windows: Critical and Error events in the last 24 hours
    "patch_days":   {"warn": 45, "fail": 90},       # Windows: days since an update was last installed
    "cert_days":    {"warn": 30, "fail": 7},        # Windows: days until a certificate expires; LOWER is worse
    "agent_silent": {"warn": 15, "fail": 60},       # Windows agent: minutes without a report
    "tx_retries":   {"warn": 15, "fail": 30},       # UniFi Network API: Wi-Fi transmit retries, % per radio
    "sensor_battery": {"warn": 25, "fail": 10},     # UniFi Protect sensors: battery %; LOWER is worse
    "wan_uptime":   {"warn": 99, "fail": 95},       # UniFi Site Manager: WAN uptime %; LOWER is worse
    "isp_latency":  {"warn": 100, "fail": 250},     # UniFi Site Manager: ISP latency, milliseconds
    "isp_loss":     {"warn": 1, "fail": 5},         # UniFi Site Manager: ISP packet loss, %
    "load_per_core": {"warn": 1.5, "fail": 3},      # SNMP: 5-minute load average per processor core
    "ups_battery":  {"warn": 50, "fail": 20},       # SNMP UPS: battery charge, %; LOWER is worse
    "ups_runtime":  {"warn": 15, "fail": 5},        # SNMP UPS: minutes of runtime left; LOWER is worse
    "ups_load":     {"warn": 80, "fail": 95},       # SNMP UPS: output load, %
    "toner":        {"warn": 20, "fail": 5},        # SNMP printers: the lowest supply left, %; LOWER is worse
    "clock_offset": {"warn": 60, "fail": 300},      # Windows: seconds the computer's clock differs from Toner's
    "failed_logons": {"warn": 50, "fail": 500},     # Windows: failed sign-ins in the last 24 hours
    "lockouts":     {"warn": 1, "fail": 5},         # Windows: account lockouts in the last 24 hours
    "av_age":       {"warn": 3, "fail": 7},         # Windows: days since Defender's signatures were updated
    "backup_days":  {"warn": 2, "fail": 7},         # Windows: days since the last good Windows Server Backup
    "rdp_disconnected": {"warn": 5, "fail": 20},    # Windows: Remote Desktop sessions left disconnected
    "content_age":  {"warn": 14, "fail": 45},       # Palo Alto: days since the newest application / threat / antivirus content
    "support_days": {"warn": 90, "fail": 30},       # any device: days until a support / warranty / licence date in its fields; LOWER is worse
}
THRESHOLD_LABELS = {"cpu": "CPU %", "memory": "Memory %", "channel_util": "Channel utilization %",
                    "temperature": "Temperature C", "port_errors": "Port errors (count)",
                    "uptime": "Uptime below (hours)", "sessions": "Session table used %",
                    "disk": "Disk used %", "utilization": "Interface utilization %",
                    "wifi_signal": "Wi-Fi signal below %", "win_events": "Windows error events (24 h)",
                    "patch_days": "Windows days since last update", "cert_days": "Windows certificate days left",
                    "agent_silent": "Windows agent silent (minutes)", "tx_retries": "UniFi Wi-Fi retries %",
                    "sensor_battery": "UniFi sensor battery below %", "wan_uptime": "UniFi WAN uptime below %",
                    "isp_latency": "UniFi ISP latency (ms)", "isp_loss": "UniFi ISP packet loss %",
                    "load_per_core": "Load average per core", "ups_battery": "UPS battery below %", "ups_runtime": "UPS runtime below (minutes)",
                    "ups_load": "UPS load %", "toner": "Printer supplies below %",
                    "support_days": "Support, warranty and licence days left", "clock_offset": "Windows clock difference (seconds)",
                    "failed_logons": "Windows failed sign-ins (24 h)", "lockouts": "Windows account lockouts (24 h)",
                    "av_age": "Windows antivirus signatures (days old)", "backup_days": "Windows Server Backup (days old)",
                    "rdp_disconnected": "Windows disconnected sessions", "content_age": "Palo Alto content (days old)"}
THRESHOLD_GROUPS = [("Network devices", ["cpu", "memory", "temperature", "uptime", "disk", "utilization", "port_errors", "sessions", "channel_util", "wifi_signal"]),
                    ("Windows computers", ["win_events", "patch_days", "cert_days", "agent_silent", "clock_offset", "failed_logons", "lockouts", "av_age", "backup_days", "rdp_disconnected"]),
                    ("UniFi (API)", ["tx_retries", "sensor_battery", "wan_uptime", "isp_latency", "isp_loss"]),
                    ("Any device", ["support_days"]),
                    ("Firewalls", ["content_age"]),
                    ("UPS, printers and servers (SNMP)", ["load_per_core", "ups_battery", "ups_runtime", "ups_load", "toner"])]
LOWER_IS_WORSE = {"uptime", "wifi_signal", "cert_days", "sensor_battery", "wan_uptime", "ups_battery", "ups_runtime", "toner", "support_days"}

DEFAULT_SETTINGS = {
    # general
    "retention_days": 90, "workers": 10, "ssh_log_days": 365,
    "default_verify_ssl": False, "default_ssh_port": 22, "scan_confirm_over": 256,
    # connections
    "ssh_timeout": 20, "http_timeout": 15, "retries": 1, "retry_delay": 3,
    # checks
    "disabled_checks": [], "counter_mode": "total", "firmware_severity": "WARN",
    "threshold_overrides": [],
    # automation (runs only while the app is open)
    "schedule_enabled": False, "schedule_minutes": 60, "schedule_groups": [], "schedule_on_start": False,
    # appearance
    "theme": "System", "ui_style": "Standard", "font_size": 0, "accent": "Blue", "color_preset": "Default", "status_colors": {},
    # terminal
    "term_font": "Consolas", "rdp_embedded": True, "term_font_size": 10, "term_scrollback": 5000, "term_scheme": "Dark",
    "paging_cmd": "terminal length 0",
    # reports
    "report_title": "Toner Health Report", "report_org": "", "report_folder": "",
    "report_include_all": True,
    # security
    "hostkey_mode": "Trust on first use",
    # notifications
    "notify_enabled": False, "notify_channels": [], "notify_snooze_until": "",
    "notify_consecutive": 1, "notify_remind_hours": 0, "notify_on_manual": True,
    # inventory view
    "inventory_view": "Folders", "inventory_expanded": [], "window_geometry": "", "ansible_backend": "wsl", "ansible_distro": "", "ansible_command": "ansible-playbook", "ansible_playbooks": "",
    "ansible_server_device": "", "ansible_server": {"host": "", "port": 22, "user": "", "key_file": ""}, "ansible_check_default": True, "ansible_keep_runs": 200,
    "sidebar_collapsed": False, "acks": {}, "client_scope": None, "onboarding_done": False, "inventory_columns": None, "results_columns": None,
    # configuration backups
    "backup_enabled": False, "backup_hours": 24, "backup_groups": [], "backup_keep": 50, "backup_mask": True,
    "backup_on_start": False,
    # background running
    "run_in_background": False, "metrics_port": 0,
    # discovery
    "discover_communities": "public", "discover_ports": "22,443,161,5985",
    # commands
    "snippets": [],
    # file servers and throughput tests (per computer: folders and paths)
    "fileserver": {}, "iperf_path": "", "openssl_path": "",
    # proxy for every connection that can use one (see core/proxy.py; the proxy password is in Credential Manager)
    # updates (see core/updates.py)
    "sessions_expanded": [],
    "update_check": True, "update_auto_install": False, "update_last_check": "", "update_skip": "", "update_pending": {},
    "proxy": {"mode": "system", "kind": "http", "host": "", "port": 8080, "username": "",
              "bypass": "localhost, 127.0.0.1"},
    # Settings > Proxy > SSH Tunnel (see core/tunnel.py): PuTTY-style dynamic forwarding on a local SOCKS5 port
    "ssh_tunnel": {"enabled": False, "host": "", "port": 22, "username": "", "key_file": "", "otp": "", "local_port": 1080,
                   "autostart": False},
    # Windows agents (see core/agents.py): Toner listens for their reports while this is on
    "agent_cert_warned": "", "trend_schedule": "", "trend_last": "", "tls_sweep": False, "tls_sweep_ports": "443", "agent_enabled": False, "agent_enroll": False, "agent_token_days": 0, "agent_port": 8750, "agent_minutes": 5, "agent_push_minutes": False, "agent_bind": "0.0.0.0", "agent_address": "",
}
# Per-machine state that must not travel in an exported settings file (channel secrets stay in
# Credential Manager, so an imported channel would be broken).
NOT_PORTABLE = {"window_geometry", "ansible_distro", "ansible_playbooks", "ansible_server", "ansible_server_device", "sidebar_collapsed", "acks", "client_scope", "onboarding_done", "inventory_columns", "results_columns", "notify_channels", "notify_snooze_until", "inventory_expanded", "snippets", "fileserver", "iperf_path", "openssl_path",
                "update_last_check", "update_skip", "update_pending", "sessions_expanded", "agent_enabled", "agent_enroll", "agent_bind",
                "agent_address"}

DEVICE_FIELDS = ["name", "vendor", "host", "port", "platform", "username",
                 "site", "verify_ssl", "ha_expected", "enabled", "location", "details", "folder_id",
                 "tags", "fields", "profile_id", "snmp", "jump", "proxy", "winopts", "checkopts"]
ALL_DEVICES = "All devices"


def db_path() -> Path:
    if os.environ.get("NETCHECK_DB"):
        return Path(os.environ["NETCHECK_DB"])
    return paths.data_dir() / "netcheck.db"


_wal_set = set()


def connect():
    """A connection to the database. WAL mode lets the window, the scheduler and the agent receiver read while one of them
    writes; a long busy timeout makes a competing write wait its turn instead of failing with 'database is locked'."""
    c = sqlite3.connect(db_path(), timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    c.execute("PRAGMA busy_timeout = 15000")
    key = str(db_path())
    if key not in _wal_set:
        try:
            c.execute("PRAGMA journal_mode = WAL")
        except sqlite3.DatabaseError:
            pass                                          # a read-only or network location: the default mode still works
        _wal_set.add(key)
    c.execute("PRAGMA synchronous = NORMAL")
    return c


def init():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, vendor TEXT NOT NULL,
            host TEXT NOT NULL, port INTEGER DEFAULT 0, platform TEXT DEFAULT '',
            username TEXT DEFAULT '', site TEXT DEFAULT 'default',
            verify_ssl INTEGER DEFAULT 0, ha_expected INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS folders (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, parent_id INTEGER);
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY, started_at TEXT NOT NULL,
            ok INTEGER, warn INTEGER, fail INTEGER, error INTEGER);
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
            device TEXT, check_name TEXT, status TEXT, value TEXT, message TEXT, numeric REAL);
        CREATE TABLE IF NOT EXISTS ssh_sessions (
            id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, ended_at TEXT, device TEXT, host TEXT,
            port INTEGER, username TEXT, operator TEXT, reason TEXT, log_path TEXT, bytes INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS counter_baseline (
            device TEXT NOT NULL, key TEXT NOT NULL, value REAL, PRIMARY KEY (device, key));
        CREATE TABLE IF NOT EXISTS alert_state (
            device TEXT NOT NULL, check_name TEXT NOT NULL, status TEXT NOT NULL, streak INTEGER DEFAULT 1,
            notified_sev INTEGER DEFAULT 0, since TEXT, last_notified TEXT, PRIMARY KEY (device, check_name));
        CREATE TABLE IF NOT EXISTS notify_log (
            id INTEGER PRIMARY KEY, at TEXT NOT NULL, channel TEXT, ok INTEGER, events INTEGER, detail TEXT);
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, username TEXT DEFAULT '', snmp TEXT DEFAULT '',
            notes TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS config_backups (
            id INTEGER PRIMARY KEY, device TEXT NOT NULL, taken_at TEXT NOT NULL, sha TEXT NOT NULL,
            size INTEGER, lines INTEGER, body BLOB, added INTEGER DEFAULT 0, removed INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS backup_log (
            id INTEGER PRIMARY KEY, device TEXT NOT NULL, at TEXT NOT NULL, status TEXT, message TEXT,
            backup_id INTEGER);
        CREATE TABLE IF NOT EXISTS custom_checks (
            id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, target TEXT DEFAULT '',
            parse TEXT DEFAULT '', mode TEXT DEFAULT 'number', warn REAL, fail REAL, higher_worse INTEGER DEFAULT 1,
            expect TEXT DEFAULT '', unit TEXT DEFAULT '', scope TEXT DEFAULT '[]', enabled INTEGER DEFAULT 1,
            port INTEGER DEFAULT 0, options TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS maintenance (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT DEFAULT 'once', start_at TEXT DEFAULT '',
            end_at TEXT DEFAULT '', days TEXT DEFAULT '[]', start_time TEXT DEFAULT '', end_time TEXT DEFAULT '',
            scope TEXT DEFAULT '[]', enabled INTEGER DEFAULT 1, note TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS diagnostics (
            id INTEGER PRIMARY KEY, device TEXT NOT NULL, check_name TEXT, at TEXT NOT NULL, body TEXT);
        CREATE TABLE IF NOT EXISTS session_folders (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, parent_id INTEGER);
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, group_name TEXT DEFAULT '',
            host TEXT DEFAULT '', port INTEGER DEFAULT 0, username TEXT DEFAULT '', device TEXT DEFAULT '',
            options TEXT DEFAULT '{}', created TEXT, last_used TEXT, folder_id INTEGER);
        CREATE TABLE IF NOT EXISTS agent_reports (
            device TEXT PRIMARY KEY, token_hash TEXT DEFAULT '', received_at TEXT DEFAULT '', source TEXT DEFAULT '',
            report TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT, action TEXT, detail TEXT);
        CREATE INDEX IF NOT EXISTS idx_backups_dev ON config_backups(device, id);
        CREATE INDEX IF NOT EXISTS idx_results_run ON results(run_id);
        CREATE INDEX IF NOT EXISTS idx_results_series ON results(device, check_name);
        """)
        _migrate(c)
    _invalidate_folders()
    _settings["key"] = None


def _m1_legacy_columns(c):
    """Databases made before folders, tags, profiles, jump hosts, proxies and Windows options existed."""
    if "folder_id" not in {r[1] for r in c.execute("PRAGMA table_info(sessions)")}:
        c.execute("ALTER TABLE sessions ADD COLUMN folder_id INTEGER")
    for (grp,) in c.execute("SELECT DISTINCT group_name FROM sessions WHERE folder_id IS NULL AND IFNULL(group_name,'')<>''").fetchall():
        row = c.execute("SELECT id FROM session_folders WHERE name=? COLLATE NOCASE AND parent_id IS NULL", (grp,)).fetchone()
        fid = row[0] if row else c.execute("INSERT INTO session_folders(name, parent_id) VALUES(?,NULL)", (grp,)).lastrowid
        c.execute("UPDATE sessions SET folder_id=?, group_name='' WHERE folder_id IS NULL AND group_name=?", (fid, grp))   # old 'Group' text -> a real folder
    if "kind" not in {r[1] for r in c.execute("PRAGMA table_info(ssh_sessions)")}:
        c.execute("ALTER TABLE ssh_sessions ADD COLUMN kind TEXT DEFAULT 'ssh'")
    if "options" not in {r[1] for r in c.execute("PRAGMA table_info(custom_checks)")}:
        c.execute("ALTER TABLE custom_checks ADD COLUMN options TEXT DEFAULT ''")
    cols = {r[1] for r in c.execute("PRAGMA table_info(devices)")}
    for col in ("location", "details"):   # upgrade databases created before these existed
        if col not in cols:
            c.execute(f"ALTER TABLE devices ADD COLUMN {col} TEXT DEFAULT ''")
    if "folder_id" not in cols:
        c.execute("ALTER TABLE devices ADD COLUMN folder_id INTEGER")
    for col, decl in (("tags", "TEXT DEFAULT ''"), ("fields", "TEXT DEFAULT ''"), ("profile_id", "INTEGER"),
                      ("snmp", "TEXT DEFAULT ''"), ("jump", "TEXT DEFAULT ''"), ("proxy", "TEXT DEFAULT ''"),
                      ("winopts", "TEXT DEFAULT ''")):
        if col not in cols:
            c.execute(f"ALTER TABLE devices ADD COLUMN {col} {decl}")


def _m2_agent_history(c):
    """Numbers from each agent report, so a Windows computer has real charts and not one point per scheduled run."""
    c.executescript("""
    CREATE TABLE IF NOT EXISTS agent_metrics (
        id INTEGER PRIMARY KEY, device TEXT NOT NULL, at TEXT NOT NULL, cpu REAL, memory REAL, disk REAL, uptime_h REAL);
    CREATE INDEX IF NOT EXISTS idx_agent_metrics ON agent_metrics(device, at);
    CREATE TABLE IF NOT EXISTS agent_seen (
        device TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_ip TEXT DEFAULT '', facts TEXT DEFAULT '');
    """)


def _m3_agent_tokens(c):
    """Tokens can be replaced on a schedule; the previous one keeps working for a while so no agent is locked out."""
    cols = {r[1] for r in c.execute("PRAGMA table_info(agent_reports)")}
    for col in ("issued_at", "prev_hash", "prev_until", "version"):
        if col not in cols:
            c.execute(f"ALTER TABLE agent_reports ADD COLUMN {col} TEXT DEFAULT ''")


def _m4_device_checks(c):
    """A device can have its own list of checks and its own thresholds; one without falls back to the global settings."""
    cols = {r[1] for r in c.execute("PRAGMA table_info(devices)")}
    if "checkopts" not in cols:
        c.execute("ALTER TABLE devices ADD COLUMN checkopts TEXT DEFAULT ''")


def _m5_ansible_runs(c):
    """The history of Ansible playbook runs (their output is kept compressed)."""
    c.executescript("""
    CREATE TABLE IF NOT EXISTS ansible_runs (
        id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, playbook TEXT NOT NULL, mode TEXT NOT NULL, backend TEXT DEFAULT '', targets TEXT DEFAULT '[]',
        ok INTEGER DEFAULT 0, changed INTEGER DEFAULT 0, unreachable INTEGER DEFAULT 0, failed INTEGER DEFAULT 0, exit_code INTEGER DEFAULT 0,
        seconds REAL DEFAULT 0, output BLOB);
    """)


MIGRATIONS = [(1, _m1_legacy_columns), (2, _m2_agent_history), (3, _m3_agent_tokens), (4, _m4_device_checks), (5, _m5_ansible_runs)]
SCHEMA_VERSION = MIGRATIONS[-1][0]


def _migrate(c):
    """Bring the database up to SCHEMA_VERSION, one numbered step at a time (PRAGMA user_version remembers where it is).
    Steps are written to be safe to repeat, because databases from before numbering start at 0."""
    have = c.execute("PRAGMA user_version").fetchone()[0]
    for number, step in MIGRATIONS:
        if have < number:
            step(c)
            c.execute(f"PRAGMA user_version = {number}")


def schema_version():
    with connect() as c:
        return c.execute("PRAGMA user_version").fetchone()[0]


# ---------- secrets (Windows Credential Manager) ----------
def set_secret(name, secret):
    keyring.set_password(SERVICE, name, secret)

def delete_secret(name):
    try:
        keyring.delete_password(SERVICE, name)
    except Exception:
        quiet.ignored()

def move_secret(old, new):
    s = keyring.get_password(SERVICE, old)
    if s:
        keyring.set_password(SERVICE, new, s)
        delete_secret(old)

# A device can hold up to four secrets: its password/token, and an SNMP community or v3 auth/privacy passwords.
SECRET_KINDS = {"main": "", "snmp": ":snmp", "snmp_auth": ":snmp-auth", "snmp_priv": ":snmp-priv", "proxy": ":proxy",
                "agent": ":agent", "ssh": ":ssh", "proxy_otp": ":proxy-otp"}

def secret_name(owner, kind="main"):
    return owner + SECRET_KINDS[kind]

def move_device_secrets(old, new):
    for kind in SECRET_KINDS:
        move_secret(secret_name(old, kind), secret_name(new, kind))

def delete_device_secrets(name):
    for kind in SECRET_KINDS:
        delete_secret(secret_name(name, kind))


# ---------- inventory ----------
def list_devices(enabled_only=False):
    q = "SELECT * FROM devices" + (" WHERE enabled=1" if enabled_only else "") + " ORDER BY name"
    with connect() as c:
        return [dict(r) for r in c.execute(q)]

def group_labels():
    """Selectable groups: 'All devices', 'Vendor: x', 'Location: y', 'Folder: a/b'."""
    devs = list_devices()
    paths = folder_paths()
    folders = set()
    for d in devs:                        # a folder is offered if it, or anything under it, holds a device
        path = paths.get(d.get("folder_id"))
        while path:
            folders.add(path)
            path = path.rpartition("/")[0]
    return ([ALL_DEVICES]
            + sorted({f"Vendor: {display.vendor_name(d['vendor'])}" for d in devs})
            + sorted({f"Location: {d['location']}" for d in devs if d.get("location")})
            + [f"Folder: {f}" for f in sorted(folders, key=str.lower)]
            + sorted({f"Tag: {tg}" for d in devs for tg in split_tags(d.get("tags"))}, key=str.lower))

def split_tags(text):
    """'core, edge ,Core' -> ['core', 'edge'] (trimmed, de-duplicated, order kept; compared case-insensitively)."""
    out, seen = [], set()
    for tg in (text or "").replace(";", ",").split(","):
        tg = tg.strip()
        if tg and tg.lower() not in seen:
            seen.add(tg.lower())
            out.append(tg)
    return out

def in_group(dev, label):
    if label.startswith("Tag: "):
        return label[len("Tag: "):].lower() in {tg.lower() for tg in split_tags(dev.get("tags"))}
    if label.startswith("Vendor: "):
        return display.vendor_name(dev["vendor"]) == label[len("Vendor: "):]
    if label.startswith("Location: "):
        return (dev.get("location") or "") == label[len("Location: "):]
    if label.startswith("Device: "):      # one device by name (the Overview's "Run checks" on a single device)
        return dev["name"] == label[len("Device: "):]
    if label.startswith("Folder: "):      # a folder includes everything in its subfolders
        want = label[len("Folder: "):].lower()
        have = (folder_paths().get(dev.get("folder_id")) or "").lower()
        return have == want or have.startswith(want + "/")
    return True

def in_groups(dev, labels):
    """True if dev is in any of the groups; no labels means everything."""
    return not labels or any(in_group(dev, l) for l in labels)

def group_device_names(labels):
    """Inventory names in the union of groups; None means no filtering."""
    if isinstance(labels, str):
        labels = [labels]
    if not labels or ALL_DEVICES in labels:
        return None
    return {d["name"] for d in list_devices() if in_groups(d, labels)}

def location_of(device_label):
    """Location for a result's device label ('controller / ap' labels use the controller)."""
    base = (device_label or "").split(" / ")[0]
    for d in list_devices():
        if d["name"] == base:
            return d.get("location") or ""
    return ""

def get_device(dev_id):
    with connect() as c:
        row = c.execute("SELECT * FROM devices WHERE id=?", (dev_id,)).fetchone()
    return dict(row) if row else None

def save_device(dev: dict) -> int:
    fields = dev.get("fields") or ""
    if isinstance(fields, dict):
        fields = json.dumps(fields) if fields else ""
    snmp = dev.get("snmp") or ""
    if isinstance(snmp, dict):
        snmp = json.dumps(snmp) if snmp else ""
    jump = dev.get("jump") or ""
    if isinstance(jump, dict):
        jump = json.dumps(jump) if jump else ""
    proxy = dev.get("proxy") or ""
    if isinstance(proxy, dict):
        proxy = json.dumps(proxy) if proxy else ""
    winopts = dev.get("winopts") or ""
    if isinstance(winopts, dict):
        winopts = json.dumps(winopts) if winopts else ""
    own = normalize_checkopts(dev.get("checkopts"))
    checkopts = json.dumps(own) if own else ""
    dev = {**dev, "location": (dev.get("location") or "").strip(),
           "details": (dev.get("details") or "").strip(),
           "tags": ", ".join(split_tags(dev.get("tags"))), "fields": fields, "snmp": snmp, "jump": jump, "proxy": proxy,
           "winopts": winopts, "checkopts": checkopts, "profile_id": dev.get("profile_id") or None}
    vals = [dev.get(f) for f in DEVICE_FIELDS]
    with connect() as c:
        if dev.get("id"):
            sets = ", ".join(f"{f}=?" for f in DEVICE_FIELDS)
            c.execute(f"UPDATE devices SET {sets} WHERE id=?", vals + [dev["id"]])
            return dev["id"]
        cur = c.execute(f"INSERT INTO devices ({','.join(DEVICE_FIELDS)}) "
                        f"VALUES ({','.join('?' * len(DEVICE_FIELDS))})", vals)
        return cur.lastrowid

def delete_device(dev_id):
    with connect() as c:
        c.execute("DELETE FROM devices WHERE id=?", (dev_id,))


# ---------- folders ----------
_folder_cache = None

def _invalidate_folders():
    global _folder_cache
    _folder_cache = None

def list_folders():
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT id, name, parent_id FROM folders ORDER BY name COLLATE NOCASE")]

def folder_paths():
    """{folder id: 'Parent/Child'}. Cached, because group matching asks for it once per device."""
    global _folder_cache
    key = str(db_path())
    if _folder_cache is None or _folder_cache[0] != key:
        rows = {f["id"]: f for f in list_folders()}
        out = {}
        for fid in rows:
            parts, cur, seen = [], fid, set()
            while cur in rows and cur not in seen:       # 'seen' guards against a corrupt parent loop
                seen.add(cur)
                parts.append(rows[cur]["name"])
                cur = rows[cur]["parent_id"]
            out[fid] = "/".join(reversed(parts))
        _folder_cache = (key, out)
    return _folder_cache[1]

def folder_descendants(fid):
    """The folder's own id plus every folder below it."""
    kids, out, todo = {}, set(), [fid]
    for f in list_folders():
        kids.setdefault(f["parent_id"], []).append(f["id"])
    while todo:
        cur = todo.pop()
        if cur not in out:
            out.add(cur)
            todo.extend(kids.get(cur, []))
    return out

def clean_folder_name(name):
    name = (name or "").strip()
    if not name or name in (".", "..") or "/" in name or "\\" in name:
        raise ValueError("A folder name cannot be empty, '.' or '..', or contain / or \\.")
    return name

def _check_sibling(c, name, parent_id, ignore_id=None):
    row = c.execute("SELECT id FROM folders WHERE name=? COLLATE NOCASE AND parent_id IS ? AND id IS NOT ?",
                    (name, parent_id, ignore_id)).fetchone()
    if row:
        raise ValueError(f"A folder named '{name}' already exists there.")

def create_folder(name, parent_id=None):
    name = clean_folder_name(name)
    with connect() as c:
        _check_sibling(c, name, parent_id)
        fid = c.execute("INSERT INTO folders(name, parent_id) VALUES(?,?)", (name, parent_id)).lastrowid
    _invalidate_folders()
    return fid

def rename_folder(fid, name):
    name = clean_folder_name(name)
    with connect() as c:
        parent = c.execute("SELECT parent_id FROM folders WHERE id=?", (fid,)).fetchone()["parent_id"]
        _check_sibling(c, name, parent, fid)
        c.execute("UPDATE folders SET name=? WHERE id=?", (name, fid))
    _invalidate_folders()

def move_folder(fid, parent_id):
    """Put a folder inside another (None = top level). A folder can never go inside itself."""
    if parent_id is not None and parent_id in folder_descendants(fid):
        raise ValueError("A folder cannot be moved into itself or one of its own subfolders.")
    with connect() as c:
        name = c.execute("SELECT name FROM folders WHERE id=?", (fid,)).fetchone()["name"]
        _check_sibling(c, name, parent_id, fid)
        c.execute("UPDATE folders SET parent_id=? WHERE id=?", (parent_id, fid))
    _invalidate_folders()

def delete_folder(fid):
    """Delete a folder. Its devices and subfolders move up one level; no device is ever deleted."""
    with connect() as c:
        parent = c.execute("SELECT parent_id FROM folders WHERE id=?", (fid,)).fetchone()["parent_id"]
        clash = [r["name"] for r in c.execute("SELECT name FROM folders WHERE parent_id=?", (fid,))
                 if c.execute("SELECT 1 FROM folders WHERE name=? COLLATE NOCASE AND parent_id IS ? AND id!=?",
                              (r["name"], parent, fid)).fetchone()]
        if clash:
            raise ValueError("Moving the contents up would clash with existing folders named: "
                             f"{', '.join(clash)}. Rename one first.")
        c.execute("UPDATE folders SET parent_id=? WHERE parent_id=?", (parent, fid))
        c.execute("UPDATE devices SET folder_id=? WHERE folder_id=?", (parent, fid))
        c.execute("DELETE FROM folders WHERE id=?", (fid,))
    _invalidate_folders()

def move_devices(device_ids, folder_id):
    if device_ids:
        with connect() as c:
            c.executemany("UPDATE devices SET folder_id=? WHERE id=?", [(folder_id, i) for i in device_ids])

def ensure_folder_path(path):
    """Id of the folder at 'A/B/C', creating any missing levels. '' means top level (None)."""
    parts = [p.strip() for p in (path or "").replace("\\", "/").split("/") if p.strip()]
    if len(parts) > 10:
        raise ValueError("Folder paths can be at most 10 levels deep.")
    parent = None
    for name in parts:
        name = clean_folder_name(name)
        with connect() as c:
            row = c.execute("SELECT id FROM folders WHERE name=? COLLATE NOCASE AND parent_id IS ?",
                            (name, parent)).fetchone()
        parent = row["id"] if row else create_folder(name, parent)
    return parent


# ---------- settings ----------
def get_thresholds():
    with connect() as c:
        row = c.execute("SELECT value FROM settings WHERE key='thresholds'").fetchone()
    stored = json.loads(row["value"]) if row else {}
    return {k: {**v, **stored.get(k, {})} for k, v in DEFAULT_THRESHOLDS.items()}

def set_thresholds(th):
    set_setting("thresholds", th)

_settings = {"key": None, "at": 0.0, "data": {}}
_settings_lock = threading.Lock()
SETTINGS_TTL = 2.0                  # seconds; another process (the service, the window) is noticed within this long


def _all_settings():
    key, now = str(db_path()), time.monotonic()
    with _settings_lock:
        if _settings["key"] != key or now - _settings["at"] > SETTINGS_TTL:
            with connect() as c:
                data = {r["key"]: r["value"] for r in c.execute("SELECT key, value FROM settings")}
            _settings.update(key=key, at=now, data=data)
        return _settings["data"]


def get_setting(key):
    raw = _all_settings().get(key)
    # defaults are copied so callers can never modify the shared default list/dict
    return json.loads(raw) if raw is not None else json.loads(json.dumps(DEFAULT_SETTINGS[key]))


# ---------- per-device thresholds and runtime options ----------
OVERRIDE_RANK = {"Vendor": 0, "Tag": 1, "Location": 1, "Folder": 2, "Device": 3}      # more specific wins

def override_scopes():
    """Scopes a threshold override can target: vendors, locations, individual devices."""
    labels = [l for l in group_labels()[1:]]
    return labels + [f"Device: {d['name']}" for d in list_devices()]

def bad_pair(key, warn, fail):
    """True if a WARN/FAIL pair contradicts itself (for 'lower is worse' checks FAIL must be the smaller number)."""
    if key in LOWER_IS_WORSE:
        return warn > 0 and fail > warn
    return warn > fail


def normalize_checkopts(raw):
    """A device's own check settings, cleaned: {'checks': [keys that run] (only when it picks its own list),
    'thresholds': {key: {'warn', 'fail'}} (only the ones it overrides), 'interfaces': [names] (only those are checked; missing = all)}. Empty when it has none: it then follows the global settings."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw) if raw.strip() else {}
        except ValueError:
            raw = {}
    if not isinstance(raw, dict):
        return {}
    out = {}
    if isinstance(raw.get("checks"), list):
        out["checks"] = [c for c in dict.fromkeys(str(x) for x in raw["checks"])]
    if isinstance(raw.get("interfaces"), list):                          # only these interfaces are checked (empty or missing: all of them)
        names = [n for n in dict.fromkeys(str(x).strip() for x in raw["interfaces"]) if n]
        if names:
            out["interfaces"] = names
    th = {}
    for key, pair in (raw.get("thresholds") or {}).items() if isinstance(raw.get("thresholds"), dict) else ():
        if key in DEFAULT_THRESHOLDS and isinstance(pair, dict):
            try:
                th[key] = {"warn": float(pair["warn"]), "fail": float(pair["fail"])}
            except (KeyError, TypeError, ValueError):
                continue
    if th:
        out["thresholds"] = th
    return out


def disabled_for(dev, disabled):
    """Which checks are switched off for this device: the global list, unless the device picked its own list of checks."""
    from core import checks
    own = normalize_checkopts((dev or {}).get("checkopts")).get("checks")
    if own is None:
        return set(disabled)
    vendor = (dev or {}).get("vendor", "")
    keys = {checks.key(vendor, k) for k, _label in checks.CATALOG.get(vendor, [])}
    on = {checks.key(vendor, k) for k in own}
    return (set(disabled) - keys) | (keys - on)


def thresholds_for(dev, base=None, overrides=None):
    """Global thresholds with any matching overrides applied: vendor, then location, then folder, then device (the table in
    Settings), and finally the limits set on the device itself, which beat everything."""
    th = json.loads(json.dumps(base or get_thresholds()))
    rules = get_setting("threshold_overrides") if overrides is None else overrides
    def applies(scope):
        if scope.startswith("Device: "):
            return dev["name"] == scope[len("Device: "):]
        return in_group(dev, scope)
    valid = (r for r in rules if isinstance(r, dict) and all(k in r for k in ("scope", "check", "warn", "fail")))
    # more specific wins; between nested folders, the deeper one
    for rule in sorted((r for r in valid if applies(str(r["scope"]))),
                       key=lambda r: (OVERRIDE_RANK.get(str(r["scope"]).split(":")[0], 0), str(r["scope"]).count("/"))):
        if rule["check"] in th:
            th[rule["check"]] = {"warn": rule["warn"], "fail": rule["fail"]}
    for key, pair in normalize_checkopts(dev.get("checkopts")).get("thresholds", {}).items():
        if key in th:
            th[key] = dict(pair)
    return th

def runtime_options():
    """Everything a run needs besides thresholds. Read once in the GUI thread, then handed to workers."""
    return {"custom": custom_checks(), "ssh_timeout": int(get_setting("ssh_timeout")), "http_timeout": int(get_setting("http_timeout")),
            "retries": int(get_setting("retries")), "retry_delay": int(get_setting("retry_delay")),
            "disabled": set(get_setting("disabled_checks")), "counter_mode": get_setting("counter_mode"),
            "firmware_severity": get_setting("firmware_severity"),
            "tls_sweep": bool(get_setting("tls_sweep")), "tls_sweep_ports": get_setting("tls_sweep_ports")}

def custom_checks():
    from core import custom
    return custom.list_checks()


# ---------- error-counter baselines (for 'increase since last run') ----------
def get_baselines(device):
    with connect() as c:
        return {r["key"]: r["value"] for r in c.execute(
            "SELECT key, value FROM counter_baseline WHERE device=?", (device,))}

def set_baselines(device, values):
    with connect() as c:
        c.executemany("INSERT INTO counter_baseline(device,key,value) VALUES(?,?,?) "
                      "ON CONFLICT(device,key) DO UPDATE SET value=excluded.value",
                      [(device, k, float(v)) for k, v in values.items()])


# ---------- settings export / import (never includes devices or secrets) ----------
def export_settings():
    out = {"thresholds": get_thresholds()}
    out.update({k: get_setting(k) for k in DEFAULT_SETTINGS if k not in NOT_PORTABLE})
    return out

def import_settings(data):
    """Apply a settings dict, keeping only known keys whose value type matches. Returns (applied, skipped)."""
    applied, skipped = [], []
    for key, value in data.items():
        if key == "thresholds":
            ok = isinstance(value, dict) and all(
                k in DEFAULT_THRESHOLDS and isinstance(v, dict) and set(v) <= {"warn", "fail"}
                and all(isinstance(x, (int, float)) for x in v.values()) for k, v in value.items())
            if ok:
                set_thresholds(value)
                applied.append(key)
            else:
                skipped.append(key)
        elif key in DEFAULT_SETTINGS and key not in NOT_PORTABLE:
            want = type(DEFAULT_SETTINGS[key])
            good = isinstance(value, want) and not (want is int and isinstance(value, bool)) \
                or (want is float and isinstance(value, int))
            if good:
                set_setting(key, value)
                applied.append(key)
            else:
                skipped.append(key)
        else:
            skipped.append(key)
    return applied, skipped

def set_setting(key, value):
    with connect() as c:
        c.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))
    with _settings_lock:
        _settings["key"] = None                           # the next read sees it


# ---------- history ----------
def save_run(results) -> int:
    n = lambda s: sum(r.status == s for r in results)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with connect() as c:
        cur = c.execute("INSERT INTO runs(started_at, ok, warn, fail, error) VALUES(?,?,?,?,?)",
                        (now, n("OK"), n("WARN"), n("FAIL"), n("ERROR")))
        rid = cur.lastrowid
        c.executemany(
            "INSERT INTO results(run_id, device, check_name, status, value, message, numeric) "
            "VALUES(?,?,?,?,?,?,?)",
            [(rid, r.device, r.check, r.status, r.value, r.message, r.numeric) for r in results])
        cutoff = (datetime.now() - timedelta(days=int(get_setting("retention_days")))
                  ).strftime("%Y-%m-%d %H:%M:%S")
        c.execute("DELETE FROM runs WHERE started_at < ?", (cutoff,))
    return rid

def list_runs(limit=200):
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,))]

def run_results(run_id):
    with connect() as c:
        return [dict(r) for r in c.execute(
            "SELECT device, check_name, status, value, message FROM results WHERE run_id=? "
            "ORDER BY device, check_name", (run_id,))]

def device_checks():
    """{device: [check, ...]} for checks that have numeric history."""
    out = {}
    with connect() as c:
        for r in c.execute("SELECT DISTINCT device, check_name FROM results "
                           "WHERE numeric IS NOT NULL ORDER BY device, check_name"):
            out.setdefault(r["device"], []).append(r["check_name"])
    return out

AGENT_COLUMNS = {"cpu": "cpu", "memory": "memory", "disks": "disk", "uptime": "uptime_h"}     # check name -> agent_metrics column


def series(device, check, limit=200):
    """(time, value) points for one check, oldest first. A Windows agent reports far more often than checks run, so its
    own reports are added in and the chart has a point per report."""
    with connect() as c:
        rows = c.execute(
            "SELECT runs.started_at AS t, results.numeric AS v FROM results "
            "JOIN runs ON runs.id = results.run_id "
            "WHERE results.device=? AND results.check_name=? AND results.numeric IS NOT NULL "
            "ORDER BY runs.id DESC LIMIT ?", (device, check, limit)).fetchall()
        pts = [(r["t"], r["v"]) for r in reversed(rows)]
        col = AGENT_COLUMNS.get(check)
        if col:
            extra = c.execute(f"SELECT at AS t, {col} AS v FROM agent_metrics WHERE device=? AND {col} IS NOT NULL "
                              "ORDER BY id DESC LIMIT ?", (device, limit)).fetchall()
            if extra:
                pts = sorted(set(pts) | {(r["t"], r["v"]) for r in extra})[-limit:]
    return pts


# ---------- dashboard data ----------
_SEV = {"OK": 0, "WARN": 1, "FAIL": 2, "ERROR": 3}


def _base(label):
    return (label or "").split(" / ")[0]


def latest_results(exclude=("config backup",)):
    """([result rows], time of the newest run among them): every device's rows from the newest run that included it (the same reading as
    device_health), for the Results section to show before anything is run in this session. Rows: device, check_name, status, value,
    message, numeric, at."""
    rows, newest_at = [], ""
    with connect() as c:
        newest = {}
        skip = ",".join("?" * len(exclude)) or "''"
        for r in c.execute(f"SELECT device, MAX(run_id) AS rid FROM results WHERE check_name NOT IN ({skip}) GROUP BY device", list(exclude)):
            b = _base(r["device"])
            newest[b] = max(newest.get(b, 0), r["rid"])
        times = {r["id"]: r["started_at"] for r in c.execute("SELECT id, started_at FROM runs")}
        by_run = {}
        for b, rid in newest.items():
            by_run.setdefault(rid, set()).add(b)
        for rid, bases in by_run.items():
            at = times.get(rid, "")
            newest_at = max(newest_at, at)
            for r in c.execute("SELECT device, check_name, status, value, message, numeric FROM results WHERE run_id=?", (rid,)):
                if _base(r["device"]) in bases and r["check_name"] not in exclude:
                    rows.append({**dict(r), "at": at})
    return rows, newest_at


def device_health(exclude=("config backup",)):
    """The latest known state of every device that has results: {device: {'status', 'at', 'checks', 'problems'}}
    where problems is [(check, status, message)] worst first. Each device is read from the newest run that
    included it, so a run of just one group does not wipe out the others."""
    out = {}
    with connect() as c:
        newest = {}
        skip = ",".join("?" * len(exclude)) or "''"
        # a backup-only run must not count as "the newest run that included this device"
        for r in c.execute(f"SELECT device, MAX(run_id) AS rid FROM results WHERE check_name NOT IN ({skip}) GROUP BY device",
                           list(exclude)):
            b = _base(r["device"])
            newest[b] = max(newest.get(b, 0), r["rid"])
        times = {r["id"]: r["started_at"] for r in c.execute("SELECT id, started_at FROM runs")}
        by_run = {}
        for b, rid in newest.items():
            by_run.setdefault(rid, []).append(b)
        for rid, bases in by_run.items():
            for r in c.execute("SELECT device, check_name, status, value, message FROM results WHERE run_id=?", (rid,)):
                b = _base(r["device"])
                if b not in bases or r["check_name"] in exclude:
                    continue
                d = out.setdefault(b, {"status": "OK", "at": times.get(rid, ""), "checks": 0, "problems": []})
                d["checks"] += 1
                if _SEV.get(r["status"], 0) > 0:
                    d["problems"].append((r["check_name"], r["status"], r["message"] or r["value"] or ""))
                if _SEV.get(r["status"], 0) > _SEV[d["status"]]:
                    d["status"] = r["status"]
    for d in out.values():
        d["problems"].sort(key=lambda p: -_SEV.get(p[1], 0))
    return out


def changes_since_previous():
    """How devices moved between the last two runs: {'worse': [(device, was, now)], 'better': [(device, was, now)]}, for devices that were in both.
    A run of one group leaves other devices out of the comparison. Empty when there are fewer than two runs."""
    with connect() as c:
        ids = [r["id"] for r in c.execute("SELECT id FROM runs ORDER BY id DESC LIMIT 2")]
        if len(ids) < 2:
            return {"worse": [], "better": []}
        worst = {}
        for rid in ids:
            seen = worst.setdefault(rid, {})
            for r in c.execute("SELECT device, status FROM results WHERE run_id=? AND check_name != 'config backup'", (rid,)):
                b = _base(r["device"])
                if _SEV.get(r["status"], 0) >= _SEV.get(seen.get(b, "OK"), 0):
                    seen[b] = r["status"]
    now, before = worst[ids[0]], worst[ids[1]]
    worse = sorted((d, before[d], now[d]) for d in now if d in before and _SEV.get(now[d], 0) > _SEV.get(before[d], 0))
    better = sorted((d, before[d], now[d]) for d in now if d in before and _SEV.get(now[d], 0) < _SEV.get(before[d], 0))
    return {"worse": worse, "better": better}


def availability(days=7, start=None, end=None):
    """{device: {'runs', 'reachable', 'healthy'}} over the last `days` days (or between two times). A run counts as 'reachable'
    when the device produced results without a 'connection' error, and 'healthy' when none of its checks was worse than WARN."""
    cutoff = start or (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    until = end or "9999-12-31 00:00:00"
    stats = {}
    with connect() as c:
        seen = {}
        for r in c.execute("SELECT results.run_id AS rid, device, check_name, status FROM results JOIN runs ON "
                           "runs.id = results.run_id WHERE runs.started_at >= ? AND runs.started_at < ? AND check_name != 'config backup'",
                           (cutoff, until)):
            key = (r["rid"], _base(r["device"]))
            s = seen.setdefault(key, {"conn": False, "bad": False})
            if r["check_name"] == "connection" and r["status"] == "ERROR":
                s["conn"] = True
            if _SEV.get(r["status"], 0) >= 2:
                s["bad"] = True
    for (rid, dev), s in seen.items():
        d = stats.setdefault(dev, {"runs": 0, "reachable": 0, "healthy": 0})
        d["runs"] += 1
        d["reachable"] += 0 if s["conn"] else 1
        d["healthy"] += 0 if s["bad"] else 1
    return stats


def last_run():
    with connect() as c:
        row = c.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    return dict(row) if row else None


# ---------- raw device output kept when a parser fails, for bug reports ----------
def save_diagnostic(device, check, body):
    with connect() as c:
        c.execute("INSERT INTO diagnostics(device, check_name, at, body) VALUES(?,?,?,?)",
                  (device, check, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), body[:60000]))
        c.execute("DELETE FROM diagnostics WHERE id NOT IN (SELECT id FROM diagnostics ORDER BY id DESC LIMIT 200)")


def get_diagnostics(device, check=None, limit=5):
    q, args = "SELECT * FROM diagnostics WHERE device=?", [_base(device)]
    if check:
        q += " AND check_name=?"
        args.append(check)
    with connect() as c:
        return [dict(r) for r in c.execute(q + " ORDER BY id DESC LIMIT ?", args + [limit])]

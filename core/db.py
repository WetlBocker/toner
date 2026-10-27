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
    "theme": "System", "ui_style": "Standard", "font_size": 0, "color_preset": "Default", "status_colors": {},
    # terminal
    "term_font": "Consolas", "rdp_embedded": True, "term_font_size": 10, "term_scrollback": 5000, "term_scheme": "Dark",
    "paging_cmd": "terminal length 0",
    # reports
    "report_title": "Toner Health Report", "report_org": "", "report_folder": "",
    "report_include_all": True,
    # security
    "hostkey_mode": "Trust on first use",
    "ssh_legacy_algorithms": True,               # ssh-rsa and SHA-1 key exchange for older devices (core/legacyssh.py)
    # notifications
    "notify_enabled": False, "notify_channels": [], "notify_snooze_until": "",
    "notify_consecutive": 1, "notify_remind_hours": 0, "notify_on_manual": True,
    # inventory view
    "inventory_view": "Folders", "inventory_expanded": [], "window_geometry": "", "splitters": {}, "ansible_backend": "wsl", "ansible_distro": "", "ansible_command": "ansible-playbook", "ansible_playbooks": "",
    "ansible_server_device": "", "ansible_server": {"host": "", "port": 22, "user": "", "key_file": ""}, "ansible_check_default": True, "ansible_keep_runs": 200,
    "sidebar_collapsed": False, "acks": {}, "client_scope": None, "org_current": 0, "onboarding_done": False, "inventory_columns": None, "results_columns": None,
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
    # proxy for every connection that can use one (see core/proxy.py; the proxy password is in the vault)
    # updates (see core/updates.py)
    "sessions_expanded": [], "sessions_list_hidden": False,
    "update_check": True, "update_auto_install": False, "update_last_check": "", "update_skip": "", "update_pending": {},
    "proxy": {"mode": "system", "kind": "http", "host": "", "port": 8080, "username": "",
              "bypass": "localhost, 127.0.0.1"},
    # Settings > Proxy > SSH Tunnel (see core/tunnel.py): PuTTY-style dynamic forwarding on a local SOCKS5 port
    "ssh_tunnel": {"enabled": False, "host": "", "port": 22, "username": "", "key_file": "", "otp": "", "local_port": 1080,
                   "autostart": False},
    # Windows agents (see core/agents.py): Toner listens for their reports while this is on
    "agent_cert_warned": "", "trend_schedule": "", "trend_last": "", "tls_sweep": False, "tls_sweep_ports": "443", "agent_enabled": False, "agent_enroll": False, "agent_token_days": 0, "agent_port": 8750, "agent_minutes": 5, "agent_push_minutes": False, "agent_bind": "0.0.0.0", "agent_address": "",
    "vault_provider": "toner", "vault_config": {}, "vault_direct": False, "update_direct": False, "vault_keep_copies": True,   # (the last two: ignore the proxy)             # where passwords are kept: Toner's vault, or a password manager (core/extstore.py)
    # Demarc (see core/demarc.py): this install's permanent ID, and the Demarc it sends to (its token is in the vault)
    "install_uid": "", "demarc": {"address": "", "pin": "", "trusted": False, "enabled": False, "history": "all"},
    # Tools > API Tester (see core/apitool.py): how many sent requests History keeps
    "api_history_keep": 100,
    # Tools > Firmware Transfer (see core/firmware.py): the image server remembered for the organization (its password is in the vault)
    "firmware_source": {},
    # the Assistant (see core/assistant): one provider, model and depth per installation; the API key is in the vault; the spend
    # limit is the installation's total over every organization, in US dollars per month
    "ai_provider": "claude", "ai_model": {}, "ai_depth": "normal", "ai_spend_limit": 20, "ai_run_commands": False, "ai_search": True,
    # where the Assistant's round button sits (per computer): which side edge, and how far down the window (0 top, 1 bottom)
    "assistant_button": {"side": "right", "y": 0.5},
}
# Per-machine state that must not travel in an exported settings file (channel secrets stay in
# the vault, so an imported channel would be broken).
NOT_PORTABLE = {"vault_provider", "vault_config", "org_current", "window_geometry", "splitters", "ansible_distro", "ansible_playbooks", "ansible_server", "ansible_server_device", "sidebar_collapsed", "sessions_list_hidden", "acks", "client_scope", "onboarding_done", "inventory_columns", "results_columns", "notify_channels", "notify_snooze_until", "inventory_expanded", "snippets", "fileserver", "iperf_path", "openssl_path",
                "update_last_check", "update_skip", "update_pending", "sessions_expanded", "agent_enabled", "agent_enroll", "agent_bind",
                "agent_address", "install_uid", "demarc", "assistant_button"}

DEVICE_FIELDS = ["name", "vendor", "host", "port", "platform", "username",
                 "site", "verify_ssl", "ha_expected", "enabled", "location", "details", "folder_id",
                 "tags", "fields", "profile_id", "snmp", "jump", "proxy", "winopts", "checkopts", "shared"]
SOFTWARE_FIELDS = ["sw_version", "sw_image", "sw_mode", "sw_read_at"]        # see set_software; not in DEVICE_FIELDS on purpose
ALL_DEVICES = "All devices"


# ---------- organizations: one database file each ----------
# The Global file (netcheck.db) holds the list of organizations, the Global settings, Global's own devices and everything marked
# Shared. Each organization has its own file with the same tables. Which file a call reads or writes:
#   - inside `with within(org):` that organization's file (0 = the Global file);
#   - otherwise the organization picked in the sidebar (set_home).
# Lists (devices, results, ...) read more than one file: an organization sees its own rows plus Global's Shared ones, and Global
# with no organization picked sees every file (see _files).
GLOBAL = 0
_home = GLOBAL
_local = threading.local()


def base_path() -> Path:
    """The Global file. Side files (logs, host keys, updates) live next to it."""
    if os.environ.get("NETCHECK_DB"):
        return Path(os.environ["NETCHECK_DB"])
    return paths.data_dir() / "netcheck.db"


def org_path(org) -> Path:
    base = base_path()
    return base if not org else base.with_name(base.stem + ".orgs") / f"{int(org)}.db"


def target():
    """The organization whose file a write goes to (0 = Global)."""
    org = getattr(_local, "org", None)
    return _home if org is None else org


def home():
    """The organization picked in the sidebar (0 = Global)."""
    return _home


def set_home(org):
    global _home
    _home = int(org or 0)
    _invalidate_folders()


def everything():
    """True while Global is picked and no `within` narrows it: lists cover every organization."""
    return getattr(_local, "org", None) is None and _home == GLOBAL


def several():
    """everything(), and there are organizations: lists show an Organization column, filter and branches."""
    return everything() and bool(org_rows())


class within:
    """`with db.within(org):` reads and writes that organization's file on this thread (None changes nothing)."""

    def __init__(self, org):
        self.org = None if org is None else int(org)

    def __enter__(self):
        self.prev = getattr(_local, "org", None)
        if self.org is not None:
            _local.org = self.org
        return self

    def __exit__(self, *exc):
        _local.org = self.prev
        return False


_orgs_cache = {"key": None, "at": 0.0, "rows": [], "names": {}}
show_archived = False                 # Global's Organization filter can ask for archived organizations too


def org_rows():
    """Every organization in the Global file: [{'id', 'name', 'code', 'colour', 'archived', 'created', 'uid'}] by name. Cached briefly."""
    return [dict(r) for r in _org_rows_kept()]


def _org_rows_kept():
    """The cached rows themselves, for reading only (org_rows hands out copies)."""
    key, now = str(base_path()), time.monotonic()
    if _orgs_cache["key"] != key or now - _orgs_cache["at"] > SETTINGS_TTL:
        try:
            c = sqlite3.connect(base_path(), timeout=15)
            c.row_factory = sqlite3.Row
            try:
                rows = [dict(r) for r in c.execute("SELECT * FROM orgs ORDER BY name COLLATE NOCASE")]
            finally:
                c.close()
        except sqlite3.Error:
            rows = []
        _orgs_cache.update(key=key, at=now, rows=rows, names={r["id"]: r["name"] for r in rows})
    return _orgs_cache["rows"]


def forget_orgs():
    _orgs_cache["key"] = None


def org_name(org):
    if not org:
        return "Global"
    _org_rows_kept()                                        # (fresh names; asked for once per row of most lists, so no copies)
    return _orgs_cache["names"].get(int(org), f"Organization {org}")


class including_archived:
    """`with db.including_archived(on):` Global's lists on this thread also cover archived organizations (Global's Organization
    filter asked for one: an archived organization can still be looked at there)."""

    def __init__(self, on=True):
        self.on = bool(on)

    def __enter__(self):
        self.prev = getattr(_local, "archived", False)
        _local.archived = self.on or self.prev
        return self

    def __exit__(self, *exc):
        _local.archived = self.prev
        return False


def archived_ids():
    return {r["id"] for r in org_rows() if r["archived"]}


def _files():
    """[(org, shared_only)]: the files a list reads right now. shared_only: just the rows marked Shared (Global's, seen from an organization)."""
    org = getattr(_local, "org", None)
    if org is None:
        org = _home
        if org == GLOBAL:
            every = show_archived or getattr(_local, "archived", False)
            return [(GLOBAL, False)] + [(r["id"], False) for r in org_rows() if every or not r["archived"]]
    return [(org, False)] + ([(GLOBAL, True)] if org else [])


def gather(here, shared=None):
    """Run here() in every file the current view covers and join what comes back. Rows (dicts) get 'org' set to the file they came
    from. Rows from Global seen from an organization are kept only when shared(row) says so (default: its 'shared' column)."""
    out = []
    keep = shared or (lambda r: bool(r.get("shared")))
    for org, shared_only in _files():
        with within(org):
            rows = here()
        for r in rows:
            if shared_only and not keep(r):
                continue
            if isinstance(r, dict):
                r["org"] = org
            out.append(r)
    return out


def gather_own(here, shared=None):
    """Like gather, but only the file being written to (plus Global's Shared rows, from an organization), even while Global lists
    everything: for things Settings edits (credential profiles, custom checks, maintenance windows), which belong to one file."""
    out = []
    keep = shared or (lambda r: bool(r.get("shared")))
    org = target()
    for o, shared_only in [(org, False)] + ([(GLOBAL, True)] if org else []):
        with within(o):
            rows = here()
        for r in rows:
            if shared_only and not keep(r):
                continue
            if isinstance(r, dict):
                r["org"] = o
            out.append(r)
    return out


def listing(here):
    """What a Settings list shows: in Global every organization's items (each with 'org'), in an organization its own plus
    Global's Shared ones."""
    return gather(here) if everything() else gather_own(here)


def dkey(name, org=None):
    """The key that tells two same-named devices apart when every organization is listed: 'edge-fw' in Global (and always in an
    organization's own view), 'edge-fw@@3' for organization 3's device in the Global view. UniFi sub-device labels keep their tail."""
    return qualified(name, org) if everything() else name


def qualified(name, org):
    """'edge-fw' of organization 3 -> 'edge-fw@@3' (Global's own stay plain); see dkey."""
    if not org:
        return name
    base, sep, rest = (name or "").partition(" / ")
    if "@@" in base:
        return name
    return f"{base}@@{int(org)}{sep}{rest}"


def label(key):
    """What to show for a device key: its name."""
    return split_key(key)[0]


def label_org(key):
    """A device key as a person reads it: 'edge-fw', or 'edge-fw (Acme)' for another organization's device in Global's lists."""
    name, org = split_key(key)
    return f"{name} ({org_name(org)})" if org else name


def split_key(key):
    """'edge-fw@@3 / ap-1' -> ('edge-fw / ap-1', 3); a plain name -> (name, None)."""
    base, sep, rest = (key or "").partition(" / ")
    name, at, org = base.partition("@@")
    if not at or not org.isdigit():
        return key, None
    return f"{name}{sep}{rest}", int(org)


def key_of(dev):
    return dkey(dev["name"], dev.get("org"))


def db_path() -> Path:
    return org_path(target())


_wal_set = set()


class _Connection(sqlite3.Connection):
    """`with connect() as c:` commits (or rolls back) at the end of the block, then closes the connection. Left open, each one
    waited for Python's garbage collector, and Toner held a hundred or more at a time, each with its file handles."""

    def __exit__(self, *exc):
        try:
            return super().__exit__(*exc)
        finally:
            self.close()


def connect():
    """A connection to the database, for one `with` block (it is closed at the end). WAL mode lets the window, the scheduler and
    the agent receiver read while one of them writes; a long busy timeout makes a competing write wait its turn instead of
    failing with 'database is locked'."""
    p = db_path()
    if target() and not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, timeout=15, factory=_Connection)
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
        CREATE TABLE IF NOT EXISTS orgs (
            id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL COLLATE NOCASE, code TEXT UNIQUE NOT NULL COLLATE NOCASE,
            colour TEXT DEFAULT '', archived INTEGER DEFAULT 0, created TEXT DEFAULT '');
        CREATE INDEX IF NOT EXISTS idx_backups_dev ON config_backups(device, id);
        CREATE INDEX IF NOT EXISTS idx_results_run ON results(run_id);
        """)
        _migrate(c)
    _invalidate_folders()
    _forget_settings()
    if target() == GLOBAL:                                # bring every organization's file up to date too
        forget_orgs()
        for r in org_rows():
            with within(r["id"]):
                init()


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


SHAREABLE = ("devices", "profiles", "custom_checks", "maintenance", "sessions", "session_folders")


def _m6_shared(c):
    """Organizations: an item in the Global file can be marked Shared, so every organization sees it."""
    for table in SHAREABLE:
        if "shared" not in {r[1] for r in c.execute(f"PRAGMA table_info({table})")}:
            c.execute(f"ALTER TABLE {table} ADD COLUMN shared INTEGER DEFAULT 0")


def _m7_org_uids(c):
    """A permanent ID for each organization, so Demarc can tell them apart (the number is only this install's, and can come back
    after an organization is removed)."""
    if "uid" not in {r[1] for r in c.execute("PRAGMA table_info(orgs)")}:
        c.execute("ALTER TABLE orgs ADD COLUMN uid TEXT DEFAULT ''")
    for (oid,) in c.execute("SELECT id FROM orgs WHERE IFNULL(uid, '') = ''").fetchall():
        c.execute("UPDATE orgs SET uid=? WHERE id=?", (new_uid(), oid))


def new_uid():
    import uuid
    return str(uuid.uuid4())


def _m8_faster_history(c):
    """Reading the newest results no longer goes through every result ever stored. An index by device, check and run replaces the
    one by device and check (it covers what that one did). The checks that have numbers, which History offers to chart, are listed
    in numeric_checks; a trigger adds to it as results are stored, however they are stored."""
    c.executescript("""
    CREATE INDEX IF NOT EXISTS idx_results_latest ON results(device, check_name, run_id);
    DROP INDEX IF EXISTS idx_results_series;
    CREATE TABLE IF NOT EXISTS numeric_checks (
        device TEXT NOT NULL, check_name TEXT NOT NULL, PRIMARY KEY (device, check_name)) WITHOUT ROWID;
    CREATE TRIGGER IF NOT EXISTS numeric_checks_add AFTER INSERT ON results WHEN NEW.numeric IS NOT NULL BEGIN
        INSERT OR IGNORE INTO numeric_checks(device, check_name) VALUES (NEW.device, NEW.check_name);
    END;
    INSERT OR IGNORE INTO numeric_checks(device, check_name) SELECT DISTINCT device, check_name FROM results WHERE numeric IS NOT NULL;
    """)


def _m9_api_tester(c):
    """Tools > API Tester: saved requests in folders (Global's can be Shared), per-organization variables, and the history of what
    was sent. Tokens, passwords and keys are never in these tables: they are in the vault (see core/apitool.py)."""
    c.executescript("""
    CREATE TABLE IF NOT EXISTS api_folders (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, parent_id INTEGER, shared INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS api_requests (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, folder_id INTEGER, method TEXT DEFAULT 'GET', url TEXT DEFAULT '',
        params TEXT DEFAULT '[]', headers TEXT DEFAULT '[]', body TEXT DEFAULT '', body_type TEXT DEFAULT 'none',
        auth TEXT DEFAULT '{}', timeout INTEGER DEFAULT 30, verify INTEGER DEFAULT 1, created TEXT DEFAULT '',
        updated TEXT DEFAULT '', shared INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS api_history (
        id INTEGER PRIMARY KEY, at TEXT NOT NULL, method TEXT, url TEXT, params TEXT, headers TEXT, body TEXT, body_type TEXT,
        auth TEXT, timeout INTEGER, verify INTEGER, request_id INTEGER, status INTEGER DEFAULT 0, reason TEXT DEFAULT '',
        ms INTEGER DEFAULT 0, size INTEGER DEFAULT 0, error TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS api_variables (
        name TEXT PRIMARY KEY COLLATE NOCASE, value TEXT DEFAULT '', secret INTEGER DEFAULT 0);
    """)


def _m10_assistant(c):
    """The Assistant's conversations (core/assistant): one row per conversation with the provider's own message history, and one row
    per line of the transcript (a question, an answer with its tokens and cost, a tool step). Each organization keeps its own."""
    c.executescript("""
    CREATE TABLE IF NOT EXISTS ai_conversations (
        id INTEGER PRIMARY KEY, provider TEXT NOT NULL, model TEXT DEFAULT '', title TEXT DEFAULT '', started TEXT NOT NULL,
        updated TEXT DEFAULT '', turns INTEGER DEFAULT 0, tokens_in INTEGER DEFAULT 0, tokens_out INTEGER DEFAULT 0,
        cost REAL DEFAULT 0, history BLOB);
    CREATE TABLE IF NOT EXISTS ai_turns (
        id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL REFERENCES ai_conversations(id) ON DELETE CASCADE,
        at TEXT NOT NULL, kind TEXT NOT NULL, text TEXT DEFAULT '', model TEXT DEFAULT '',
        tokens_in INTEGER DEFAULT 0, tokens_out INTEGER DEFAULT 0, cost REAL DEFAULT 0);
    CREATE INDEX IF NOT EXISTS idx_ai_turns_conv ON ai_turns(conversation_id, id);
    """)


def _m11_device_software(c):
    """The software each device runs, as the checks (and the Firmware Transfer wizard) last read it: the version, the running image
    (Cisco), the mode (IOS XE: INSTALL or BUNDLE) and when it was read. Written by set_software only, never by save_device, so editing
    a device keeps them."""
    cols = {r[1] for r in c.execute("PRAGMA table_info(devices)")}
    for col in SOFTWARE_FIELDS:
        if col not in cols:
            c.execute(f"ALTER TABLE devices ADD COLUMN {col} TEXT DEFAULT ''")


def _m12_assistant_searches(c):
    """An answer's web searches: how many the provider made for it (priced into its cost) and the pages it rests on (JSON list of
    [title, url]), both on the assistant turn."""
    cols = {r[1] for r in c.execute("PRAGMA table_info(ai_turns)")}
    if "searches" not in cols:
        c.execute("ALTER TABLE ai_turns ADD COLUMN searches INTEGER DEFAULT 0")
    if "sources" not in cols:
        c.execute("ALTER TABLE ai_turns ADD COLUMN sources TEXT DEFAULT ''")


MIGRATIONS = [(1, _m1_legacy_columns), (2, _m2_agent_history), (3, _m3_agent_tokens), (4, _m4_device_checks), (5, _m5_ansible_runs),
              (6, _m6_shared), (7, _m7_org_uids), (8, _m8_faster_history), (9, _m9_api_tester), (10, _m10_assistant), (11, _m11_device_software),
              (12, _m12_assistant_searches)]
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


# ---------- secrets (Toner's vault, core/passvault.py, reached through keyring) ----------
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
    try:
        from core import extstore
        extstore.move_link(old, new)                     # a link to a password manager item follows the password
    except Exception:
        quiet.ignored()

# A device can hold several secrets: its password/token, an SNMP community or v3 auth/privacy passwords, a proxy password,
# an SSH password, and (Cisco) an enable password.
SECRET_KINDS = {"main": "", "snmp": ":snmp", "snmp_auth": ":snmp-auth", "snmp_priv": ":snmp-priv", "proxy": ":proxy",
                "agent": ":agent", "ssh": ":ssh", "proxy_otp": ":proxy-otp", "enable": ":enable"}

def qualify(name):
    """A vault entry name for the organization being written to: Global keeps the plain name (so nothing stored before
    organizations existed moves), an organization's entries start with 'org3/', so two organizations can each have an 'edge-fw'."""
    org = target()
    return f"org{org}/{name}" if org else name


def secret_name(owner, kind="main"):
    return qualify(owner + SECRET_KINDS[kind])

def move_device_secrets(old, new):
    for kind in SECRET_KINDS:
        move_secret(secret_name(old, kind), secret_name(new, kind))

def delete_device_secrets(name):
    for kind in SECRET_KINDS:
        delete_secret(secret_name(name, kind))


# ---------- inventory ----------
def _devices_here(enabled_only=False):
    """enabled_only: the devices that can be checked. A device with no vendor yet (imported from a session file) is not: nothing
    knows how to sign in to it, so the checks, backups and commands leave it out until a vendor is chosen."""
    q = "SELECT * FROM devices" + (" WHERE enabled=1 AND vendor != ''" if enabled_only else "") + " ORDER BY name"
    with connect() as c:
        return [dict(r) for r in c.execute(q)]


def list_devices(enabled_only=False):
    """The devices of the current view, each with 'org' (the file it lives in) and 'key' (see dkey). Seen from an organization,
    Global's Shared devices are included without a folder (their folder belongs to the Global file); saving one puts it back."""
    rows = gather(lambda: _devices_here(enabled_only))
    me = target()
    for d in rows:
        if d["org"] != me:
            d["_folder_id"], d["folder_id"] = d.get("folder_id"), None
        d["key"] = dkey(d["name"], d["org"])
    if len({d["org"] for d in rows}) > 1:
        rows.sort(key=lambda d: d["name"].lower())
    return rows


def find_device(key):
    """The device a key (or plain name) from a list of the current view stands for, or None."""
    with including_archived():
        devs = list_devices()
    return next((d for d in devs if d["key"] == key), None) or next((d for d in devs if d["name"] == key), None)


class NameTaken(sqlite3.IntegrityError):
    """A device name that is already used where it would clash: in the same organization, or by a Shared device."""


def name_clash(name, org=None, ignore_id=None, shared=False):
    """Where a device called `name` saved in `org` (default: the target) would clash, as an organization name, or None. Names only
    have to be unique inside one organization, but a Shared device shows up in every organization, so it clashes with any of them."""
    org = target() if org is None else int(org)
    def taken(o, only_shared=False):
        with within(o):
            with connect() as c:
                q = "SELECT id FROM devices WHERE name=? COLLATE NOCASE" + (" AND shared=1" if only_shared else "")
                return [r["id"] for r in c.execute(q, (name,))]
    ids = [i for i in taken(org) if i != ignore_id]
    if ids:
        return org_name(org)
    if org and taken(GLOBAL, only_shared=True):
        return "Global (Shared)"
    if not org and shared:
        for r in org_rows():
            if taken(r["id"]):
                return r["name"]
    return None

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
    if label.startswith("Device: "):      # one device by name or key (the Overview's "Run checks" on a single device)
        return (dev.get("key") or dev["name"]) == label[len("Device: "):]
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

def get_device(dev_id, org=None):
    with within(org):
        with connect() as c:
            row = c.execute("SELECT * FROM devices WHERE id=?", (dev_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["org"] = target()
        d["key"] = dkey(d["name"], d["org"])
        return d

def save_device(dev: dict) -> int:
    """Insert or update a device in its own organization's file (dev['org'], else the one being written to)."""
    with within(dev.get("org")):
        return _save_device(dev)

def _save_device(dev):
    if "_folder_id" in dev:                                  # a Shared device edited from an organization keeps its Global folder
        dev = {**dev, "folder_id": dev["_folder_id"]}
    shared = 1 if dev.get("shared") and target() == GLOBAL else 0
    where = name_clash(dev.get("name") or "", None, dev.get("id"), bool(shared))
    if where:
        raise NameTaken(f"A device named {dev.get('name')} already exists in {where}.")
    dev = {**dev, "shared": shared}
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

def delete_device(dev_id, org=None):
    with within(org):
        with connect() as c:
            c.execute("DELETE FROM devices WHERE id=?", (dev_id,))


# ---------- the software a device runs, as last read ----------
def set_software(dev, info, when=None):
    """Keep what a check (or the Firmware Transfer wizard) just read from a device: info is {'version', 'image' (optional),
    'mode' (optional)}. Nothing is written without a version. The device is found by its id in its own organization's file, so
    the row's other columns are untouched. When the version differs from the one stored, one audit line says so.
    Returns the stored {'version', 'image', 'mode', 'read_at'}, or None when nothing was written."""
    version = str((info or {}).get("version") or "").strip()
    if not version or not dev.get("id"):
        return None
    image, mode = str(info.get("image") or "").strip(), str(info.get("mode") or "").strip().upper()
    now = (when or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    with within(dev.get("org")):
        with connect() as c:
            row = c.execute("SELECT name, sw_version FROM devices WHERE id=?", (dev["id"],)).fetchone()
            if not row:
                return None
            c.execute("UPDATE devices SET sw_version=?, sw_image=?, sw_mode=?, sw_read_at=? WHERE id=?",
                      (version, image, mode, now, dev["id"]))
        before = row["sw_version"] or ""
        if before and before != version:
            from core import audit
            audit.log("version", f"{row['name']} now runs {version} (was {before})")
    return {"version": version, "image": image, "mode": mode, "read_at": now}


def software_of(dev):
    """{'version', 'image', 'mode', 'read_at'} from a device row ('' each when nothing was read yet)."""
    return {"version": dev.get("sw_version") or "", "image": dev.get("sw_image") or "", "mode": dev.get("sw_mode") or "",
            "read_at": dev.get("sw_read_at") or ""}


def copy_software(src_dev, dst_dev):
    """A device moved or copied to another organization keeps what was last read from it."""
    sw = software_of(src_dev)
    if not (sw["version"] and dst_dev.get("id")):
        return
    with within(dst_dev.get("org")):
        with connect() as c:
            c.execute("UPDATE devices SET sw_version=?, sw_image=?, sw_mode=?, sw_read_at=? WHERE id=?",
                      (sw["version"], sw["image"], sw["mode"], sw["read_at"], dst_dev["id"]))


# ---------- folders ----------
_folder_cache = {}                  # file -> {folder id: path}

def _invalidate_folders():
    _folder_cache.clear()

def list_folders():
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT id, name, parent_id FROM folders ORDER BY name COLLATE NOCASE")]

def folder_paths():
    """{folder id: 'Parent/Child'}. Cached, because group matching asks for it once per device."""
    key = str(db_path())
    if key not in _folder_cache:
        rows = {f["id"]: f for f in list_folders()}
        out = {}
        for fid in rows:
            parts, cur, seen = [], fid, set()
            while cur in rows and cur not in seen:       # 'seen' guards against a corrupt parent loop
                seen.add(cur)
                parts.append(rows[cur]["name"])
                cur = rows[cur]["parent_id"]
            out[fid] = "/".join(reversed(parts))
        _folder_cache[key] = out
    return _folder_cache[key]

def path_of(dev):
    """The device's folder path, read from its own organization's file ('' at the top, and for a Shared device seen from an
    organization, which has no folder there)."""
    if dev.get("folder_id") is None:
        return ""
    org = dev.get("org")
    if org is None or org == target():
        return folder_paths().get(dev["folder_id"]) or ""
    with within(org):
        return folder_paths().get(dev["folder_id"]) or ""


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
# Settings: Global's apply everywhere; an organization's file holds only the ones it changes (Settings > ... while it is picked).
# These are about this computer or the whole program, so they are always read from and written to the Global file:
GLOBAL_ONLY = {"window_geometry", "splitters", "sidebar_collapsed", "sessions_list_hidden", "onboarding_done", "org_current",
               "theme", "ui_style", "font_size", "color_preset", "status_colors",
               "term_font", "rdp_embedded", "term_font_size", "term_scrollback", "term_scheme", "paging_cmd",
               "hostkey_mode", "ssh_legacy_algorithms", "run_in_background", "metrics_port", "proxy", "ssh_tunnel",
               "update_check", "update_auto_install", "update_last_check", "update_skip", "update_pending",
               "ansible_backend", "ansible_distro", "ansible_command", "ansible_playbooks", "ansible_server_device", "ansible_server",
               "ansible_check_default", "ansible_keep_runs", "fileserver", "iperf_path", "openssl_path", "snippets",
               "ssh_log_days",
               "agent_cert_warned", "agent_enabled", "agent_token_days", "agent_port", "agent_bind", "agent_address",
               "vault_provider", "vault_config", "vault_direct", "update_direct", "vault_keep_copies", "install_uid", "demarc",
               "ai_provider", "ai_model", "ai_depth", "ai_spend_limit", "ai_run_commands", "ai_search", "assistant_button"}
# (agent sign-up, its interval and whether installed agents are told it are each organization's own: Settings > Agents)
# ...and these belong to one organization's own lists, so an organization never borrows Global's:
ORG_LOCAL = {"acks", "inventory_expanded", "sessions_expanded", "client_scope", "trend_last", "notify_snooze_until", "firmware_source"}

_settings = {}                      # file -> (read at, {key: raw json})
_settings_lock = threading.Lock()
SETTINGS_TTL = 2.0                  # seconds; another process (the service, the window) is noticed within this long


def _forget_settings():
    with _settings_lock:
        _settings.clear()


def _settings_of(org):
    key, now = str(org_path(org)), time.monotonic()
    with _settings_lock:
        hit = _settings.get(key)
        if hit is None or now - hit[0] > SETTINGS_TTL:
            with within(org):
                with connect() as c:
                    data = {r["key"]: r["value"] for r in c.execute("SELECT key, value FROM settings")}
            hit = _settings[key] = (now, data)
        return hit[1]


def _all_settings():
    return _settings_of(target())


def _home_of(key):
    """The file a setting is read from first: Global for GLOBAL_ONLY ones, else the organization being written to."""
    return GLOBAL if key in GLOBAL_ONLY else target()


def _raw_setting(key):
    org = _home_of(key)
    raw = _settings_of(org).get(key)
    if raw is None and org and key not in ORG_LOCAL:
        raw = _settings_of(GLOBAL).get(key)
    return raw


def get_setting(key):
    raw = _raw_setting(key)
    # defaults are copied so callers can never modify the shared default list/dict
    return json.loads(raw) if raw is not None else json.loads(json.dumps(DEFAULT_SETTINGS[key]))


def get_thresholds():
    raw = _raw_setting("thresholds")
    stored = json.loads(raw) if raw else {}
    return {k: {**v, **stored.get(k, {})} for k, v in DEFAULT_THRESHOLDS.items()}

def set_thresholds(th):
    set_setting("thresholds", th)


def overridden(key):
    """True when the organization being written to has its own value for this setting (Global never 'overrides')."""
    org = _home_of(key)
    return bool(org) and key not in ORG_LOCAL and key in _settings_of(org)


def follow_global(key):
    """Forget the organization's own value, so it follows Global again (Settings' Reset to Global)."""
    org = _home_of(key)
    if not org:
        return
    with within(org):
        with connect() as c:
            c.execute("DELETE FROM settings WHERE key=?", (key,))
    _forget_settings()


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
    """Save a setting. In an organization, a value that is the same as Global's is not kept as the organization's own: it then
    follows Global, including later changes there."""
    org = _home_of(key)
    if org and key not in ORG_LOCAL:
        with within(GLOBAL):
            try:
                same = (get_thresholds() if key == "thresholds" else get_setting(key)) == json.loads(json.dumps(value))
            except KeyError:
                same = False
        if same:
            follow_global(key)
            return
    with within(org):
        with connect() as c:
            c.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))
    _forget_settings()                                    # the next read sees it


# ---------- history ----------
def save_run(results) -> int:
    """Store a run. Results from devices in other organizations' files (Global listing everything, Shared devices) are stored
    in those files, as runs of their own. Returns the id of the run in the file being written to (else the first one stored)."""
    groups = {}
    for r in results:
        groups.setdefault(getattr(r, "org", None), []).append(r)
    here = target()
    if set(groups) <= {None, here}:
        return _save_run_here(results)
    ids = {}
    for org, rows in groups.items():
        with within(org):
            ids[target()] = _save_run_here(rows)
    return ids.get(here, next(iter(ids.values())))

def _save_run_here(results):
    n = lambda s: sum(r.status == s for r in results)
    results = [r if "@@" not in (r.device or "") else type(r)(**{**r.__dict__, "device": split_key(r.device)[0]}) for r in results]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    path, stored = str(db_path()), None
    with connect() as c:
        before = _history_mark(c)
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
        after = _history_mark(c)
        if _kept_for(path, before):                          # read back as stored, so what is kept matches a fresh read exactly
            stored = [dict(r) for r in c.execute("SELECT device, check_name, status, value, message, numeric FROM results "
                                                 "WHERE run_id=? ORDER BY rowid", (rid,))]
    # only this run changed the file (no other process stored one meanwhile, no old run was removed): bring it up to date
    if stored is not None and after[0] == rid and after[1] == before[1] + 1 and after[2] - before[2] == len(results):
        _advance_kept(path, before, after, now, stored)
    return rid

def list_runs(limit=200):
    """Runs, newest first, each with 'org'. An organization lists its own; Global listing everything lists every file's."""
    def here():
        with connect() as c:
            return [dict(r) for r in c.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,))]
    rows = gather(here)
    if len({r["org"] for r in rows}) > 1:
        rows.sort(key=lambda r: (r["started_at"], r["id"]), reverse=True)
    return rows[:limit]

def run_results(run_id, org=None):
    """A run's rows. In the Global view, device names of other organizations come back as keys (see dkey)."""
    qualify_names = everything()
    with within(org):
        with connect() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT device, check_name, status, value, message FROM results WHERE run_id=? "
                "ORDER BY device, check_name", (run_id,))]
        o = target()
    if qualify_names and o:
        for r in rows:
            r["device"] = dkey(r["device"], o)
    return rows

def _shared_names():
    with within(GLOBAL):
        with connect() as c:
            return {r[0] for r in c.execute("SELECT name FROM devices WHERE shared=1")}

def _each_file():
    """[(org, only)] for history reads: only = the Shared device names to keep from that file, or None for all of it."""
    out = []
    for org, shared_only in _files():
        if shared_only:
            names = _shared_names()
            if names:
                out.append((org, names))
        else:
            out.append((org, None))
    return out

def _per_device(here):
    """Join {device: value} dicts from every file of the view, keyed with dkey."""
    out = {}
    for org, only in _each_file():
        with within(org):
            part = here()
        for name, v in part.items():
            if only is None or _base(name) in only:
                out[dkey(name, org)] = v
    return out

per_device = _per_device                 # for other modules: {device: value} read from every file of the view, keyed with dkey


def device_checks():
    """{device: [check, ...]} for checks that have numeric history."""
    def here():
        out = {}
        with connect() as c:
            for r in c.execute("SELECT device, check_name FROM numeric_checks ORDER BY device, check_name"):
                out.setdefault(r["device"], []).append(r["check_name"])
        return out
    return _per_device(here)

AGENT_COLUMNS = {"cpu": "cpu", "memory": "memory", "disks": "disk", "uptime": "uptime_h"}     # check name -> agent_metrics column


def series(device, check, limit=200):
    """(time, value) points for one check, oldest first. A Windows agent reports far more often than checks run, so its
    own reports are added in and the chart has a point per report. `device` can be a key from the Global view."""
    device, org = split_key(device)
    if org is not None or not everything():
        with within(org):
            return _series_here(device, check, limit)
    with within(GLOBAL):                               # a plain name in the Global view is Global's own device
        return _series_here(device, check, limit)

def _series_here(device, check, limit):
    with connect() as c:
        rows = c.execute(
            "SELECT runs.started_at AS t, results.numeric AS v FROM results "
            "JOIN runs ON runs.id = results.run_id "
            "WHERE results.device=? AND results.check_name=? AND results.numeric IS NOT NULL "
            "ORDER BY results.run_id DESC LIMIT ?", (device, check, limit)).fetchall()
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


# ---------- remembering the newest results ----------
# Every device's newest results are asked for often (each section shown, each refresh), and reading them takes a while on a long
# history. What a file holds only changes when runs are stored or removed, so each file's answer is kept until then.
_remember = {}
_remember_lock = threading.Lock()


def _history_mark(c):
    """Changes whenever runs or results are added or removed: the newest run, how many there are, and the newest result."""
    return tuple(c.execute("SELECT (SELECT IFNULL(MAX(id), 0) FROM runs), (SELECT COUNT(*) FROM runs), "
                           "(SELECT IFNULL(MAX(rowid), 0) FROM results)").fetchone())


def _kept_for(path, mark):
    with _remember_lock:
        return any(k[0] == path and v[0] == mark for k, v in _remember.items())


def _advance_kept(path, before, after, at, stored):
    """A run this process just stored: what is kept for this file (each device's newest state and results) is brought up to date
    from that run alone, instead of reading every device's newest results again. Only what was up to date just before the run;
    anything else (availability, or what another process changed) is read afresh as usual."""
    with _remember_lock:
        for key, (mark, value) in list(_remember.items()):
            if key[0] != path or mark != before or key[1] not in ("_device_health_here", "_latest_results_here"):
                continue
            exclude = key[2][0] if key[2] else dict(key[3]).get("exclude", ("config backup",))
            fresh = [r for r in stored if r["check_name"] not in exclude]      # a backup-only run leaves a device as it was
            if key[1] == "_device_health_here":
                new = {}
                for r in fresh:
                    _health_add(new, r, at)
                _remember[key] = (after, {**value, **_health_sorted(new)})
            else:
                rows, newest = value
                bases = {_base(r["device"]) for r in fresh}
                _remember[key] = (after, ([r for r in rows if _base(r["device"]) not in bases] + [{**r, "at": at} for r in fresh],
                                          max(newest, at) if fresh else newest))


def forget_history():
    """Read the newest results afresh (moving devices between organizations takes results out of a file without a new run)."""
    with _remember_lock:
        _remember.clear()


def _remembered(fn, copy):
    """fn, answered from what was kept for this file while its runs have not changed. `copy` hands each caller its own copy."""
    def kept(*args, **kw):
        key = (str(db_path()), fn.__name__, args, tuple(sorted(kw.items())))
        with connect() as c:
            mark = _history_mark(c)
        with _remember_lock:
            hit = _remember.get(key)
        if hit is None or hit[0] != mark:
            hit = (mark, fn(*args, **kw))                     # stored under the mark read first: a run saved meanwhile is read next time
            with _remember_lock:
                _remember[key] = hit
        return copy(hit[1])
    kept.__name__, kept.__doc__ = fn.__name__, fn.__doc__
    return kept


def latest_results(exclude=("config backup",)):
    """_latest_results_here for every file of the view; device labels from other organizations come back as keys (see dkey)."""
    rows, newest = [], ""
    for org, only in _each_file():
        with within(org):
            part, _at = _latest_results_here(exclude)
        for r in part:
            if only is None or _base(r["device"]) in only:
                r["device"], r["org"] = dkey(r["device"], org), org
                rows.append(r)
                newest = max(newest, r["at"])
    return rows, newest


def _latest_results_here(exclude=("config backup",)):
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


_latest_results_here = _remembered(_latest_results_here, lambda r: ([dict(x) for x in r[0]], r[1]))


def device_health(exclude=("config backup",)):
    """_device_health_here for every file of the view, keyed with dkey."""
    return _per_device(lambda: _device_health_here(exclude))


def _device_health_here(exclude=("config backup",)):
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
                if _base(r["device"]) in bases and r["check_name"] not in exclude:
                    _health_add(out, r, times.get(rid, ""))
    return _health_sorted(out)


def _health_add(out, r, at):
    """One stored result into its device's latest state (see _device_health_here)."""
    d = out.setdefault(_base(r["device"]), {"status": "OK", "at": at, "checks": 0, "problems": []})
    d["checks"] += 1
    if _SEV.get(r["status"], 0) > 0:
        d["problems"].append((r["check_name"], r["status"], r["message"] or r["value"] or ""))
    if _SEV.get(r["status"], 0) > _SEV[d["status"]]:
        d["status"] = r["status"]


def _health_sorted(out):
    for d in out.values():
        d["problems"].sort(key=lambda p: -_SEV.get(p[1], 0))
    return out


_device_health_here = _remembered(_device_health_here, lambda h: {k: {**v, "problems": list(v["problems"])} for k, v in h.items()})


def changes_since_previous():
    """_changes_here for each file of the view (each compares its own last two runs)."""
    out = {"worse": [], "better": []}
    for org, only in _each_file():
        with within(org):
            part = _changes_here()
        for k in out:
            out[k] += [(dkey(d, org), was, now) for d, was, now in part[k] if only is None or d in only]
    for k in out:
        out[k].sort()
    return out


def _changes_here():
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
    return _per_device(lambda: _availability_here(days, start, end))


def _availability_here(days=7, start=None, end=None):
    """{device: {'runs', 'reachable', 'healthy'}} over the last `days` days (or between two times). A run counts as 'reachable'
    when the device produced results without a 'connection' error, and 'healthy' when none of its checks was worse than WARN.
    The last `days` days start on the minute, so the answer can be kept until a run is stored or the next minute begins."""
    cutoff = start or (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:00")
    return _availability_between(cutoff, end or "9999-12-31 00:00:00")


def _availability_between(cutoff, until):
    """Counted by SQLite: a week of runs is a lot of results to go through one by one."""
    with connect() as c:
        rows = c.execute(
            "SELECT dev, COUNT(*) AS runs, SUM(1 - conn) AS reachable, SUM(1 - bad) AS healthy FROM ("
            "  SELECT r.run_id, CASE WHEN instr(r.device, ' / ') > 0 THEN substr(r.device, 1, instr(r.device, ' / ') - 1)"
            "         ELSE r.device END AS dev,"                         # a UniFi sub-device counts for its controller (_base)
            "         MAX(r.check_name = 'connection' AND r.status = 'ERROR') AS conn, MAX(r.status IN ('FAIL', 'ERROR')) AS bad"
            "  FROM results r WHERE r.run_id IN (SELECT id FROM runs WHERE started_at >= ? AND started_at < ?)"
            "  AND r.check_name != 'config backup' GROUP BY r.run_id, dev) GROUP BY dev", (cutoff, until)).fetchall()
    return {r["dev"]: {"runs": r["runs"], "reachable": r["reachable"], "healthy": r["healthy"]} for r in rows}


_availability_between = _remembered(_availability_between, lambda a: {k: dict(v) for k, v in a.items()})


def last_run():
    def here():
        with connect() as c:
            row = c.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        return [dict(row)] if row else []
    rows = gather(here)
    return max(rows, key=lambda r: r["started_at"]) if rows else None


# ---------- raw device output kept when a parser fails, for bug reports ----------
def save_diagnostic(device, check, body):
    with connect() as c:
        c.execute("INSERT INTO diagnostics(device, check_name, at, body) VALUES(?,?,?,?)",
                  (device, check, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), body[:60000]))
        c.execute("DELETE FROM diagnostics WHERE id NOT IN (SELECT id FROM diagnostics ORDER BY id DESC LIMIT 200)")


def get_diagnostics(device, check=None, limit=5):
    device, org = split_key(device)
    with within(org):
        return _diagnostics_here(device, check, limit)

def _diagnostics_here(device, check, limit):
    q, args = "SELECT * FROM diagnostics WHERE device=?", [_base(device)]
    if check:
        q += " AND check_name=?"
        args.append(check)
    with connect() as c:
        return [dict(r) for r in c.execute(q + " ORDER BY id DESC LIMIT ?", args + [limit])]

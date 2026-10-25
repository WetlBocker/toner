"""What the Assistant can read, defined once and translated per provider (see providers.py).

Every tool reads through Toner's own code, inside the organization the question was asked in, and only reads: nothing here
changes a device, a setting or a database. Every result goes through `mask`, which replaces every password Toner holds in its
vault (and anything that looks like a password in a URL) with ****; configuration backups are read from the masked copy only
and masked again on the way out. Every call writes one audit line ("assistant", "read core-sw1's history").
"""
import json
import os
import re
from datetime import datetime

from core import audit, backup, db, display, sessionlog
from core import firmware as fw

TEXT_LIMIT = 60_000            # characters of one backup or log handed over (the rest is said to be cut)
ROW_LIMIT = 400                # rows of one list handed over
SCREEN_LIMIT = 20_000          # characters of text from the screen


class ToolError(Exception):
    """A tool could not do what was asked; its message is handed to the model as the result."""


class Tool:
    """One thing the Assistant can read: its name and description for the model, the JSON schema of its arguments, the function,
    and how a call reads in the panel ("Reading core-sw1's history…") and in the audit log ("read core-sw1's history")."""

    def __init__(self, name, description, schema, fn, step, audit=None):
        self.name, self.description, self.schema, self.fn = name, description, schema, fn
        self._step, self._audit = step, audit

    def step(self, args):
        return self._step(args) + "…"

    def audit(self, args):
        if self._audit:
            return self._audit(args)
        s = self._step(args)                                              # "Reading core-sw1's history" -> "read core-sw1's history"
        for now, then in (("Reading ", "read "), ("Comparing ", "compared ")):
            if s.startswith(now):
                return then + s[len(now):]
        return s[:1].lower() + s[1:]


def _schema(**props):
    """A JSON schema object with these properties; a property given as (schema, True) is required."""
    out, req = {}, []
    for name, spec in props.items():
        if isinstance(spec, tuple):
            spec, required = spec
            if required:
                req.append(name)
        out[name] = spec
    s = {"type": "object", "properties": out}
    if req:
        s["required"] = req
    return s


DEVICE_ARG = ({"type": "string", "description": "The device's name as the Inventory shows it."}, True)


# ---------------------------------------------------------------- masking
_secrets_cache = {"key": None, "values": ()}


def secrets():
    """Every password, token and community string in the vault (Global's and every organization's), newest read once per turn."""
    from core import vault
    try:
        values = tuple(v for v in vault.collect().values() if v and len(v) >= 4)
    except Exception:
        values = ()
    from core.assistant import key_names
    import keyring
    for name in key_names():                                        # the Assistant's own API keys, too
        try:
            v = keyring.get_password(db.SERVICE, name)
        except Exception:
            v = None
        if v and len(v) >= 4:
            values += (v,)
    return values


def mask(text, values=None):
    """`text` with every vault secret replaced by **** (and the password of any user:password@ URL)."""
    return fw.mask(text, secrets() if values is None else values)


def masked(obj, values=None):
    """A copy of a result (dict, list, str) with every string masked."""
    if isinstance(obj, str):
        return mask(obj, values)
    if isinstance(obj, dict):
        return {k: masked(v, values) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [masked(v, values) for v in obj]
    return obj


# ---------------------------------------------------------------- helpers
def _find(name):
    dev = db.find_device(name or "")
    if dev is None:
        raise ToolError(f"No device called '{name}' in this organization. Use list_devices to see the names.")
    return dev


def _whose(dev):
    return dev["name"] + (f" ({db.org_name(dev['org'])})" if dev.get("org") and db.several() else "")


def _device_row(d, health=None):
    """A device as the model sees it: no ids, no settings that only Toner understands, never a secret."""
    h = (health or {}).get(d.get("key") or d["name"])
    try:
        folder = db.path_of(d) or ""
    except Exception:
        folder = ""
    row = {"name": d["name"], "vendor": display.vendor_name(d["vendor"]), "host": d["host"], "platform": d.get("platform") or "",
           "location": d.get("location") or "", "tags": db.split_tags(d.get("tags")), "folder": folder, "details": d.get("details") or "",
           "enabled": bool(d.get("enabled", 1)), "status": (h or {}).get("status") or ("Not checked" if d.get("enabled", 1) else "Disabled"),
           "last_checked": (h or {}).get("at") or ""}
    if db.several():
        row["organization"] = db.org_name(d.get("org"))
    if d.get("shared"):
        row["shared"] = True
    return row


def _cut(text, limit=TEXT_LIMIT):
    text = text or ""
    if len(text) <= limit:
        return text, False
    return text[:limit] + f"\n[cut: showing the first {limit:,} of {len(text):,} characters]", True


# ---------------------------------------------------------------- the tools
def list_devices(args):
    devs = db.list_devices()
    health = db.device_health()
    rows = [_device_row(d, health) for d in devs]
    return {"organization": db.org_name(db.target()) if not db.everything() else "Global (every organization)",
            "count": len(rows), "devices": rows[:ROW_LIMIT], "cut": len(rows) > ROW_LIMIT}


def device_details(args):
    d = _find(args.get("device"))
    health = db.device_health()
    row = _device_row(d, health)
    row["username"] = d.get("username") or ""
    row["port"] = d.get("port") or 0
    row["custom_fields"] = _fields(d)
    h = health.get(d["key"])
    row["problems"] = [{"check": display.check_name(c), "status": s, "message": m} for c, s, m in (h or {}).get("problems", [])]
    row["latest_results"] = latest_results({"device": d["key"]})["results"]
    last = backup.latest(d["key"])
    row["last_backup"] = last["taken_at"] if last else ""
    return row


def _fields(d):
    try:
        raw = d.get("fields") or ""
        return json.loads(raw) if raw.startswith("{") else {}
    except ValueError:
        return {}


def latest_results(args):
    d = _find(args.get("device"))
    rows, _newest = db.latest_results()
    base = lambda name: (name or "").split(" / ")[0]
    mine = [r for r in rows if base(r["device"]) == d["key"]]
    out = [{"device": db.label(r["device"]), "check": display.check_name(r["check_name"]), "status": r["status"],
            "value": display.value(r.get("value")), "message": r.get("message") or "", "at": r.get("at") or ""} for r in mine]
    return {"device": _whose(d), "results": out[:ROW_LIMIT], "count": len(out)}


def device_history(args):
    d = _find(args.get("device"))
    limit = max(1, min(int(args.get("runs") or 30), 200))
    check = (args.get("check") or "").strip().lower()
    name, org = db.split_key(d["key"])
    with db.within(org if org is not None else (None if not db.everything() else db.GLOBAL)):
        with db.connect() as c:
            q = ("SELECT results.run_id AS rid, runs.started_at AS at, results.check_name, results.status, results.value, results.message FROM results "
                 "JOIN runs ON runs.id = results.run_id WHERE (results.device = ? OR results.device LIKE ?) ")
            params = [name, name + " / %"]
            if check:
                q += "AND LOWER(results.check_name) = ? "
                params.append(check)
            q += "ORDER BY results.run_id DESC, results.check_name LIMIT ?"
            params.append(limit * 40)
            rows = [dict(r) for r in c.execute(q, params)]
    runs = {}                                                            # by run id: two runs in one second are still two runs
    for r in rows:
        runs.setdefault((r["rid"], r["at"]), []).append({"check": display.check_name(r["check_name"]), "status": r["status"],
                                                         "value": display.value(r.get("value")), "message": r.get("message") or ""})
    out = [{"at": at, "results": res} for (_rid, at), res in list(runs.items())[:limit]]
    checks = sorted({display.check_name(r["check_name"]) for r in rows})
    return {"device": _whose(d), "runs": out, "checks_seen": checks, "note": "Newest run first." if out else "No results stored for this device."}


def list_backups(args):
    d = _find(args.get("device"))
    rows = backup.list_backups(d["key"])
    return {"device": _whose(d), "supported": backup.supported(d), "count": len(rows),
            "versions": [{"id": r["id"], "taken_at": r["taken_at"], "size": r["size"], "lines": r["lines"], "added": r["added"], "removed": r["removed"]}
                         for r in rows[:ROW_LIMIT]],
            "note": "Newest first. Read one with read_backup; compare two with diff_backups." if rows else
                    ("No backup of this device yet." if backup.supported(d) else "Toner cannot back up this kind of device: " + backup.why_unsupported(d))}


def _version(d, backup_id):
    rows = backup.list_backups(d["key"])
    v = next((r for r in rows if r["id"] == int(backup_id)), None)
    if v is None:
        raise ToolError(f"{d['name']} has no backup with id {backup_id}. Use list_backups to see its versions.")
    return v


def _masked_text(v):
    """A stored version, masked whatever the backup setting was when it was stored."""
    return backup.clean(backup.get_text(v["id"], v["org"]), mask=True)


def read_backup(args):
    d = _find(args.get("device"))
    v = _version(d, args.get("backup_id") or (backup.latest(d["key"]) or {}).get("id") or 0)
    text, cut = _cut(_masked_text(v))
    return {"device": _whose(d), "taken_at": v["taken_at"], "backup_id": v["id"], "lines": v["lines"], "configuration": text, "cut": cut,
            "note": "Passwords, keys and SNMP communities are masked."}


def diff_backups(args):
    d = _find(args.get("device"))
    a, b = _version(d, args.get("older_id")), _version(d, args.get("newer_id"))
    if a["id"] > b["id"]:
        a, b = b, a
    lines, added, removed = backup.diff_lines(_masked_text(a), _masked_text(b), f"{d['name']} {a['taken_at']}", f"{d['name']} {b['taken_at']}")
    text, cut = _cut("\n".join(lines))
    return {"device": _whose(d), "older": a["taken_at"], "newer": b["taken_at"], "added": added, "removed": removed,
            "diff": text or "These two versions are identical.", "cut": cut}


LATEST = {"firmware_check": None}          # the Firmware Transfer page puts its newest Check devices results here (per organization)


def firmware_check(args):
    snap = LATEST.get("firmware_check")
    if not snap or snap.get("org") != db.target():
        return {"results": [], "note": "The Firmware Transfer page has not checked any devices in this organization since Toner started. "
                                       "Its results appear here after Tools > Firmware Transfer > Check devices."}
    return {"checked_at": snap["at"], "server": snap.get("server", ""), "results": snap["results"]}


def firmware_snapshot(results, server_text=""):
    """What the Firmware Transfer page hands over after Check devices: the rows as the page shows them, nothing more."""
    rows = []
    for r in results:
        main = r["flashes"][0] if r.get("flashes") else {}
        rows.append({"device": r.get("name", ""), "host": r.get("host", ""), "platform": fw.PLATFORM_NAMES.get(r.get("platform"), r.get("platform", "")),
                     "version": r.get("version", ""), "mode": r.get("mode", ""), "running_image": r.get("image", ""), "boot": list(r.get("boot") or []),
                     "free_space": fw.human_size(main.get("free")) if main and main.get("free") is not None else "",
                     "reaches_server": r.get("ping"), "port_open": r.get("port"), "status": r.get("held") or r.get("note") or "Ready",
                     "stack": [{"member": f["member"], "role": f.get("role", ""), "free_space": fw.human_size(f.get("free")) if f.get("free") is not None else ""}
                               for f in (r.get("flashes") or [])[1:]]})
    LATEST["firmware_check"] = {"org": db.target(), "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "server": server_text, "results": rows}


def audit_log(args):
    limit = max(1, min(int(args.get("limit") or 100), 500))
    rows = audit.recent(limit, (args.get("text") or "").strip())
    return {"count": len(rows), "entries": [{"at": r["at"], "who": r["actor"], "action": r["action"], "detail": r["detail"],
                                             **({"organization": db.org_name(r["org"])} if db.several() else {})} for r in rows]}


def list_session_logs(args):
    limit = max(1, min(int(args.get("limit") or 100), 500))
    rows = db.gather(lambda: sessionlog.list_sessions(limit))
    rows.sort(key=lambda r: (r["started_at"], r["id"]), reverse=True)
    return {"count": len(rows), "sessions": [{"id": r["id"], "started": r["started_at"], "ended": r["ended_at"] or "", "type": (r.get("kind") or "ssh").upper(),
                                              "device": r["device"], "host": f"{r['host']}:{r['port']}", "user": r["username"], "result": r["reason"] or "",
                                              **({"organization": db.org_name(r["org"])} if db.several() else {})} for r in rows[:limit]],
            "note": "Read one with read_session_log and its id." if rows else "No session logs in this organization."}


def read_session_log(args):
    sid = int(args.get("session_id") or 0)
    rows = db.gather(lambda: sessionlog.list_sessions(5000))
    s = next((r for r in rows if r["id"] == sid), None)
    if s is None:
        raise ToolError(f"No session log with id {sid}. Use list_session_logs to see them.")
    try:
        with open(s["log_path"], "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - TEXT_LIMIT))
            text = sessionlog.clean(f.read().decode("utf-8", "replace"))
    except OSError as e:
        raise ToolError(f"The log file could not be opened: {e}") from None
    note = f"Showing the last {TEXT_LIMIT // 1000} KB of {size // 1000} KB." if size > TEXT_LIMIT else ""
    return {"session_id": sid, "device": s["device"], "host": f"{s['host']}:{s['port']}", "started": s["started_at"], "ended": s["ended_at"] or "",
            "log": text, "note": note}


def _screen(args, screen=None):
    if not screen:
        return {"note": "Nothing was captured from the screen for this question."}
    return screen


TOOLS = [
    Tool("list_devices", "Every device in the organization being looked at: name, kind, address, location, tags, folder, whether it is enabled, "
         "and its latest status (OK, WARN, FAIL, ERROR, Not checked).",
         _schema(), list_devices, lambda a: "Reading the device list"),
    Tool("device_details", "One device in full: its settings (never its passwords), its latest health check results, its problems and when it was last backed up.",
         _schema(device=DEVICE_ARG), device_details, lambda a: f"Reading {a.get('device', '')}'s details"),
    Tool("latest_results", "A device's newest health check results: one row per check with its status, value and message.",
         _schema(device=DEVICE_ARG), latest_results, lambda a: f"Reading {a.get('device', '')}'s latest results"),
    Tool("device_history", "A device's check results over earlier runs, newest run first, to see how a value or status changed. "
         "Optionally one check only.",
         _schema(device=DEVICE_ARG, check={"type": "string", "description": "A check name to narrow to, e.g. 'cpu' or 'uptime' (optional)."},
                 runs={"type": "integer", "description": "How many runs to go back (default 30, at most 200)."}),
         device_history, lambda a: f"Reading {a.get('device', '')}'s history"),
    Tool("list_backups", "The stored configuration backups of a device: each version's id, time, size and how many lines changed.",
         _schema(device=DEVICE_ARG), list_backups, lambda a: f"Reading {a.get('device', '')}'s backup list"),
    Tool("read_backup", "The text of one configuration backup (passwords masked). Without a backup_id, the newest.",
         _schema(device=DEVICE_ARG, backup_id={"type": "integer", "description": "The version's id from list_backups (optional: the newest)."}),
         read_backup, lambda a: f"Reading {a.get('device', '')}'s backup" + (f" {a['backup_id']}" if a.get("backup_id") else "")),
    Tool("diff_backups", "What changed between two configuration backups of a device, as a unified diff (passwords masked).",
         _schema(device=DEVICE_ARG, older_id=({"type": "integer", "description": "The older version's id."}, True),
                 newer_id=({"type": "integer", "description": "The newer version's id."}, True)),
         diff_backups, lambda a: f"Comparing {a.get('device', '')}'s backups {a.get('older_id', '?')} and {a.get('newer_id', '?')}"),
    Tool("firmware_check", "The Firmware Transfer page's latest Check devices results in this organization: each device's software version, "
         "mode, free space, whether it reaches the image server, and why it was held back.",
         _schema(), firmware_check, lambda a: "Reading the Firmware Transfer check results"),
    Tool("audit_log", "Toner's audit log: who changed or did what, and when, newest first. Optionally only entries containing a word.",
         _schema(text={"type": "string", "description": "Only entries that mention this (optional)."},
                 limit={"type": "integer", "description": "How many entries (default 100, at most 500)."}),
         audit_log, lambda a: "Reading the audit log"),
    Tool("list_session_logs", "The logged terminal sessions (SSH, Telnet, Serial): when, which device, who, and how each ended. Newest first.",
         _schema(limit={"type": "integer", "description": "How many (default 100, at most 500)."}),
         list_session_logs, lambda a: "Reading the session log list"),
    Tool("read_session_log", "The text of one terminal session log: what the device printed (passwords are never in it).",
         _schema(session_id=({"type": "integer", "description": "The session's id from list_session_logs."}, True)),
         read_session_log, lambda a: f"Reading session log {a.get('session_id', '?')}"),
    Tool("whats_on_screen", "What the person is looking at in Toner right now: the section and page, the organization, what is selected, "
         "and the visible content (tables, output, a configuration). Use it when the question says 'this', 'here' or 'on screen'.",
         _schema(), _screen, lambda a: "Reading what is on screen"),
]
BY_NAME = {t.name: t for t in TOOLS}
WHAT_THEY_READ = ["the device list and each device's details", "the latest check results and each device's history",
                  "configuration backups (passwords masked) and what changed between versions", "the Firmware Transfer check results",
                  "the audit log", "terminal session logs", "what is on screen"]


def run(name, args, screen=None, values=None):
    """Run a tool and return its result as text for the model (JSON), masked. Unknown tools and failures come back as a message, so
    the model can say so instead of the turn failing."""
    tool = BY_NAME.get(name)
    if tool is None:
        return json.dumps({"error": f"There is no tool called {name}."})
    args = args if isinstance(args, dict) else {}
    audit.log("assistant", tool.audit(args))
    try:
        result = tool.fn(args, screen) if name == "whats_on_screen" else tool.fn(args)
    except ToolError as e:
        result = {"error": str(e)}
    except Exception as e:                                           # noqa: BLE001  (the model is told, the turn goes on)
        result = {"error": f"Toner could not read that: {type(e).__name__}: {e}"}
    return json.dumps(masked(result, values), ensure_ascii=False, default=str)

"""Organizations: each keeps its own devices, checks, results, sessions and settings in a file of its own (see db.py).

Global is the program's own file. It lists everything, holds the Global settings every organization starts from, and anything
marked Shared, which every organization sees. Settings > Organizations creates, renames, archives and removes them; the sidebar
switches between them. The pick is kept per computer."""
import re
import sqlite3
from datetime import datetime

import keyring

from core import db, quiet

GLOBAL = db.GLOBAL
SETTING = "org_current"
COLOURS = ["#2f6fed", "#1e9e6a", "#c2410c", "#7c3aed", "#0e7490", "#be185d", "#a16207", "#4d7c0f"]

# Tables whose rows belong to one device (by its name; UniFi sub-devices are 'controller / ap'), moved with it.
DEVICE_TABLES = ("counter_baseline", "alert_state", "diagnostics", "agent_reports", "agent_metrics", "agent_seen", "ssh_sessions")


def list_orgs(archived=True):
    """[{'id', 'name', 'code', 'colour', 'archived', 'created', 'uid'}] by name. 'uid' never changes (Demarc knows it by that)."""
    return [r for r in db.org_rows() if archived or not r["archived"]]


def get(org):
    return next((r for r in db.org_rows() if r["id"] == org), None)


def name(org):
    return db.org_name(org)


def current():
    """The organization picked in the sidebar (0 = Global; also when it has gone or been archived)."""
    with db.within(GLOBAL):
        org = db.get_setting(SETTING)
    try:
        org = int(org or 0)
    except (TypeError, ValueError):
        return GLOBAL
    row = get(org)
    return org if row and not row["archived"] else GLOBAL


def set_current(org):
    org = int(org or 0)
    with db.within(GLOBAL):
        db.set_setting(SETTING, org)
    db.set_home(org)


def start():
    """At startup: open the organization picked last time."""
    db.set_home(current())


# ---------------------------------------------------------------- create, rename, archive
def clean(name_, code, ignore=None):
    name_ = (name_ or "").strip()
    code = (code or "").strip().upper()
    if not name_:
        raise ValueError("An organization needs a name.")
    if name_.lower() in ("global", "shared"):
        raise ValueError(f"'{name_}' is used by Toner itself. Pick another name.")
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9_-]{0,11}", code):
        raise ValueError("The code is 1 to 12 letters, digits, - or _ (for example ACME).")
    for r in db.org_rows():
        if r["id"] == ignore:
            continue
        if r["name"].lower() == name_.lower():
            raise ValueError(f"An organization named '{name_}' already exists.")
        if r["code"].upper() == code:
            raise ValueError(f"The code {code} is already used by {r['name']}.")
    return name_, code


def suggest_code(name_):
    """'Acme Charter Schools' -> 'ACS'; 'Globex' -> 'GLOBEX'."""
    words = re.findall(r"[A-Za-z0-9]+", name_ or "")
    code = ("".join(w[0] for w in words) if len(words) > 1 else (words[0] if words else "ORG")).upper()[:12]
    taken, out, n = {r["code"].upper() for r in db.org_rows()}, code, 2
    while out in taken:
        out, n = f"{code[:10]}{n}", n + 1
    return out


def create(name_, code, colour=""):
    name_, code = clean(name_, code)
    colour = colour or COLOURS[len(db.org_rows()) % len(COLOURS)]
    with db.within(GLOBAL):
        with db.connect() as c:
            org = c.execute("INSERT INTO orgs(name, code, colour, archived, created, uid) VALUES(?,?,?,0,?,?)",
                            (name_, code, colour, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), db.new_uid())).lastrowid
    db.forget_orgs()
    with db.within(org):
        db.init()
    return org


def update(org, name_, code, colour):
    name_, code = clean(name_, code, ignore=org)
    with db.within(GLOBAL):
        with db.connect() as c:
            c.execute("UPDATE orgs SET name=?, code=?, colour=? WHERE id=?", (name_, code, colour or "", org))
    db.forget_orgs()


def set_archived(org, archived):
    with db.within(GLOBAL):
        with db.connect() as c:
            c.execute("UPDATE orgs SET archived=? WHERE id=?", (1 if archived else 0, org))
    db.forget_orgs()
    if archived and db.home() == org:
        set_current(GLOBAL)


def counts(org):
    """{'devices', 'sessions'} in one organization's own file."""
    with db.within(org):
        with db.connect() as c:
            return {"devices": c.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
                    "sessions": c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]}


# ---------------------------------------------------------------- moving devices between organizations
def _like(name_):
    return name_.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + " / %"


def _rows(c, table, where, args):
    return [dict(r) for r in c.execute(f"SELECT * FROM {table} WHERE {where}", args)]


def _insert(c, table, row):
    row = {k: v for k, v in row.items() if k != "id"}
    cols = list(row)
    return c.execute(f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", [row[k] for k in cols]).lastrowid


def _secret(name_):
    try:
        return keyring.get_password(db.SERVICE, name_)
    except Exception:
        return None


def _move_secret(src_org, dst_org, plain):
    """Move one vault entry from one organization's names to another's."""
    with db.within(src_org):
        old = db.qualify(plain)
    with db.within(dst_org):
        new = db.qualify(plain)
    if old == new:
        return
    value = _secret(old)
    if value:
        db.set_secret(new, value)
        db.delete_secret(old)


def clashes(devices, dst):
    """The names among `devices` that are already used in organization `dst` (or by a Shared device)."""
    out = []
    for d in devices:
        if d.get("org") == dst:
            continue
        if db.name_clash(d["name"], dst, shared=False):
            out.append(d["name"])
    return out


def move_devices(devices, dst, with_data=True):
    """Move devices (dicts from db.list_devices, with 'org') into organization `dst`. Their folder path, credential profile and
    stored passwords go with them; with_data also moves their results, config backups, saved sessions, agent reports and alert
    state. Raises ValueError, before changing anything, when a name is already used there. Returns how many moved."""
    devices = [d for d in devices if d.get("org", db.target()) != dst]
    taken = clashes(devices, dst)
    if taken:
        where = db.org_name(dst)
        raise ValueError("\n".join(f"A device named {n} already exists in {where}." for n in taken))
    by_src = {}
    for d in devices:
        by_src.setdefault(d.get("org", db.target()), []).append(d)
    for src, devs in by_src.items():
        _move_from(src, dst, devs, with_data)
    return len(devices)


def _move_from(src, dst, devs, with_data):
    with db.within(src):
        paths = db.folder_paths()
        with db.connect() as c:
            profiles = {r["id"]: dict(r) for r in c.execute("SELECT * FROM profiles")}
    for d in devs:
        with db.within(src):
            row = db.get_device(d["id"])
        if not row:
            continue
        folder = paths.get(row.get("folder_id"))
        with db.within(dst):
            new = {k: row.get(k) for k in db.DEVICE_FIELDS}
            new["shared"] = 0
            new["folder_id"] = db.ensure_folder_path(folder) if folder else None
            new["profile_id"] = _profile_in(src, dst, row.get("profile_id"), profiles)
            db.save_device(new)
        for kind in db.SECRET_KINDS:
            _move_secret(src, dst, row["name"] + db.SECRET_KINDS[kind])
        if with_data:
            _move_data(src, dst, row["name"])
        else:                                                  # its agent's token goes with it, so the agent keeps reporting
            with db.within(src), db.connect() as c:
                token = _rows(c, "agent_reports", "device=?", (row["name"],))
                c.execute("DELETE FROM agent_reports WHERE device=?", (row["name"],))
            with db.within(dst), db.connect() as c:
                for r in token:
                    c.execute("DELETE FROM agent_reports WHERE device=?", (r["device"],))
                    _insert(c, "agent_reports", r)
        with db.within(src):                                   # without its data, its history stays in the old organization's file
            db.delete_device(row["id"])


def _profile_in(src, dst, pid, known):
    """What a moved device's profile_id becomes in `dst`: a Shared profile stays shared (its id is negative outside Global), anything
    else is copied over (see _copy_profile)."""
    if not pid:
        return None
    if pid < 0:                                            # Global's Shared profile, used from an organization
        return -pid if dst == GLOBAL else pid
    prof = known.get(pid)
    if src == GLOBAL and prof and prof.get("shared") and dst != GLOBAL:
        return -pid
    return _copy_profile(src, dst, prof)


def _copy_profile(src, dst, prof):
    """The id in `dst` of a profile with the same name (copied there, with its passwords, when it is missing)."""
    if not prof:
        return None
    with db.within(dst):
        with db.connect() as c:
            row = c.execute("SELECT id FROM profiles WHERE name=? COLLATE NOCASE", (prof["name"],)).fetchone()
            if row:
                return row["id"]
            pid = _insert(c, "profiles", {**prof, "shared": 0})
    for kind in db.SECRET_KINDS:
        plain = f"profile:{prof['name']}" + db.SECRET_KINDS[kind]
        with db.within(src):
            value = _secret(db.qualify(plain))
        if value:
            with db.within(dst):
                db.set_secret(db.qualify(plain), value)
    return pid


def _move_data(src, dst, dev_name):
    where, args = "device=? OR device LIKE ? ESCAPE '\\'", (dev_name, _like(dev_name))
    with db.within(src):
        with db.connect() as c:
            data = {t: _rows(c, t, where, args) for t in DEVICE_TABLES}
            backups = _rows(c, "config_backups", "device=?", (dev_name,))
            blog = _rows(c, "backup_log", "device=?", (dev_name,))
            results = _rows(c, "results", where, args)
            runs = {r["id"]: dict(r) for r in c.execute("SELECT * FROM runs WHERE id IN (SELECT DISTINCT run_id FROM results WHERE "
                                                         + where + ")", args)}
            sessions = _rows(c, "sessions", "device=?", (dev_name,))
            spaths = _session_paths(c)
    with db.within(dst):
        with db.connect() as c:
            for t, rows in data.items():
                for r in rows:
                    if t in ("agent_reports", "agent_seen"):
                        c.execute(f"DELETE FROM {t} WHERE device=?", (r["device"],))
                    if t in ("counter_baseline", "alert_state"):
                        c.execute(f"DELETE FROM {t} WHERE device=? AND " + ("key=?" if t == "counter_baseline" else "check_name=?"),
                                  (r["device"], r["key"] if t == "counter_baseline" else r["check_name"]))
                    _insert(c, t, r)
            ids = {r["id"]: _insert(c, "config_backups", r) for r in backups}
            for r in blog:
                _insert(c, "backup_log", {**r, "backup_id": ids.get(r.get("backup_id"))})
            new_run = {}
            for rid, run in runs.items():
                mine = [r for r in results if r["run_id"] == rid]
                count = lambda s: sum(1 for r in mine if r["status"] == s)
                new_run[rid] = _insert(c, "runs", {"started_at": run["started_at"], "ok": count("OK"), "warn": count("WARN"),
                                                   "fail": count("FAIL"), "error": count("ERROR")})
            for r in results:
                _insert(c, "results", {**r, "run_id": new_run[r["run_id"]]})
    moved_sessions = []
    for s in sessions:
        path = spaths.get(s.get("folder_id"))
        from core import sessions as S
        with db.within(dst):
            fid = S.ensure_folder_path(path) if path else None
            with db.connect() as c:
                new_id = _insert(c, "sessions", {**s, "folder_id": fid, "shared": 0})
        moved_sessions.append((s["id"], new_id))
    for old_id, new_id in moved_sessions:
        with db.within(src):
            old = db.qualify(f"session:{old_id}")
        with db.within(dst):
            new = db.qualify(f"session:{new_id}")
        value = _secret(old)
        if value:
            db.set_secret(new, value)
            db.delete_secret(old)
    with db.within(src):
        with db.connect() as c:
            for t in DEVICE_TABLES:
                c.execute(f"DELETE FROM {t} WHERE {where}", args)
            c.execute("DELETE FROM backup_log WHERE device=?", (dev_name,))
            c.execute("DELETE FROM config_backups WHERE device=?", (dev_name,))
            c.execute(f"DELETE FROM results WHERE {where}", args)
            c.execute(f"DELETE FROM numeric_checks WHERE {where}", args)      # (the new file's list fills itself as the results go in)
            for rid in runs:                                   # what is left of each run is counted again; an empty one goes
                left = [r["status"] for r in c.execute("SELECT status FROM results WHERE run_id=?", (rid,))]
                if left:
                    c.execute("UPDATE runs SET ok=?, warn=?, fail=?, error=? WHERE id=?",
                              (left.count("OK"), left.count("WARN"), left.count("FAIL"), left.count("ERROR"), rid))
                else:
                    c.execute("DELETE FROM runs WHERE id=?", (rid,))
            for old_id, _new in moved_sessions:
                c.execute("DELETE FROM sessions WHERE id=?", (old_id,))
    db.forget_history()                                    # results left this file without a new run


def _session_paths(c):
    rows = {r["id"]: dict(r) for r in c.execute("SELECT id, name, parent_id FROM session_folders")}
    out = {}
    for fid in rows:
        parts, cur, seen = [], fid, set()
        while cur in rows and cur not in seen:
            seen.add(cur)
            parts.append(rows[cur]["name"])
            cur = rows[cur]["parent_id"]
        out[fid] = "/".join(reversed(parts))
    return out


# ---------------------------------------------------------------- removing an organization
def remove(org, move_to=None):
    """Remove an organization. With move_to, its devices (with their data), sessions, credential profiles, custom checks and
    maintenance windows go to that organization first; without, they are deleted. Its file and its passwords go."""
    if not org:
        raise ValueError("Global cannot be removed.")
    if move_to is not None and move_to == org:
        raise ValueError("Pick another organization to move them to.")
    with db.within(org):
        devices = [d for d in db.list_devices() if d["org"] == org]
    if move_to is not None:
        move_devices(devices, move_to, with_data=True)
        _move_rest(org, move_to)
    _forget_secrets(org)
    with db.within(GLOBAL):
        with db.connect() as c:
            c.execute("DELETE FROM orgs WHERE id=?", (org,))
    db.forget_orgs()
    if db.home() == org:
        set_current(GLOBAL)
    path = db.org_path(org)
    db._forget_settings()
    import gc
    gc.collect()                                           # a connection still waiting to be collected keeps the file open on Windows
    for p in (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")):
        try:
            p.unlink(missing_ok=True)
        except OSError:
            quiet.ignored()


def _move_rest(src, dst):
    """Sessions not tied to a device, profiles, custom checks, maintenance windows and the audit log, after the devices moved."""
    from core import sessions as S
    with db.within(src):
        with db.connect() as c:
            sessions = _rows(c, "sessions", "1=1", ())
            spaths = _session_paths(c)
            profiles = _rows(c, "profiles", "1=1", ())
            checks = _rows(c, "custom_checks", "1=1", ())
            windows = _rows(c, "maintenance", "1=1", ())
            audit = _rows(c, "audit", "1=1", ())
    for p in profiles:
        _copy_profile(src, dst, p)
    with db.within(dst):
        with db.connect() as c:
            have = {r[0].lower() for r in c.execute("SELECT name FROM custom_checks")}
            for chk in checks:
                n, i = chk["name"], 2
                while n.lower() in have:
                    n, i = f"{chk['name']} ({i})", i + 1
                have.add(n.lower())
                _insert(c, "custom_checks", {**chk, "name": n, "shared": 0})
            for w in windows:
                _insert(c, "maintenance", {**w, "shared": 0})
            for a in audit:
                _insert(c, "audit", a)
    for s in sessions:
        path = spaths.get(s.get("folder_id"))
        with db.within(dst):
            fid = S.ensure_folder_path(path) if path else None
            with db.connect() as c:
                taken = c.execute("SELECT 1 FROM sessions WHERE name=? COLLATE NOCASE AND folder_id IS ?", (s["name"], fid)).fetchone()
                new_id = _insert(c, "sessions", {**s, "folder_id": fid, "shared": 0,
                                                 "name": f"{s['name']} (2)" if taken else s["name"]})
        with db.within(src):
            old = db.qualify(f"session:{s['id']}")
        with db.within(dst):
            new = db.qualify(f"session:{new_id}")
        value = _secret(old)
        if value:
            db.set_secret(new, value)
            db.delete_secret(old)


def _forget_secrets(org):
    """Every vault entry of the organization's devices, profiles and sessions, and its agent sign-up key."""
    with db.within(org):
        db.delete_secret(db.qualify("service:agent-enroll"))     # (agents.ENROLL_SECRET) its packages stop signing computers up
    try:
        with db.within(org):
            with db.connect() as c:
                names = [r[0] for r in c.execute("SELECT name FROM devices")]
                profs = [r[0] for r in c.execute("SELECT name FROM profiles")]
                sess = [r[0] for r in c.execute("SELECT id FROM sessions")]
            for n in names:
                db.delete_device_secrets(n)
            for p in profs:
                db.delete_device_secrets(f"profile:{p}")
            for s in sess:
                db.delete_secret(db.qualify(f"session:{s}"))
    except sqlite3.Error:
        quiet.ignored()

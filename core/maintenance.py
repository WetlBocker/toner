"""Maintenance windows: planned work during which a device's problems are not announced.

A window is either `once` (from start_at to end_at) or `weekly` (on chosen weekdays between start_time and end_time;
a window may run past midnight). Its scope uses the same group labels as everything else; no scope means every device.
Checks still run and are still recorded during a window. Only notifications are held back, and the alert state is left
as it was, so afterwards a problem that is still there is announced once and a fixed one is reported as recovered.
"""
import json
from datetime import datetime, timedelta

from core import db

DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
_DT, _T = "%Y-%m-%d %H:%M", "%H:%M"
FIELDS = ["name", "kind", "start_at", "end_at", "days", "start_time", "end_time", "scope", "enabled", "note"]


def _windows_here():
    with db.connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM maintenance ORDER BY name COLLATE NOCASE")]


def list_windows():
    """The organization's windows plus Global's Shared ones (each with 'org')."""
    rows = db.gather_own(_windows_here)
    for r in rows:
        for k in ("days", "scope"):
            try:
                r[k] = json.loads(r[k] or "[]")
            except ValueError:
                r[k] = []
    return rows


def listing():
    """For Settings > Maintenance: in Global every organization's windows, in an organization its own and the Shared ones."""
    rows = db.listing(_windows_here)
    for r in rows:
        for k in ("days", "scope"):
            try:
                r[k] = json.loads(r[k] or "[]")
            except ValueError:
                r[k] = []
    return rows


def validate(w):
    name = (w.get("name") or "").strip()
    if not name:
        raise ValueError("The window needs a name.")
    if w.get("kind") == "weekly":
        if not [d for d in w.get("days") or [] if d in range(7)]:
            raise ValueError("Choose at least one day of the week.")
        try:
            a, b = (datetime.strptime(w.get(k) or "", _T) for k in ("start_time", "end_time"))
        except ValueError:
            raise ValueError("Enter the start and end times as HH:MM, for example 22:00.") from None
        if a == b:
            raise ValueError("The start and end times are the same.")
    elif w.get("kind") == "once":
        try:
            a, b = (datetime.strptime(w.get(k) or "", _DT) for k in ("start_at", "end_at"))
        except ValueError:
            raise ValueError("Enter the start and end as YYYY-MM-DD HH:MM.") from None
        if b <= a:
            raise ValueError("The window must end after it starts.")
    else:
        raise ValueError("Choose a one-off or a weekly window.")
    return name


def save_window(w):
    name = validate(w)
    row = {k: w.get(k) for k in FIELDS}
    row.update(name=name, days=json.dumps(sorted(set(w.get("days") or []))), scope=json.dumps(w.get("scope") or []),
               enabled=int(bool(w.get("enabled", 1))), note=w.get("note") or "")
    with db.within(w.get("org")), db.connect() as c:
        cols, vals = FIELDS + ["shared"], [row[k] for k in FIELDS] + [1 if w.get("shared") and db.target() == db.GLOBAL else 0]
        if w.get("id"):
            c.execute("UPDATE maintenance SET " + ", ".join(f"{k}=?" for k in cols) + " WHERE id=?", vals + [w["id"]])
            return w["id"]
        return c.execute(f"INSERT INTO maintenance ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals).lastrowid


def delete_window(wid, org=None):
    with db.within(org), db.connect() as c:
        c.execute("DELETE FROM maintenance WHERE id=?", (wid,))


def is_active(w, now=None):
    now = now or datetime.now()
    if not w.get("enabled", 1):
        return False
    try:
        if w["kind"] == "once":
            return datetime.strptime(w["start_at"], _DT) <= now < datetime.strptime(w["end_at"], _DT)
        a, b = (datetime.strptime(w[k], _T).time() for k in ("start_time", "end_time"))
    except (ValueError, KeyError, TypeError):
        return False
    t, today, yesterday = now.time(), now.weekday(), (now.weekday() - 1) % 7
    days = w.get("days") or []
    if a < b:
        return today in days and a <= t < b
    return (today in days and t >= a) or (yesterday in days and t < b)          # runs past midnight


def active_windows(now=None, windows=None):
    return [w for w in (list_windows() if windows is None else windows) if is_active(w, now)]


def window_for(dev, now=None, windows=None):
    """The active window that covers this device, or None."""
    for w in active_windows(now, windows):
        if db.in_groups(dev, w.get("scope") or []):
            return w
    return None


def devices_in_maintenance(now=None):
    """{device key: window} for every device covered by an active window right now (each organization's windows cover its devices)."""
    if not db.everything():
        return _held_here(now)
    out = {}
    for org, _only in db._each_file():
        with db.within(org):
            part = _held_here(now)
        out.update({db.dkey(name, org): w for name, w in part.items()})
    return out


def _held_here(now=None):
    wins = active_windows(now)
    if not wins:
        return {}
    out = {}
    for d in db.list_devices():
        for w in wins:
            if db.in_groups(d, w.get("scope") or []):
                out[d["name"]] = w
                break
    return out


def describe(w):
    if w["kind"] == "once":
        return f"{w['start_at']} to {w['end_at']}"
    days = [DAYS[d] for d in w.get("days") or []]
    spans = "every day" if len(days) == 7 else ", ".join(days)
    return f"{spans} {w['start_time']}-{w['end_time']}"


def ends_at(w, now=None):
    """When an active window ends (for 'until 02:00' messages); None if it is not active."""
    now = now or datetime.now()
    if not is_active(w, now):
        return None
    if w["kind"] == "once":
        return datetime.strptime(w["end_at"], _DT)
    end = datetime.strptime(w["end_time"], _T).time()
    day = now.date() if now.time() < end else now.date() + timedelta(days=1)
    return datetime.combine(day, end)

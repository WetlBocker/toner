"""The devices a UniFi console reports (APs, switches and the like), listed under the console's entry in the Inventory, each with a page of
its own. They are views of the console's own results ('console / device' rows): no polling, credentials or schedule of their own.

The only thing kept beyond those results is unifi_seen: per device id (MAC when there is none), its latest name and model and when it was
first and last seen. A device the console stops reporting stays listed, greyed, with its history, until it is removed (forget), which
drops that bookkeeping row and nothing else."""
from core import db, display

KINDS = ("unifi", "unifi_network", "unifi_cloud")    # consoles by login or Network API key, and Site Manager entries scoped to a site
WORST = {"ERROR": 0, "FAIL": 1, "WARN": 2}


def note(c, results, now):
    """db.save_run, in its transaction: each row a driver marked with its device's key (Result.kid) is a sighting of that device, and so
    is each device a row carries in Result.seen (listed by the console, with no row of its own)."""
    seen = {}
    for r in results:
        parent, _, label = (r.device or "").partition(" / ")
        kid = getattr(r, "kid", None)
        for name, k in ([(label, kid)] if kid and label else []) + list(getattr(r, "seen", None) or []):
            seen[(parent, str(k[0]))] = (name, k[1] or "")
    if seen:
        c.executemany("INSERT INTO unifi_seen(device, key, label, model, first_seen, last_seen) VALUES(?,?,?,?,?,?) "
                      "ON CONFLICT(device, key) DO UPDATE SET label=excluded.label, model=excluded.model, last_seen=excluded.last_seen",
                      [(p, k, label, model, now, now) for (p, k), (label, model) in seen.items()])
        # a name this run reported under another key (the console is now read another way: an id then, a MAC now) is listed once
        for parent in {p for p, _k in seen}:
            keys, names = {k for p, k in seen if p == parent}, {v[0] for (p, _k), v in seen.items() if p == parent}
            c.executemany("DELETE FROM unifi_seen WHERE device=? AND key=?",
                          [(parent, r["key"]) for r in c.execute("SELECT key, label FROM unifi_seen WHERE device=?", (parent,)).fetchall()
                           if r["label"] in names and r["key"] not in keys])


def _seen(dev):
    if dev.get("vendor") not in KINDS:
        return []
    with db.within(dev.get("org")), db.connect() as c:
        return [dict(r) for r in c.execute("SELECT key, label, model, first_seen, last_seen FROM unifi_seen WHERE device=?", (dev["name"],))]


def has_children(dev):
    if dev.get("vendor") not in KINDS:
        return False
    with db.within(dev.get("org")), db.connect() as c:
        return c.execute("SELECT 1 FROM unifi_seen WHERE device=? LIMIT 1", (dev["name"],)).fetchone() is not None


def labels(dev):
    """The names its devices' rows are stored under ('console / <label>'), so the console's own page can leave them out."""
    return {r["label"] for r in _seen(dev)}


def children(dev):
    """[{'key', 'name', 'model', 'first_seen', 'last_seen', 'gone', 'status'}], worst status first and gone ones last. Gone: not in the
    newest run that reported any of its devices (a run that could not read the console marks nothing gone). Status is '' for a
    device the console's newest run did not report (the console could not be read): how it is now is not known."""
    seen = _seen(dev)
    if not seen:
        return []
    newest = max(r["last_seen"] for r in seen)
    with db.within(dev.get("org")):
        latest, _at = db._latest_results_here()
    worst, ran = {}, ""
    for r in latest:
        parent, _, label = (r["device"] or "").partition(" / ")
        if parent == dev["name"]:
            ran = max(ran, r["at"] or "")
        if parent == dev["name"] and label and WORST.get(r["status"], 9) < WORST.get(worst.get(label), 9):
            worst[label] = r["status"]
    out = [{"key": r["key"], "name": r["label"], "model": r["model"] or "", "first_seen": r["first_seen"], "last_seen": r["last_seen"],
            "gone": r["last_seen"] < newest, "status": worst.get(r["label"], "OK") if r["last_seen"] >= ran else ""} for r in seen]
    out.sort(key=lambda k: (k["gone"], WORST.get(k["status"], 9), k["name"].lower()))
    return out


def rows_for(dev, key):
    """That device's latest rows (from the last run that reported it, so a gone device keeps its last readings), as result dicts with 'at'."""
    with db.within(dev.get("org")), db.connect() as c:
        r = c.execute("SELECT label FROM unifi_seen WHERE device=? AND key=?", (dev["name"], key)).fetchone()
        if not r:
            return []
        name = f"{dev['name']} / {r['label']}"
        rid = c.execute("SELECT MAX(run_id) FROM results WHERE device=? AND check_name != 'config backup'", (name,)).fetchone()[0]
        if rid is None:
            return []
        at = c.execute("SELECT started_at FROM runs WHERE id=?", (rid,)).fetchone()
        return [{**dict(x), "at": at[0] if at else ""} for x in c.execute(
            "SELECT device, check_name, status, value, message, numeric FROM results WHERE run_id=? AND device=? ORDER BY rowid", (rid, name))]


def forget(dev, key=None):
    """Remove: the device is no longer listed (until the console reports it again). Its history rows stay. No key: every device of
    a console that is deleted."""
    with db.within(dev.get("org")), db.connect() as c:
        c.execute("DELETE FROM unifi_seen WHERE device=?" + (" AND key=?" if key is not None else ""),
                  (dev["name"], key) if key is not None else (dev["name"],))


def rename(old, new):
    """A console renamed in the Inventory keeps its devices' first and last seen (in the file being written to)."""
    with db.connect() as c:
        c.execute("DELETE FROM unifi_seen WHERE device=?", (new,))          # rows left by a console that once had the new name
        c.execute("UPDATE unifi_seen SET device=? WHERE device=?", (new, old))


def shown_name(kid):
    """Its name, or '{name} (not seen since {date})' once the console no longer reports it."""
    return f"{kid['name']} (not seen since {display.read_on(kid['last_seen']).split(' at ')[0]})" if kid["gone"] else kid["name"]

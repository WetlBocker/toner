"""Decide WHAT to tell people: compare each run with the last known state and report only the changes.

A check that keeps failing is announced once (and optionally re-announced as a reminder), not on
every run. A check that gets worse is announced again. A check that comes back is announced as
recovered. Nothing here sends anything; see core/notify.py for delivery.
"""
from dataclasses import dataclass
from datetime import datetime

from core import db
from drivers.base import SEVERITY

_FMT = "%Y-%m-%d %H:%M:%S"
NO_RECOVERY = {"config backup", "changes"}          # a changed configuration is news, not a fault that gets fixed


@dataclass
class Event:
    kind: str          # "new" | "worse" | "reminder" | "recovered"
    device: str
    check: str
    status: str        # status now ("OK" for a recovery)
    prev: str          # status before ("OK" for a new problem)
    value: str = ""
    message: str = ""
    since: str = ""    # when the problem first appeared

    @property
    def severity(self):
        """How serious this event is, for per-channel filtering. A recovery counts as what it recovered from."""
        return SEVERITY[self.prev if self.kind == "recovered" else self.status]


def base(device):
    """UniFi rows are 'controller / device'; the inventory name is the first part."""
    return (device or "").split(" / ")[0]


def evaluate(results, ran, consecutive=1, remind_hours=0, now=None):
    """Compare `results` (from devices named in `ran`) with the stored state; return the events to announce
    and update the state. Devices that did not run in this pass are left exactly as they were."""
    now = now or datetime.now()
    stamp = now.strftime(_FMT)
    ran = set(ran)
    inventory = {d["name"] for d in db.list_devices()}
    events, upserts, deletes = [], [], []

    with db.connect() as c:
        rows = {(r["device"], r["check_name"]): dict(r) for r in c.execute("SELECT * FROM alert_state")}
        for key, row in rows.items():                         # forget devices that left the inventory
            if base(key[0]) not in inventory:
                deletes.append(key)
        seen = set()
        for r in results:
            key = (r.device, r.check)
            seen.add(key)
            prev = rows.get(key)
            sev = SEVERITY[r.status]
            if sev == 0:                                      # healthy now
                if prev and prev["notified_sev"] > 0 and r.check not in NO_RECOVERY:
                    events.append(Event("recovered", r.device, r.check, "OK", prev["status"], r.value, "",
                                        prev["since"] or ""))
                if prev:
                    deletes.append(key)
                continue
            streak = prev["streak"] + 1 if prev else 1
            since = prev["since"] if prev and prev["since"] else stamp
            notified, last = (prev["notified_sev"], prev["last_notified"]) if prev else (0, None)
            kind = None
            if streak >= max(1, consecutive):
                if notified == 0:
                    kind = "new"
                elif sev > notified:
                    kind = "worse"
                elif remind_hours and last and (now - datetime.strptime(last, _FMT)).total_seconds() \
                        >= remind_hours * 3600:
                    kind = "reminder"
            if kind:
                events.append(Event(kind, r.device, r.check, r.status, prev["status"] if prev else "OK",
                                    r.value, r.message, since))
                notified, last = sev, stamp
            elif notified and sev < notified:
                notified = sev                                # improved but still a problem: re-arm
            upserts.append((r.device, r.check, r.status, streak, notified, since, last))

        for key, row in rows.items():                         # a device ran but this check is gone
            if key not in seen and base(key[0]) in ran:
                if row["notified_sev"] > 0 and key[1] not in NO_RECOVERY:
                    events.append(Event("recovered", key[0], key[1], "OK", row["status"], "", "no longer reported",
                                        row["since"] or ""))
                deletes.append(key)

        c.executemany("DELETE FROM alert_state WHERE device=? AND check_name=?", deletes)
        c.executemany("INSERT INTO alert_state(device, check_name, status, streak, notified_sev, since, "
                      "last_notified) VALUES(?,?,?,?,?,?,?) ON CONFLICT(device, check_name) DO UPDATE SET "
                      "status=excluded.status, streak=excluded.streak, notified_sev=excluded.notified_sev, "
                      "since=excluded.since, last_notified=excluded.last_notified", upserts)
    return events


def unmark(events):
    """Delivery failed everywhere: forget that these were announced so the next run tries again."""
    with db.connect() as c:
        for e in events:
            if e.kind == "new":
                c.execute("UPDATE alert_state SET notified_sev=0, last_notified=NULL "
                          "WHERE device=? AND check_name=?", (e.device, e.check))
            elif e.kind == "worse":
                c.execute("UPDATE alert_state SET notified_sev=?, last_notified=NULL "
                          "WHERE device=? AND check_name=?", (SEVERITY.get(e.prev, 0), e.device, e.check))
            elif e.kind == "reminder":                     # due again on the next run
                c.execute("UPDATE alert_state SET last_notified=since WHERE device=? AND check_name=?",
                          (e.device, e.check))


def log_delivery(channel, ok, events, detail):
    with db.connect() as c:
        c.execute("INSERT INTO notify_log(at, channel, ok, events, detail) VALUES(?,?,?,?,?)",
                  (datetime.now().strftime(_FMT), channel, int(ok), events, detail[:500]))
        c.execute("DELETE FROM notify_log WHERE id NOT IN (SELECT id FROM notify_log ORDER BY id DESC LIMIT 500)")


def recent_deliveries(limit=30):
    with db.connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM notify_log ORDER BY id DESC LIMIT ?", (limit,))]

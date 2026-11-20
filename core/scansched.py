"""Scans on a schedule (Settings > Scanning > Scan automatically). The window runs it on the Scanning page's own worker, the
service through run_scheduled_scan; either way only the process that owns the schedule (service.owns_schedule)."""
from datetime import datetime

from core import advisories, audit, db, periods, service


def scan_due(now=None):
    with db.within(db.GLOBAL):                       # one schedule and one clock for every organization (Settings > Scanning is Global's)
        return periods.is_due(db.get_setting("scan_schedule"), db.get_setting("scan_last"), now)


def begin(now=None, who=None):
    """Remember the scan now (before its network work: a source that fails must not make it start again each minute), write the
    audit line, and return the devices to scan: the enabled ones in the chosen groups of Global (its own and Shared) and of every
    organization that is not archived ([] when those groups exist nowhere)."""
    with db.within(db.GLOBAL):
        db.set_setting("scan_last", (now or datetime.now()).strftime(periods.FMT))
        groups = db.get_setting("scan_groups")
    devices = []
    for org in [db.GLOBAL] + [o["id"] for o in db.org_rows() if not o["archived"]]:
        with db.within(org):
            alive = service._groups_alive(groups)
            devices += [] if alive is None else service.own_devices(alive)
    if devices:
        with db.within(db.GLOBAL):
            audit.log("scan", f"{len(devices)} device(s)" + (f" ({who})" if who else ""), who=who)
    return devices


def scan(devices):
    """Scan these devices and save each row in its device's organization's file (save_scan routes them, as save_run does)."""
    rows = advisories.scan_all(devices)
    if rows:
        with db.within(db.GLOBAL):
            db.save_scan(rows)
    return rows


def run_scheduled_scan(now=None):
    """The service's scan, all of it. Returns the rows."""
    return scan(begin(now, who="service"))

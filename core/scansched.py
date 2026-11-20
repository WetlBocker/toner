"""Scans on a schedule (Settings > Scanning > Scan automatically). The window runs it on the Scanning page's own worker, the
service through run_scheduled_scan; either way only the process that owns the schedule (service.owns_schedule)."""
from datetime import datetime

from core import advisories, audit, db, periods, service


def scan_due(now=None):
    return periods.is_due(db.get_setting("scan_schedule"), db.get_setting("scan_last"), now)


def begin(now=None, who=None):
    """Remember the scan now (before its network work: a source that fails must not make it start again each minute), write the
    audit line, and return the devices to scan: the enabled ones in the chosen groups ([] when those groups have all gone)."""
    db.set_setting("scan_last", (now or datetime.now()).strftime(periods.FMT))
    groups = service._groups_alive(db.get_setting("scan_groups"))
    devices = [] if groups is None else service.own_devices(groups)
    if devices:
        audit.log("scan", f"{len(devices)} device(s)" + (f" ({who})" if who else ""), who=who)
    return devices


def run_scheduled_scan(now=None):
    """The service's scan: saved like one made on the Scanning page. Returns the rows."""
    rows = advisories.scan_all(begin(now, who="service"))
    if rows:
        db.save_scan(rows)
    return rows

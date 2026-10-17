"""A summary of the Windows computers (and every device's certificates) for the Overview, from the stored results."""
from core import db

def _latest():
    """The rows (device, check, status, value, message) of the newest run that included each device, in every file of the view
    (device labels are keys, see db.dkey)."""
    rows, _at = db.latest_results()
    return [{"device": r["device"], "check": r["check_name"], "status": r["status"], "value": r["value"] or "", "message": r["message"] or ""}
            for r in rows]


# the groups the Overview shows, and their headings
SECTIONS = [("silent", "Not reporting"), ("reboot", "Waiting for a reboot"), ("disks", "Disks filling up"),
            ("certs", "Certificates running out"), ("patches", "Behind on updates"), ("changes", "Changed since the last check")]


def summary():
    """{'computers': n, 'by': {'agent': n, ...}, 'sections': {key: [(device, text)]}} or None when there are no Windows computers."""
    from core import winmon
    every = db.list_devices()
    wins = [d for d in every if d["vendor"] == "windows" and d["enabled"]]
    names = {d["key"] for d in every}
    by = {}
    for d in wins:
        by[winmon.transport(d)] = by.get(winmon.transport(d), 0) + 1
    sections = {k: [] for k, _ in SECTIONS}
    win_names = {d["key"] for d in wins}
    for r in _latest():
        key, check, status = r["device"], r["check"], r["status"]
        is_win, dev = key in win_names, db.label_org(key)
        if check.startswith("certificate") and key in names and status in ("WARN", "FAIL", "ERROR") and r["value"] != "no certificate":
            sections["certs"].append((dev, f"{r['value']}: {r['message']}" if r["message"] else r["value"]))
        if not is_win:
            continue
        if check == "reachability" and status in ("WARN", "FAIL") and "report" in (r["value"] + r["message"]):
            sections["silent"].append((dev, r["value"]))
        elif check == "pending reboot" and r["value"] == "yes":
            sections["reboot"].append((dev, r["message"] or "reboot pending"))
        elif check == "disks" and status in ("WARN", "FAIL"):
            sections["disks"].append((dev, r["value"] + (f" ({r['message'].split(';')[0]})" if r["message"] else "")))
        elif check == "patches" and status in ("WARN", "FAIL"):
            sections["patches"].append((dev, r["value"]))
        elif check == "changes" and status == "WARN":
            sections["changes"].append((dev, r["message"]))
    if not wins and not sections["certs"]:
        return None
    return {"computers": len(wins), "by": by, "sections": sections}

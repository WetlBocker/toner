"""A summary of the Windows computers (and every device's certificates) for the Overview, from the stored results."""
from core import db

def _latest():
    """The rows (device, check, status, value, message) of the newest run that included each device."""
    out = []
    with db.connect() as c:
        newest = {}
        for r in c.execute("SELECT device, MAX(run_id) rid FROM results WHERE check_name != 'config backup' GROUP BY device"):
            b = (r["device"] or "").split(" / ")[0]
            newest[b] = max(newest.get(b, 0), r["rid"])
        runs = {}
        for b, rid in newest.items():
            runs.setdefault(rid, set()).add(b)
        for rid, bases in runs.items():
            for r in c.execute("SELECT device, check_name, status, value, message FROM results WHERE run_id=?", (rid,)):
                if (r["device"] or "").split(" / ")[0] in bases and r["check_name"] != "config backup":
                    out.append({"device": r["device"], "check": r["check_name"], "status": r["status"], "value": r["value"] or "",
                                "message": r["message"] or ""})
    return out


# the groups the Overview shows, and their headings
SECTIONS = [("silent", "Not reporting"), ("reboot", "Waiting for a reboot"), ("disks", "Disks filling up"),
            ("certs", "Certificates running out"), ("patches", "Behind on updates"), ("changes", "Changed since the last check")]


def summary():
    """{'computers': n, 'by': {'agent': n, ...}, 'sections': {key: [(device, text)]}} or None when there are no Windows computers."""
    from core import winmon
    wins = [d for d in db.list_devices() if d["vendor"] == "windows" and d["enabled"]]
    names = {d["name"] for d in db.list_devices()}
    by = {}
    for d in wins:
        by[winmon.transport(d)] = by.get(winmon.transport(d), 0) + 1
    sections = {k: [] for k, _ in SECTIONS}
    win_names = {d["name"] for d in wins}
    for r in _latest():
        dev, check, status = r["device"], r["check"], r["status"]
        is_win = dev in win_names
        if check.startswith("certificate") and dev in names and status in ("WARN", "FAIL", "ERROR") and r["value"] != "no certificate":
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

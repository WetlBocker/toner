"""Running Toner without a window: scheduled checks and backups, alerts, and a Prometheus metrics endpoint.
Used by cli.py (for Task Scheduler or a Windows service wrapper); the desktop app has its own timers."""
import http.server
import threading
import time
from datetime import datetime, timedelta

from core import alerts, audit, backup, db, notify
from core.runner import run_all
from drivers.base import SEVERITY


def _groups_alive(groups):
    """Saved groups that still exist; None means they were chosen but all gone (so do nothing)."""
    alive = [g for g in groups if g in db.group_labels()]
    return None if groups and not alive else alive


def run_checks(groups=None, do_notify=True, scheduled=True, on_result=None):
    """Check every enabled device in the groups. Saves the run, then alerts like the desktop app does.
    Returns the list of Results (empty when there is nothing to check)."""
    groups = list(groups or [])
    devices = [d for d in db.list_devices(enabled_only=True) if db.in_groups(d, groups)]
    if not devices:
        return []
    base, rules = db.get_thresholds(), db.get_setting("threshold_overrides")
    per_device = {d["name"]: db.thresholds_for(d, base, rules) for d in devices}
    results = run_all(devices, lambda d: per_device[d["name"]], on_results=on_result,
                      workers=int(db.get_setting("workers")), opts=db.runtime_options())
    results.sort(key=lambda r: (-SEVERITY[r.status], r.device, r.check))
    db.save_run(results)
    if do_notify:
        notify.process_run(results, [d["name"] for d in devices], scheduled, desktop=None)
    return results


def run_backups(groups=None, do_notify=True, scheduled=True):
    groups = list(groups or [])
    devices = [d for d in db.list_devices(enabled_only=True) if db.in_groups(d, groups)]
    if not devices:
        return []
    results = backup.backup_many(devices, workers=min(5, int(db.get_setting("workers"))))
    db.save_run(results)
    audit.log("config backup", f"{len(results)} device(s) (service)", who="service")
    if do_notify:
        notify.process_run(results, [d["name"] for d in devices], scheduled, desktop=None)
    return results


# ---------------------------------------------------------------- Prometheus text
def _esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def latest_rows():
    """Per device, the rows of the newest run that included it (config-backup rows excluded)."""
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
            for r in c.execute("SELECT device, check_name, status, numeric FROM results WHERE run_id=?", (rid,)):
                if (r["device"] or "").split(" / ")[0] in bases and r["check_name"] != "config backup":
                    out.append(dict(r))
    return out


def metrics_text():
    rows = latest_rows()
    health = db.device_health()
    lines = ["# HELP toner_check_status Latest status of each check: 0 OK, 1 WARN, 2 FAIL, 3 ERROR.",
             "# TYPE toner_check_status gauge"]
    for r in sorted(rows, key=lambda r: (r["device"], r["check_name"])):
        lines.append(f'toner_check_status{{device="{_esc(r["device"])}",check="{_esc(r["check_name"])}"}} '
                     f'{SEVERITY.get(r["status"], 0)}')
    lines += ["# HELP toner_check_value Latest numeric value of a check (percent, hours, count...).",
              "# TYPE toner_check_value gauge"]
    for r in sorted(rows, key=lambda r: (r["device"], r["check_name"])):
        if r["numeric"] is not None:
            lines.append(f'toner_check_value{{device="{_esc(r["device"])}",check="{_esc(r["check_name"])}"}} {r["numeric"]:g}')
    lines += ["# HELP toner_device_status Worst status across a device's latest checks.", "# TYPE toner_device_status gauge"]
    for name in sorted(health):
        lines.append(f'toner_device_status{{device="{_esc(name)}"}} {SEVERITY.get(health[name]["status"], 0)}')
    last = db.last_run()
    stamp = datetime.strptime(last["started_at"], "%Y-%m-%d %H:%M:%S").timestamp() if last else 0
    lines += ["# HELP toner_devices Devices in the inventory.", "# TYPE toner_devices gauge",
              f"toner_devices {len(db.list_devices())}",
              "# HELP toner_last_run_timestamp_seconds When the newest run started.",
              "# TYPE toner_last_run_timestamp_seconds gauge", f"toner_last_run_timestamp_seconds {stamp:.0f}",
              "# HELP toner_config_changes_24h Device configurations that changed in the last 24 hours.",
              "# TYPE toner_config_changes_24h gauge", f"toner_config_changes_24h {len(backup.recent_changes(24))}"]
    return "\n".join(lines) + "\n"


class MetricsServer:
    """Serves /metrics (and /healthz) from the stored results. Read-only: it never runs a check itself."""

    def __init__(self, port, bind="127.0.0.1"):
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.split("?")[0] == "/metrics":
                    body, code, kind = metrics_text().encode(), 200, "text/plain; version=0.0.4; charset=utf-8"
                elif self.path.split("?")[0] == "/healthz":
                    body, code, kind = b"ok\n", 200, "text/plain"
                else:
                    body, code, kind = b"not found\n", 404, "text/plain"
                self.send_response(code)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.httpd = http.server.ThreadingHTTPServer((bind, int(port)), H)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class Daemon:
    """The same schedules the desktop app uses (Settings > Automation and Config backups), without a window."""

    def __init__(self, log=print):
        self.log = log
        self.stop_event = threading.Event()
        self.next_checks = self.next_backup = None

    def _arm(self):
        now = datetime.now()
        self.next_checks = now + timedelta(minutes=max(1, int(db.get_setting("schedule_minutes")))) \
            if db.get_setting("schedule_enabled") else None
        self.next_backup = now + timedelta(hours=max(1, int(db.get_setting("backup_hours")))) \
            if db.get_setting("backup_enabled") else None

    def tick(self, now=None):
        """Run whatever is due. Returns a list of what it did (for tests and the log)."""
        now = now or datetime.now()
        did = []
        if self.next_checks and now >= self.next_checks:
            groups = _groups_alive(db.get_setting("schedule_groups"))
            if groups is not None:
                res = run_checks(groups)
                did.append(("checks", len(res)))
                self.log(f"{now:%Y-%m-%d %H:%M:%S} checks: {len(res)} result(s), {sum(1 for r in res if r.status != 'OK')} not OK")
            self.next_checks = now + timedelta(minutes=max(1, int(db.get_setting("schedule_minutes"))))
        if self.next_backup and now >= self.next_backup:
            groups = _groups_alive(db.get_setting("backup_groups"))
            if groups is not None:
                res = run_backups(groups)
                did.append(("backup", len(res)))
                self.log(f"{now:%Y-%m-%d %H:%M:%S} backups: {len(res)} device(s), {sum(1 for r in res if r.status == 'WARN')} changed")
            self.next_backup = now + timedelta(hours=max(1, int(db.get_setting("backup_hours"))))
        return did

    def run(self, poll=5.0):
        self._arm()
        if db.get_setting("schedule_enabled") and db.get_setting("schedule_on_start"):
            self.next_checks = datetime.now()
        if db.get_setting("backup_enabled") and db.get_setting("backup_on_start"):
            self.next_backup = datetime.now()
        self.log("Toner service started. "
                 + ("Checks every %s min. " % db.get_setting("schedule_minutes") if self.next_checks else "Scheduled checks are off (Settings > Automation). ")
                 + ("Backups every %s h." % db.get_setting("backup_hours") if self.next_backup else "Scheduled backups are off."))
        while not self.stop_event.is_set():
            try:
                self.tick()
            except Exception as e:                       # one bad run must not stop the service
                self.log(f"error: {type(e).__name__}: {e}")
            self.stop_event.wait(poll)

    def stop(self):
        self.stop_event.set()

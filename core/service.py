"""Running Toner without a window: scheduled checks and backups, alerts, and a Prometheus metrics endpoint.
Used by cli.py (for Task Scheduler or a Windows service wrapper); the desktop app has its own timers."""
import http.server
import threading
import time
from datetime import datetime, timedelta

from core import alerts, audit, backup, db, notify, platforms
from core.runner import run_all
from drivers.base import SEVERITY

_schedule_lock = None
_schedule_guard = threading.Lock()


def owns_schedule():
    """True while this process runs the scheduled checks and backups. Toner's window and its service share the data, so only one
    of them does: the first to ask holds a lock file beside the database until it closes, and the other takes over after that
    (two would check every device twice, and count each failure twice towards an alert)."""
    global _schedule_lock
    with _schedule_guard:                                # a second thread asking at once must not drop the lock held
        if _schedule_lock is None:
            base = db.base_path()
            _schedule_lock = platforms.try_lock(base.with_name(base.name + ".schedule.lock"))
        return _schedule_lock is not None


def _groups_alive(groups):
    """Saved groups that still exist; None means they were chosen but all gone (so do nothing)."""
    alive = [g for g in groups if g in db.group_labels()]
    return None if groups and not alive else alive


def own_devices(groups=None):
    """The enabled devices in the groups that the organization being written to owns (its schedule's; Global's are its own and
    the Shared ones, which live in its file)."""
    me = db.target()
    return [d for d in db.list_devices(enabled_only=True) if db.in_groups(d, list(groups or [])) and d.get("org", me) == me]


def run_checks(groups=None, do_notify=True, scheduled=True, on_result=None, own=False):
    """Check every enabled device in the groups (own: only the organization's own, for its schedule). Saves the run, then alerts
    like the desktop app does. Returns the list of Results (empty when there is nothing to check)."""
    groups = list(groups or [])
    devices = own_devices(groups) if own else [d for d in db.list_devices(enabled_only=True) if db.in_groups(d, groups)]
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


def run_backups(groups=None, do_notify=True, scheduled=True, own=False):
    groups = list(groups or [])
    devices = own_devices(groups) if own else [d for d in db.list_devices(enabled_only=True) if db.in_groups(d, groups)]
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
    """Per device, the rows of the newest run that included it (config-backup rows excluded), in every organization; another
    organization's device is named 'edge-fw (Acme)'."""
    rows, _at = db.latest_results()
    return [{"device": db.label_org(r["device"]), "check_name": r["check_name"], "status": r["status"], "numeric": r["numeric"]} for r in rows]


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
        lines.append(f'toner_device_status{{device="{_esc(db.label_org(name))}"}} {SEVERITY.get(health[name]["status"], 0)}')
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
    """The same schedules the desktop app uses (Settings > Checks > Schedule and Config backups), without a window."""

    def __init__(self, log=print):
        self.log = log
        self.stop_event = threading.Event()
        self.next_checks = self.next_backup = None

    def _arm(self):
        """When each organization's next checks and backups are due (Global's, and every organization's that is not archived)."""
        self.due = {}
        self._follow_settings(datetime.now())
        self.next_checks, self.next_backup = self.due[db.GLOBAL]["checks"], self.due[db.GLOBAL]["backup"]

    def _follow_settings(self, now):
        """Settings as they are now, read at every tick: an organization added or archived, a schedule turned on or off, a shorter
        interval. A run already due stays due; one turned off is dropped."""
        orgs = [db.GLOBAL] + [o["id"] for o in db.org_rows() if not o["archived"]]
        for org in [o for o in self.due if o not in orgs]:
            del self.due[org]
        for org in orgs:
            with db.within(org):
                every = {"checks": timedelta(minutes=max(1, int(db.get_setting("schedule_minutes"))))
                         if db.get_setting("schedule_enabled") else None,
                         "backup": timedelta(hours=max(1, int(db.get_setting("backup_hours"))))
                         if db.get_setting("backup_enabled") else None}
            when = self.due.setdefault(org, {"checks": None, "backup": None})
            for kind, step in every.items():
                when[kind] = None if step is None else min(when[kind] or now + step, now + step)

    def tick(self, now=None):
        """Run whatever is due. Returns a list of what it did (for tests and the log)."""
        now = now or datetime.now()
        did = []
        try:
            from core import trends
            if trends.due(now):
                path = trends.generate_scheduled(now)
                if path:
                    did.append(("trend report", path))
                    self.log(f"{now:%Y-%m-%d %H:%M:%S} trend report: {path}")
        except Exception as e:
            self.log(f"trend report failed: {type(e).__name__}: {e}")
        if not hasattr(self, "due"):
            self.due = {db.GLOBAL: {"checks": self.next_checks, "backup": self.next_backup}}
        self.due[db.GLOBAL].update(checks=self.next_checks, backup=self.next_backup)      # (tests set these directly)
        if not owns_schedule():                             # the window runs the schedule while it is open
            return did
        self._follow_settings(now)
        for org, when in list(self.due.items()):
            who = "" if org == db.GLOBAL else f"{db.org_name(org)}: "
            with db.within(org):
                if when["checks"] and now >= when["checks"]:
                    groups = _groups_alive(db.get_setting("schedule_groups"))
                    if groups is not None:
                        res = run_checks(groups, own=True)
                        did.append(("checks", len(res)))
                        self.log(f"{now:%Y-%m-%d %H:%M:%S} {who}checks: {len(res)} result(s), {sum(1 for r in res if r.status not in ('OK', 'N/A'))} not OK")
                    when["checks"] = now + timedelta(minutes=max(1, int(db.get_setting("schedule_minutes"))))
                if when["backup"] and now >= when["backup"]:
                    groups = _groups_alive(db.get_setting("backup_groups"))
                    if groups is not None:
                        res = run_backups(groups, own=True)
                        did.append(("backup", len(res)))
                        self.log(f"{now:%Y-%m-%d %H:%M:%S} {who}backups: {len(res)} device(s), {sum(1 for r in res if r.status == 'WARN')} changed")
                    when["backup"] = now + timedelta(hours=max(1, int(db.get_setting("backup_hours"))))
        self.next_checks, self.next_backup = self.due[db.GLOBAL]["checks"], self.due[db.GLOBAL]["backup"]
        return did

    def run(self, poll=5.0):
        self._arm()
        for org, when in self.due.items():
            with db.within(org):
                if db.get_setting("schedule_enabled") and db.get_setting("schedule_on_start"):
                    when["checks"] = datetime.now()
                if db.get_setting("backup_enabled") and db.get_setting("backup_on_start"):
                    when["backup"] = datetime.now()
        self.next_checks, self.next_backup = self.due[db.GLOBAL]["checks"], self.due[db.GLOBAL]["backup"]
        from core import agents
        err = agents.apply()
        if db.get_setting("agent_enabled"):
            self.log(f"Agent receiver: {'could not start: ' + err if err else 'listening on port ' + str(agents.status()['port'])}")
            if not err:
                try:
                    agents.check_cert()
                except Exception as e:
                    self.log(f"agent certificate check failed: {e}")
        from core import demarc
        demarc.apply()                                   # sends to Demarc when it is connected
        self.log("Toner service started. "
                 + ("Checks every %s min. " % db.get_setting("schedule_minutes") if self.next_checks else "Scheduled checks are off (Settings > Checks > Schedule). ")
                 + ("Backups every %s h." % db.get_setting("backup_hours") if self.next_backup else "Scheduled backups are off."))
        while not self.stop_event.is_set():
            try:
                self.tick()
            except Exception as e:                       # one bad run must not stop the service
                self.log(f"error: {type(e).__name__}: {e}")
            self.stop_event.wait(poll)

    def stop(self):
        self.stop_event.set()
        from core import agents, demarc
        agents.stop()
        demarc.stop()

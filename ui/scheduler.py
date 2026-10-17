"""Runs the health checks and configuration backups on a timer while the app is open.

Each organization has its own schedule (Settings > Checks > Schedule and Config backups; one that does not set its own follows
Global's, as a separate run). Global's covers Global's own and Shared devices; an organization's, its own devices. The schedule of
the organization being looked at runs through the Results and Configs sections, so it shows there; the others run quietly in the
background, are stored in their own files and alert as usual. Archived organizations do not run."""
from datetime import datetime, timedelta

from PySide6.QtCore import QObject, QThread, QTimer, Signal

from core import db


def _files():
    return [db.GLOBAL] + [o["id"] for o in db.org_rows() if not o["archived"]]


def _alive(saved):
    """Saved groups that still exist. None = they were chosen but have all gone, so skip the run."""
    alive = [g for g in saved if g in db.group_labels()]
    return None if saved and not alive else alive


class _Background(QThread):
    """One organization's scheduled checks or backups, while another organization is being looked at."""
    finished_run = Signal(list, list)                 # results, device names

    def __init__(self, org, kind, groups):
        super().__init__()
        self.org, self.kind, self.groups = org, kind, groups

    def run(self):
        from core import service
        with db.within(self.org):
            fn = service.run_checks if self.kind == "checks" else service.run_backups
            devices = service.own_devices(self.groups)
            results = fn(self.groups, do_notify=False, own=True) if devices else []
        self.finished_run.emit(results, [d["name"] for d in devices])


class _OrgTimers(QObject):
    """A timer for the organization being looked at (it runs through a section) and one per other organization (in the background)."""
    KIND = ""                                         # "checks" or "backups"
    background_done = Signal(list, list)              # results, device names: for the alerts and to refresh what is shown

    def __init__(self):
        super().__init__()
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self._fire)
        self.next_at = None
        self.others, self.jobs = {}, []

    # what each kind reads from the settings
    def _settings(self):
        """(enabled, interval in ms, groups, run on start)."""
        raise NotImplementedError

    def _run_here(self, groups):
        raise NotImplementedError

    def apply(self, first=False):
        """(Re)read every organization's settings and arm the timers. first=True on app start, for 'run on start'."""
        self.timer.stop()
        self.next_at = None
        for t in self.others.values():
            t.stop()
            t.deleteLater()
        self.others = {}
        home = db.home()
        for org in _files():
            with db.within(org):
                on, every, _groups, on_start = self._settings()
            if org == home:
                if on:
                    self.timer.start(every)
                    self.next_at = datetime.now() + timedelta(milliseconds=every)
                if first and on and on_start:
                    QTimer.singleShot(self.START_DELAY, self._run)
                continue
            if on:
                t = QTimer(self)
                t.setSingleShot(True)
                t.timeout.connect(lambda org=org: self._fire_other(org))
                t.start(every)
                self.others[org] = t
                if first and on_start:
                    QTimer.singleShot(self.START_DELAY + 1000, lambda org=org: self._run_other(org))
        self._shown()

    def _shown(self):
        """Where the next run of the organization being looked at is announced."""

    def _run(self):
        with db.within(db.home()):
            groups = _alive(self._settings()[2])
        if groups is not None:
            self._run_here(groups)

    def _fire(self):
        self._run()
        self.apply_home()

    def apply_home(self):
        """Arm the next run of the organization being looked at, leaving the others' timers alone."""
        with db.within(db.home()):
            on, every, _g, _s = self._settings()
        self.timer.stop()
        self.next_at = None
        if on:
            self.timer.start(every)
            self.next_at = datetime.now() + timedelta(milliseconds=every)
        self._shown()

    def _run_other(self, org):
        if any(j.isRunning() and j.org == org for j in self.jobs):
            return                                    # still running from last time
        with db.within(org):
            groups = _alive(self._settings()[2])
        if groups is None:
            return
        job = _Background(org, self.KIND, groups)
        job.finished_run.connect(self.background_done)
        job.finished.connect(lambda j=job: self.jobs.remove(j) if j in self.jobs else None)
        self.jobs.append(job)
        job.start()

    def _fire_other(self, org):
        self._run_other(org)
        with db.within(org):
            on, every, _g, _s = self._settings()
        t = self.others.get(org)
        if t is not None and on:
            t.start(every)

    def shutdown(self):
        for j in list(self.jobs):
            j.wait(30000)


class Scheduler(_OrgTimers):
    KIND = "checks"
    START_DELAY = 2000

    def __init__(self, results_tab):
        super().__init__()
        self.results = results_tab

    def _settings(self):
        return (bool(db.get_setting("schedule_enabled")), max(1, int(db.get_setting("schedule_minutes"))) * 60_000,
                db.get_setting("schedule_groups"), bool(db.get_setting("schedule_on_start")))

    def _groups(self):
        """Saved groups that still exist. None = they were chosen but have all gone, so skip the run."""
        return _alive(db.get_setting("schedule_groups"))

    def _run_here(self, groups):
        self.results.start_scheduled(groups)

    def _shown(self):
        self.results.schedule_note.setText(f"Next scheduled run: {self.next_at:%H:%M}" if self.next_at else "")


class BackupScheduler(_OrgTimers):
    """Backs configurations up on a timer while the app is open."""
    KIND = "backups"
    START_DELAY = 8000

    def __init__(self, configs_tab):
        super().__init__()
        self.configs = configs_tab

    def _settings(self):
        on = bool(db.get_setting("backup_enabled"))
        return (on, max(1, int(db.get_setting("backup_hours"))) * 3_600_000, db.get_setting("backup_groups"),
                on and bool(db.get_setting("backup_on_start")))

    def _run_here(self, groups):
        self.configs.start_scheduled(groups)

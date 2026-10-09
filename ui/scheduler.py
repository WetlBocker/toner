"""Runs the health checks on a timer while the app is open."""
from datetime import datetime, timedelta

from PySide6.QtCore import QObject, QTimer

from core import db


class Scheduler(QObject):
    def __init__(self, results_tab):
        super().__init__()
        self.results = results_tab
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self._fire)
        self.next_at = None

    def apply(self, first=False):
        """(Re)read the settings and arm the timer. first=True on app start, for 'run on start'."""
        self.timer.stop()
        self.next_at = None
        if db.get_setting("schedule_enabled"):
            minutes = max(1, int(db.get_setting("schedule_minutes")))
            self.timer.start(minutes * 60_000)
            self.next_at = datetime.now() + timedelta(minutes=minutes)
        self.results.schedule_note.setText(
            f"Next scheduled run: {self.next_at:%H:%M}" if self.next_at else "")
        if first and db.get_setting("schedule_on_start"):
            QTimer.singleShot(2000, self._run)

    def _groups(self):
        """Saved groups that still exist. None = they were chosen but have all gone, so skip the run."""
        saved = db.get_setting("schedule_groups")
        alive = [g for g in saved if g in db.group_labels()]
        return None if saved and not alive else alive

    def _run(self):
        groups = self._groups()
        if groups is not None:
            self.results.start_scheduled(groups)

    def _fire(self):
        self._run()
        self.apply()                      # arm the next one, whether or not this one ran


class BackupScheduler(QObject):
    """Backs configurations up on a timer while the app is open."""

    def __init__(self, configs_tab):
        super().__init__()
        self.configs = configs_tab
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self._fire)
        self.next_at = None

    def apply(self, first=False):
        self.timer.stop()
        self.next_at = None
        if db.get_setting("backup_enabled"):
            hours = max(1, int(db.get_setting("backup_hours")))
            self.timer.start(hours * 3_600_000)
            self.next_at = datetime.now() + timedelta(hours=hours)
        if first and db.get_setting("backup_enabled") and db.get_setting("backup_on_start"):
            QTimer.singleShot(8000, self._run)

    def _run(self):
        saved = db.get_setting("backup_groups")
        alive = [g for g in saved if g in db.group_labels()]
        if saved and not alive:
            return
        self.configs.start_scheduled(alive)

    def _fire(self):
        self._run()
        self.apply()

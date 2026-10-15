"""The line along the bottom of the window: what Toner is doing and what it will do next, without visiting each section.

Last run (or the progress of the one going now), the next scheduled run and backup, the agent receiver, and whether notifications go
out. Each part opens the place where it is set."""
from datetime import datetime

from PySide6.QtCore import QTimer, Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QProgressBar, QWidget

from core import agents, db, display, notify
from ui import status as st
from ui import theme


class Part(QLabel):
    """A piece of the strip that opens its section or settings page when clicked."""
    clicked = Signal()

    def __init__(self, text=""):
        super().__init__(text)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setTextFormat(Qt.TextFormat.RichText)

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()


class StatusStrip(QWidget):
    navigate = Signal(str, str)                 # (section, settings page or "")

    def __init__(self, main):
        super().__init__()
        self.main = main
        self.setObjectName("statusStrip")
        self.run, self.schedule, self.backups, self.receiver, self.notify = Part(), Part(), Part(), Part(), Part()
        self.progress = QProgressBar()
        self.progress.setMaximumWidth(160)
        self.progress.setMaximumHeight(12)
        self.progress.setTextVisible(False)
        self.progress.hide()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 3, 14, 4)
        lay.setSpacing(8)
        lay.addWidget(self.run)
        lay.addWidget(self.progress)
        lay.addStretch()
        for i, w in enumerate((self.schedule, self.backups, self.receiver, self.notify)):
            if i:
                dot = QLabel("·")
                dot.setProperty("muted", True)
                lay.addWidget(dot)
            lay.addWidget(w)
        self.run.clicked.connect(lambda: self.navigate.emit("Results", ""))
        self.schedule.clicked.connect(lambda: self.navigate.emit("Settings", "Checks/Schedule"))
        self.backups.clicked.connect(lambda: self.navigate.emit("Settings", "Config backups"))
        self.receiver.clicked.connect(lambda: self.navigate.emit("Settings", "Agents"))
        self.notify.clicked.connect(lambda: self.navigate.emit("Settings", "Notifications"))
        self.running = None                       # (done, total) while a run is going
        self.timer = QTimer(self)                 # "12 min ago" moves on, and schedules change
        self.timer.setInterval(30_000)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()
        self.restyle()

    def restyle(self):
        t = theme.current() or {}
        self.setStyleSheet(f"QWidget#statusStrip {{ background: {t.get('surface', '#ffffff')}; border-top: 1px solid {t.get('border', '#dddddd')}; }}"
                           f"QWidget#statusStrip QLabel {{ color: {t.get('muted', '#666666')}; font-size: 8.5pt; background: transparent; }}")
        self.refresh()

    # ---------------------------------------------------------------- the run going now
    def on_progress(self, done, total):
        self.running = (done, total) if done < total else None
        self.progress.setVisible(self.running is not None)
        if self.running:
            self.progress.setMaximum(max(1, total))
            self.progress.setValue(done)
        self.refresh()

    # ---------------------------------------------------------------- everything else
    @staticmethod
    def _counts(run):
        bits = []
        for key, word in (("fail", "FAIL"), ("error", "ERROR"), ("warn", "WARN")):
            n = int(run.get(key) or 0)
            if n:
                bits.append(f"<span style='color:{st.ink(word)}; font-weight:600'>{n} {word}</span>")
        return ", ".join(bits) if bits else f"<span style='color:{st.ink('OK')}; font-weight:600'>all OK</span>"

    def refresh(self):
        if self.running:
            done, total = self.running
            self.run.setText(f"Checking devices: {done} of {total} done")
            self.run.setToolTip("Open Results to watch it")
        else:
            try:
                run = db.last_run()
            except Exception:
                run = None
            self.run.setText(f"Last run {display.ago(run['started_at'])}: {self._counts(run)}" if run else "No checks run yet")
            self.run.setToolTip(f"{run['started_at']}. Open Results." if run else "Open Results to run the checks")
        nxt = getattr(getattr(self.main, "scheduler", None), "next_at", None)
        self.schedule.setText(f"Next run {self._when(nxt)}" if nxt else "Scheduled runs off")
        self.schedule.setToolTip("Settings > Checks > Schedule")
        bnext = getattr(getattr(self.main, "backup_scheduler", None), "next_at", None)
        self.backups.setText(f"Next backup {self._when(bnext)}" if bnext else "Scheduled backups off")
        self.backups.setToolTip("Settings > Config backups")
        try:
            s = agents.status()
            n = len(agents.overview())
            self.receiver.setText(f"Agents: listening on {s['port']} ({n} computer{'s' if n != 1 else ''})" if s["running"]
                                  else ("Agents: receiver stopped" if db.get_setting("agent_enabled") else "Agents off"))
        except Exception:
            self.receiver.setText("Agents off")
        self.receiver.setToolTip("Settings > Agents")
        if not db.get_setting("notify_enabled"):
            self.notify.setText("Notifications off")
        elif notify.snoozed():
            self.notify.setText(f"<span style='color:{st.ink('WARN')}'>Notifications snoozed</span>")
        else:
            n = sum(1 for c in notify.channels() if c.get("enabled", True))
            self.notify.setText(f"Notifications on ({n} channel{'s' if n != 1 else ''})" if n else "Notifications: no channels")
        self.notify.setToolTip("Settings > Notifications")

    @staticmethod
    def _when(at):
        """'14:30' today, 'tomorrow 02:00' or 'Oct 16 02:00'."""
        now = datetime.now()
        if at.date() == now.date():
            return f"{at:%H:%M}"
        if (at.date() - now.date()).days == 1:
            return f"tomorrow {at:%H:%M}"
        return f"{at:%b %d %H:%M}"

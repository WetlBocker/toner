"""The line along the bottom of the window: what Toner is doing and what it will do next, without visiting each section.

Last run (or the progress of the one going now), the next scheduled run and backup, the agent receiver, and whether notifications go
out. Each part opens the place where it is set."""
import threading
import time
from datetime import datetime

from PySide6.QtCore import QTimer, Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QProgressBar, QWidget

from core import agents, db, display, notify, proxy, tunnel
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
    probed = Signal(object)                     # (proxy "host:port", answers, message), from the thread that asked it
    tunnel_done = Signal(str)                   # the sign-in to an SSH tunnel ended: "" or why it did not work

    def __init__(self, main):
        super().__init__()
        self.main = main
        self.setObjectName("statusStrip")
        self.probe_state, self._probing = None, False
        self.opening, self.tunnel_error = False, ""
        self.proxy = Part()
        self.probed.connect(self._on_probe)
        self.tunnel_done.connect(self._on_tunnel_done)
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
        for i, w in enumerate((self.proxy, self.schedule, self.backups, self.receiver, self.notify)):
            if i:
                dot = QLabel("·")
                dot.setProperty("muted", True)
                lay.addWidget(dot)
            lay.addWidget(w)
        self.proxy.clicked.connect(self._proxy_clicked)
        self.run.clicked.connect(lambda: self.navigate.emit("Results", ""))
        self.schedule.clicked.connect(lambda: self.navigate.emit("Settings", "Checks/Schedule"))
        self.backups.clicked.connect(lambda: self.navigate.emit("Settings", "Config backups"))
        self.receiver.clicked.connect(lambda: self.navigate.emit("Settings", "Agents"))
        self.notify.clicked.connect(lambda: self.navigate.emit("Settings", "Notifications"))
        self.running = None                       # (done, total) while a run is going
        self.timer = QTimer(self)                 # "12 min ago" moves on, and schedules change
        self.timer.setInterval(30_000)
        self.timer.timeout.connect(self._tick)
        self.timer.start()
        self.restyle()

    def _tick(self):
        self.check_proxy()
        self.refresh()

    def restyle(self):
        t = theme.current() or {}
        self.setStyleSheet(f"QWidget#statusStrip {{ background: {t.get('surface', '#ffffff')}; border-top: 1px solid {t.get('border', '#dddddd')}; }}"
                           f"QWidget#statusStrip QLabel {{ color: {t.get('muted', '#666666')}; font-size: 8.5pt; background: transparent; }}")
        self.check_proxy()                         # also runs when Settings are saved, so a new proxy is looked at at once
        self.refresh()

    # ---------------------------------------------------------------- the proxy
    def check_proxy(self):
        """Ask the proxy chosen in Settings whether it answers, off the main thread. A proxy is not a standing connection (each
        check opens its own), so this is: does it answer now, and did the last real connection through it work."""
        cfg = proxy.global_config()
        if cfg is None or self._probing or cfg.kind == "tunnel":           # a tunnel is open or not: nothing to ask it
            return
        self._probing = True
        key = f"{cfg.host}:{cfg.port}"
        threading.Thread(target=lambda: self.probed.emit((key, *proxy.probe(cfg))), daemon=True).start()

    def _proxy_clicked(self):
        """A tunnel that is down is signed in to from here (it may ask for a code); anything else opens its settings."""
        cfg = proxy.global_config(full=True)
        if cfg is None or cfg.kind != "tunnel" or tunnel.is_open(cfg) or self.opening:
            self.navigate.emit("Settings", "Proxy")
            return
        self.opening, self.tunnel_error = True, ""
        self.refresh()

        def work():
            err = ""
            try:
                tunnel.get(cfg)
            except OSError as e:
                err = str(e)
            self.tunnel_done.emit(err)
        threading.Thread(target=work, daemon=True).start()

    def _on_tunnel_done(self, err):
        self.opening, self.tunnel_error = False, err
        self.refresh()

    def _on_probe(self, result):
        self._probing = False
        self.probe_state = (*result, time.time())
        cfg = proxy.global_config()
        if cfg is not None and f"{cfg.host}:{cfg.port}" != result[0]:
            self.check_proxy()                    # the setting changed while it was asking
        self.refresh()

    def _proxy_part(self):
        """(text, tooltip) for the proxy indicator."""
        cfg = proxy.global_config()
        if cfg is None:
            how = db.get_setting("proxy").get("mode") if isinstance(db.get_setting("proxy"), dict) else "none"
            if how == "system" and proxy.system_text():
                return "Proxy: Windows settings", f"{proxy.system_text()}. Web connections follow the Windows proxy. Settings > Proxy"
            return "No proxy", "Connections go directly. Settings > Proxy"
        key = f"{cfg.host}:{cfg.port}"
        dot = lambda word: f"<span style='color:{st.ink(word)}'>&#9679;</span>"
        if cfg.kind == "tunnel":
            if self.opening:
                return "Proxy: signing in...", f"Signing in to {cfg.label()}"
            if tunnel.is_open(cfg):
                return f"{dot('OK')} Proxy connected", f"{cfg.label()} is open. Click to open Settings > Proxy."
            why = f" The last try failed: {self.tunnel_error}." if self.tunnel_error else ""
            return f"{dot('FAIL')} Proxy disconnected", f"{cfg.label()} is not open.{why} Click to sign in."
        st_ = self.probe_state if self.probe_state and self.probe_state[0] == key else None
        if st_ is None:
            return "Proxy: checking...", f"Asking {cfg.label()} whether it answers"
        _k, answers, msg, at = st_
        if not answers:
            return f"{dot('FAIL')} Proxy disconnected", f"{msg}. Settings > Proxy"
        last = proxy.last_result(cfg)
        if last and not last[0] and last[1] > at - 1:
            return f"{dot('WARN')} Proxy connected, but refused the last connection", f"{cfg.label()} answers, but the last connection through it failed: {last[2]}"
        worked = f" The last connection through it worked {display.ago(datetime.fromtimestamp(last[1]).strftime('%Y-%m-%d %H:%M:%S'))}." if last and last[0] else ""
        return f"{dot('OK')} Proxy connected", f"{cfg.label()} answers. The sign-in is checked each time a connection is made.{worked} Settings > Proxy"

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
        text, tip = self._proxy_part()
        self.proxy.setText(text)
        self.proxy.setToolTip(tip)
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

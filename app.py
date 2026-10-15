import logging
import os
import sys
import traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QAction, QColor, QIcon, QKeySequence, QPainter, QPixmap, QShortcut
from PySide6.QtWidgets import QApplication, QMainWindow, QMenu, QMessageBox, QSystemTrayIcon
from core import agents, audit, checks, db, display, notify, paths, reports, sessionlog, sessions, trends
from ui import theme
from ui.about import AboutTab
from ui.configs import ConfigsTab
from ui.dashboard import DashboardTab
from ui.device_view import DeviceView
from ui.history import HistoryTab
from ui.nav import NavStack
from ui.inventory import InventoryTab
from ui.notifier import Notifier
from ui.palette import CommandPalette
from ui.reports_tab import ReportsTab
from ui.results import ResultsTab
from ui.scheduler import BackupScheduler, Scheduler
from ui.sessions import SessionsTab
from ui.automation import AutomationTab
from ui.settings import SettingsTab
from ui.tools import ToolsTab

log = logging.getLogger("toner")


def data_dir():
    return paths.data_dir()


def setup_logging():
    """A rolling log file next to the database, and a handler that turns an unexpected crash into a readable dialog."""
    handler = RotatingFileHandler(data_dir() / "toner.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.DEBUG if os.environ.get("TONER_DEBUG") else logging.INFO)

    def hook(kind, value, tb):
        text = "".join(traceback.format_exception(kind, value, tb))
        log.error("Unhandled exception:\n%s", text)
        try:
            if QApplication.instance():
                box = QMessageBox(QMessageBox.Icon.Critical, "Toner hit a problem",
                                  f"Something unexpected happened:\n\n{value}\n\nThe details were saved to:\n"
                                  f"{data_dir() / 'toner.log'}\n\nToner will keep running; if it misbehaves, restart it.")
                box.setDetailedText(text)
                box.exec()
        except Exception:
            pass
        sys.__excepthook__(kind, value, tb)
    sys.excepthook = hook


def app_icon(accent=None):
    """The Toner logo: a tone probe sending out signal waves (see ui/logo.py). It keeps its own colours."""
    from ui import logo
    return logo.icon()


def apply_look(app):
    """Theme, text size and status colours from Settings > Appearance."""
    theme.apply(app, db.get_setting("theme"), int(db.get_setting("font_size")), db.get_setting("accent"),
                db.get_setting("ui_style"))
    reports.apply_colors(db.get_setting("color_preset"), db.get_setting("status_colors"))
    app.setWindowIcon(app_icon(theme.current().get("accent", "#2563eb")))


class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Toner")
        self.resize(1240, 760)
        self.setMinimumSize(900, 560)
        self._quitting = False
        self._told_about_tray = False
        self.views = {}                                  # open device windows by name
        self.dashboard = DashboardTab()
        self.results, self.inventory, self.history = ResultsTab(), InventoryTab(), HistoryTab()
        self.reports = ReportsTab(lambda: self.results.results)
        self.tools = ToolsTab()
        self.sessions = SessionsTab()
        self.automation = AutomationTab()
        self.configs = ConfigsTab()
        self.settings = SettingsTab()
        self.about = AboutTab()
        self.scheduler = Scheduler(self.results)
        self.backup_scheduler = BackupScheduler(self.configs)
        # Windows pop-ups come from a tray icon, shown while a desktop channel is enabled or the app runs in the background.
        self.tray = QSystemTrayIcon(app_icon(), self)
        self.tray.setToolTip("Toner")
        self.tray.activated.connect(self._tray_clicked)
        menu = QMenu()
        menu.addAction("Open Toner", self.show_window)
        menu.addAction("Run checks now", lambda: (self.show_window(), self.go("Results"), self.results.start()))
        menu.addAction("Back up configurations now", lambda: self.configs.start())
        menu.addSeparator()
        menu.addAction("Quit Toner", self.quit_for_real)
        self.tray_menu = menu
        self.tray.setContextMenu(menu)
        self.notifier = Notifier(QSystemTrayIcon.isSystemTrayAvailable())
        self.notifier.desktop.connect(self.show_desktop)
        for page in self.settings.pages:
            if hasattr(page, "desktop_cb"):
                page.desktop_cb = self.show_desktop
        self.results.run_finished.connect(self.on_run_finished)
        self.results.run_finished.connect(self.dashboard.refresh)
        self.inventory.changed.connect(self.tools.refresh)
        self.inventory.changed.connect(self.configs.refresh)
        self.inventory.changed.connect(self.dashboard.refresh)
        self.configs.backed_up.connect(self.on_backup_finished)
        self.results.run_finished.connect(self.history.refresh)
        self.results.run_finished.connect(self.reports.refresh)
        self.inventory.changed.connect(self.results.refresh_groups)
        self.inventory.changed.connect(self.history.refresh)
        self.inventory.changed.connect(self.reports.refresh)
        self.inventory.changed.connect(self.settings.refresh_dynamic)
        self.inventory.open_ssh.connect(self.open_ssh_console)
        self.inventory.open_rdp_tab.connect(self.open_rdp_console)
        self.inventory.open_details.connect(self.open_device_view)
        self.inventory.open_agent_settings.connect(self.open_agent_settings)
        self.results.open_device.connect(self.open_device_by_name)
        self.dashboard.open_device.connect(self.open_device_by_name)
        self.dashboard.goto.connect(self.go)
        self.history.runs_hint.set_actions([("Run checks", lambda: (self.go("Results"), self.results.start()))])
        self.inventory.scan_requested.connect(lambda: (self.go("Tools"), self.tools.tabs.setCurrentWidget(self.tools.discovery)))
        self.dashboard.device_action.connect(self.on_device_action)
        self.dashboard.show_results.connect(lambda what: (self.go("Results"), self.results.show_filter(what)))
        self.dashboard.action.connect(self.dashboard_action)
        self.dashboard.run_requested.connect(lambda: (self.go("Results"), self.results.start()))
        self.dashboard.backup_requested.connect(lambda: (self.go("Configs"), self.configs.start()))
        self.tools.inventory_changed.connect(self.inventory_reloaded)
        self.settings.changed.connect(self.settings_applied)
        self.settings.changed.connect(self.automation.refresh)
        self.inventory.changed.connect(self.automation.refresh)
        self.automation.edit_requested.connect(self.edit_playbook)
        self.automation.settings_requested.connect(self.open_ansible_settings)
        self.tools.playbooks.run_requested.connect(self.run_playbook)
        self.tools.playbooks.settings_requested.connect(self.open_ansible_settings)
        self.tools.playbooks.library_changed.connect(self.automation.refresh)
        self.about.update_available.connect(self._update_available)
        self.about.update_cleared.connect(lambda: self.tabs.setBadge(self.about, False))
        self.about.quit_requested.connect(self.quit_for_real)           # the installer has been started
        tabs = self.tabs = NavStack("Toner")
        for page, label, icon in ((self.dashboard, "Overview", "dashboard"), (self.results, "Results", "results"),
                                  (self.inventory, "Inventory", "inventory"), (self.configs, "Configs", "configs"),
                                  (self.history, "History", "history"), (self.reports, "Reports", "reports"),
                                  (self.tools, "Tools", "tools"), (self.sessions, "Sessions", "sessions"),
                                  (self.automation, "Automation", "automation"),
                                  (self.settings, "Settings", "settings"),
                                  (self.about, "About", "about")):
            tabs.addTab(page, label, icon)
        self.setCentralWidget(tabs)
        from ui.statusstrip import StatusStrip
        self.strip = StatusStrip(self)
        self.statusBar().addWidget(self.strip, 1)
        self.statusBar().setSizeGripEnabled(False)
        self.statusBar().setStyleSheet("QStatusBar { border: 0; padding: 0; } QStatusBar::item { border: 0; }")
        self.strip.navigate.connect(self._strip_go)
        self.results.progress.connect(self.strip.on_progress)
        self.results.run_finished.connect(self.strip.refresh)
        self.palette = CommandPalette(self)
        QShortcut(QKeySequence("Ctrl+K"), self, activated=self.open_palette)
        for i in range(min(9, tabs.count())):
            QShortcut(QKeySequence(f"Ctrl+{i + 1}"), self, activated=lambda i=i: tabs.setCurrentIndex(i))
        tabs.search_requested.connect(self.open_palette)
        self._add_headers()
        tabs.client_changed.connect(self.set_client)
        self.inventory.changed.connect(self.refresh_clients)
        self.refresh_clients()
        tabs.currentChanged.connect(lambda _i: self.update_headers())
        self.results.run_finished.connect(self.update_headers)
        self.inventory.changed.connect(self.update_headers)
        tabs.setCollapsed(bool(db.get_setting("sidebar_collapsed")))
        tabs.collapsed_changed.connect(lambda on: db.set_setting("sidebar_collapsed", on))
        QShortcut(QKeySequence("Ctrl+B"), self, activated=lambda: tabs.setCollapsed(not tabs.collapsed()))
        self.restore_layout()
        self.scheduler.apply(first=True)
        QTimer.singleShot(0, self.strip.refresh)                      # once the schedules are armed
        self.backup_scheduler.apply(first=True)
        self.update_tray()
        agents.apply()                                  # the Windows agent receiver, if it is turned on
        self.housekeeping = QTimer(self)                # things that happen now and then: a scheduled trend report, the agent certificate
        self.housekeeping.setInterval(30 * 60 * 1000)
        self.housekeeping.timeout.connect(self.do_housekeeping)
        self.housekeeping.start()
        QTimer.singleShot(5000, self.do_housekeeping)

    # ---------- section headers
    HEADERS = (("inventory", "Inventory"), ("configs", "Configs"), ("history", "History"), ("reports", "Reports"), ("tools", "Tools"),
               ("sessions", "Sessions"), ("automation", "Automation"), ("settings", "Settings"))

    def _add_headers(self):
        """The same top line on every section: its name and a line of context (Overview and Results make their own; About is its own page)."""
        from ui.widgets import SectionHeader
        self.headers = {}
        for attr, title in self.HEADERS:
            page = getattr(self, attr)
            h = SectionHeader(title)
            page.layout().insertWidget(0, h)
            self.headers[attr] = h
        self.update_headers()

    def update_headers(self):
        """Refill the context lines (cheap: read when a section is shown, after a run and when the inventory changes)."""
        if not getattr(self, "headers", None):
            return
        try:
            from core import scope
            devs = scope.keep(db.list_devices())
            health = db.device_health()
        except Exception:
            return
        on = [d for d in devs if d["enabled"]]
        bad = {s: sum(1 for d in on if (health.get(d["name"]) or {}).get("status") == s) for s in ("FAIL", "ERROR", "WARN")}
        bits = [f"{len(devs)} device{'s' if len(devs) != 1 else ''}"]
        if bad["FAIL"] + bad["ERROR"]:
            bits.append(f"{bad['FAIL'] + bad['ERROR']} failing")
        if bad["WARN"]:
            bits.append(f"{bad['WARN']} with warnings")
        if len(on) < len(devs):
            bits.append(f"{len(devs) - len(on)} disabled")
        self.headers["inventory"].set_context("  ·  ".join(bits))
        try:
            from core import backup
            mine = {d["name"] for d in devs}
            summ = {k: v for k, v in backup.summary().items() if k in mine}
            last = max((v.get("last") or "" for v in summ.values()), default="")
            n = sum(1 for v in summ.values() if v.get("versions"))
            self.headers["configs"].set_context(f"{n} device{'s' if n != 1 else ''} backed up" + (f"  ·  last backup {display.ago(last)}" if last else ""))
        except Exception:
            pass
        run = db.last_run()
        self.headers["history"].set_context(f"Last run {display.ago(run['started_at'])}" if run else "No runs yet")
        self.headers["reports"].set_context("Exports (CSV, HTML, PDF) and trend reports")
        self.headers["tools"].set_context("Troubleshooting, discovery, SNMP, file transfer and certificates")
        try:
            saved = len(sessions.list_sessions())
            live = self.sessions.count_open()
            opened = self.sessions.tabs.count()
            self.headers["sessions"].set_context(f"{saved} saved" + (f"  ·  {opened} open" if opened else "") + (f"  ·  {live} connected" if live else ""))
        except Exception:
            pass
        self.headers["automation"].set_context("Run Ansible playbooks on your devices. Write them in Tools > Playbook Editor.")
        self.headers["settings"].set_context("Checks, connections, alerts, look and data. Nothing changes until you press Save changes.")

    # ---------- window size and place, remembered between runs
    def restore_layout(self):
        try:
            import base64
            raw = db.get_setting("window_geometry")
            if raw:
                self.restoreGeometry(base64.b64decode(raw))
        except Exception:
            log.exception("could not restore the window layout")

    def remember_layout(self):
        try:
            import base64
            db.set_setting("window_geometry", base64.b64encode(bytes(self.saveGeometry())).decode("ascii"))
        except Exception:
            log.exception("could not save the window layout")

    # ---------- Ansible: the editor (Tools) and the runner (Automation) hand over to each other
    def edit_playbook(self, name):
        self.go("Tools")
        self.tools.edit_playbook(name)

    def run_playbook(self, name):
        self.go("Automation")
        self.automation.select_playbook(name)

    def open_ansible_settings(self):
        self.go("Settings")
        self.settings.select_page("Ansible")

    # ---------- navigation
    def go(self, section):
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == section:
                self.tabs.setCurrentIndex(i)
                return

    def show_window(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def inventory_reloaded(self):
        """Devices were added outside the Inventory tab (discovery)."""
        self.inventory.refresh()
        self.inventory.changed.emit()

    # ---------- the client being looked at
    def refresh_clients(self):
        """The sidebar's list of clients (top-level folders), after the folders changed."""
        from core import scope
        self.tabs.set_clients(scope.clients(), scope.current())
        name = scope.name()
        self.setWindowTitle(f"Toner - {name}" if name else "Toner")

    def set_client(self, fid):
        """Narrow every section to one client (or show all), and say so in the window title."""
        from core import scope
        scope.set_current(fid)
        name = scope.name()
        self.setWindowTitle(f"Toner - {name}" if name else "Toner")
        self.dashboard.refresh()
        self.results.load_stored() if self.results.stored else self.results.repopulate()
        self.inventory.refresh()
        self.configs.refresh()
        self.history.refresh()
        self.reports.refresh()
        self.update_headers()

    def _strip_go(self, section, page):
        self.go(section)
        if page:
            self.settings.select_page(page)

    def on_device_action(self, what, name):
        """What the Overview's Needs attention asks for on one device."""
        dev = next((d for d in db.list_devices() if d["name"] == name), None)
        if dev is None:
            return
        if what == "open":
            self.open_device_view(dev)
        elif what == "run":
            self.go("Results")
            self.results.run_devices([name])
        elif what == "ssh":
            self.open_ssh_console(dev)
        elif what == "rdp":
            self.open_rdp_console(dev)

    def open_rdp_console(self, dev):
        """Inventory > Open Remote Desktop, the device window and the palette: a Remote Desktop tab in Sessions (or Windows' own client, per Settings > Terminal)."""
        if sessions.use_embedded():
            self.tabs.setCurrentWidget(self.sessions)
            self.sessions.open_rdp_device(dev)
            return
        try:
            sessions.launch_rdp(sessions.rdp_for_device(dev))
        except OSError as e:
            QMessageBox.warning(self, "Remote Desktop", str(e))

    def open_ssh_console(self, dev):
        """Inventory > right-click > Open SSH session, the device window and the palette: an SSH tab in Sessions."""
        self.tabs.setCurrentWidget(self.sessions)
        self.sessions.open_device(dev)

    def open_tool(self, name, dev):
        widget = {"ping": self.tools.liveping, "snmp": self.tools.snmp, "tls": self.tools.tls, "mtr": self.tools.mtr}[name]
        self.tabs.setCurrentWidget(self.tools)
        self.tools.show_tool(widget, dev)
        if name == "ping":                                   # asked to ping this device: start pinging it, not just fill in the box
            if widget.running():
                widget.halt()
            widget.start()
        self.raise_()
        self.activateWindow()

    def dashboard_action(self, name):
        """The steps of the Overview's getting-started card."""
        if name == "add":
            self.go("Inventory")
            self.inventory.add()
        elif name == "scan":
            self.go("Tools")
            self.tools.tabs.setCurrentWidget(self.tools.discovery)
        elif name == "notify":
            self.go("Settings")
            self.settings.select_page("Notifications")

    def open_agent_settings(self):
        self.go("Settings")
        self.settings.select_page("Agents")

    def open_device_by_name(self, name):
        dev = next((d for d in db.list_devices() if d["name"] == name), None)
        if dev:
            self.open_device_view(dev)

    def open_device_view(self, dev):
        view = self.views.get(dev["name"])
        if view is None:
            view = DeviceView(dev, self)
            # what these open takes over the main window, so the details page gets out of the way (it would otherwise stay in front)
            view.ssh_requested.connect(lambda d, v=view: (v.close(), self.open_ssh_console(d)))
            view.rdp_requested.connect(lambda d, v=view: (v.close(), self.open_rdp_console(d)))
            view.tool_requested.connect(lambda name, d, v=view: (v.close(), self.open_tool(name, d)))
            view.edit_requested.connect(lambda d: self.inventory.edit_device(d))
            view.changed.connect(self._view_changed)
            view.finished.connect(lambda _=0, n=dev["name"]: self.views.pop(n, None))
            self.views[dev["name"]] = view
        else:
            view.reload()
        view.show()
        view.raise_()
        view.activateWindow()

    def _view_changed(self):
        self.dashboard.refresh()
        self.history.refresh()
        self.configs.refresh()

    def open_palette(self):
        entries = []
        for i in range(self.tabs.count()):
            name = self.tabs.tabText(i)
            entries.append((f"Go to {name}", f"Ctrl+{i + 1}" if i < 9 else "", lambda i=i: self.tabs.setCurrentIndex(i)))
        entries += [("Run checks", "all enabled devices", lambda: (self.go("Results"), self.results.start())),
                    ("Back up configurations", "all enabled devices", lambda: (self.go("Configs"), self.configs.start())),
                    ("Check for updates", "About", lambda: (self.go("About"), self.about.check(True))),
                    ("New session", "Sessions", lambda: (self.go("Sessions"), self.sessions.new_session())),
                    ("Add a device", "", lambda: (self.go("Inventory"), self.inventory.add())),
                    ("Scan the network for devices", "discovery", lambda: (self.go("Tools"), self.tools.tabs.setCurrentWidget(self.tools.discovery)))]
        for i in range(self.tools.tabs.count()):
            entries.append((f"Tool: {self.tools.tabs.tabText(i)}", "",
                            lambda i=i: (self.go("Tools"), self.tools.tabs.setCurrentIndex(i))))
        other = "Standard" if db.get_setting("ui_style") == theme.OPS else theme.OPS
        entries.append((f"Style: {other}", "Settings > Appearance", lambda o=other: self.set_style(o)))
        entries.append(("New playbook", "Tools > Playbook Editor", lambda: (self.go("Tools"), self.tools.playbooks.new_playbook())))
        try:
            from core import ansible
            for pb in ansible.list_playbooks():
                entries.append((f"Playbook: {pb['name']}", "edit in Tools > Playbook Editor", lambda n=pb["name"]: self.edit_playbook(n)))
        except Exception:
            log.exception("could not list the playbooks for the search")
        for s in sessions.list_sessions():
            entries.append((f"Session: {s['name']}", " - ".join(x for x in (sessions.NAMES[s["kind"]], sessions.path_of(s)) if x),
                            lambda s=s: (self.go("Sessions"), self.sessions.open_session(s["id"]))))
        for d in db.list_devices():
            entries.append((f"Device: {d['name']}", d["host"], lambda d=d: self.open_device_view(d)))
            if d["vendor"] in ("cisco", "juniper", "arista", "hpe", "mikrotik"):
                entries.append((f"SSH to {d['name']}", d["host"], lambda d=d: self.open_ssh_console(d)))
            if d["vendor"] == "windows":
                entries.append((f"Remote Desktop to {d['name']}", d["host"], lambda d=d: self.open_rdp_console(d)))
        # found by typing, so they come after what the list shows first: sections, tools, sessions and devices
        for title in self.settings.page_titles():                       # any page of Settings by name
            entries.append((f"Settings: {title}", "", lambda t=title: (self.go("Settings"), self.settings.select_page(t))))
        for tab, hint in (("Schedule", "when the checks run, and the certificate check"), ("Custom", "checks you write yourself")):
            entries.append((f"Settings: Checks > {tab}", hint, lambda t=tab: (self.go("Settings"), self.settings.select_page("Checks", t))))
        for key, label in db.THRESHOLD_LABELS.items():
            entries.append((f"Threshold: {label}", "Settings > Thresholds", lambda: (self.go("Settings"), self.settings.select_page("Thresholds"))))
        shown = set()
        for d in db.list_devices():                                     # the checks of the kinds of device that are in use
            for _key, label in checks.CATALOG.get(d["vendor"], []):
                if label not in shown:
                    shown.add(label)
                    entries.append((f"Check: {label}", "Settings > Checks", lambda: (self.go("Settings"), self.settings.select_page("Checks"))))
        self.palette.set_entries(entries)
        self.palette.popup()

    # ---------- tray and background running
    def _tray_clicked(self, reason):
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            self.show_window()

    def _update_available(self, version):
        self.tabs.setBadge(self.about, True)
        if self.tray.isVisible():
            self.tray.showMessage("Toner update available", f"Version {version} is ready. Open Toner > About to install it.",
                                  QSystemTrayIcon.MessageIcon.Information, 8000)

    def show_desktop(self, title, body):
        self.update_tray(force=True)
        self.tray.showMessage(title, body, QSystemTrayIcon.MessageIcon.Warning, 10000)

    def background_mode(self):
        return bool(db.get_setting("run_in_background")) and self.notifier.tray_available

    def update_tray(self, force=False):
        wanted = force or self.background_mode() or any(
            c["type"] == "desktop" and c.get("enabled", True) for c in notify.channels())
        if wanted and self.notifier.tray_available:
            self.tray.show()
        else:
            self.tray.hide()

    def quit_for_real(self):
        self._quitting = True
        self.close()
        QApplication.quit()

    def on_run_finished(self):
        self.notifier.handle_run(self.results.results, self.results.last_ran, self.results.last_scheduled)

    def on_backup_finished(self, results, ran, scheduled):
        """Backups are recorded in history and run through the same alerting as health checks."""
        db.save_run(results)
        self.history.refresh()
        self.dashboard.refresh()
        self.notifier.handle_run(results, ran, scheduled)

    def do_housekeeping(self):
        try:
            if trends.due():
                path = trends.generate_scheduled()
                if path:
                    log.info("Trend report saved to %s", path)
                    audit.log("trend report made", path)
            if agents.running():
                agents.check_cert()
        except Exception:
            log.exception("housekeeping failed")

    def set_style(self, style):
        """Switch between the Standard and Ops console looks (Ctrl+K); the same setting as Settings > Appearance."""
        db.set_setting("ui_style", style)
        self.settings.reload()
        self.settings_applied()

    def settings_applied(self):
        """Make a saved (or imported) settings change take effect everywhere, without a restart."""
        apply_look(QApplication.instance())
        self.tabs.restyle()
        self.update_tray()
        self.inventory.refresh()
        self.results.repopulate()
        self.reports.show_preview()
        self.history.show_run()
        self.sessions.apply_settings()
        self.scheduler.apply()
        self.backup_scheduler.apply()
        agents.apply()
        self.strip.restyle()
        self.results.refresh_groups()
        self.dashboard.refresh()

    def closeEvent(self, event):
        self.remember_layout()
        if not self._quitting and self.background_mode():
            event.ignore()                         # keep scheduled checks and backups running from the tray
            self.hide()
            self.update_tray()
            if not self._told_about_tray:
                self._told_about_tray = True
                self.tray.showMessage("Toner is still running", "Scheduled checks and backups continue. "
                                      "Use the tray icon to open Toner or quit.", QSystemTrayIcon.MessageIcon.Information, 6000)
            return
        if not self.tools.playbooks.leave():                 # an unsaved playbook: the person chose to keep editing
            self._quitting = False
            event.ignore()
            return
        if self.automation.running() and QMessageBox.question(self, "A playbook is running", "Ansible is still running a playbook. Stop it and quit?") != QMessageBox.StandardButton.Yes:
            self._quitting = False
            event.ignore()
            return
        for v in list(self.views.values()):
            v.close()
        self.tools.shutdown()          # stop any running ping/scan/transfer before exiting
        self.automation.shutdown()     # stop a playbook that is still running
        self.sessions.shutdown()       # close every open terminal and finish its log
        self.configs.shutdown()
        agents.stop()
        self.about.apply_on_exit()     # a downloaded update installs as Toner closes, if automatic updating is on
        self.about.shutdown()
        super().closeEvent(event)


def console_streams():
    """Toner.exe has no console of its own (it is a window program). When it runs `cli ...` it borrows the one it was started from;
    with none (Task Scheduler, a service wrapper) its output goes to toner-service.log in the data folder instead."""
    if sys.stdout is not None and sys.stderr is not None:
        return None
    try:
        import ctypes
        import msvcrt
        handle = ctypes.windll.kernel32.GetStdHandle(-11)             # output that was redirected to a file or pipe (> file, a service wrapper)
        if handle not in (None, 0, ctypes.c_void_p(-1).value):
            sys.stdout = sys.stderr = os.fdopen(msvcrt.open_osfhandle(handle, os.O_WRONLY), "w", encoding="utf-8", errors="replace", buffering=1)
            return "redirected"
        if ctypes.windll.kernel32.AttachConsole(-1):                 # the console of the program that started us
            sys.stdout = sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1)
            return "console"
    except Exception:
        pass
    sys.stdout = sys.stderr = open(data_dir() / "toner-service.log", "a", encoding="utf-8", errors="replace", buffering=1)
    return "log"


def run_cli(args):
    """`Toner.exe cli service` and friends: Toner without a window (see cli.py), including the agent receiver."""
    console_streams()
    import cli
    return cli.main(args)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "cli":
        sys.exit(run_cli(sys.argv[2:]))
    setup_logging()
    db.init()
    sessionlog.purge(int(db.get_setting("ssh_log_days")))
    audit.purge(max(365, int(db.get_setting("ssh_log_days"))))
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(True)
    apply_look(app)
    win = Main()
    if "--minimized" in sys.argv and win.background_mode():
        win.update_tray()                          # started with Windows: wait in the tray
    else:
        win.show()
    win.about.start_background_checks()
    log.info("Toner started")
    code = app.exec()
    log.info("Toner stopped")
    sys.exit(code)


if __name__ == "__main__":
    main()

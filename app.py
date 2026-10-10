import logging
import os
import sys
import traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QAction, QColor, QIcon, QKeySequence, QPainter, QPixmap, QShortcut
from PySide6.QtWidgets import QApplication, QMainWindow, QMenu, QMessageBox, QSystemTrayIcon
from core import audit, db, notify, reports, sessionlog
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
from ui.settings import SettingsTab
from ui.tools import ToolsTab

log = logging.getLogger("toner")


def data_dir():
    base = Path(os.environ.get("APPDATA", Path.home())) / "NetCheck"
    base.mkdir(parents=True, exist_ok=True)
    return base


def setup_logging():
    """A rolling log file next to the database, and a handler that turns an unexpected crash into a readable dialog."""
    handler = RotatingFileHandler(data_dir() / "toner.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)

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
    theme.apply(app, db.get_setting("theme"), int(db.get_setting("font_size")), db.get_setting("accent"))
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
        self.inventory.open_details.connect(self.open_device_view)
        self.results.open_device.connect(self.open_device_by_name)
        self.dashboard.open_device.connect(self.open_device_by_name)
        self.dashboard.goto.connect(self.go)
        self.dashboard.run_requested.connect(lambda: (self.go("Results"), self.results.start()))
        self.dashboard.backup_requested.connect(lambda: (self.go("Configs"), self.configs.start()))
        self.tools.inventory_changed.connect(self.inventory_reloaded)
        self.settings.changed.connect(self.settings_applied)
        self.about.update_available.connect(self._update_available)
        self.about.update_cleared.connect(lambda: self.tabs.setBadge(self.about, False))
        self.about.quit_requested.connect(self.quit_for_real)           # the installer has been started
        tabs = self.tabs = NavStack("Toner")
        for page, label, icon in ((self.dashboard, "Overview", "dashboard"), (self.results, "Results", "results"),
                                  (self.inventory, "Inventory", "inventory"), (self.configs, "Configs", "configs"),
                                  (self.history, "History", "history"), (self.reports, "Reports", "reports"),
                                  (self.tools, "Tools", "tools"), (self.settings, "Settings", "settings"),
                                  (self.about, "About", "about")):
            tabs.addTab(page, label, icon)
        self.setCentralWidget(tabs)
        self.palette = CommandPalette(self)
        QShortcut(QKeySequence("Ctrl+K"), self, activated=self.open_palette)
        for i in range(min(9, tabs.count())):
            QShortcut(QKeySequence(f"Ctrl+{i + 1}"), self, activated=lambda i=i: tabs.setCurrentIndex(i))
        self.scheduler.apply(first=True)
        self.backup_scheduler.apply(first=True)
        self.update_tray()

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

    def open_ssh_console(self, dev):
        """Inventory > right-click > Open SSH console."""
        self.tabs.setCurrentWidget(self.tools)
        self.tools.show_ssh(dev)

    def open_tool(self, name, dev):
        widget = {"ping": self.tools.liveping, "snmp": self.tools.snmp, "tls": self.tools.tls, "mtr": self.tools.mtr}[name]
        self.tabs.setCurrentWidget(self.tools)
        self.tools.show_tool(widget, dev)

    def open_device_by_name(self, name):
        dev = next((d for d in db.list_devices() if d["name"] == name), None)
        if dev:
            self.open_device_view(dev)

    def open_device_view(self, dev):
        view = self.views.get(dev["name"])
        if view is None:
            view = DeviceView(dev, self)
            view.ssh_requested.connect(self.open_ssh_console)
            view.tool_requested.connect(self.open_tool)
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
                    ("Add a device", "", lambda: (self.go("Inventory"), self.inventory.add())),
                    ("Scan the network for devices", "discovery", lambda: (self.go("Tools"), self.tools.tabs.setCurrentWidget(self.tools.discovery)))]
        for i in range(self.tools.tabs.count()):
            entries.append((f"Tool: {self.tools.tabs.tabText(i)}", "",
                            lambda i=i: (self.go("Tools"), self.tools.tabs.setCurrentIndex(i))))
        for d in db.list_devices():
            entries.append((f"Device: {d['name']}", d["host"], lambda d=d: self.open_device_view(d)))
            if d["vendor"] in ("cisco", "juniper", "arista", "hpe", "mikrotik"):
                entries.append((f"SSH to {d['name']}", d["host"], lambda d=d: self.open_ssh_console(d)))
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

    def settings_applied(self):
        """Make a saved (or imported) settings change take effect everywhere, without a restart."""
        apply_look(QApplication.instance())
        self.tabs.restyle()
        self.update_tray()
        self.inventory.refresh()
        self.results.repopulate()
        self.reports.show_preview()
        self.history.show_run()
        self.tools.apply_settings()
        self.scheduler.apply()
        self.backup_scheduler.apply()
        self.results.refresh_groups()
        self.dashboard.refresh()

    def closeEvent(self, event):
        if not self._quitting and self.background_mode():
            event.ignore()                         # keep scheduled checks and backups running from the tray
            self.hide()
            self.update_tray()
            if not self._told_about_tray:
                self._told_about_tray = True
                self.tray.showMessage("Toner is still running", "Scheduled checks and backups continue. "
                                      "Use the tray icon to open Toner or quit.", QSystemTrayIcon.MessageIcon.Information, 6000)
            return
        for v in list(self.views.values()):
            v.close()
        self.tools.shutdown()          # stop any running ping/scan/SSH session before exiting
        self.configs.shutdown()
        self.about.apply_on_exit()     # a downloaded update installs as Toner closes, if automatic updating is on
        self.about.shutdown()
        super().closeEvent(event)


def main():
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

import json
import logging
import os
import sys
import traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path

from PySide6.QtCore import QTimer, Qt, Signal
from PySide6.QtGui import QAction, QIcon, QKeySequence, QPixmap, QShortcut
from PySide6.QtWidgets import QApplication, QMainWindow, QMenu, QMessageBox, QSplitter, QSystemTrayIcon, QWidget
from core import agents, audit, checks, db, demarc, dircheck, display, legacyssh, notify, paths, perms, reports, roles, session, sessionlog, sessions, trends, trust, tunnel, updates
from ui import theme
from ui.about import AboutTab
from ui.configs import ConfigsTab
from ui.dashboard import DashboardTab
from ui.device_view import DeviceView
from ui.history import HistoryTab
from ui.nav import NavStack
from ui.inventory import InventoryTab
from ui import otpprompt
from ui.notifier import Notifier
from ui.palette import CommandPalette
from ui.results import ResultsTab
from ui.scanning import ScanningTab
from ui.scheduler import BackupScheduler, Scheduler
from ui.sessions import SessionsTab
from ui.automation import AutomationTab
from ui.assistant import AssistantPanel, SideButton, PANEL_WIDTH
HEADER_CLEAR = 72                                   # the Assistant button stays below a section's title row (Run checks lives there)
from core import assistant as AI
from core import quiet
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
            quiet.ignored()
        sys.__excepthook__(kind, value, tb)
    sys.excepthook = hook


def app_icon(accent=None):
    """The Toner logo: a tone probe sending out signal waves (see ui/logo.py). It keeps its own colours."""
    from ui import logo
    return logo.icon()


_look = None                 # the look last applied; applying the same one again restyles every widget and changes nothing


def apply_look(app):
    """Theme, look, text size and status colours from Settings > Appearance. Returns False when they are what is shown already.
    An interactive theme (Follows health, Time of day, Follows organization, System) is applied again only when what it follows changed."""
    global _look
    from ui import themes
    look = theme.saved_look()
    ctx = theme.context(app)
    key = (json.dumps(look, sort_keys=True), int(db.get_setting("font_size")), db.get_setting("color_preset"),
           json.dumps(db.get_setting("status_colors"), sort_keys=True), tuple(ctx.get(k) for k in themes.uses(look["theme"])))
    if key == _look:
        return False
    reports.apply_colors(db.get_setting("color_preset"), db.get_setting("status_colors"))
    theme.apply(app, look, int(db.get_setting("font_size")), ctx=ctx)
    if look["theme"] == "Follows health":                # its accent is a status ink, which depends on the surface just applied
        theme.apply(app, look, int(db.get_setting("font_size")), ctx=theme.context(app))
    app.setWindowIcon(app_icon(theme.current().get("accent", "#2563eb")))
    _look = key
    return True


def plain_look(app):
    """The look before anyone signs in: the theme defaults, but for the theme's name, kept in plain beside netcheck.keys (nothing is
    read from the database, which stays encrypted until then)."""
    from datetime import datetime
    from ui import themes
    try:
        dark = app.styleHints().colorScheme() == Qt.ColorScheme.Dark
    except Exception:
        dark = False
    hour = datetime.now().hour
    theme.apply(app, theme.plain_look(), ctx=dict(system_dark=dark, hour=hour, period=themes.period(hour), worst=None,
                                                          org_colour="", status=None))
    app.setWindowIcon(app_icon())


def restart():
    """Start Toner again after Sign out, so nothing of the old session stays in memory: the same program and arguments (an
    AppImage starts the AppImage; its mount goes when this process ends), without --minimized, as someone is about to sign in."""
    from PySide6.QtCore import QProcess
    args = sys.argv[1:] if getattr(sys, "frozen", False) else sys.argv
    QProcess.startDetached(os.environ.get("APPIMAGE") or sys.executable, [a for a in args if a != "--minimized"])


class Main(QMainWindow):
    ai_state_changed = Signal(object, str)          # the Assistant's connection was checked (on another thread): connected?, the sentence
    rules_changed = Signal()                        # roles told its listeners, maybe on the directory check's thread

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Toner")
        self.resize(1240, 760)
        self.setMinimumSize(900, 560)
        self._quitting = False
        self._signing_out = False                        # Sign out: closing ends the process, and app.main starts Toner again
        self._told_about_tray = False
        self.views = {}                                  # open device windows by name
        self.dashboard = DashboardTab()
        self.results, self.inventory, self.history = ResultsTab(), InventoryTab(), HistoryTab()
        self.tools = ToolsTab()
        self.sessions = SessionsTab()
        self.automation = AutomationTab()
        self.configs = ConfigsTab()
        self.scanning = ScanningTab()
        self.settings = SettingsTab()
        self.settings.reset_requested.connect(self.factory_reset)
        self._wiped = False                              # a factory reset happened: nothing may be written while quitting
        self.about = AboutTab()
        self.scheduler = Scheduler(self.results)
        self.backup_scheduler = BackupScheduler(self.configs)
        self.scheduler.background_done.connect(self.on_background_run)         # other organizations' schedules
        self.backup_scheduler.background_done.connect(self.on_background_run)
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
        self.results.run_finished.connect(self.inventory.update_values)    # the versions and states the run just read
        self.results.run_started.connect(self.inventory.pane.run_started)  # the details pane counts the device's checks as they run
        self.results.check_done.connect(self.inventory.pane.check_done)
        self.results.run_finished.connect(self.inventory.pane.run_finished)
        self.results.run_finished.connect(self.dashboard.refresh)
        self.dashboard.open_org.connect(lambda oid: self.tabs.org.setCurrentIndex(max(0, self.tabs.org.findData(oid))))   # (the switcher's own path)
        self.dashboard.attention_count.connect(lambda n, failing, words: self.tabs.setBadge(self.results, n, "FAIL" if failing else "WARN", words))
        self.inventory.changed.connect(self.tools.refresh)
        self.inventory.changed.connect(self.configs.refresh)
        self.inventory.changed.connect(self.dashboard.refresh)
        self.configs.backed_up.connect(self.on_backup_finished)
        self.results.run_finished.connect(self.history.refresh)
        self.inventory.changed.connect(self.results.refresh_groups)
        self.inventory.changed.connect(self.history.refresh)
        self.inventory.changed.connect(self.settings.refresh_dynamic)
        self.inventory.open_ssh.connect(self.open_ssh_console)
        self.inventory.sessions_imported.connect(self.sessions.refresh)
        self.inventory.orgs_created.connect(lambda: (self.refresh_orgs(), self.inventory.refresh(), self.settings.refresh_dynamic()))
        self.inventory.open_rdp_tab.connect(self.open_rdp_console)
        self.inventory.open_details.connect(self.open_device_view)
        self.inventory.run_checks.connect(self.results.run_devices)
        self.inventory.tool_requested.connect(self.open_tool)                # right-click > Open in Tools
        self.dashboard.tool_requested.connect(self.open_tool)        # right-click > Run Checks (progress in the status bar)
        self.inventory.scan_vulns.connect(lambda keys: (self.go("Scanning"), self.scanning.run_devices(keys)))
        self.scanning.open_device.connect(self.open_device_by_name)
        self.inventory.open_agent_settings.connect(self.open_agent_settings)
        self.results.open_device.connect(self.open_device_by_name)
        self.dashboard.open_device.connect(self.open_device_by_name)
        self.dashboard.goto.connect(self.go)
        self.inventory.scan_requested.connect(lambda: (self.go("Tools"), self.tools.tabs.setCurrentWidget(self.tools.discovery)))
        self.dashboard.device_action.connect(self.on_device_action)
        self.dashboard.show_results.connect(lambda what: (self.go("Results"), self.results.show_filter(what)))
        self.dashboard.action.connect(self.dashboard_action)
        self.dashboard.run_requested.connect(lambda: (self.go("Results"), self.results.start()))
        self.dashboard.backup_requested.connect(lambda: (self.go("Configs"), self.configs.start()))
        self.tools.inventory_changed.connect(self.inventory_reloaded)
        topo = self.tools.topology                               # a box on the map: open the device, a session, checks, a ping, or add it
        topo.open_device.connect(self.open_device_by_name)
        topo.open_ssh.connect(lambda key: self.open_ssh_console(db.find_device(key)) if db.find_device(key) else None)
        topo.run_checks.connect(self.results.run_devices)
        topo.ping.connect(self.quick_ping)
        topo.add_device.connect(lambda info: (self.go("Inventory"), self.inventory.add(info)))
        topo.inventory_action.connect(self.inventory.act_on)       # Edit..., Scan for vulnerabilities, Edit tags..., Delete... as on the Inventory tab
        self.settings.changed.connect(self.settings_applied)
        self.settings.look_preview.connect(self.preview_look)
        self.settings.look_reset.connect(self.reset_look)
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
        # the sections, in the order Ctrl+1..9 and go() know them, each under its group in the sidebar
        for page, label, icon, group in ((self.dashboard, "Overview", "dashboard", "Observability"), (self.results, "Results", "results", "Observability"),
                                         (self.inventory, "Inventory", "inventory", "Network"), (self.configs, "Configs", "configs", "Network"),
                                         (self.scanning, "Scanning", "scanning", "Network"),
                                         (self.history, "History", "history", "Observability"),
                                         (self.tools, "Tools", "tools", "Work"), (self.sessions, "Sessions", "sessions", "Work"),
                                         (self.automation, "Automation/AI", "automation", "Work"),
                                         (self.settings, "Settings", "settings", NavStack.BOTTOM),
                                         (self.about, "About", "about", NavStack.BOTTOM)):
            tabs.addTab(page, label, icon, group)
        # the Assistant's panel sits beside the sections and pushes them narrower when it is open; its width is remembered
        from ui.widgets import remember_sizes
        self.assistant = AssistantPanel(self.screen_context)
        self.assistant.hide()
        self.body = QSplitter(Qt.Orientation.Horizontal)
        self.body.setChildrenCollapsible(False)
        self.body.setHandleWidth(1)
        tabs.setMinimumWidth(600)                          # the sections can give the panel room (the sidebar folds to icons by itself)
        self.body.addWidget(tabs)
        self.body.addWidget(self.assistant)
        self.body.setStretchFactor(0, 1)
        self.body.setStretchFactor(1, 0)
        remember_sizes(self.body, "assistant_panel")
        self.body.splitterMoved.connect(lambda *_: self._place_ai_button())
        self.setCentralWidget(self.body)
        self.ai_button = SideButton(self)                  # the round button at the right edge, on every section, while connected (a child of
        self.ai_button.setAutoFillBackground(True)         # the window, not of the splitter, which would make it a pane)
        self.ai_button.hide()
        self.ai_button.clicked.connect(lambda: self.show_assistant(not self.assistant_open()))
        self.ai_button.moved.connect(self._ai_button_moved)
        self.ai_state_changed.connect(self._ai_state)
        AI.add_listener(lambda on, text: self.ai_state_changed.emit(on, text))
        self.automation.assistant_page.open_requested.connect(self.open_assistant_conversation)
        self.automation.assistant_page.settings_requested.connect(lambda: (self.go("Settings"), self.settings.select_page("AI")))
        self.assistant.turn_done.connect(self.automation.assistant_page.refresh)
        from ui.statusstrip import StatusStrip
        self.strip = StatusStrip(self)
        self.statusBar().addWidget(self.strip, 1)
        self.statusBar().setSizeGripEnabled(False)
        self.statusBar().setStyleSheet("QStatusBar { border: 0; padding: 0; } QStatusBar::item { border: 0; }")
        self.strip.navigate.connect(self._strip_go)
        self.results.progress.connect(self.strip.on_progress)
        self.results.progress.connect(self.dashboard.set_progress)       # the Overview's Run checks says Checking... and fills a line
        self.results.run_started.connect(self.dashboard.run_started)      # the map rings the devices being checked
        self.results.device_done.connect(self.dashboard.device_done)
        self.scanning.progress.connect(self.strip.on_progress)
        self.results.run_finished.connect(self.strip.refresh)
        self.palette = CommandPalette(self)
        self.palette_shortcut = QShortcut(QKeySequence("Ctrl+K"), self, activated=self.open_palette)
        for i in range(min(9, tabs.count())):
            QShortcut(QKeySequence(f"Ctrl+{i + 1}"), self, activated=lambda i=i: tabs.setCurrentIndex(i))
        tabs.search_requested.connect(self.open_palette)
        self._add_headers()
        tabs.org_changed.connect(self.set_org)
        tabs.leave_guard = lambda was, _to: tabs.stack.widget(was) is not self.settings or self.settings.confirm_leave()
        self.settings.orgs_changed.connect(self.refresh_orgs)
        self.refresh_orgs()
        self.assistant.set_org(db.home())
        tabs.currentChanged.connect(lambda _i: self.update_headers(if_changed=True))
        self.results.run_finished.connect(self.update_headers)
        self.inventory.changed.connect(self.update_headers)
        self.results.run_finished.connect(self.relook)                   # Follows health
        self.relook_timer = QTimer(self)                                 # Time of day
        self.relook_timer.setInterval(60000)
        self.relook_timer.timeout.connect(self.relook)
        self.relook_timer.start()
        try:
            QApplication.instance().styleHints().colorSchemeChanged.connect(lambda _s: self.relook())     # System (Qt 6.5+)
        except Exception:
            quiet.ignored()
        tabs.setCollapsed(bool(db.get_setting("sidebar_collapsed")))
        tabs.collapsed_changed.connect(lambda on: db.set_setting("sidebar_collapsed", on))
        QShortcut(QKeySequence("Ctrl+B"), self, activated=lambda: tabs.setCollapsed(not tabs.collapsed()))
        self.restore_layout()
        self.scheduler.apply(first=True)
        QTimer.singleShot(0, self.strip.refresh)                      # once the schedules are armed
        self.backup_scheduler.apply(first=True)
        self.update_tray()
        agents.apply()                                  # the Windows agent receiver, if it is turned on
        demarc.apply()                                  # sends to Demarc once it is connected (Settings > Connections > Demarc)
        self.housekeeping = QTimer(self)                # things that happen now and then: a scheduled trend report, the agent certificate
        self.housekeeping.setInterval(30 * 60 * 1000)
        self.housekeeping.timeout.connect(self.do_housekeeping)
        self.housekeeping.start()
        QTimer.singleShot(5000, self.do_housekeeping)
        QTimer.singleShot(0, AI.check_in_background)   # the same test as Settings > AI > Test, when a key is stored
        self.user_menu = QMenu(self)                    # who is signed in, Lock and Sign out
        if session.user():
            self.user_menu.addAction(session.user()).setEnabled(False)
            self.user_menu.addSeparator()
            self.user_menu.addAction("Lock (Ctrl+Shift+L)", self.lock)
            self.user_menu.addAction("Sign out", self.sign_out)
            tabs.set_user(session.user(), self.user_menu)
        self.lock_shortcut = QShortcut(QKeySequence("Ctrl+Shift+L"), self, activated=self.lock)
        from ui.lockscreen import LockScreen
        self.lock_screen = LockScreen(self)             # last, so it is above everything else in the window
        self.apply_permissions()
        self.rules_changed.connect(lambda: (self.apply_permissions(), self.settings.apply_role()),
                                   Qt.ConnectionType.QueuedConnection)
        roles.on_change(self.rules_changed.emit)        # e.g. an Admin changing their own role, or the directory demoting them
        session.on_change(lambda st: dircheck.stop() if st == "signed_out" else dircheck.start())   # the directory check runs while a session is open or locked
        if session.state() != "signed_out":
            dircheck.start()

    def apply_permissions(self):
        """Once the window is built, and again whenever the rules change (safe to call again): what the signed-in role may not use is
        hidden. Sessions follow tool:sessions. Automation/AI holds Ansible (tool:automation) and the Assistant's page (ai), so the section
        goes only when both are off."""
        self.tools.apply_permissions()
        self.automation.apply_permissions()
        t, ai = self.tabs, perms.allowed("ai")
        t.setTabVisible(self.tools, self.tools.any_allowed())
        t.setTabVisible(self.sessions, perms.allowed("tool:sessions"))
        t.setTabVisible(self.automation, perms.allowed("tool:automation") or ai)
        if not ai:
            self.show_assistant(False)
            self.ai_button.hide()
        self.strip.show_ai()

    # ---------- signing in (core/session.py)
    def lock(self):
        """Ctrl+Shift+L: the lock screen covers the window until the password is entered (a recovery-key session can't lock)."""
        if session.state() == "open" and session.user() is not None:
            session.lock()

    def sign_out(self):
        """Sign out (the user menu, or Sign in as someone else): the usual questions before closing first; if one is refused, nothing
        happens. Then the data key closes and Toner ends; app.main starts it again."""
        self._signing_out = self._quitting = True
        if not self.close():
            self._signing_out = self._quitting = False
            return
        session.sign_out()
        QApplication.quit()

    # ---------- the Assistant (core/assistant, ui/assistant.py)
    def _ai_state(self, connected, text):
        """The connection check finished (startup, Test, Save): the strip's words, and the side button only while connected."""
        self.strip.show_ai()
        self.ai_button.set_provider(AI.provider_id())
        connected = bool(connected) and perms.allowed("ai")
        self.ai_button.setVisible(connected)
        if not connected and self.assistant_open():
            self.show_assistant(False)
        self.assistant.show_model()
        self.automation.assistant_page.refresh()
        self._place_ai_button()

    PANEL_MS = 220                                                      # the panel's slide and fade

    def show_assistant(self, on=True):
        """Open the panel (the sections get narrower, never covered) or close it."""
        on = bool(on) and perms.allowed("ai")
        from ui import motion
        motion.stop(getattr(self, "_panel_slide", None))                # a slide under way ends at once, where it was going
        if getattr(self, "_panel_finish", None):
            self._panel_finish()
        if on == self.assistant.isVisible():
            return
        width = 0
        if on:
            remembered = (db.get_setting("splitters") or {}).get("assistant_panel")
            width = remembered[1] if remembered and len(remembered) == 2 and remembered[1] >= self.assistant.minimumWidth() else PANEL_WIDTH
        self._slide_panel(on, width)
        self.ai_button.setChecked(on)
        self._place_ai_button()

    def assistant_open(self):
        """Is the panel open, or on its way open? (While it slides the real panel is hidden; this is where it is going.)"""
        target = getattr(self, "_panel_target", None)
        return self.assistant.isVisible() if target is None else target

    def _slide_panel(self, on, width):
        """The panel slides in from the right edge (or out), ease-out, no bounce, no fade, and the page narrows (or widens) with it frame
        by frame, as it does beside the sidebar. While it moves the page stands alone in the splitter, its contents held back by a right
        margin the panel's width so far, and a picture of the panel rides over that margin; the real panel takes its place at the end.
        (A margin, not a maximum width: the splitter, and the window's body with it, would shrink to that.) With motion off it all happens
        at once."""
        from PySide6.QtCore import QEasingCurve, QPoint
        from PySide6.QtWidgets import QLabel
        from ui import motion
        total = sum(self.body.sizes())
        least = self.assistant.minimumWidth()
        margins = self.tabs.contentsMargins()
        if on:
            width = min(width, max(least, total - 300))                 # the page keeps at least 300 px (a remembered width may not fit)
        else:
            width = self.assistant.width()

        def settle():
            self.tabs.setContentsMargins(margins)                        # the page's own room back
            self.assistant.setMinimumWidth(0)                           # (the splitter may take it to nothing)
            if on:
                self.assistant.setVisible(True)
                self.body.setSizes([max(0, total - width), width])
            else:
                self.body.setSizes([total, 0])
                self.assistant.setVisible(False)
            self.assistant.setMinimumWidth(least)
            self._place_ai_button()
            if on:
                self.assistant.input.setFocus()
        if not (motion.enabled() and self.isVisible()):
            settle()
            return
        if on:
            self.assistant.resize(width, self.body.height())            # laid out at its full width once, then photographed
            self.assistant.layout().activate()
        shot = self.assistant.grab()
        self.assistant.setVisible(False)                                # the picture stands in for it until the end
        top, full = self.body.mapTo(self, QPoint(0, 0)), self.body.width()
        edge = top.x() + full
        cover = QLabel(self)                                            # a child of the window, not of the splitter (which would adopt it)
        cover.setObjectName("assistantSlide")
        cover.setPixmap(shot)
        cover.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        cover.resize(width, self.body.height())
        cover.show()
        b = self.ai_button
        shut_x, open_x = full - b.width() - 8, full - width - b.width() // 2

        def step(p):
            q = p if on else 1 - p                                      # q: how far in the panel is
            shown = round(width * q)
            self.tabs.setContentsMargins(margins.left(), margins.top(), margins.right() + shown, margins.bottom())
            cover.move(edge - shown, top.y())
            self._place_ai_button(round(shut_x + (open_x - shut_x) * q))
        step(0.0)

        def done():
            if self._panel_finish is not done:
                return
            self._panel_slide = self._panel_finish = self._panel_target = None
            cover.setParent(None)
            cover.deleteLater()
            settle()
        self._panel_finish, self._panel_target = done, on
        self._panel_slide = motion.animate(self, self.PANEL_MS, step, curve=QEasingCurve.Type.OutCubic, on_done=done)

    def open_assistant_conversation(self, conv_id, org):
        """Automation/AI > Assistant > Open: that conversation in the panel (its organization is picked first when it is another)."""
        if not perms.allowed("ai"):
            return
        if org != db.home():
            self.set_org(org)
        self.assistant.open_conversation(conv_id, org)
        self.show_assistant(True)

    def _ai_button_moved(self, side, y):
        """Dropped after a drag: it snaps to that side edge at that height, and the place is remembered on this computer."""
        db.set_setting("assistant_button", {"side": side, "y": round(y, 3)})
        self._place_ai_button()

    def _place_ai_button(self, slide_x=None):
        """Pinned at a side edge of the window (the right by default) at the remembered height; at the panel's left edge while the
        panel is open on that side. slide_x: where it rides while the panel slides."""
        from ui.assistant import button_place
        b = self.ai_button
        if b.dragging():
            return
        side, frac = button_place()
        if side == "left":
            x = 8
        elif slide_x is not None:
            x = slide_x
        else:
            x = (self.assistant.x() - b.width() // 2) if self.assistant.isVisible() else (self.body.width() - b.width() - 8)
        y = int(round(frac * self.body.height() - b.height() / 2))
        y = max(HEADER_CLEAR, y)                                                # never over a section's title row and its buttons
        from PySide6.QtCore import QPoint
        b.settle(self.body.mapTo(self, QPoint(max(0, x), min(max(0, y), max(0, self.body.height() - b.height())))))   # by rubber band after a drop
        b.raise_()
        if getattr(self, "lock_screen", None) is not None:
            self.lock_screen.keep_covered()            # the button never shows over the lock's cover

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if getattr(self, "ai_button", None) is not None:
            self._place_ai_button()

    def screen_context(self):
        """What the Assistant is told about the screen: the section and page, the organization, and what the page says about itself."""
        from core import orgs
        page = self.tabs.currentWidget()
        out = {"section": self.tabs.tabText(self.tabs.currentIndex()), "organization": orgs.name(db.home())}
        inner = getattr(page, "tabs", None) or getattr(page, "pages", None)
        if inner is not None and hasattr(inner, "currentWidget") and hasattr(inner, "tabText") and hasattr(inner, "indexOf"):
            sub = inner.currentWidget()
            try:
                i = inner.indexOf(sub) if sub is not None else -1
                if i >= 0:
                    out["page"] = inner.tabText(i)
            except Exception:
                quiet.ignored()
            if hasattr(sub, "screen_context") and not hasattr(page, "screen_context"):
                page = sub
        fn = getattr(page, "screen_context", None)
        if callable(fn):
            try:
                detail = fn() or {}
            except Exception as e:                                # noqa: BLE001  (a page that cannot describe itself does not stop the question)
                detail = {"note": f"This page could not describe itself: {e}"}
            if "page" in detail and "page" not in out:
                out["page"] = detail.pop("page")
            elif "page" in detail:
                detail.pop("page")
            out.update(detail)
        return out

    # ---------- section headers
    HEADERS = (("inventory", "Inventory"), ("configs", "Configs"), ("history", "History"), ("tools", "Tools"),
               ("sessions", "Sessions"), ("automation", "Automation/AI"), ("settings", "Settings"))
    REFRESHABLE = ("inventory", "configs", "history")        # sections whose header gets a Refresh button (Overview, Results and Scanning make their own)

    def _add_headers(self):
        """The same top line on every section: its name and a line of context (Overview and Results make their own; About is its own page)."""
        from ui.widgets import RefreshButton, SectionHeader
        self.headers = {}
        for attr, title in self.HEADERS:
            page = getattr(self, attr)
            h = SectionHeader(title)
            if attr in self.REFRESHABLE:
                h.add(RefreshButton(lambda p=page: (p.refresh(), self.update_headers())))
            page.layout().insertWidget(0, h)
            self.headers[attr] = h
        self.update_headers()

    def update_headers(self, if_changed=False):
        """Refill the context lines: after a run, when the inventory changes, and when a section is shown (if_changed: then only
        when a data file changed since the last fill, by a run from the tray, the service or the device window). In Global each
        fill reads every organization's file several times over. Returns whether it filled."""
        if not getattr(self, "headers", None):
            return False
        stamp = db.data_stamp()
        if if_changed and stamp == getattr(self, "_headers_stamp", None):
            return False
        self._headers_stamp = stamp
        try:
            from core import scope
            devs = scope.keep(db.list_devices())
            health = db.device_health()
        except Exception:
            return False
        on = [d for d in devs if d["enabled"]]
        bad = {s: sum(1 for d in on if (health.get(d["key"]) or {}).get("status") == s) for s in ("FAIL", "ERROR", "WARN")}
        bits = [f"{len(devs)} device{'s' if len(devs) != 1 else ''}"]
        if bad["FAIL"] + bad["ERROR"]:
            bits.append(f"{bad['FAIL'] + bad['ERROR']} failing")
        if bad["WARN"]:
            bits.append(f"{bad['WARN']} with warnings")
        if len(on) < len(devs):
            bits.append(f"{len(devs) - len(on)} disabled")
        self.headers["inventory"].set_context(", ".join(bits))
        try:
            from core import backup
            mine = {d["key"] for d in devs}
            summ = {k: v for k, v in backup.summary().items() if k in mine}
            last = max((v.get("last") or "" for v in summ.values()), default="")
            n = sum(1 for v in summ.values() if v.get("versions"))
            self.headers["configs"].set_context(f"{n} device{'s' if n != 1 else ''} backed up" + (f", last backup {display.ago(last)}" if last else ""))
        except Exception:
            quiet.ignored()
        run = db.last_run()
        self.headers["history"].set_context((f"Last run {display.ago(run['started_at'])}" if run else "No runs yet") + "; reports (CSV, HTML, PDF) and the trend report")
        self.headers["tools"].set_context("Troubleshooting, discovery, SNMP, file transfer and certificates")
        try:
            saved = len(sessions.list_sessions())
            live = self.sessions.count_open()
            opened = len(self.sessions.panes())
            self.headers["sessions"].set_context(f"{saved} saved" + (f", {opened} open" if opened else "") + (f", {live} connected" if live else ""))
        except Exception:
            quiet.ignored()
        self.headers["automation"].set_context("Run Ansible playbooks on your devices. Write them in Tools > Playbook Editor.")
        self.headers["settings"].set_context("Checks, connections, alerts, look and data. Nothing changes until you press Save changes.")
        return True

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
        if not perms.allowed("tool:automation"):
            return
        self.go("Automation")
        self.automation.select_playbook(name)

    def open_ansible_settings(self):
        self.go("Settings")
        self.settings.select_page("Ansible")

    # ---------- navigation
    def go(self, section):
        names = [self.tabs.tabText(i) for i in range(self.tabs.count())]
        for i, name in enumerate(names):
            if name == section:
                self.tabs.setCurrentIndex(i)
                return
        for i, name in enumerate(names):                      # "Automation" still opens "Automation/AI"
            if name.split("/")[0] == section:
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

    # ---------- the organization being looked at
    def refresh_orgs(self):
        """The sidebar's list of organizations, after Settings > Organizations changed it (the open one may have been archived)."""
        from core import orgs
        was = db.home()
        db.set_home(orgs.current())
        self.tabs.set_orgs([(o["id"], o["name"], o["colour"]) for o in orgs.list_orgs(archived=False)], db.home())
        if db.home() != was:
            self._show_org()
        else:
            self.set_titles()
            self._redraw_lists()                           # in Global, a removed or archived organization's rows must go

    def set_titles(self):
        """Each section's title starts with the organization: 'Global - Overview', 'Acme - Inventory'."""
        from core import orgs
        org = orgs.name(db.home())
        for attr, title in self.HEADERS:
            self.headers[attr].title.setText(f"{org} - {title}")
        self.dashboard.title.setText(f"{org} - Overview")
        self.results.header.title.setText(f"{org} - Results")
        self.scanning.header.title.setText(f"{org} - Scanning")

    def set_org(self, org):
        """The switcher: every section shows that organization (Global: all of them). Unsaved settings belong to the one being left."""
        from core import orgs
        if org == db.home():
            return
        if not self.settings.confirm_leave("switching organization", reload=False):
            self.tabs.set_orgs([(o["id"], o["name"], o["colour"]) for o in orgs.list_orgs(archived=False)], db.home())
            return
        orgs.set_current(org)
        self._show_org()

    def _show_org(self):
        self.set_titles()
        self.assistant.set_org(db.home())
        self.settings.reload(announce=False)           # its settings take effect here, once (the schedules too: the organization
        self.settings_applied(lists=False)             # being looked at runs through the sections)
        self._redraw_lists()

    def _redraw_lists(self):
        self.results.reset_view()
        self.scanning.reset_view()
        self.tools.topology.reset_view()
        self.sessions.refresh()
        self.inventory.org_switched()
        self.inventory.changed.emit()                  # everything that follows the inventory refills itself, the headers too

    def _strip_go(self, section, page):
        self.go(section)
        if page:
            self.settings.select_page(page)

    def on_device_action(self, what, name):
        """What the Overview's Needs attention asks for on one device."""
        dev = db.find_device(name)
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
        if not perms.allowed("tool:rdp") or (sessions.use_embedded() and not perms.allowed("tool:sessions")):
            return
        if sessions.use_embedded():
            self.tabs.setCurrentWidget(self.sessions)
            self.sessions.open_rdp_device(dev)
            return
        from ui import rdpprompt
        rdpprompt.start(self, sessions.rdp_for_device(dev))       # (Linux: FreeRDP, after asking for the password)

    def quick_ping(self, key):
        """Right-click > Ping on a device anywhere: the small window that sends five echoes."""
        from ui.pingpop import ping_popup
        dev = db.find_device(key)
        if dev and dev.get("host") and perms.allowed("tool:ping"):
            ping_popup(self, dev["name"], dev["host"])

    def open_ssh_console(self, dev):
        """Inventory > right-click > Open SSH session, the device window and the palette: an SSH tab in Sessions."""
        if not perms.allowed("tool:sessions"):
            return
        self.tabs.setCurrentWidget(self.sessions)
        self.sessions.open_device(dev)

    def open_tool(self, name, dev):
        widget = {"ping": self.tools.liveping, "snmp": self.tools.snmp, "tls": self.tools.tls, "mtr": self.tools.mtr}[name]
        if not self.tools.tool_allowed(widget):
            return
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
        dev = db.find_device(name)                     # a key from Global's lists, or a plain name
        if dev:
            self.open_device_view(dev)

    def open_device_view(self, dev):
        key = dev.get("key") or dev["name"]
        view = self.views.get(key)
        if view is None:
            view = DeviceView(dev, self)
            # what these open takes over the main window, so the details page gets out of the way (it would otherwise stay in front)
            view.ssh_requested.connect(lambda d, v=view: (v.close(), self.open_ssh_console(d)))
            view.rdp_requested.connect(lambda d, v=view: (v.close(), self.open_rdp_console(d)))
            view.tool_requested.connect(lambda name, d, v=view: (v.close(), self.open_tool(name, d)))
            view.edit_requested.connect(lambda d: self.inventory.edit_device(d))
            view.changed.connect(self._view_changed)
            view.finished.connect(lambda _=0, n=key: self.views.pop(n, None))
            self.views[key] = view
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
        can = perms.allowed
        for i in range(self.tabs.count()):
            name = self.tabs.tabText(i)
            if not self.tabs.shown(i):
                continue
            entries.append((f"Go to {name}", f"Ctrl+{i + 1}" if i < 9 else "", lambda i=i: self.tabs.setCurrentIndex(i)))
        entries += [("Run checks", "all enabled devices", lambda: (self.go("Results"), self.results.start())),
                    ("Back up configurations", "all enabled devices", lambda: (self.go("Configs"), self.configs.start())),
                    ("Check for updates", "About", lambda: (self.go("About"), self.about.check(True))),
                    ("Add a device", "", lambda: (self.go("Inventory"), self.inventory.add()))]
        if can("tool:sessions"):
            entries.append(("New session", "Sessions", lambda: (self.go("Sessions"), self.sessions.new_session())))
        if can("tool:find-devices"):
            entries.append(("Scan the network for devices", "discovery", lambda: (self.go("Tools"), self.tools.tabs.setCurrentWidget(self.tools.discovery))))
        for i in range(self.tools.tabs.count()):
            if i in self.tools.tabs._off:
                continue
            entries.append((f"Tool: {self.tools.tabs.tabText(i)}", "",
                            lambda i=i: (self.go("Tools"), self.tools.tabs.setCurrentIndex(i))))
        from ui import themes
        for other in themes.LOOKS:                        # the other looks (Soft, Sharp, Terminal...), as Settings > Appearance > Look
            if other != db.get_setting("look"):
                entries.append((f"Look: {other}", "Settings > Appearance", lambda o=other: self.set_look(o)))
        if can("tool:playbook-editor"):
            entries.append(("New playbook", "Tools > Playbook Editor", lambda: (self.go("Tools"), self.tools.playbooks.new_playbook())))
        try:
            from core import ansible
            for pb in ansible.list_playbooks() if can("tool:playbook-editor") else []:
                entries.append((f"Playbook: {pb['name']}", "edit in Tools > Playbook Editor", lambda n=pb["name"]: self.edit_playbook(n)))
        except Exception:
            log.exception("could not list the playbooks for the search")
        whose = (lambda x: f"  ({db.org_name(x['org'])})") if db.several() else (lambda x: "")      # Global: whose it is
        for s in sessions.list_sessions() if can("tool:sessions") else []:
            entries.append((f"Session: {s['name']}{whose(s)}", " - ".join(x for x in (sessions.NAMES[s["kind"]], sessions.path_of(s)) if x),
                            lambda s=s: (self.go("Sessions"), self.sessions.open_session(s["id"], s["org"]))))
        for d in db.list_devices():
            entries.append((f"Device: {d['name']}{whose(d)}", d["host"], lambda d=d: self.open_device_view(d)))
            if d["vendor"] in ("cisco", "juniper", "arista", "hpe", "mikrotik") and can("tool:sessions"):
                entries.append((f"SSH to {d['name']}", d["host"], lambda d=d: self.open_ssh_console(d)))
            if d["vendor"] == "windows" and can("tool:rdp"):
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

    def on_background_run(self, results, ran):
        """Another organization's scheduled checks or backups finished (stored already): alert, and refresh what Global shows."""
        if results:
            self.notifier.handle_run(results, ran, True)
        if db.everything():                            # many organizations finishing together: one refresh, a moment after the first
            if getattr(self, "_global_timer", None) is None:
                self._global_timer = QTimer(self)      # the window's own timer (it goes with the window)
                self._global_timer.setSingleShot(True)
                self._global_timer.timeout.connect(self._refresh_global)
            if not self._global_timer.isActive():
                self._global_timer.start(self.GLOBAL_WAIT)

    GLOBAL_WAIT = 3000                                 # ms

    def _refresh_global(self):
        if db.everything():
            self.results.load_stored() if self.results.stored else None
            self.inventory.update_values()
            self.dashboard.refresh()
            self.history.refresh()
            self.update_headers()

    def on_backup_finished(self, results, ran, scheduled):
        """Backups are recorded in history and run through the same alerting as health checks."""
        db.save_run(results)
        self.inventory.update_values()                 # a backup may have read a version
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

    def set_look(self, look):
        """Switch the Look (Standard, Soft, Sharp, Terminal) from Ctrl+K; the same setting as Settings > Appearance."""
        db.set_setting("look", look)
        self.settings.reload()
        self.settings_applied()

    set_style = set_look                               # the old name

    def preview_look(self, look):
        """Settings > Appearance: show a look at once, before it is saved. `look` is the dict the page holds (theme, look, panels...);
        a theme name alone still works."""
        app = QApplication.instance()
        global _look
        if not isinstance(look, dict):
            look = dict(theme.saved_look(), theme=look)
        theme.apply(app, look, int(db.get_setting("font_size")), ctx=theme.context(app))
        if look.get("theme") == "Follows health":
            theme.apply(app, look, int(db.get_setting("font_size")), ctx=theme.context(app))
        _look = None                                   # what is shown is not the saved look any more
        self._previewing = True                        # until Save or Cancel: relook leaves it on screen
        self._restyle()

    def reset_look(self):
        """Edits dropped: the saved look again (nothing to do when it is what is shown)."""
        self._previewing = False
        if theme.current().get("accent") is None:
            return
        if apply_look(QApplication.instance()):
            self._restyle()

    def relook(self):
        """An interactive theme's input may have changed (a run finished, the hour or the organization changed, Windows switched
        light/dark): apply the look again if so. Costs nothing otherwise. An unsaved preview stays as it is."""
        if getattr(self, "_previewing", False):
            return
        try:
            if apply_look(QApplication.instance()):
                self._restyle()
        except Exception:
            log.exception("could not re-apply the look")

    def _restyle(self):
        app = QApplication.instance()
        app.setWindowIcon(app_icon(theme.current().get("accent", "#2563eb")))
        self.tabs.restyle()
        self.strip.restyle()
        self.ai_button.restyle()
        self.inventory.refresh()
        self.dashboard.restyle()
        self.history.restyle()
        self.scanning.restyle()
        for page in self.settings.pages:                   # the theme cards' name strips follow the window's colours
            if hasattr(page, "restyle"):
                page.restyle()

    def settings_applied(self, lists=True):
        """Make a saved (or imported) settings change take effect everywhere, without a restart. lists=False leaves out the lists
        that follow the inventory: switching organization refills those once itself."""
        self._previewing = False
        apply_look(QApplication.instance())
        self.tabs.restyle()
        self.dashboard.restyle()
        self.update_tray()
        if lists:
            self.inventory.refresh()
        self.results.repopulate()
        self.scanning.repopulate()
        self.history.show_rows()
        self.sessions.apply_settings()
        self.scheduler.apply()
        self.backup_scheduler.apply()
        agents.apply()
        self.strip.restyle()
        self.strip.show_ai()
        self.ai_button.set_provider(AI.provider_id())
        self.ai_button.restyle()
        if lists:
            self.results.refresh_groups()
            self.scanning.refresh_groups()
            self.dashboard.refresh()

    def factory_reset(self):
        """Settings > Data and logs > Reset Toner to factory settings: ask, stop everything, delete Toner's data, quit (ui/factoryreset.py)."""
        from ui import factoryreset
        factoryreset.perform(self)

    def closeEvent(self, event):
        if self._wiped:
            event.accept()                         # Toner's data is gone: write nothing new, just go
            return
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
            self._quitting = self._signing_out = False
            event.ignore()
            return
        from core import extstore, extvault
        n = extstore.unsent()
        if n:
            name = extvault.LABELS[extstore.active()]
            text = (f"1 change hasn't reached {name} yet and will be lost if Toner closes. Close anyway?" if n == 1 else
                    f"{n} changes haven't reached {name} yet and will be lost if Toner closes. Close anyway?")
            if QMessageBox.question(self, "Toner", text) != QMessageBox.StandardButton.Yes:
                self._quitting = self._signing_out = False
                event.ignore()
                return
        if self.settings.unsaved_count():
            if not self.isVisible():
                self.show_window()                           # quitting from the tray: show what the question is about
            self.go("Settings")
            if not self.settings.confirm_leave("closing Toner", reload=False):
                self._quitting = self._signing_out = False
                event.ignore()
                return
        if self.automation.running() and QMessageBox.question(self, "A playbook is running", "Ansible is still running a playbook. Stop it and quit?") != QMessageBox.StandardButton.Yes:
            self._quitting = self._signing_out = False
            event.ignore()
            return
        if self.tools.firmware.transferring() and not self.tools.firmware.ask_stop():
            self._quitting = self._signing_out = False
            event.ignore()
            return
        for v in list(self.views.values()):
            v.close()
        self.assistant.shutdown()      # a question still being answered is stopped
        self.tools.shutdown()          # stop any running ping/scan/transfer before exiting
        self.automation.shutdown()     # stop a playbook that is still running
        self.sessions.shutdown()       # close every open terminal and finish its log
        self.configs.shutdown()
        self.scheduler.shutdown()
        self.backup_scheduler.shutdown()
        agents.stop()
        demarc.stop()
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
        quiet.ignored()
    sys.stdout = sys.stderr = open(data_dir() / "toner-service.log", "a", encoding="utf-8", errors="replace", buffering=1)
    return "log"


def run_cli(args):
    """`Toner.exe cli service` and friends: Toner without a window (see cli.py), including the agent receiver."""
    console_streams()
    trust.install()
    from core import passvault
    passvault.install()                            # saved passwords come from Toner's vault...
    from core import datakey

    def ready():
        try:
            db.init()                              # cli.main does this too; the move below needs the database first
            tunnel.migrate()
            legacyssh.apply()
        except Exception:
            quiet.ignored("cli.main reports a database problem in its own words")
        try:
            from core import extstore
            if extstore.memory_only():             # ...or only from the password manager: read them now, keep them in step
                extstore.sync_once()
                extstore.start()
        except Exception:
            log.exception("could not read the passwords from the password manager")
    import cli
    if datakey.exists() or datakey.missing():
        return cli.main(args, ready)               # the vault opens through sign-in, so cli.main runs this after it
    passvault.unlock_remembered()                  # ...which opens by itself when it is remembered on this computer
    ready()
    return cli.main(args)


def watch_password_manager(win):
    """Keep the chosen password manager in step, and say so once at start when it can't be reached (Toner then uses its copies)."""
    from core import extstore
    if extstore.active() == "toner":
        return
    extstore.start()

    def tell():
        s = extstore.status()
        if not s.get("at"):
            QTimer.singleShot(1000, tell)                    # the first round is still running
        elif not s.get("connected"):
            from ui.toast import toast
            toast(win, extstore.status_text(s))
    QTimer.singleShot(1500, tell)


def sign_in_at_start():
    """The first start (a new install or an upgrade) or the sign-in window; then whatever is still plain gets encrypted (looked at
    every start: a session log left open last time, or a first start that stopped halfway). False: the person quit."""
    from PySide6.QtWidgets import QDialog
    from core import datakey, lockdown
    from ui import setupdlg
    from ui.signinwindow import SignInWindow
    if not datakey.exists():
        if not setupdlg.run_first_start():
            return False
    elif SignInWindow().exec() != QDialog.DialogCode.Accepted:
        return False
    if lockdown.pending() and not setupdlg.encrypt():
        return False
    if roles.backups_public():
        setupdlg.split_backups()                   # (every sign-in: passwords in old backups go behind the backups key)
    setupdlg.carry_credential_manager()            # (every start: a first start that stopped halfway left them there)
    return True


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "cli":
        sys.exit(run_cli(sys.argv[2:]))
    setup_logging()
    from ui import webchart
    webchart.prepare_application()                 # the charts' QtWebEngine shares OpenGL contexts with the window
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(True)
    plain_look(app)                                # the saved look is in the database, encrypted until someone signs in
    from ui.widgets import MenuPlacer
    app._menu_placer = MenuPlacer(app)             # drop-down menus open upward when there is no room below
    app.installEventFilter(app._menu_placer)
    from ui.widgets import KeyboardAccess
    app._keys = KeyboardAccess(app)                 # Tab gets out of lists; icon buttons and boxes have names for screen readers
    app.installEventFilter(app._keys)
    from ui import tablefit
    tablefit.install_everywhere(app)               # every table and tree: columns fit their text and can always be dragged
    from ui import ipmenu
    ipmenu.install(app)                            # right-click on a selected IP address anywhere: Ping and WHOIS Lookup
    from core import passvault
    passvault.install()                            # saved passwords live in Toner's vault, which signing in opens
    if not sign_in_at_start():
        session.sign_out()
        sys.exit(0)
    db.init()
    trust.install()                                # web requests also trust what Windows trusts (HTTPS inspection)
    legacyssh.apply()                              # ssh-rsa and SHA-1 key exchange for older devices, unless turned off
    tunnel.migrate()                               # 1.5.2-1.5.5: the SSH tunnel was a proxy type; it is its own section now
    from core import orgs
    orgs.start()                                   # the organization picked last time
    sessionlog.purge(int(db.get_setting("ssh_log_days")))
    audit.purge(max(365, int(db.get_setting("ssh_log_days"))))
    try:
        updates.prune()                            # keep the installers of the newest few versions, for going back
    except OSError:
        pass
    apply_look(app)
    theme.write_plain(theme.saved_look()["theme"])    # (every start: existing users get the plain copy without visiting Settings)
    otpprompt.install()
    win = Main()
    if "--minimized" in sys.argv and win.background_mode():
        win.update_tray()                          # started with Windows: wait in the tray
    else:
        win.show()
    win.about.start_background_checks()
    watch_password_manager(win)                    # Bitwarden, Vaultwarden, Keeper or 1Password, when one is chosen
    if tunnel.enabled() and tunnel.settings()["autostart"]:
        QTimer.singleShot(1500, win.strip.connect_tunnel)          # Settings > Proxy > SSH Tunnel > Connect when Toner starts
    log.info("Toner started")
    code = app.exec()
    tunnel.close_all()
    log.info("Toner stopped")
    if win._signing_out:
        restart()
    sys.exit(code)


if __name__ == "__main__":
    main()

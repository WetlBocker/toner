"""Settings tab: a category list on the left, one page per category, one Save for everything.

Pages whose controls change data immediately (forget a host key, back up the database, ...)
say so on the page; everything else waits for 'Save changes'."""
import json
import re
import os
import sqlite3
from datetime import datetime, timedelta

import keyring
from PySide6.QtCore import QDateTime, QRectF, QSize, QTime, QTimer, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont, QPainter
from PySide6.QtWidgets import (QAbstractButton, QAbstractItemView, QAbstractSpinBox, QApplication, QCheckBox, QColorDialog, QComboBox, QDialog,
                               QDateTimeEdit, QDialogButtonBox, QDoubleSpinBox, QFileDialog, QFontComboBox, QFormLayout,
                               QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMenu, QMessageBox, QPushButton,
                               QPlainTextEdit, QScrollArea, QSpinBox, QStackedWidget, QStyledItemDelegate, QTableWidget, QTextEdit, QTableWidgetItem, QTimeEdit,
                               QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)
import ipaddress
from core import agents, alerts, audit, checks, custom, db, display, maintenance, nettools, notify, profiles, proxy, reports, sessionlog, trends, vault
from ui import terminal, theme
from ui.snmpfields import SnmpFields
from ui.widgets import GroupPicker
from ui.nav import HEADING_HEIGHT, ITEM_HEIGHT
from ui import settings_diff as SD
from ui.toast import toast
from ui.settings_base import Page, TrimSpin, note, row_of, spin, tidy  # noqa: F401  (re-exported: other modules and the tests use them)
from ui.settings_pages.general import GeneralPage, ConnectionsPage, _bad_pair, ThresholdsPage, ChecksPage, ChecksListPage, AutomationPage  # noqa: F401
from ui.settings_pages.appearance import AppearancePage, TerminalPage, ReportsPage  # noqa: F401
from ui.settings_pages.notifications import ChannelDialog, NotificationsPage  # noqa: F401
from ui.settings_pages.security import SecurityPage, DataPage  # noqa: F401
from ui.settings_pages.profiles import ProfileDialog, ProfilesPage  # noqa: F401
from ui.settings_pages.checks import CheckDialog, row_of_layout, CustomChecksPage, BackupsPage, AuditPage  # noqa: F401
from ui.settings_pages.network import ProxyPage, AgentsPage, MaintenanceDialog, MaintenancePage  # noqa: F401
from ui.settings_pages.ansible import AnsiblePage  # noqa: F401
from ui.settings_pages.orgs import OrganizationsPage  # noqa: F401
from ui.settings_pages.demarc import DemarcPage  # noqa: F401
from ui.settings_pages.ai import AiPage  # noqa: F401
from ui.settings_pages.scanning import ScanningPage  # noqa: F401



# The order and grouping of the list on the left. A page that is not named here still appears, under "Other".
GROUPS = [("Monitoring", ["General", "Thresholds", "Checks", "Scanning", "Maintenance"]),
          ("Connections", ["Connections", "Proxy", "Credentials", "Agents", "Demarc"]),
          ("Alerts and reports", ["Notifications", "Reports", "Config backups"]),
          ("Automation", ["Ansible", "AI"]),
          ("Look and feel", ["Appearance", "Terminal"]),
          ("Security and data", ["Security", "Audit log", "Data and logs"]),
          ("Organizations", ["Organizations"])]


DIRTY = Qt.ItemDataRole.UserRole + 1          # on a list entry: the page has edits that are not saved yet

# Pages about this computer or the whole program: an organization sees them, read-only, as "Managed by Global".
GLOBAL_PAGES = {"Proxy", "Ansible", "AI", "Scanning", "Appearance", "Terminal", "Security", "Data and logs", "Demarc"}   # (Agents: only the receiver part)
GLOBAL_ONLY_PAGES = {"Organizations"}               # shown in Global only

# What an organization's own value of a setting is called on its page's "Reset to Global" line.
KEY_LABELS = {"retention_days": "Keep run history", "workers": "Devices checked in parallel", "default_ssh_port": "Default SSH port",
              "default_verify_ssl": "Verify SSL certificates on new devices", "scan_confirm_over": "Confirm scans larger than",
              "ssh_timeout": "SSH timeout", "http_timeout": "HTTP timeout", "retries": "Retries", "retry_delay": "Retry delay",
              "disabled_checks": "Checks that run", "counter_mode": "Port error counting", "firmware_severity": "Firmware update severity",
              "threshold_overrides": "Threshold overrides", "thresholds": "Thresholds", "schedule_enabled": "Scheduled checks",
              "schedule_minutes": "Check interval", "schedule_groups": "Devices checked on the schedule", "schedule_on_start": "Run when Toner starts",
              "report_title": "Report title", "report_org": "Report organization name", "report_folder": "Reports folder",
              "report_include_all": "Reports include every check", "trend_schedule": "Scheduled trend report",
              "notify_enabled": "Notifications", "notify_channels": "Notification channels", "notify_consecutive": "Alert after failed runs",
              "notify_remind_hours": "Reminders", "notify_on_manual": "Alert on runs started by hand",
              "backup_enabled": "Scheduled backups", "backup_hours": "Backup interval", "backup_groups": "Devices backed up on the schedule",
              "backup_keep": "Versions kept", "backup_mask": "Hide passwords in backups", "backup_on_start": "Back up when Toner starts",
              "discover_communities": "Discovery SNMP communities", "discover_ports": "Discovery ports", "tls_sweep": "Certificate sweep",
              "tls_sweep_ports": "Certificate sweep ports", "agent_enroll": "Agent sign-up", "agent_minutes": "Agent report interval",
              "agent_push_minutes": "Change computers that already have the agent"}


class _NavDelegate(QStyledItemDelegate):
    """The list entries, plus a small dot at the right edge of a page with unsaved edits."""

    def paint(self, painter, option, index):
        super().paint(painter, option, index)
        if index.data(DIRTY):
            r = option.rect
            painter.save()
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor((theme.current() or {}).get("accent", "#2f6fed")))
            painter.drawEllipse(QRectF(r.right() - 18, r.center().y() - 4, 8, 8))
            painter.restore()


def _not_setting(w, page):
    while w is not None and w is not page:
        if w.property("notSetting"):
            return True
        w = w.parentWidget()
    return False


def signature(page):
    """What the person can type or tick on a page, as one comparable value (lists kept in memory are not part of it)."""
    out = []
    if not getattr(page, "track", True):
        return ()
    for w in page.findChildren(QWidget):
        if _not_setting(w, page):
            continue                                  # acts by its own buttons (Settings > Security's vault section)
        if isinstance(w, QLineEdit):
            if isinstance(w.parentWidget(), (QAbstractSpinBox, QComboBox)) and w.parentWidget().property("notSetting"):
                continue
            out.append(w.text())
        elif isinstance(w, QAbstractButton):
            if w.isCheckable() and not w.property("notSetting"):
                out.append(w.isChecked())
        elif isinstance(w, QComboBox) and not w.property("notSetting"):
            out.append((w.currentIndex(), w.currentText()))
        elif isinstance(w, QAbstractSpinBox):
            out.append(w.text())
        elif isinstance(w, (QPlainTextEdit, QTextEdit)) and not w.isReadOnly():
            out.append(w.toPlainText())
    extra = getattr(page, "describe_extra", None)
    if callable(extra):
        out.append(tuple(extra()))                  # settings held in a table or a tree
    return tuple(out)


class SettingsTab(QWidget):
    changed = Signal()                    # emitted after a successful save (or an import)
    orgs_changed = Signal()               # Settings > Organizations created, renamed, archived or removed one
    look_preview = Signal(object)         # Appearance: the look (theme, look, panels...) shown at once, before Save
    look_reset = Signal()                 # edits dropped (Cancel, Discard, reload): back to the saved look
    reset_requested = Signal()            # Data and logs > Reset Toner to factory settings: the window stops everything and wipes

    def __init__(self):
        super().__init__()
        self.pages = [GeneralPage(), ThresholdsPage(), ChecksPage(), ConnectionsPage(), ProxyPage(), AgentsPage(), DemarcPage(),
                      BackupsPage(), ScanningPage(), MaintenancePage(), NotificationsPage(), ProfilesPage(), AnsiblePage(), AiPage(), AppearancePage(), TerminalPage(), ReportsPage(), SecurityPage(),
                      AuditPage(), DataPage(self.reload), OrganizationsPage()]
        self.pages[-1].changed_orgs.connect(self.orgs_changed)
        self.pages[-2].reset_requested.connect(self.reset_requested)
        for i, p in enumerate(self.pages):
            if p.title == "Appearance":
                p.preview.connect(self.look_preview)
            if p.title == "Demarc":
                p.acted.connect(lambda i=i: self.rebase(only={i}))
        for p in self.pages:
            tidy(p)                                           # no drop-down or button stretches across a wide window
        self._texts = {}                                      # page index -> lower-case words on the page, for the search box
        from ui.finder import SearchBox
        self.search = SearchBox("Search settings", "Type a word to list only the pages that mention it.")
        self.search.setMaximumWidth(16777215)
        from PySide6.QtGui import QKeySequence, QShortcut
        QShortcut(QKeySequence("Ctrl+F"), self, activated=self._focus_search)
        self.nav = QListWidget()
        self.nav.setObjectName("settingsNav")
        self.nav.setSpacing(0)
        self.nav.setItemDelegate(_NavDelegate(self.nav))
        self.baseline = {}                                   # page index -> signature when last loaded or saved
        self.snaps = {}                                      # page index -> the page's settings in words, taken at the same time
        self._dirty = {}                                     # page index -> it differs from that
        self.stack = QStackedWidget()
        self.managed = {}                                     # page index -> its "Managed by Global" line
        self.own_lines = {}                                   # page index -> the line listing the organization's own values
        self.page_keys = {}                                   # page index -> the settings the page shows (read while it loads)
        for i, p in enumerate(self.pages):
            area = QScrollArea()
            area.setWidgetResizable(True)
            area.setFrameShape(QScrollArea.Shape.NoFrame)
            holder = QWidget()
            hl = QVBoxLayout(holder)
            hl.setContentsMargins(0, 0, 0, 0)
            if p.title in GLOBAL_PAGES:
                lab = self.managed[i] = QLabel("Managed by Global")
                lab.setProperty("banner", True)
                lab.setStyleSheet("font-weight:600; padding:6px 0;")
                lab.hide()
                hl.addWidget(lab)
            own = self.own_lines[i] = QLabel("")               # an organization's own values on this page, each with Reset to Global
            own.setWordWrap(True)
            own.setTextFormat(Qt.TextFormat.RichText)
            own.linkActivated.connect(lambda key, i=i: self.reset_to_global(i, key))
            own.hide()
            hl.addWidget(own)
            hl.addWidget(p, 1)
            area.setWidget(holder)
            self.stack.addWidget(area)
        self.scope_note = QLabel("Changes here only apply to this Organization.")    # shown while an organization is picked
        self.scope_note.setStyleSheet("font-weight:600; padding:2px 0 6px 0;")
        self.scope_note.hide()
        self._fill_nav()
        from ui.nav import fold_button
        left = self.left = QWidget()
        left.setFixedWidth(200)
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        self.fold = fold_button()
        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.setSpacing(4)
        top.addWidget(self.search, 1)
        top.addWidget(self.fold)
        ll.addLayout(top)
        ll.addWidget(self.nav, 1)
        ll.addStretch(0)                                     # folded, the button stays at the top
        self.fold.clicked.connect(lambda: self.show_list(not self.list_shown()))
        self.show_list(not db.get_setting("settings_list_hidden"), remember=False)
        self.nav.currentRowChanged.connect(self._nav_changed)
        self.search.textChanged.connect(self.filter_pages)
        self.search.returnPressed.connect(self._first_match)

        self.status = QLabel("")
        self.unsaved = QLabel("")                                       # "Unsaved changes on 2 pages", next to the buttons
        self.unsaved.setStyleSheet("font-weight:600;")
        save, cancel = self.save_btn, self.cancel_btn = QPushButton("Save changes"), QPushButton("Cancel")
        save.setProperty("primary", True)
        save.setDefault(True)
        save.clicked.connect(self.ask_save)                  # says what it is about to change, and asks
        cancel.clicked.connect(self.cancel)                  # drops the edits without asking
        bar = QHBoxLayout()
        bar.addWidget(self.status, 1)
        bar.addWidget(self.unsaved)
        bar.addWidget(cancel)
        bar.addWidget(save)
        right = QVBoxLayout()
        right.addWidget(self.stack, 1)
        right.addLayout(bar)
        body = QHBoxLayout()
        body.addWidget(left)
        body.addLayout(right, 1)
        lay = QVBoxLayout(self)
        lay.addWidget(self.scope_note)
        lay.addLayout(body, 1)
        self.select_page(self.pages[0].title)
        self.reload()
        self.watch = QTimer(self)                             # edits are noticed by looking, a few times a second, at the page in view
        self.watch.setInterval(500)
        self.watch.timeout.connect(self.check_dirty)
        self.watch.start()

    # ---------- unsaved edits
    def rebase(self, only=None):
        for i, p in enumerate(self.pages):
            if only is None or i in only:
                self.baseline[i] = signature(p)
                self.snaps[i] = SD.snapshot(p)
        self._mark()

    def dirty_pages(self):
        return [i for i, v in self._dirty.items() if v]

    def check_dirty(self, hidden_too=False):
        """Compare the page in view with how it was when loaded or saved; its list entry gets a dot if it differs."""
        if not (self.isVisible() or hidden_too):
            return
        i = self.stack.currentIndex()
        if i in self.baseline:
            self._dirty[i] = signature(self.pages[i]) != self.baseline[i]
            self._mark()

    def _mark(self):
        flags = self._dirty
        for i in self.baseline:
            flags.setdefault(i, False)
        by_page = {self._index_of(r): r for r in range(self.nav.count()) if self._index_of(r) is not None}
        for i, r in by_page.items():
            self.nav.item(r).setData(DIRTY, bool(flags.get(i)))
        self.nav.viewport().update()
        n = sum(1 for v in flags.values() if v)
        self.unsaved.setText(f"Unsaved changes on {n} page{'s' if n != 1 else ''}" if n else "")
        if n:
            self.status.setText("")

    # ---------- the list on the left
    def _fill_nav(self):
        by_title = {p.title: i for i, p in enumerate(self.pages)}
        placed, groups = set(), list(GROUPS)
        rest = [p.title for p in self.pages if not any(p.title in names for _, names in GROUPS)]
        if rest:
            groups.append(("Other", rest))
        for heading, names in groups:
            names = [n for n in names if n in by_title]
            if not names:
                continue
            h = QListWidgetItem(heading.upper())
            h.setFlags(Qt.ItemFlag.NoItemFlags)
            f = h.font()
            f.setBold(True)
            f.setPointSizeF(max(7.0, f.pointSizeF() - 2))
            h.setFont(f)
            h.setSizeHint(QSize(0, HEADING_HEIGHT if self.nav.count() else HEADING_HEIGHT - 10))
            h.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignBottom)
            self.nav.addItem(h)
            for n in names:
                it = QListWidgetItem(n)
                it.setData(Qt.ItemDataRole.UserRole, by_title[n])
                it.setSizeHint(QSize(0, ITEM_HEIGHT))
                self.nav.addItem(it)

    def _index_of(self, row):
        item = self.nav.item(row) if row >= 0 else None
        data = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return data if isinstance(data, int) else None

    def _nav_changed(self, row):
        i = self._index_of(row)
        if i is not None:
            self.stack.setCurrentIndex(i)

    def page_titles(self):
        """The pages in the order the list shows them."""
        return [self.nav.item(r).text() for r in range(self.nav.count()) if self._index_of(r) is not None]

    def select_page(self, title, tab=""):
        """Open a page by its name in the list. `tab` opens one of its tabs (Checks > Schedule)."""
        title, _, inline = title.partition("/")                          # "Checks/Schedule" works as well as ("Checks", "Schedule")
        tab = tab or inline
        for r in range(self.nav.count()):
            if self._index_of(r) is not None and self.nav.item(r).text() == title:
                self.search.clear() if self.nav.isRowHidden(r) else None
                self.nav.setCurrentRow(r)
                page = self.pages[self._index_of(r)]
                if tab and hasattr(page, "select_tab"):
                    page.select_tab(tab)
                return True
        return False

    def current_title(self):
        i = self.stack.currentIndex()
        return self.pages[i].title if 0 <= i < len(self.pages) else ""

    # ---------- search
    def _focus_search(self):
        """Ctrl+F: the open page's own search box (the audit log has one), else the one above the page list (shown again
        when it was folded away)."""
        page = self.pages[self.stack.currentIndex()] if 0 <= self.stack.currentIndex() < len(self.pages) else None
        box = getattr(page, "search", None)
        if box is not None and box.isVisible():
            box.focus_here()
            return
        if not self.list_shown():
            self.show_list(True)
        self.search.focus_here()

    # ---------- the page list, folded away for room
    def list_shown(self):
        return not self.nav.isHidden()

    def show_list(self, on, remember=True):
        from ui.nav import FOLD_WIDTH, show_fold
        self.search.setVisible(on)
        self.nav.setVisible(on)
        self.left.setFixedWidth(200 if on else FOLD_WIDTH)
        show_fold(self.fold, on)
        if remember:
            db.set_setting("settings_list_hidden", not on)

    def _page_text(self, i):
        """Everything a person could look for on a page: its title, labels, buttons, tick boxes and tooltips."""
        if i not in self._texts:
            page, words = self.pages[i], [self.pages[i].title]
            for w in page.findChildren(QWidget):
                if isinstance(w, (QLabel, QAbstractButton)):
                    words.append(w.text())
                if w.toolTip():
                    words.append(w.toolTip())
            self._texts[i] = re.sub(r"<[^>]+>|&", " ", " ".join(words)).lower()
        return self._texts[i]

    def filter_pages(self, text=""):
        """Show only the pages that mention every word typed (and the group headings that still have a page)."""
        words = text.lower().split()
        shown, heading = 0, None
        rows = list(range(self.nav.count()))
        visible_in_group = {}
        for r in rows:
            i = self._index_of(r)
            if i is None:
                heading = r
                visible_in_group[heading] = 0
                continue
            ok = all(w in self._page_text(i) for w in words) and not self._hidden(i)
            self.nav.setRowHidden(r, not ok)
            if ok:
                visible_in_group[heading] = visible_in_group.get(heading, 0) + 1
                shown += 1
        for h, n in visible_in_group.items():
            self.nav.setRowHidden(h, n == 0)
        cur = self._index_of(self.nav.currentRow())
        if (cur is None or self.nav.isRowHidden(self.nav.currentRow())) and shown:
            self._first_match()
        return shown

    def _first_match(self):
        for r in range(self.nav.count()):
            if self._index_of(r) is not None and not self.nav.isRowHidden(r):
                self.nav.setCurrentRow(r)
                return

    def _hidden(self, i):
        """A page that does not apply where we are (Organizations, inside an organization)."""
        return db.home() != db.GLOBAL and self.pages[i].title in GLOBAL_ONLY_PAGES

    def apply_org(self):
        """Global or an organization: the line at the top, read-only pages managed by Global, and the Organizations page."""
        inside = db.home() != db.GLOBAL
        self.scope_note.setVisible(inside)
        for i, lab in self.managed.items():
            lab.setVisible(inside)
            self.pages[i].setEnabled(not inside)
        for p in self.pages:                                  # single settings about this computer on an organization's pages
            for w in p.findChildren(QWidget):
                if w.property("globalOnly"):
                    if w.property("tipBefore") is None:
                        w.setProperty("tipBefore", w.toolTip())
                    w.setEnabled(not inside)
                    w.setToolTip("Managed by Global" if inside else w.property("tipBefore"))
        self.filter_pages(self.search.text())
        cur = self._index_of(self.nav.currentRow())
        if cur is None or self._hidden(cur):
            self._first_match()

    def _load_page(self, i):
        """Load one page, noting which settings it shows (so its organization's own values can be listed)."""
        real, seen = db._raw_setting, set()

        def spy(key):
            seen.add(key)
            return real(key)
        db._raw_setting = spy
        try:
            self.pages[i].load()
        finally:
            db._raw_setting = real
        self.page_keys[i] = seen

    def show_own(self):
        """In an organization: on each page, the settings it changes from Global, each with a Reset to Global link."""
        inside = db.home() != db.GLOBAL
        for i, lab in self.own_lines.items():
            keys = sorted(k for k in self.page_keys.get(i, ()) if inside and db.overridden(k)) if self.pages[i].title not in GLOBAL_PAGES else []
            lab.setText("<br>".join(f"<b>{KEY_LABELS.get(k, k.replace('_', ' ').capitalize())}</b> is set for this organization. "
                                    f"<a href='{k}'>Reset to Global</a>" for k in keys))
            lab.setVisible(bool(keys))

    def reset_to_global(self, i, key):
        """Forget the organization's own value of one setting: it follows Global again (right away)."""
        db.follow_global(key)
        audit.log("setting reset to Global", KEY_LABELS.get(key, key))
        self._load_page(i)
        self.rebase(only={i})
        self.show_own()
        self.changed.emit()
        toast(self, f"{KEY_LABELS.get(key, key)} follows Global again.")

    def reload(self, announce=True):
        """Show what is stored, discarding unsaved edits (and a look being previewed). announce=False: no `changed` signal, for a
        caller that makes the settings take effect itself."""
        self.look_reset.emit()
        self.apply_org()
        for i in range(len(self.pages)):
            self._load_page(i)
        self.show_own()
        self.status.setText("")
        self._dirty = {}
        self.rebase()
        if announce:
            self.changed.emit()

    def refresh_dynamic(self):
        clean = [i for i in range(len(self.pages)) if i in self.baseline and signature(self.pages[i]) == self.baseline[i]]
        for p in self.pages:
            p.refresh()
        self.rebase(only=set(clean))              # a list that refilled itself is not an edit

    def showEvent(self, e):
        self.refresh_dynamic()
        super().showEvent(e)

    # ---------- asking before Save, and before leaving with unsaved edits
    def pending_changes(self):
        """[(page title, [(setting, stored value, value now)])] for every page whose settings differ from what was loaded or saved."""
        groups = []
        for i, p in enumerate(self.pages):
            rows = SD.changes(self.snaps.get(i, {}), SD.snapshot(p))
            if rows:
                groups.append((p.title, rows))
        return groups

    def _problems(self):
        problems, first_bad = [], None
        for i, p in enumerate(self.pages):
            found = p.validate()
            if found and first_bad is None:
                first_bad = i
            problems += found
        return problems, first_bad

    def ask_save(self):
        """Save changes: list what will change (page, setting, from, to) and wait for a yes. Problems are reported first."""
        problems, _ = self._problems()
        groups = self.pending_changes()
        if problems or not groups:                           # nothing to list (or something to fix first): the plain save says so
            self.save()
            return
        dlg = SD.ConfirmChanges(self, "Save changes", "These {n} setting{s} will be changed. Save them?", ("Now", "Will become"), groups,
                                "Save changes", "Keep editing")
        if dlg.exec():
            self.save()

    def unsaved_count(self):
        """How many pages have edits that are not saved (looking again at the page in view, for an edit made a moment ago)."""
        self.check_dirty(hidden_too=True)
        return len({self.pages[i].title for i in self.dirty_pages()} | {title for title, _rows in self.pending_changes()})

    def cancel(self):
        """Cancel: every page goes back to what was last saved, without asking."""
        if self.unsaved_count():
            self.reload()

    def confirm_leave(self, before="leaving Settings", reload=True):
        """Unsaved edits when leaving Settings (or switching organization, or closing Toner): Save changes, Discard changes or Stay in
        Settings. True when it is fine to go on. Save changes is the usual Save (it lists the changes and asks)."""
        n = self.unsaved_count()
        if not n:
            return True
        box = QMessageBox(QMessageBox.Icon.Warning, "Unsaved settings",
                          f"You have unsaved changes on {n} page{'s' if n != 1 else ''}.\nSave them before {before}?", parent=self)
        save = box.addButton("Save changes", QMessageBox.ButtonRole.ActionRole)
        discard = box.addButton("Discard changes", QMessageBox.ButtonRole.ActionRole)
        stay = box.addButton("Stay in Settings", QMessageBox.ButtonRole.ActionRole)
        box.setDefaultButton(save)                           # (all one role, so they stay in this order)
        box.setEscapeButton(stay)
        box.exec()
        if box.clickedButton() is save:
            self.ask_save()
            return not self.unsaved_count()                  # kept editing, or something to fix first: stay
        if box.clickedButton() is discard:
            if reload:
                self.reload()
            else:
                self._dirty = {}
            return True
        return False

    def save(self):
        problems, first_bad = self._problems()
        if problems:
            self.search.clear()
            self.select_page(self.pages[first_bad].title)
            QMessageBox.warning(self, "Cannot save", "Please fix:\n\n" + "\n".join(f"\u2022 {p}" for p in problems))
            return
        for p in self.pages:
            p.save()
        audit.log("settings saved")
        self._dirty = {}
        self.rebase()
        self.show_own()
        self.status.setText(f"Saved at {datetime.now():%H:%M:%S}")
        self.changed.emit()

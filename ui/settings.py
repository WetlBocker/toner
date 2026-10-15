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



# The order and grouping of the list on the left. A page that is not named here still appears, under "Other".
GROUPS = [("Monitoring", ["General", "Thresholds", "Checks", "Maintenance"]),
          ("Connections", ["Connections", "Proxy", "Credentials", "Agents"]),
          ("Alerts and reports", ["Notifications", "Reports", "Config backups"]),
          ("Automation", ["Ansible"]),
          ("Look and feel", ["Appearance", "Terminal"]),
          ("Security and data", ["Security", "Audit log", "Data and logs"])]


DIRTY = Qt.ItemDataRole.UserRole + 1          # on a list entry: the page has edits that are not saved yet


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


def signature(page):
    """What the person can type or tick on a page, as one comparable value (lists kept in memory are not part of it)."""
    out = []
    if not getattr(page, "track", True):
        return ()
    for w in page.findChildren(QWidget):
        if isinstance(w, QLineEdit):
            out.append(w.text())
        elif isinstance(w, QAbstractButton):
            if w.isCheckable() and not w.property("notSetting"):
                out.append(w.isChecked())
        elif isinstance(w, QComboBox):
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

    def __init__(self):
        super().__init__()
        self.pages = [GeneralPage(), ThresholdsPage(), ChecksPage(), ConnectionsPage(), ProxyPage(), AgentsPage(),
                      BackupsPage(), MaintenancePage(), NotificationsPage(), ProfilesPage(), AnsiblePage(), AppearancePage(), TerminalPage(), ReportsPage(), SecurityPage(),
                      AuditPage(), DataPage(self.reload)]
        for p in self.pages:
            tidy(p)                                           # no drop-down or button stretches across a wide window
        self._texts = {}                                      # page index -> lower-case words on the page, for the search box
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search settings")
        self.search.setClearButtonEnabled(True)
        self.nav = QListWidget()
        self.nav.setObjectName("settingsNav")
        self.nav.setSpacing(0)
        self.nav.setItemDelegate(_NavDelegate(self.nav))
        self.baseline = {}                                   # page index -> signature when last loaded or saved
        self.snaps = {}                                      # page index -> the page's settings in words, taken at the same time
        self._dirty = {}                                     # page index -> it differs from that
        self.stack = QStackedWidget()
        for p in self.pages:
            area = QScrollArea()
            area.setWidgetResizable(True)
            area.setFrameShape(QScrollArea.Shape.NoFrame)
            area.setWidget(p)
            self.stack.addWidget(area)
        self._fill_nav()
        left = QWidget()
        left.setFixedWidth(200)
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.addWidget(self.search)
        ll.addWidget(self.nav, 1)
        self.nav.currentRowChanged.connect(self._nav_changed)
        self.search.textChanged.connect(self.filter_pages)
        self.search.returnPressed.connect(self._first_match)

        self.status = QLabel("")
        self.unsaved = QLabel("")                                       # "Unsaved changes on 2 pages", next to the buttons
        self.unsaved.setStyleSheet("font-weight:600;")
        save, revert = self.save_btn, self.revert_btn = QPushButton("Save changes"), QPushButton("Revert")
        save.setProperty("primary", True)
        save.setDefault(True)
        save.clicked.connect(self.ask_save)                  # both say what they are about to change, and ask
        revert.clicked.connect(self.ask_revert)
        bar = QHBoxLayout()
        bar.addWidget(self.status, 1)
        bar.addWidget(self.unsaved)
        bar.addWidget(revert)
        bar.addWidget(save)
        right = QVBoxLayout()
        right.addWidget(self.stack, 1)
        right.addLayout(bar)
        body = QHBoxLayout()
        body.addWidget(left)
        body.addLayout(right, 1)
        lay = QVBoxLayout(self)
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

    def check_dirty(self):
        """Compare the page in view with how it was when loaded or saved; its list entry gets a dot if it differs."""
        if not self.isVisible():
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
            ok = all(w in self._page_text(i) for w in words)
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

    def reload(self):
        """Show what is stored, discarding unsaved edits."""
        for p in self.pages:
            p.load()
        self.status.setText("")
        self._dirty = {}
        self.rebase()
        self.changed.emit()

    def refresh_dynamic(self):
        clean = [i for i in range(len(self.pages)) if i in self.baseline and signature(self.pages[i]) == self.baseline[i]]
        for p in self.pages:
            p.refresh()
        self.rebase(only=set(clean))              # a list that refilled itself is not an edit

    def showEvent(self, e):
        self.refresh_dynamic()
        super().showEvent(e)

    # ---------- asking before Save and Revert
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

    def ask_revert(self):
        """Revert: list what the edits are and what each goes back to, and wait for a yes."""
        groups = [(title, [(name, now, stored) for name, stored, now in rows]) for title, rows in self.pending_changes()]
        if not groups:
            toast(self, "Nothing to revert: every setting is as it was saved.")
            return
        dlg = SD.ConfirmChanges(self, "Revert changes", "These {n} edited setting{s} will go back to what was last saved. Revert them?",
                                ("Your edit", "Goes back to"), groups, "Revert", "Keep editing")
        if dlg.exec():
            self.reload()

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
        self.status.setText(f"Saved at {datetime.now():%H:%M:%S}")
        self.changed.emit()

"""Settings tab: a category list on the left, one page per category, one Save for everything.

Pages whose controls change data immediately (forget a host key, back up the database, ...)
say so on the page; everything else waits for 'Save changes'."""
import json
import re
import os
import sqlite3
from datetime import datetime, timedelta

import keyring
from PySide6.QtCore import QDateTime, QSize, QTime, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont
from PySide6.QtWidgets import (QAbstractButton, QAbstractItemView, QApplication, QCheckBox, QColorDialog, QComboBox, QDialog,
                               QDateTimeEdit, QDialogButtonBox, QDoubleSpinBox, QFileDialog, QFontComboBox, QFormLayout,
                               QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMenu, QMessageBox, QPushButton,
                               QScrollArea, QSpinBox, QStackedWidget, QTableWidget, QTableWidgetItem, QTimeEdit,
                               QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)
import ipaddress
from core import agents, alerts, audit, checks, custom, db, display, maintenance, nettools, notify, profiles, proxy, reports, sessionlog, trends, vault
from ui import terminal, theme
from ui.snmpfields import SnmpFields
from ui.widgets import GroupPicker
from ui.nav import HEADING_HEIGHT, ITEM_HEIGHT
from ui.settings_base import Page, TrimSpin, note, row_of, spin  # noqa: F401  (re-exported: other modules and the tests use them)
from ui.settings_pages.general import GeneralPage, ConnectionsPage, _bad_pair, ThresholdsPage, ChecksPage, AutomationPage  # noqa: F401
from ui.settings_pages.appearance import AppearancePage, TerminalPage, ReportsPage  # noqa: F401
from ui.settings_pages.notifications import ChannelDialog, NotificationsPage  # noqa: F401
from ui.settings_pages.security import SecurityPage, DataPage  # noqa: F401
from ui.settings_pages.profiles import ProfileDialog, ProfilesPage  # noqa: F401
from ui.settings_pages.checks import CheckDialog, row_of_layout, CustomChecksPage, BackupsPage, AuditPage  # noqa: F401
from ui.settings_pages.network import ProxyPage, AgentsPage, MaintenanceDialog, MaintenancePage  # noqa: F401



# The order and grouping of the list on the left. A page that is not named here still appears, under "Other".
GROUPS = [("Monitoring", ["General", "Thresholds", "Checks", "Custom checks", "Automation", "Maintenance"]),
          ("Connections", ["Connections", "Proxy", "Credentials", "Agents"]),
          ("Alerts and reports", ["Notifications", "Reports", "Config backups"]),
          ("Look and feel", ["Appearance", "Terminal"]),
          ("Security and data", ["Security", "Audit log", "Data and logs"])]


class SettingsTab(QWidget):
    changed = Signal()                    # emitted after a successful save (or an import)

    def __init__(self):
        super().__init__()
        self.pages = [GeneralPage(), ThresholdsPage(), ChecksPage(), CustomChecksPage(), ConnectionsPage(), ProxyPage(), AgentsPage(), AutomationPage(),
                      BackupsPage(), MaintenancePage(), NotificationsPage(), ProfilesPage(), AppearancePage(), TerminalPage(), ReportsPage(), SecurityPage(),
                      AuditPage(), DataPage(self.reload)]
        self._texts = {}                                      # page index -> lower-case words on the page, for the search box
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search settings")
        self.search.setClearButtonEnabled(True)
        self.nav = QListWidget()
        self.nav.setObjectName("settingsNav")
        self.nav.setSpacing(0)
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
        save, revert = QPushButton("Save changes"), QPushButton("Revert")
        save.setProperty("primary", True)
        save.setDefault(True)
        save.clicked.connect(self.save)
        revert.clicked.connect(self.reload)
        bar = QHBoxLayout()
        bar.addWidget(self.status, 1)
        bar.addWidget(revert)
        bar.addWidget(save)
        right = QVBoxLayout()
        right.addWidget(self.stack, 1)
        right.addLayout(bar)
        lay = QHBoxLayout(self)
        lay.addWidget(left)
        lay.addLayout(right, 1)
        self.select_page(self.pages[0].title)
        self.reload()

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

    def select_page(self, title):
        for r in range(self.nav.count()):
            if self._index_of(r) is not None and self.nav.item(r).text() == title:
                self.search.clear() if self.nav.isRowHidden(r) else None
                self.nav.setCurrentRow(r)
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
        self.changed.emit()

    def refresh_dynamic(self):
        for p in self.pages:
            p.refresh()

    def showEvent(self, e):
        self.refresh_dynamic()
        super().showEvent(e)

    def save(self):
        problems = []
        first_bad = None
        for i, p in enumerate(self.pages):
            found = p.validate()
            if found and first_bad is None:
                first_bad = i
            problems += found
        if problems:
            self.search.clear()
            self.select_page(self.pages[first_bad].title)
            QMessageBox.warning(self, "Cannot save", "Please fix:\n\n" + "\n".join(f"\u2022 {p}" for p in problems))
            return
        for p in self.pages:
            p.save()
        audit.log("settings saved")
        self.status.setText(f"Saved at {datetime.now():%H:%M:%S}")
        self.changed.emit()

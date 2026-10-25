"""Configs section: back devices up, browse versions, see what changed, search every stored configuration."""
from datetime import datetime

from PySide6.QtCore import QRegularExpression, Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont, QFontDatabase, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
                               QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QSplitter,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)
from core import audit, backup, db, display, scope
from drivers.base import SEVERITY
from ui import theme
from ui.widgets import EmptyHint, filling, remember_sizes
from ui.finder import FilterButton, SearchBox, device_sections, listed_devices, shown_devices, wants_archived
from ui.toast import toast
from ui import status as st


class DiffHighlighter(QSyntaxHighlighter):
    """Colours added and removed lines of a unified diff."""

    def highlightBlock(self, text):
        dark = theme.current().get("dark", False)
        fmt = QTextCharFormat()
        if text.startswith("+") and not text.startswith("+++"):
            fmt.setBackground(QColor(22, 101, 52, 120) if dark else QColor(187, 247, 208))
        elif text.startswith("-") and not text.startswith("---"):
            fmt.setBackground(QColor(153, 27, 27, 120) if dark else QColor(254, 202, 202))
        elif text.startswith("@@"):
            fmt.setForeground(QColor("#8b5cf6" if not dark else "#a78bfa"))
            fmt.setFontWeight(QFont.Weight.Bold)
        elif text.startswith("+++") or text.startswith("---"):
            fmt.setForeground(QColor(theme.current().get("muted", "#777")))
        else:
            return
        self.setFormat(0, len(text), fmt)


class BackupWorker(QThread):
    one = Signal(object)                 # a Result as each device finishes
    done = Signal(list)

    def __init__(self, devices, workers, opts):
        super().__init__()
        self.devices, self.workers, self.opts = devices, workers, opts

    def run(self):
        res = backup.backup_many(self.devices, self.workers, on_result=self.one.emit, opts=self.opts)
        self.done.emit(res)


class SearchDialog(QDialog):
    jump = Signal(str, int)              # device, backup id

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Search configurations")
        self.resize(820, 520)
        self.box = QLineEdit()
        self.box.setPlaceholderText("text to find, e.g.  snmp-server community   or   10.9.9.9")
        self.regex = QPushButton("Regex")
        self.regex.setCheckable(True)
        self.all_versions = QPushButton("All versions")
        self.all_versions.setCheckable(True)
        self.all_versions.setToolTip("Also search older versions, not only the newest copy of each device")
        go = QPushButton("Search")
        go.setProperty("primary", True)
        go.clicked.connect(self.run)
        self.box.returnPressed.connect(self.run)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Device", "Backup taken", "Line", "Text"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.doubleClicked.connect(self.open_row)
        self.info = QLabel("")
        self.info.setProperty("muted", True)
        top = QHBoxLayout()
        for w in (self.box, self.regex, self.all_versions, go):
            top.addWidget(w, 1 if w is self.box else 0)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.table, 1)
        lay.addWidget(self.info)
        self.hits = []
        self.devices = None

    def run(self):
        text = self.box.text()
        if not text.strip():
            return
        try:
            self.hits = backup.search(text, self.devices, regex=self.regex.isChecked(),
                                      all_versions=self.all_versions.isChecked())
        except Exception as e:
            self.info.setText(f"Search failed: {e}")
            return
        self.table.setRowCount(len(self.hits))
        for i, h in enumerate(self.hits):
            for j, v in enumerate([db.label(h["device"]), h["taken_at"], str(h["line_no"]), h["line"]]):
                self.table.setItem(i, j, QTableWidgetItem(v))
        self.table.resizeColumnsToContents()
        self.info.setText(f"{len(self.hits)} match(es)" + ("  (stopped at the limit)" if len(self.hits) >= 500 else "")
                          + "  -  double-click a row to open that backup")

    def open_row(self, *_):
        r = self.table.currentRow()
        if 0 <= r < len(self.hits):
            self.jump.emit(self.hits[r]["device"], self.hits[r]["id"])
            self.accept()


class ConfigsTab(QWidget):
    backed_up = Signal(list, list, bool)         # results, device names, scheduled

    def __init__(self):
        super().__init__()
        self.worker = None
        self.versions = []
        self.find = SearchBox("Search devices", "Type part of a name, address, vendor, location, tag or detail. Several words must all match.",
                              page=self)
        self.funnel = FilterButton(lambda: device_sections(listed_devices(self.funnel)))
        self.find.textChanged.connect(lambda _t: self.refresh())
        self.funnel.changed.connect(self.refresh)
        self.run_btn = QPushButton("Back up now")
        self.run_btn.setToolTip("Backs up the devices shown")
        self.run_btn.setProperty("primary", True)
        self.run_btn.clicked.connect(self.start)
        self.one_btn = QPushButton("Back up selected")
        self.one_btn.clicked.connect(lambda: self.current_device() and self._start([], False, only=self.current_device()))
        self.search_btn = QPushButton("Search configs...")
        self.search_btn.clicked.connect(self.search)
        self.status = QLabel("")
        self.status.setProperty("muted", True)

        self.devs = QTableWidget(0, 6)
        self.devs.setHorizontalHeaderLabels(["Device", "Vendor", "Versions", "Last backup", "State", "Organization"])
        self.vers = QTableWidget(0, 4)
        self.vers.setHorizontalHeaderLabels(["Taken", "Size", "Lines", "Change"])
        for t in (self.devs, self.vers):
            t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            t.verticalHeader().setVisible(False)
            t.setShowGrid(False)
            t.horizontalHeader().setStretchLastSection(True)
        self.devs.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)          # fit the pane instead of scrolling sideways
        self.devs.setTextElideMode(Qt.TextElideMode.ElideRight)
        hh = self.devs.horizontalHeader()
        hh.setStretchLastSection(False)
        for col, mode in ((0, hh.ResizeMode.ResizeToContents), (1, hh.ResizeMode.Stretch), (2, hh.ResizeMode.ResizeToContents),
                          (3, hh.ResizeMode.ResizeToContents), (4, hh.ResizeMode.ResizeToContents), (5, hh.ResizeMode.ResizeToContents)):
            hh.setSectionResizeMode(col, mode)
        self.devs.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.vers.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.devs.itemSelectionChanged.connect(self.show_versions)
        self.vers.itemSelectionChanged.connect(self.show_text)
        self.hint = EmptyHint(self.devs, "No devices to back up", "Add devices on the Inventory tab")
        self.vers_hint = EmptyHint(self.vers, "No saved versions", "Select a device on the left, then press Back up now",
                                   actions=[("Back up now", lambda: self.start())])

        self.view = QComboBox()
        self.view.addItem("Changes from the previous version", "diff")
        self.view.addItem("Full configuration", "full")
        self.view.currentIndexChanged.connect(self.show_text)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setPlaceholderText("The configuration of the selected version appears here.")
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.text.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.highlighter = DiffHighlighter(self.text.document())
        self.note = QLabel("")
        self.note.setProperty("muted", True)
        self.save_btn, self.copy_btn, self.prune_btn = QPushButton("Save as..."), QPushButton("Copy"), QPushButton("Delete older versions...")
        self.save_btn.clicked.connect(self.save_version)
        self.copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.text.toPlainText()))
        self.prune_btn.clicked.connect(self.prune)

        top = QHBoxLayout()
        top.setSpacing(10)
        top.addWidget(self.run_btn)
        top.addWidget(self.one_btn)
        top.addWidget(self.search_btn)
        top.addSpacing(8)
        top.addWidget(self.status, 1)
        top.addWidget(self.find, 1)                    # on the right, as on Inventory
        top.addWidget(self.funnel)
        right_bar = QHBoxLayout()
        right_bar.addWidget(QLabel("Show"))
        right_bar.addWidget(self.view)
        right_bar.addWidget(self.note, 1)
        right_bar.addWidget(self.copy_btn)
        right_bar.addWidget(self.save_btn)
        right_bar.addWidget(self.prune_btn)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rsplit = QSplitter(Qt.Orientation.Vertical)
        rsplit.addWidget(self.vers)
        box = QWidget()
        bl = QVBoxLayout(box)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.addLayout(right_bar)
        bl.addWidget(self.text, 1)
        rsplit.addWidget(box)
        rsplit.setSizes([170, 450])
        remember_sizes(rsplit, "configs_versions")
        rl.addWidget(rsplit)
        split = QSplitter()
        split.addWidget(self.devs)
        split.addWidget(right)
        self.devs.setMinimumWidth(440)                 # the device name keeps room to be read; the other columns fit their contents
        split.setCollapsible(0, False)
        split.setSizes([560, 620])
        remember_sizes(split, "configs")
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(split, 1)
        self.names = []
        self.refresh()

    # ---------- the device list
    def refresh(self):
        keep = self.current_device()
        every = listed_devices(self.funnel)
        devs = shown_devices(every, self.find, self.funnel)
        with db.including_archived(wants_archived(self.funnel)):
            info = backup.summary()
        self.names = [d["key"] for d in devs]
        self.devs.setColumnHidden(5, not db.several())        # the Organization column: Global lists every organization
        self.devs.blockSignals(True)
        with filling(self.devs):
            self.devs.setRowCount(len(devs))
            for i, d in enumerate(devs):
                s = info.get(d["key"], {})
                state = ("not supported" if not backup.supported(d) else
                         {"error": "last backup FAILED", "changed": "changed", "new": "ok", "unchanged": "ok"}.get(s.get("status"), "never backed up"))
                for j, v in enumerate([d["name"], display.vendor_name(d["vendor"]), str(s.get("versions", 0)),
                                       (s.get("last", "") or "")[:16], state, db.org_name(d["org"])]):
                    it = QTableWidgetItem(v)
                    if j == 4 and state == "last backup FAILED":
                        it.setForeground(st.qink("FAIL"))
                    self.devs.setItem(i, j, it)
        self.devs.resizeColumnsToContents()
        self.devs.blockSignals(False)
        self.hint.setVisible(not every)
        self.devs.blockSignals(True)
        if keep in self.names:
            self.devs.selectRow(self.names.index(keep))
        self.devs.blockSignals(False)
        self.show_versions()                  # always reload: the selection may not have changed but the data did

    def current_device(self):
        r = self.devs.currentRow() if self.devs.selectedItems() else -1
        return self.names[r] if 0 <= r < len(self.names) else None

    def select_device(self, name, backup_id=None):
        if name in self.names:
            self.devs.selectRow(self.names.index(name))
            if backup_id is not None:
                for i, v in enumerate(self.versions):
                    if v["id"] == backup_id:
                        self.vers.selectRow(i)
                        self.view.setCurrentIndex(self.view.findData("full"))
                        break

    # ---------- versions and text
    def show_versions(self):
        name = self.current_device()
        self.versions = backup.list_backups(name) if name else []
        self.vers.setRowCount(len(self.versions))
        for i, v in enumerate(self.versions):
            change = "first copy" if i == len(self.versions) - 1 else f"+{v['added']} / -{v['removed']}"
            for j, val in enumerate([v["taken_at"], f"{v['size']:,} bytes", str(v["lines"]), change]):
                self.vers.setItem(i, j, QTableWidgetItem(val))
        self.vers.resizeColumnsToContents()
        self.vers_hint.setVisible(not self.versions)
        if self.versions:
            self.vers.selectRow(0)
        else:
            self.text.setPlainText("" if not name else "No backup of this device yet. Use 'Back up now'.")
            self.note.setText("")

    def selected_rows(self):
        return sorted({i.row() for i in self.vers.selectedItems()})

    def show_text(self, *_):
        rows = self.selected_rows()
        if not rows or not self.versions:
            return
        mode = self.view.currentData()
        name = self.current_device()
        if len(rows) >= 2:                                           # compare any two versions
            a, b = self.versions[rows[-1]], self.versions[rows[0]]  # older, newer (list is newest first)
            lines, ad, rm = backup.diff_lines(backup.get_text(a["id"], a["org"]), backup.get_text(b["id"], b["org"]),
                                              f"{db.label(name)} {a['taken_at']}", f"{db.label(name)} {b['taken_at']}")
            self.highlighter.setDocument(self.text.document())
            self.text.setPlainText("\n".join(lines) if lines else "These two versions are identical.")
            self.note.setText(f"Comparing {a['taken_at']} with {b['taken_at']}:  +{ad} / -{rm}")
            return
        v = self.versions[rows[0]]
        if mode == "diff":
            older = self.versions[rows[0] + 1] if rows[0] + 1 < len(self.versions) else None
            if older is None:
                self.text.setPlainText("This is the first copy, so there is nothing to compare it with.\n"
                                       "Switch to 'Full configuration' to read it.")
                self.note.setText(v["taken_at"])
            else:
                lines, ad, rm = backup.diff_lines(backup.get_text(older["id"], older["org"]), backup.get_text(v["id"], v["org"]),
                                                  f"{db.label(name)} {older['taken_at']}", f"{db.label(name)} {v['taken_at']}")
                self.text.setPlainText("\n".join(lines) if lines else "No difference.")
                self.note.setText(f"{older['taken_at']} -> {v['taken_at']}:  +{ad} / -{rm}")
        else:
            self.text.setPlainText(backup.get_text(v["id"], v["org"]))
            self.note.setText(f"{v['taken_at']}  ({v['lines']} lines)")

    def save_version(self):
        rows = self.selected_rows()
        name = self.current_device()
        if not rows or not name:
            return
        v = self.versions[rows[0]]
        stamp = v["taken_at"].replace(":", "").replace(" ", "_").replace("-", "")
        path, _ = QFileDialog.getSaveFileName(self, "Save configuration", f"{db.label(name)}_{stamp}.txt", "Text files (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(backup.get_text(v["id"], v["org"]))

    def prune(self):
        name = self.current_device()
        if name and len(self.versions) > 1 and QMessageBox.question(
                self, "Delete older versions",
                f"Keep only the newest copy of {db.label(name)} and delete {len(self.versions) - 1} older version(s)?") \
                == QMessageBox.StandardButton.Yes:
            backup.delete_versions(name, 1)
            audit.log("config versions deleted", db.label(name))
            self.refresh()

    # ---------- backing up
    def running(self):
        return bool(self.worker and self.worker.isRunning())

    def start(self):
        """Back up the devices shown (the search box and the funnel decide; with neither, every device)."""
        self._start([], scheduled=False, among=set(self.names))

    def start_scheduled(self, labels):
        if not self.running():
            self._start(labels, scheduled=True)

    def _start(self, labels, scheduled, only=None, among=None):
        if self.running():
            return
        devices = [d for d in listed_devices(self.funnel, enabled_only=True) if db.in_groups(d, labels) and (only is None or d["key"] == only)
                   and (among is None or d["key"] in among)]
        if scheduled:                                        # a schedule covers the organization's own devices (Global's: its own and Shared)
            devices = [d for d in devices if d.get("org", db.home()) == db.home()]
        if not scheduled:
            devices = scope.keep(devices)
        if not devices:
            if not scheduled:
                toast(self, "No enabled devices are shown." if among is not None else "No enabled devices in this group.")
            return
        self.scheduled = scheduled
        self.run_btn.setEnabled(False)
        self.one_btn.setEnabled(False)
        self.status.setText(f"{'Scheduled backup: ' if scheduled else ''}backing up {len(devices)} device(s)...")
        self.done_count = 0
        self.total = len(devices)
        self.ran = [d["key"] for d in devices]
        self.worker = BackupWorker(devices, min(5, int(db.get_setting("workers"))), db.runtime_options())
        self.worker.one.connect(self._one)
        self.worker.done.connect(self._done)
        self.worker.start()

    def _one(self, r):
        self.done_count += 1
        self.status.setText(f"Backed up {self.done_count} of {self.total}...")

    def _done(self, results):
        self.run_btn.setEnabled(True)
        self.one_btn.setEnabled(True)
        n = lambda v: sum(1 for r in results if r.value == v)
        changed = sum(1 for r in results if r.status == "WARN")
        errors = sum(1 for r in results if r.status == "ERROR")
        self.status.setText(f"Done: {changed} changed, {errors} failed, "
                            f"{sum(1 for r in results if r.status == 'OK' and r.value in ('unchanged', 'first copy'))} unchanged or new.")
        audit.log("config backup", f"{len(results)} device(s), {changed} changed, {errors} failed")
        if results:
            self.refresh()
            self.backed_up.emit(results, self.ran, self.scheduled)

    def search(self):
        dlg = SearchDialog(self)
        dlg.jump.connect(self.select_device)
        dlg.exec()

    def shutdown(self):
        if self.running():
            self.worker.wait(30000)


    def screen_context(self):
        """What the Assistant is told about this page: the device, the version(s) chosen, and the text shown (a configuration or a diff)."""
        name = self.current_device()
        out = {"page": "Configs", "selected_device": db.label(name) if name else ""}
        rows = self.selected_rows()
        if name and rows and self.versions:
            out["selected_versions"] = [{"id": self.versions[r]["id"], "taken_at": self.versions[r]["taken_at"]} for r in rows if r < len(self.versions)]
            comparing = len(rows) >= 2 or self.view.currentData() == "diff"
            out["view"] = "comparison" if len(rows) >= 2 else ("changes from the previous version" if comparing else "full configuration")
            out["note"] = self.note.text()
            text = self.text.toPlainText() if comparing else backup.clean(self.text.toPlainText(), mask=True)
            out["text"] = text[:20000] + ("\n[cut]" if len(text) > 20000 else "")
        return out

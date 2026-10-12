"""Configs section: back devices up, browse versions, see what changed, search every stored configuration."""
from datetime import datetime

from PySide6.QtCore import QRegularExpression, Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont, QFontDatabase, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
                               QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QSplitter,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)
from core import audit, backup, db, display
from drivers.base import SEVERITY
from ui import theme
from ui.widgets import EmptyHint, GroupPicker
from ui.toast import toast


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
            for j, v in enumerate([h["device"], h["taken_at"], str(h["line_no"]), h["line"]]):
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
        self.group = GroupPicker()
        self.group.set_labels(db.group_labels()[1:])
        self.run_btn = QPushButton("Back up now")
        self.run_btn.setProperty("primary", True)
        self.run_btn.clicked.connect(self.start)
        self.one_btn = QPushButton("Back up selected")
        self.one_btn.clicked.connect(lambda: self.current_device() and self._start([], False, only=self.current_device()))
        self.search_btn = QPushButton("Search configs...")
        self.search_btn.clicked.connect(self.search)
        self.status = QLabel("")
        self.status.setProperty("muted", True)

        self.devs = QTableWidget(0, 5)
        self.devs.setHorizontalHeaderLabels(["Device", "Vendor", "Versions", "Last backup", "State"])
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
        for col, mode in ((0, hh.ResizeMode.Stretch), (1, hh.ResizeMode.ResizeToContents), (2, hh.ResizeMode.ResizeToContents),
                          (3, hh.ResizeMode.ResizeToContents), (4, hh.ResizeMode.ResizeToContents)):
            hh.setSectionResizeMode(col, mode)
        self.devs.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.vers.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.devs.itemSelectionChanged.connect(self.show_versions)
        self.vers.itemSelectionChanged.connect(self.show_text)
        self.hint = EmptyHint(self.devs, "No devices to back up", "Add devices on the Inventory tab")
        self.vers_hint = EmptyHint(self.vers, "No saved versions", "Select a device on the left, then press Back up now")

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
        top.addWidget(self.group)
        top.addWidget(self.run_btn)
        top.addWidget(self.one_btn)
        top.addWidget(self.search_btn)
        top.addSpacing(8)
        top.addWidget(self.status, 1)
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
        rl.addWidget(rsplit)
        split = QSplitter()
        split.addWidget(self.devs)
        split.addWidget(right)
        split.setSizes([480, 710])
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(split, 1)
        self.names = []
        self.refresh()

    # ---------- the device list
    def refresh(self):
        keep = self.current_device()
        devs = db.list_devices()
        info = backup.summary()
        self.names = [d["name"] for d in devs]
        self.devs.blockSignals(True)
        self.devs.setRowCount(len(devs))
        for i, d in enumerate(devs):
            s = info.get(d["name"], {})
            state = ("not supported" if not backup.supported(d) else
                     {"error": "last backup FAILED", "changed": "changed", "new": "ok", "unchanged": "ok"}.get(s.get("status"), "never backed up"))
            for j, v in enumerate([d["name"], display.vendor_name(d["vendor"]), str(s.get("versions", 0)),
                                   (s.get("last", "") or "")[:16], state]):
                it = QTableWidgetItem(v)
                if j == 4 and state == "last backup FAILED":
                    it.setForeground(QColor("#d32f2f"))
                self.devs.setItem(i, j, it)
        self.devs.resizeColumnsToContents()
        self.devs.blockSignals(False)
        self.hint.setVisible(not devs)
        self.devs.blockSignals(True)
        if keep in self.names:
            self.devs.selectRow(self.names.index(keep))
        self.devs.blockSignals(False)
        self.show_versions()                  # always reload: the selection may not have changed but the data did
        self.group.set_labels(db.group_labels()[1:])

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
            lines, ad, rm = backup.diff_lines(backup.get_text(a["id"]), backup.get_text(b["id"]),
                                              f"{name} {a['taken_at']}", f"{name} {b['taken_at']}")
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
                lines, ad, rm = backup.diff_lines(backup.get_text(older["id"]), backup.get_text(v["id"]),
                                                  f"{name} {older['taken_at']}", f"{name} {v['taken_at']}")
                self.text.setPlainText("\n".join(lines) if lines else "No difference.")
                self.note.setText(f"{older['taken_at']} -> {v['taken_at']}:  +{ad} / -{rm}")
        else:
            self.text.setPlainText(backup.get_text(v["id"]))
            self.note.setText(f"{v['taken_at']}  ({v['lines']} lines)")

    def save_version(self):
        rows = self.selected_rows()
        name = self.current_device()
        if not rows or not name:
            return
        v = self.versions[rows[0]]
        stamp = v["taken_at"].replace(":", "").replace(" ", "_").replace("-", "")
        path, _ = QFileDialog.getSaveFileName(self, "Save configuration", f"{name}_{stamp}.txt", "Text files (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(backup.get_text(v["id"]))

    def prune(self):
        name = self.current_device()
        if name and len(self.versions) > 1 and QMessageBox.question(
                self, "Delete older versions",
                f"Keep only the newest copy of {name} and delete {len(self.versions) - 1} older version(s)?") \
                == QMessageBox.StandardButton.Yes:
            backup.delete_versions(name, 1)
            audit.log("config versions deleted", name)
            self.refresh()

    # ---------- backing up
    def running(self):
        return bool(self.worker and self.worker.isRunning())

    def start(self):
        self._start(self.group.selected(), scheduled=False)

    def start_scheduled(self, labels):
        if not self.running():
            self._start(labels, scheduled=True)

    def _start(self, labels, scheduled, only=None):
        if self.running():
            return
        devices = [d for d in db.list_devices(enabled_only=True) if db.in_groups(d, labels) and (only is None or d["name"] == only)]
        if not devices:
            if not scheduled:
                toast(self, "No enabled devices in this group.")
            return
        self.scheduled = scheduled
        self.run_btn.setEnabled(False)
        self.one_btn.setEnabled(False)
        self.status.setText(f"{'Scheduled backup: ' if scheduled else ''}backing up {len(devices)} device(s)...")
        self.done_count = 0
        self.total = len(devices)
        self.ran = [d["name"] for d in devices]
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

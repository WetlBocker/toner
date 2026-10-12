from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QHBoxLayout, QLabel, QMessageBox,
                               QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)
from core import db, display, reports
from core.alerts import base as device_of
from core.runner import run_all
from drivers.base import SEVERITY
from ui.widgets import EmptyHint, GroupPicker, StatChips, StatusDelegate
from ui.toast import toast


ROLE = Qt.ItemDataRole.UserRole
AUTO_OPEN = 12                       # failing devices opened by themselves when a run ends


class Worker(QThread):
    batch = Signal(list)

    def __init__(self, devices, thresholds, workers, opts):
        super().__init__()
        self.devices, self.th, self.workers, self.opts = devices, thresholds, workers, opts

    def run(self):
        run_all(self.devices, self.th, on_results=self.batch.emit, workers=self.workers, opts=self.opts)


class ResultsTab(QWidget):
    run_finished = Signal()
    open_device = Signal(str)
    COLS = ["Device", "Check", "Status", "Value", "Message"]

    def __init__(self):
        super().__init__()
        self.results = []
        self._active = False                     # a run is in progress (rows keep arrival order)
        self.expanded = set()                    # devices whose checks are open; survives live updates
        self._building = False
        self.table = QTreeWidget()               # one row per device; its checks are the children
        self.table.setColumnCount(len(self.COLS))
        self.table.setHeaderLabels(self.COLS)
        self.table.header().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setUniformRowHeights(True)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_menu)
        self.table.setItemDelegateForColumn(2, StatusDelegate(self.table))
        self.table.setIndentation(18)
        self.table.setAlternatingRowColors(False)
        self.hint = EmptyHint(self.table, "No results yet", "Choose devices and press Run checks")
        self.table.itemExpanded.connect(lambda it: self._remember(it, True))
        self.table.itemCollapsed.connect(lambda it: self._remember(it, False))
        self.run_btn = QPushButton("Run checks")
        self.run_btn.setProperty("primary", True)
        self.run_btn.clicked.connect(self.start)
        self.group = GroupPicker()
        self.refresh_groups()
        self.filter = QComboBox()
        self.filter.addItems(["All results", "Problems only"])
        self.filter.currentIndexChanged.connect(self.repopulate)
        self.chips = StatChips()
        self.summary = QLabel("Ready")
        self.summary.setProperty("muted", True)
        self.last_ran, self.last_scheduled = [], False
        self.schedule_note = QLabel("")
        self.schedule_note.setToolTip("Scheduled runs happen only while Toner is open (Settings > Automation)")
        self.worker = None
        top = QHBoxLayout()
        top.setSpacing(10)
        top.addWidget(self.group)
        top.addWidget(self.run_btn)
        top.addSpacing(8)
        top.addWidget(self.summary, 1)
        top.addWidget(self.schedule_note)
        top.addWidget(self.chips)
        sub = QHBoxLayout()
        sub.setSpacing(8)
        sub.addWidget(self.filter)
        sub.addStretch()
        for text, fn in (("Expand all", lambda: self.table.expandAll()), ("Collapse all", lambda: self.table.collapseAll())):
            b = QPushButton(text)
            b.setProperty("ghost", True)
            b.clicked.connect(lambda _=False, fn=fn: fn())
            sub.addWidget(b)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addLayout(sub)
        lay.addWidget(self.table, 1)

    def refresh_groups(self):
        """Reload the group list (after inventory changes), keeping the current choice."""
        self.group.set_labels(db.group_labels()[1:])      # [0] is 'All devices' = nothing ticked

    def _show(self, r):
        return self.filter.currentIndex() == 0 or r.status != "OK"

    def show_menu(self, pos):
        """Right-click a row: copy it, open the device, or see the raw output of a check that failed to parse."""
        from PySide6.QtWidgets import QApplication, QMenu
        item = self.table.itemAt(pos)
        if item is None:
            return
        top = item.parent() or item
        device, check = top.text(0), (item.text(1) if item.parent() else "")
        menu = QMenu(self)
        menu.addAction("Copy row", lambda: QApplication.clipboard().setText(
            "\t".join(item.text(i) for i in range(self.table.columnCount()))))
        menu.addAction("Open device details", lambda: self.open_device.emit(device))
        diag = db.get_diagnostics(device, check or None, 1)
        if diag:
            menu.addSeparator()
            menu.addAction("Show raw device output...", lambda: self.show_diagnostic(device, diag[0]))
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def show_diagnostic(self, device, diag):
        from PySide6.QtWidgets import QApplication, QDialog, QDialogButtonBox, QPlainTextEdit
        from PySide6.QtGui import QFontDatabase
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Raw output - {device} / {diag['check_name']}")
        dlg.resize(780, 520)
        box = QPlainTextEdit(f"Captured {diag['at']}. Passwords and keys are masked.\n"
                             "Send this text with a bug report if a check says 'unexpected output'.\n\n" + diag["body"])
        box.setReadOnly(True)
        box.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        copy = buttons.addButton("Copy", QDialogButtonBox.ButtonRole.ActionRole)
        copy.clicked.connect(lambda: QApplication.clipboard().setText(box.toPlainText()))
        buttons.rejected.connect(dlg.reject)
        lay = QVBoxLayout(dlg)
        lay.addWidget(box)
        lay.addWidget(buttons)
        dlg.exec()

    def _remember(self, item, open_):
        if self._building:
            return
        (self.expanded.add if open_ else self.expanded.discard)(item.data(0, ROLE))

    @staticmethod
    def _paint(item, status, cols):
        bg = reports.COLORS.get(status)
        for i in cols:
            if bg:
                item.setBackground(i, QColor(bg))
                item.setForeground(i, QColor(reports.fg_for(bg)))

    def _group(self):
        """Results grouped by the inventory device they belong to (UniFi rows are 'controller / device')."""
        groups = {name: [] for name in self.last_ran}    # a device that was checked is listed even with no rows
        for r in self.results:
            groups.setdefault(device_of(r.device), []).append(r)
        return groups

    def repopulate(self):
        groups = self._group()
        worst = lambda rs: max((SEVERITY[r.status] for r in rs), default=-1)
        order = list(groups) if self._active else sorted(groups, key=lambda n: (-worst(groups[n]), n.lower()))
        problems_only = self.filter.currentIndex() == 1
        bold = QFont()
        bold.setBold(True)
        self._building = True
        self.table.setUpdatesEnabled(False)
        self.table.clear()
        for name in order:
            rows = sorted(groups[name], key=lambda r: (-SEVERITY[r.status], r.device, r.check))
            bad = [r for r in rows if r.status != "OK"]
            if problems_only and not bad:
                continue
            top = QTreeWidgetItem([name, "", "", "", ""])
            top.setData(0, ROLE, name)
            top.setFont(0, bold)
            if rows:
                status = next(r.status for r in rows if SEVERITY[r.status] == worst(rows))
                counts = {}
                for r in rows:
                    counts[r.status] = counts.get(r.status, 0) + 1
                top.setText(1, f"{len(rows)} check{'s' if len(rows) != 1 else ''}")
                top.setText(2, status)
                top.setText(4, ", ".join(f"{counts[s]} {s}" for s in ("ERROR", "FAIL", "WARN") if s in counts)
                            or "all OK")
            else:
                top.setText(2, "Running..." if self._active else "No results")
            self.table.addTopLevelItem(top)
            for r in (bad if problems_only else rows):
                label = r.check if device_of(r.device) == r.device else \
                    f"{r.device.split(' / ', 1)[1]}: {r.check}"
                child = QTreeWidgetItem(["", label, r.status, r.value, r.message])
                top.addChild(child)
            top.setExpanded(name in self.expanded)
        self.table.setUpdatesEnabled(True)
        self._building = False
        self.hint.setVisible(self.table.topLevelItemCount() == 0)
        self.chips.restyle()
        for i in range(self.table.columnCount() - 1):
            self.table.resizeColumnToContents(i)

    def running(self):
        return bool(self.worker and self.worker.isRunning())

    def start(self):
        self._start(self.group.selected(), scheduled=False)

    def start_scheduled(self, labels):
        """Run on a timer. Skips quietly (no dialogs) if a run is already going or nothing matches."""
        if not self.running():
            self._start(labels, scheduled=True)

    def _start(self, picked, scheduled):
        if self.running():
            return
        label = ", ".join(picked) or db.ALL_DEVICES
        devices = [d for d in db.list_devices(enabled_only=True) if db.in_groups(d, picked)]
        if not devices:
            if not scheduled:
                toast(self, "No enabled devices in this group. Add or enable devices on the Inventory tab.")
            return
        self.last_ran, self.last_scheduled = [d["name"] for d in devices], scheduled   # for notifications
        # Read settings here, in the GUI thread, and hand the worker plain values.
        base, rules = db.get_thresholds(), db.get_setting("threshold_overrides")
        per_device = {d["name"]: db.thresholds_for(d, base, rules) for d in devices}
        self.results = []
        self.chips.set_counts({})
        self.expanded = set()
        self.run_btn.setEnabled(False)
        self.summary.setText(f"{'Scheduled run: ' if scheduled else ''}running {len(devices)} "
                             f"device(s) in '{label}'...")
        self.worker = Worker(devices, lambda d: per_device[d["name"]], int(db.get_setting("workers")),
                             db.runtime_options())
        self._active = True
        self.repopulate()
        self.worker.batch.connect(self.add)
        self.worker.finished.connect(self.done)
        self.worker.start()

    def add(self, batch):
        self.results.extend(batch)
        self.repopulate()

    def done(self):
        self._active = False
        self.results.sort(key=lambda r: (-SEVERITY[r.status], r.device, r.check))
        worst_first = list(dict.fromkeys(device_of(r.device) for r in self.results if r.status != "OK"))
        self.expanded |= set(worst_first[:AUTO_OPEN])      # what needs a look is already open (not hundreds of rows at once)
        self.repopulate()
        db.save_run(self.results)
        counts = {}
        for r in self.results:
            counts[r.status] = counts.get(r.status, 0) + 1
        self.chips.set_counts(counts)
        devices = len({device_of(r.device) for r in self.results})
        self.summary.setText(f"{devices} device{'s' if devices != 1 else ''}, {len(self.results)} checks")
        self.run_btn.setEnabled(True)
        self.run_finished.emit()

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont, QKeySequence, QShortcut
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QHBoxLayout, QLabel, QMessageBox,
                               QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)
from core import db, display, reports, scope
from core.alerts import base as device_of
from core.runner import run_all
from drivers.base import SEVERITY, Result, is_problem
from ui.columns import ColumnChooser
from ui.widgets import EmptyHint, GroupPicker, SectionHeader, StatChips, StatusDelegate, flow
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
    progress = Signal(int, int)                  # devices done, devices in the run (for the status strip)
    open_device = Signal(str)
    COLS = ["Device", "Check", "Status", "Value", "Message"]
    FILTERS = ["All results", "Problems only", "Warnings", "Failing", "Healthy devices"]
    FILTER_KEYS = {"all": 0, "problems": 1, "warn": 2, "fail": 3, "healthy": 4}

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
        self.columns = ColumnChooser(self.table, self.table.header(), "results_columns", self.COLS, locked=(0, 2))      # right-click a heading
        self.table.setIndentation(18)
        self.table.setAlternatingRowColors(False)
        self.hint = EmptyHint(self.table, "No results yet", "Choose devices and press Run checks", actions=[("Run checks", lambda: self.start())])
        for key in ("Return", "Enter"):                          # Enter opens the selected device's window
            QShortcut(QKeySequence(key), self.table, activated=self._enter, context=Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self.table.itemExpanded.connect(lambda it: self._remember(it, True))
        self.table.itemCollapsed.connect(lambda it: self._remember(it, False))
        self.run_btn = QPushButton("Run checks")
        self.run_btn.setProperty("primary", True)
        self.run_btn.clicked.connect(self.start)
        self.group = GroupPicker()
        self.refresh_groups()
        self.filter = QComboBox()
        self.filter.addItems(self.FILTERS)
        self.filter.currentIndexChanged.connect(self.repopulate)
        self.chips = StatChips()
        self.summary = QLabel("Ready")
        self.summary.setProperty("muted", True)
        self.last_ran, self.last_scheduled = [], False
        self.schedule_note = QLabel("")
        self.schedule_note.setToolTip("Scheduled runs happen only while Toner is open (Settings > Checks > Schedule)")
        self.worker = None
        self.header = SectionHeader("Results")
        self.header.lay.replaceWidget(self.header.context, self.summary)          # the context line is the run's summary
        self.header.context.hide()
        self.header.context.setParent(None)          # gone now, not when Qt gets round to it
        self.header.context.deleteLater()
        self.header.context = self.summary
        self.summary.setWordWrap(True)
        self.summary.setMinimumWidth(80)
        self.header.add(self.chips)
        folds = []
        for text, fn in (("Expand all", lambda: self.table.expandAll()), ("Collapse all", lambda: self.table.collapseAll())):
            b = QPushButton(text)
            b.clicked.connect(lambda _=False, fn=fn: fn())
            folds.append(b)
        bar = flow(self.group, self.run_btn, self.filter, *folds, self.schedule_note)      # wraps in a narrow window
        lay = QVBoxLayout(self)
        lay.addWidget(self.header)
        lay.addLayout(bar)
        lay.addWidget(self.table, 1)
        self.stored = False                      # what is shown is the latest stored results, not a run from this session
        self.load_stored()

    def load_stored(self):
        """Show every device's latest stored results, so the section is not empty after a restart. A run started here replaces them."""
        if self.running() or (self.results and not self.stored):
            return
        rows, at = db.latest_results()
        self.results = [Result(r["device"], r["check_name"], r["status"], r["value"] or "", r["message"] or "", r["numeric"]) for r in rows]
        self.results.sort(key=lambda r: (-SEVERITY.get(r.status, 0), r.device, r.check))
        self.stored = bool(self.results)
        self.last_ran = []
        counts = {}
        for r in self.results:
            counts[r.status] = counts.get(r.status, 0) + 1
        self.chips.set_counts(counts)
        if self.stored:
            n = len([g for g in self._group().values() if g])
            self.summary.setText(f"Latest results for {n} device{'s' if n != 1 else ''}, from {at[:16]} ({display.ago(at)}). Run checks for fresh ones.")
            self.summary.setToolTip("Each device shows the newest run that included it.")
            worst_first = list(dict.fromkeys(device_of(r.device) for r in self.results if is_problem(r.status)))
            self.expanded = set(worst_first[:AUTO_OPEN])
        self.repopulate()

    def showEvent(self, e):
        super().showEvent(e)
        if self.stored:                           # stored results may have moved on (a run from the tray, the service, the device window)
            self.load_stored()

    def _enter(self):
        item = self.table.currentItem()
        if item is not None:
            self.open_device.emit((item.parent() or item).text(0))

    def refresh_groups(self):
        """Reload the group list (after inventory changes), keeping the current choice."""
        self.group.set_labels(db.group_labels()[1:])      # [0] is 'All devices' = nothing ticked

    def _show(self, r):
        return self.filter.currentIndex() == 0 or is_problem(r.status)

    def show_filter(self, key):
        """Show only what an Overview card counted: 'warn', 'fail', 'healthy', 'problems' or 'all'."""
        self.filter.setCurrentIndex(self.FILTER_KEYS.get(key, 0))

    def _rows_for(self, rows):
        """(include this device?, the rows to list under it) for the chosen filter."""
        mode = self.filter.currentIndex()
        if mode == 0:
            return True, rows
        if mode == 4:                                           # healthy devices: nothing worse than OK, every check listed
            return bool(rows) and not any(is_problem(r.status) for r in rows), rows
        want = {1: ("WARN", "FAIL", "ERROR"), 2: ("WARN",), 3: ("FAIL", "ERROR")}[mode]
        shown = [r for r in rows if r.status in want]
        return bool(shown), shown

    def show_menu(self, pos):
        """Right-click a row: copy it, open the device, or see the raw output of a check that failed to parse."""
        from PySide6.QtWidgets import QApplication, QMenu
        item = self.table.itemAt(pos)
        if item is None:
            return
        top = item.parent() or item
        device, check = top.text(0), (item.text(1) if item.parent() or item.data(1, ROLE) == "check" else "")
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
        """Results grouped by the inventory device they belong to (UniFi rows are 'controller / device'), for the client being looked at."""
        names = scope.names()
        groups = {name: [] for name in self.last_ran if names is None or name in names}    # a device that was checked is listed even with no rows
        for r in self.results:
            if names is None or device_of(r.device) in names:
                groups.setdefault(device_of(r.device), []).append(r)
        return groups

    def visible_counts(self):
        """OK / WARN / FAIL / ERROR counts of what is shown (the client's devices)."""
        counts = {}
        for rows in self._group().values():
            for r in rows:
                counts[r.status] = counts.get(r.status, 0) + 1
        return counts

    def repopulate(self):
        groups = self._group()
        worst = lambda rs: max((SEVERITY.get(r.status, 0) for r in rs), default=-1)
        order = list(groups) if self._active else sorted(groups, key=lambda n: (-worst(groups[n]), n.lower()))
        bold = QFont()
        bold.setBold(True)
        self._building = True
        self.table.setUpdatesEnabled(False)
        self.table.clear()
        for name in order:
            rows = sorted(groups[name], key=lambda r: (-SEVERITY.get(r.status, 0), r.status == "N/A", r.device, r.check))
            bad = [r for r in rows if is_problem(r.status)]
            include, listed = self._rows_for(rows)
            if not include and not (self._active and not rows):
                continue
            top = QTreeWidgetItem([name, "", "", "", ""])
            top.setData(0, ROLE, name)
            top.setFont(0, bold)
            if rows:
                status = max(rows, key=lambda r: (SEVERITY.get(r.status, 0), r.status != "N/A")).status    # OK over N/A
                counts = {}
                for r in rows:
                    counts[r.status] = counts.get(r.status, 0) + 1
                top.setText(1, f"{len(rows)} check{'s' if len(rows) != 1 else ''}")
                top.setText(2, status)
                if bad:                                   # say what is wrong, so a collapsed row is readable without opening it
                    first = bad[0]
                    what = first.check if device_of(first.device) == first.device else f"{first.device.split(' / ', 1)[1]}: {first.check}"
                    detail = first.message or first.value
                    top.setText(4, display.said(what, detail))
                    if len(bad) > 1:
                        top.setText(4, top.text(4) + f"   (+{len(bad) - 1} more)")
                    top.setToolTip(4, ", ".join(f"{counts[s]} {s}" for s in ("ERROR", "FAIL", "WARN") if s in counts))
                else:
                    top.setText(4, "all OK")
            else:
                top.setText(2, "Running..." if self._active else "No results")
            self.table.addTopLevelItem(top)
            if len(rows) == 1 and len(listed) == 1:           # one check: the device row says it all, with nothing to open
                only = listed[0]
                top.setText(1, only.check if device_of(only.device) == only.device else f"{only.device.split(' / ', 1)[1]}: {only.check}")
                top.setData(1, ROLE, "check")                  # the right-click menu treats this row as the check it carries
                top.setText(3, only.value)
                top.setText(4, only.message if only.message else ("" if only.status in ("OK", "N/A") else only.value))
                listed = []
            for r in listed:
                label = r.check if device_of(r.device) == r.device else \
                    f"{r.device.split(' / ', 1)[1]}: {r.check}"
                child = QTreeWidgetItem(["", label, r.status, r.value, r.message])
                top.addChild(child)
            top.setExpanded(name in self.expanded)
        if not self._active:
            self.chips.set_counts(self.visible_counts())
        self.columns.apply()
        self.table.setUpdatesEnabled(True)
        self._building = False
        empty = self.table.topLevelItemCount() == 0
        if empty and self.results and self.filter.currentIndex():
            self.hint.set_text("Nothing matches this filter", "Every device is listed under All results")
            self.hint.set_actions([("Show all results", lambda: self.filter.setCurrentIndex(0))])
        else:
            self.hint.set_text("No results yet", "Choose devices and press Run checks")
            self.hint.set_actions([("Run checks", lambda: self.start())])
        self.hint.setVisible(empty)
        self.chips.restyle()
        for i in range(self.table.columnCount() - 1):
            self.table.resizeColumnToContents(i)

    def running(self):
        return bool(self.worker and self.worker.isRunning())

    def start(self):
        self._start(self.group.selected(), scheduled=False)

    def run_devices(self, names):
        """Run checks on just these devices (the Overview's "Run checks" on a problem)."""
        self._start([f"Device: {n}" for n in names], scheduled=False)

    def start_scheduled(self, labels):
        """Run on a timer. Skips quietly (no dialogs) if a run is already going or nothing matches."""
        if not self.running():
            self._start(labels, scheduled=True)

    def _start(self, picked, scheduled):
        if self.running():
            return
        label = ", ".join(picked) or db.ALL_DEVICES
        devices = [d for d in db.list_devices(enabled_only=True) if db.in_groups(d, picked)]
        if not scheduled:                                    # a run started here covers the client being looked at; a scheduled one, its own groups
            devices = scope.keep(devices)
        if not devices:
            if not scheduled:
                toast(self, "No enabled devices in this group. Add or enable devices on the Inventory tab.")
            return
        self.last_ran, self.last_scheduled = [d["name"] for d in devices], scheduled   # for notifications
        # Read settings here, in the GUI thread, and hand the worker plain values.
        base, rules = db.get_thresholds(), db.get_setting("threshold_overrides")
        per_device = {d["name"]: db.thresholds_for(d, base, rules) for d in devices}
        self.results = []
        self.stored = False
        self.summary.setToolTip("")
        self.chips.set_counts({})
        self.expanded = set()
        self.run_btn.setEnabled(False)
        self.summary.setText(f"{'Scheduled run: ' if scheduled else ''}running {len(devices)} "
                             f"device(s) in '{label}'...")
        self.worker = Worker(devices, lambda d: per_device[d["name"]], int(db.get_setting("workers")),
                             db.runtime_options())
        self._active = True
        self.repopulate()
        self.progress.emit(0, len(self.last_ran))
        self.worker.batch.connect(self.add)
        self.worker.finished.connect(self.done)
        self.worker.start()

    def add(self, batch):
        self.results.extend(batch)
        self.repopulate()
        done = len({device_of(r.device) for r in self.results} & set(self.last_ran))
        self.progress.emit(min(done, len(self.last_ran) - 1), len(self.last_ran))     # the end is announced by done()

    def done(self):
        self._active = False
        self.results.sort(key=lambda r: (-SEVERITY[r.status], r.device, r.check))
        worst_first = list(dict.fromkeys(device_of(r.device) for r in self.results if is_problem(r.status)))
        self.expanded |= set(worst_first[:AUTO_OPEN])      # what needs a look is already open (not hundreds of rows at once)
        self.repopulate()
        db.save_run(self.results)
        self.chips.set_counts(self.visible_counts())             # what is shown: the client being looked at
        devices = len({device_of(r.device) for r in self.results})
        self.summary.setText(f"{devices} device{'s' if devices != 1 else ''}, {len(self.results)} checks")
        self.run_btn.setEnabled(True)
        self.progress.emit(len(self.last_ran), len(self.last_ran))
        self.run_finished.emit()

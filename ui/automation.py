"""Automation section: run Ansible playbooks on Inventory devices and look back at earlier runs. (More automation will be added here later.)"""
import json
import threading
from datetime import datetime

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                               QMessageBox, QPlainTextEdit, QPushButton, QSplitter, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from core import ansible as AN, audit, db, scope
from ui import status as st
from ui.nav import PageStack
from ui.widgets import EmptyHint, filling, flow
from ui.finder import FilterButton, SearchBox, device_sections, shown_devices

MODES = {"check": "Check", "run": "Run", "syntax": "Syntax"}
VERBOSITY = ["Normal output", "More (-v)", "Even more (-vv)", "Debug (-vvv)"]
SHOWN_TARGETS = 12                              # devices named in the confirmation before "and N more"


def _table(cols):
    t = QTableWidget(0, len(cols))
    t.setHorizontalHeaderLabels(cols)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.verticalHeader().setVisible(False)
    t.setShowGrid(False)
    t.horizontalHeader().setStretchLastSection(True)
    return t


def _mono(read_only=True):
    box = QPlainTextEdit()
    box.setReadOnly(read_only)
    box.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    box.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
    return box


def confirm_text(playbook, devices):
    """What the person is told before a real run: the playbook and the devices it will touch."""
    names = [d["name"] for d in devices]
    shown = "\n".join("  " + n for n in names[:SHOWN_TARGETS]) + (f"\n  ... and {len(names) - SHOWN_TARGETS} more" if len(names) > SHOWN_TARGETS else "")
    return (f"This runs  {playbook}  on {len(names)} device{'s' if len(names) != 1 else ''} and can change {'it' if len(names) == 1 else 'them'}:\n\n{shown}\n\n"
            "To see what would change without changing it, cancel and tick 'Check mode'.\n\nRun it?")


class _RunWorker(QThread):
    line = Signal(str)
    done = Signal(object)                       # the result dict, or the exception that stopped the run

    def __init__(self, spec):
        super().__init__()
        self.spec = spec
        self.cancel = threading.Event()

    def run(self):
        try:
            res = AN.run(self.spec, self.line.emit, self.cancel)
        except Exception as e:                  # a missing WSL, a wrong password: shown in the output, not raised into the event loop
            res = e
        self.done.emit(res)


class PlaybooksPage(QWidget):
    """Pick a playbook and devices, choose check or real run, watch the output, read the recap."""
    edit_requested = Signal(str)
    settings_requested = Signal()
    finished = Signal()                         # a run is over (the history has a new row)

    def __init__(self):
        super().__init__()
        self.worker = None
        self.result = None
        self.listing = QListWidget()
        self.listing.setMaximumWidth(300)
        self.list_hint = EmptyHint(self.listing, "No playbooks yet", "Write one in Tools > Playbook Editor", wrap=True)
        self.edit_btn, self.settings_btn = QPushButton("Edit"), QPushButton("Ansible settings")
        self.edit_btn.setToolTip("Open the playbook in Tools > Playbook Editor")
        self.settings_btn.setToolTip("Where Ansible runs (WSL or a server), the playbook folder and defaults: Settings > Ansible")
        self.find = SearchBox("Search devices", "Type part of a name, address, vendor, location, tag or detail. Several words must all match.",
                              page=self)
        self.funnel = FilterButton(lambda: device_sections(db.list_devices(enabled_only=True)))
        self.find.textChanged.connect(lambda _t: self.fill_devices())
        self.funnel.changed.connect(self.fill_devices)
        self.devs = QListWidget()
        self.devs.setMaximumWidth(300)
        self.devs_hint = EmptyHint(self.devs, "No devices", "Add devices in the Inventory", wrap=True)
        self.all_btn, self.none_btn = QPushButton("All"), QPushButton("None")
        self.check = QCheckBox("Check mode (change nothing)")
        self.check.setToolTip("Runs the playbook with --check --diff: Ansible reports what would change and changes nothing.\nUntick it for a real run, which asks first.")
        self.tags = QLineEdit()
        self.tags.setPlaceholderText("tags, e.g. ntp,snmp (optional)")
        self.extra = QLineEdit()
        self.extra.setPlaceholderText('variables, e.g. ntp_server=10.0.0.1 retries=3  (optional)')
        self.verbosity = QComboBox()
        self.verbosity.addItems(VERBOSITY)
        self.go, self.stop = QPushButton("Run check"), QPushButton("Stop")
        self.go.setProperty("primary", True)
        self.stop.setEnabled(False)
        self.where = QLabel("")
        self.where.setProperty("muted", True)
        self.where.setWordWrap(True)
        self.status = QLabel("Choose a playbook and tick the devices to run it on.")
        self.status.setWordWrap(True)
        self.output = _mono()
        self.recap = _table(["Device", "OK", "Changed", "Unreachable", "Failed", "Skipped"])
        hdr = self.recap.horizontalHeader()
        hdr.setStretchLastSection(False)
        hdr.setSectionResizeMode(0, hdr.ResizeMode.Stretch)
        for c in range(1, 6):
            hdr.setSectionResizeMode(c, hdr.ResizeMode.ResizeToContents)
        self.recap_hint = EmptyHint(self.recap, "No recap yet", "Ansible's summary per device appears when a run finishes")
        self.copy_btn, self.save_btn = QPushButton("Copy"), QPushButton("Save output...")
        left = QVBoxLayout()
        left.addWidget(QLabel("Playbook"))
        left.addWidget(self.listing, 1)
        pb = QHBoxLayout()
        pb.addWidget(self.edit_btn)
        pb.addWidget(self.settings_btn)
        left.addLayout(pb)
        left.addWidget(QLabel("Run on"))
        finder = QHBoxLayout()                           # where the "All devices" drop-down was
        finder.addWidget(self.find, 1)
        finder.addWidget(self.funnel)
        left.addLayout(finder)
        left.addWidget(self.devs, 2)
        lb = QHBoxLayout()
        lb.addWidget(self.all_btn)
        lb.addWidget(self.none_btn)
        left.addLayout(lb)
        opts = flow(self.check, self.verbosity, self.go, self.stop)                  # wraps in a narrow window
        split = QSplitter(Qt.Orientation.Vertical)
        out_box = QWidget()
        ol = QVBoxLayout(out_box)
        ol.setContentsMargins(0, 0, 0, 0)
        ob = QHBoxLayout()
        ob.addStretch(1)
        ob.addWidget(self.copy_btn)
        ob.addWidget(self.save_btn)
        ol.addLayout(ob)
        ol.addWidget(self.output, 1)
        split.addWidget(out_box)
        split.addWidget(self.recap)
        split.setSizes([380, 140])
        right = QVBoxLayout()
        right.addWidget(self.where)
        right.addLayout(opts)
        right.addLayout(flow(self.tags, self.extra))
        right.addWidget(self.status)
        right.addWidget(split, 1)
        lay = QHBoxLayout(self)
        lay.addLayout(left)
        lay.addLayout(right, 1)
        self.go.clicked.connect(lambda: self.start())
        self.stop.clicked.connect(self.halt)
        self.check.toggled.connect(self._mode_changed)
        self.all_btn.clicked.connect(lambda: self._tick_all(True))
        self.none_btn.clicked.connect(lambda: self._tick_all(False))
        self.edit_btn.clicked.connect(lambda: self.selected() and self.edit_requested.emit(self.selected()))
        self.settings_btn.clicked.connect(self.settings_requested.emit)
        self.listing.itemSelectionChanged.connect(self._buttons)
        self.copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.output.toPlainText()))
        self.save_btn.clicked.connect(self.save_output)
        self.recap.model().rowsInserted.connect(self._sync_hint)
        self.recap.model().rowsRemoved.connect(self._sync_hint)
        self.recap.model().modelReset.connect(self._sync_hint)
        self.check.setChecked(bool(db.get_setting("ansible_check_default")))
        self._mode_changed(self.check.isChecked())
        self.refresh()

    # ---- what is shown
    def _sync_hint(self, *_):
        try:
            self.recap_hint.setVisible(self.recap.rowCount() == 0)
        except RuntimeError:                    # the window is closing
            pass

    def refresh(self):
        """Re-read the playbook folder, the devices and where Ansible runs (the Inventory or Settings changed)."""
        keep = self.selected()
        self.listing.clear()
        for p in AN.list_playbooks():
            it = QListWidgetItem(p["name"])
            it.setData(Qt.ItemDataRole.UserRole, p["name"])
            self.listing.addItem(it)
            if p["name"] == keep:
                self.listing.setCurrentItem(it)
        self.list_hint.setVisible(self.listing.count() == 0)
        self.fill_devices()
        self.where.setText(self.where_text())
        self._buttons()

    def where_text(self):
        try:
            back = AN.backend()
        except AN.BackendError as e:
            return str(e)
        return f"Runs on {back.describe()}. Change it in Settings > Ansible."

    def selected(self):
        it = self.listing.currentItem()
        return it.data(Qt.ItemDataRole.UserRole) if it is not None else ""

    def select(self, name):
        for i in range(self.listing.count()):
            if self.listing.item(i).data(Qt.ItemDataRole.UserRole) == name:
                self.listing.setCurrentRow(i)
                return True
        return False

    def candidates(self):
        return shown_devices(db.list_devices(enabled_only=True), self.find, self.funnel)

    def fill_devices(self):
        ticked = {self.devs.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.devs.count()) if self.devs.item(i).checkState() == Qt.CheckState.Checked}
        self.devs.clear()
        for d in self.candidates():
            it = QListWidgetItem(db.label_org(d["key"]))
            it.setData(Qt.ItemDataRole.UserRole, d["key"])
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(Qt.CheckState.Checked if d["key"] in ticked else Qt.CheckState.Unchecked)
            it.setToolTip(f"{d['vendor']}  {d['host']}")
            self.devs.addItem(it)
        self.devs_hint.setVisible(self.devs.count() == 0)

    def _tick_all(self, on):
        for i in range(self.devs.count()):
            self.devs.item(i).setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)

    def checked_devices(self):
        names = {self.devs.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.devs.count()) if self.devs.item(i).checkState() == Qt.CheckState.Checked}
        return [d for d in self.candidates() if d["key"] in names]

    def _mode_changed(self, on):
        self.go.setText("Run check" if on else "Run playbook")
        self.go.setToolTip("Show what would change, and change nothing" if on else "Run the playbook for real: it can change the devices (asks first)")

    def _buttons(self):
        busy = self.running()
        self.edit_btn.setEnabled(bool(self.selected()))
        self.go.setEnabled(not busy)
        self.stop.setEnabled(busy)

    # ---- running
    def running(self):
        return bool(self.worker and self.worker.isRunning())

    def start(self, confirmed=False):
        """Run the chosen playbook on the ticked devices. A real run (not check mode) asks first, naming the playbook and the devices.
        `confirmed` skips the question (the tests answer it themselves through QMessageBox)."""
        if self.running():
            return False
        name, devs = self.selected(), self.checked_devices()
        if not name:
            self.status.setText("Choose a playbook first.")
            return False
        if not devs:
            self.status.setText("Tick at least one device to run it on.")
            return False
        try:
            extra = AN.parse_extra_vars(self.extra.text())
        except ValueError as e:
            self.status.setText(f"Variables: {e}")
            return False
        check = self.check.isChecked()
        if not check and not confirmed:
            if QMessageBox.question(self, "Run playbook", confirm_text(name, devs), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                    QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
                self.status.setText("Not run.")
                return False
        spec = AN.RunSpec(name, devs, check=check, tags=self.tags.text(), extra_vars=extra, verbosity=self.verbosity.currentIndex())
        audit.log("ansible " + ("check" if check else "run"), f"{name} on {len(devs)} device(s): " + ", ".join(d["name"] for d in devs[:20]))
        self.output.clear()
        self.recap.setRowCount(0)
        self.result = None
        self.status.setText(f"{'Checking' if check else 'Running'} {name} on {len(devs)} device{'s' if len(devs) != 1 else ''}...")
        self.status.setStyleSheet("")
        self.worker = _RunWorker(spec)
        self.worker.line.connect(self.output.appendPlainText)
        self.worker.done.connect(self._done)
        self._buttons()
        self.worker.start()
        self._buttons()
        return True

    def halt(self):
        if self.running():
            self.worker.cancel.set()
            self.status.setText("Stopping...")

    def _done(self, res):
        if isinstance(res, Exception):
            self.output.appendPlainText(str(res))
            self.status.setText("It did not run: " + str(res)[:300] + ("  Open Ansible settings to set it up." if isinstance(res, AN.BackendError) else ""))
            self.status.setStyleSheet(f"color:{st.ink('FAIL')};")
        else:
            self.result = res
            self._fill_recap(res["rows"])
            good = res["exit_code"] == 0
            what = {"check": "Check", "run": "Run", "syntax": "Syntax check"}[res["mode"]]
            bits = [f"{what} {'finished' if good else 'finished with problems'}", f"{res['seconds']:.0f} s"]
            if res["rows"]:
                bits.insert(1, f"{sum(r['changed'] for r in res['rows'])} changed, {sum(r['failed'] + r['unreachable'] for r in res['rows'])} failed or unreachable")
            self.status.setText("  ·  ".join(bits))
            self.status.setStyleSheet(f"color:{st.ink('OK' if good else 'FAIL')};")
        self._buttons()
        self.finished.emit()

    def _fill_recap(self, rows):
        with filling(self.recap):
            self.recap.setRowCount(len(rows))
            for i, r in enumerate(rows):
                for j, v in enumerate((r["host"], r["ok"], r["changed"], r["unreachable"], r["failed"], r.get("skipped", 0))):
                    it = QTableWidgetItem(str(v))
                    if j in (3, 4) and v:
                        it.setForeground(st.qink("FAIL"))
                    elif j == 2 and v:
                        it.setForeground(st.qink("WARN"))
                    self.recap.setItem(i, j, it)

    def save_output(self):
        if not self.output.toPlainText():
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save output", f"ansible-{datetime.now():%Y%m%d-%H%M}.txt", "Text files (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.output.toPlainText())

    def shutdown(self):
        if self.running():
            self.worker.cancel.set()
            self.worker.wait(8000)


class HistoryPage(QWidget):
    """Earlier runs, newest first, with their output."""

    def __init__(self):
        super().__init__()
        self.table = _table(["When", "Playbook", "Mode", "Backend", "Devices", "Changed", "Failed", "Result"])
        self.hint = EmptyHint(self.table, "No runs yet", "Checks and runs from Automation > Playbooks are listed here")
        self.output = _mono()
        self.copy_btn, self.save_btn, self.clear_btn = QPushButton("Copy"), QPushButton("Save output..."), QPushButton("Clear history")
        self.runs = []
        bar = QHBoxLayout()
        bar.addStretch(1)
        bar.addWidget(self.copy_btn)
        bar.addWidget(self.save_btn)
        bar.addWidget(self.clear_btn)
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.table)
        box = QWidget()
        bl = QVBoxLayout(box)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.addLayout(bar)
        bl.addWidget(self.output, 1)
        split.addWidget(box)
        split.setSizes([260, 300])
        lay = QVBoxLayout(self)
        lay.addWidget(split, 1)
        self.table.itemSelectionChanged.connect(self.show_output)
        self.copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.output.toPlainText()))
        self.save_btn.clicked.connect(self.save_output)
        self.clear_btn.clicked.connect(self.clear)
        self.refresh()

    def refresh(self):
        keep = self.selected_id()
        self.runs = AN.list_runs()
        self.table.setRowCount(len(self.runs))
        for i, r in enumerate(self.runs):
            targets = len(json.loads(r["targets"] or "[]"))
            good = r["exit_code"] == 0
            vals = (r["started_at"], r["playbook"], MODES.get(r["mode"], r["mode"]), r["backend"], targets, r["changed"], r["failed"] + r["unreachable"], "OK" if good else "Problems")
            for j, v in enumerate(vals):
                it = QTableWidgetItem(str(v))
                if j == 7:
                    it.setForeground(st.qink("OK" if good else "FAIL"))
                self.table.setItem(i, j, it)
            self.table.item(i, 0).setData(Qt.ItemDataRole.UserRole, r["id"])
        self.table.resizeColumnsToContents()
        self.hint.setVisible(not self.runs)
        rows = [i for i, r in enumerate(self.runs) if r["id"] == keep]
        if rows:
            self.table.selectRow(rows[0])
        elif self.runs:
            self.table.selectRow(0)
        else:
            self.output.clear()

    def selected_id(self):
        rows = {i.row() for i in self.table.selectedItems()}
        if len(rows) != 1:
            return None
        return self.table.item(next(iter(rows)), 0).data(Qt.ItemDataRole.UserRole)

    def show_output(self):
        rid = self.selected_id()
        run = AN.get_run(rid) if rid else None
        self.output.setPlainText(run["output"] if run else "")

    def save_output(self):
        if not self.output.toPlainText():
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save output", f"ansible-run-{datetime.now():%Y%m%d-%H%M}.txt", "Text files (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.output.toPlainText())

    def clear(self):
        if not self.runs:
            return
        if QMessageBox.question(self, "Clear history", f"Delete all {len(self.runs)} saved runs and their output?") != QMessageBox.StandardButton.Yes:
            return
        with db.connect() as c:
            c.execute("DELETE FROM ansible_runs")
        audit.log("ansible history cleared", f"{len(self.runs)} runs")
        self.refresh()


class AutomationTab(QWidget):
    edit_requested = Signal(str)                 # open this playbook in Tools > Playbook Editor
    settings_requested = Signal()                # open Settings > Ansible

    def __init__(self):
        super().__init__()
        self.playbooks, self.history = PlaybooksPage(), HistoryPage()
        self.pages = PageStack(width=200)
        self.pages.addSection("Ansible")
        self.pages.addTab(self.playbooks, "Playbooks")
        self.pages.addTab(self.history, "Run history")
        lay = QVBoxLayout(self)
        lay.addWidget(self.pages, 1)
        self.playbooks.edit_requested.connect(self.edit_requested.emit)
        self.playbooks.settings_requested.connect(self.settings_requested.emit)
        self.playbooks.finished.connect(self.history.refresh)

    def refresh(self):
        self.playbooks.refresh()

    def select_playbook(self, name):
        self.pages.setCurrentWidget(self.playbooks)
        self.playbooks.refresh()
        return self.playbooks.select(name)

    def running(self):
        return self.playbooks.running()

    def shutdown(self):
        self.playbooks.shutdown()

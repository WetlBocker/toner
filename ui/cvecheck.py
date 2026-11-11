"""Check CVEs (the Scanning page): whether the devices shown are affected by CVEs the user enters, from the same sources as Scan
(core.advisories.check_all). The answers show here only: they are not saved and not part of the Scanning list or its reports."""
from PySide6.QtCore import QThread, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout

from core import advisories
from ui.detaillist import DetailList

TITLE = "Check CVEs"
PROMPT = "Enter or paste CVE IDs. Toner picks out each one, such as CVE-2024-55591."
NONE_ENTERED = "No CVE IDs found in what you entered."
NO_DEVICES = "No enabled devices are shown."
COLUMNS = [("device", "Device"), ("cve", "CVE"), ("status", "Status"), ("details", "Details")]


def checking(cves, devices):
    n, m = len(cves), len(devices)
    return f"Checking {n} CVE{'s' if n != 1 else ''} on {m} device{'s' if m != 1 else ''}..."


class CheckWorker(QThread):
    batch = Signal(list)

    def __init__(self, devices, cves):
        super().__init__()
        self.devices, self.cves = devices, cves

    def run(self):
        advisories.check_all(self.devices, self.cves, on_rows=self.batch.emit)


class CveCheckDialog(QDialog):
    def __init__(self, devices_shown, parent=None):
        """devices_shown() gives the devices to check, asked each time Check is pressed (the search and filter may have changed)."""
        super().__init__(parent)
        self.devices_shown, self.worker, self.rows = devices_shown, None, []
        self.setWindowTitle(TITLE)
        self.resize(860, 520)
        prompt = QLabel(PROMPT)
        prompt.setWordWrap(True)
        self.box = QPlainTextEdit()
        self.box.setAccessibleName("CVE IDs")
        self.box.setFixedHeight(72)
        self.go = QPushButton("Check")
        self.go.setProperty("primary", True)
        self.go.clicked.connect(self.check)
        self.info = QLabel("")
        self.info.setProperty("muted", True)
        self.table = DetailList()
        self.table.setAccessibleName(TITLE)
        self.table.doubleClicked.connect(self._open)
        row = QHBoxLayout()
        row.addWidget(self.info, 1)
        row.addWidget(self.go)
        lay = QVBoxLayout(self)
        lay.addWidget(prompt)
        lay.addWidget(self.box)
        lay.addLayout(row)
        lay.addWidget(self.table, 1)

    def check(self):
        if self.worker and self.worker.isRunning():
            return
        cves = advisories.cve_ids(self.box.toPlainText())
        if not cves:
            self.info.setText(NONE_ENTERED)
            return
        devices = self.devices_shown()
        if not devices:
            self.info.setText(NO_DEVICES)
            return
        self.rows = []
        self.table.show_rows([], COLUMNS)
        self.info.setText(checking(cves, devices))
        self.go.setEnabled(False)
        self.worker = CheckWorker(devices, cves)
        self.worker.batch.connect(self._add)
        self.worker.finished.connect(self._done)
        self.worker.start()

    def _add(self, rows):
        self.rows += rows
        self.table.show_rows(self.rows, COLUMNS)

    def _done(self):
        self.info.setText("")
        self.go.setEnabled(True)

    def _open(self, index):
        r = self.table.row_at(index)
        if r and r["link"]:
            QDesktopServices.openUrl(QUrl(r["link"]))

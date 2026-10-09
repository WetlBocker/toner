import os
from datetime import datetime

from PySide6.QtCore import QUrl
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QFileDialog, QHBoxLayout, QLabel,
                               QMessageBox, QPushButton, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)
from core import db, reports
from drivers.base import SEVERITY, Result
from ui.widgets import GroupPicker, StatusDelegate

NO_LOCATION = "(no location)"
CURRENT = "Current results"


class ReportsTab(QWidget):
    """Preview and export health-check reports from the current results or any past run."""

    def __init__(self, get_current):
        super().__init__()
        self.get_current = get_current          # callable -> this session's results
        self.run_times = {}
        self.base = []                          # results of the chosen source, before location filter

        self.source = QComboBox()
        self.source.setMinimumWidth(320)
        self.source.setToolTip("This session's results, or any past run from history")
        self.locations = GroupPicker(all_text="All locations")
        self.locations.setToolTip("Limit the report to these locations (none ticked = all)")
        self.info = QLabel("")

        self.table = QTableWidget(0, len(reports.COLS))
        self.table.setHorizontalHeaderLabels(reports.COLS)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setItemDelegateForColumn(2, StatusDelegate(self.table))

        top = QHBoxLayout()
        top.addWidget(QLabel("Report from"))
        top.addWidget(self.source)
        top.addWidget(QLabel("Locations"))
        top.addWidget(self.locations)
        top.addWidget(self.info, 1)
        buttons = QHBoxLayout()
        for text, fn in (("Export CSV", self.export_csv), ("HTML report", self.export_html),
                         ("PDF report", self.export_pdf)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            buttons.addWidget(b)
        buttons.addStretch()
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addLayout(buttons)
        lay.addWidget(self.table)

        self.source.currentIndexChanged.connect(lambda _: self.load_source())
        self.locations.changed.connect(self.show_preview)
        self.refresh()

    # ---------- data ----------
    def refresh(self):
        """Reload the run list (after a new run), keeping the current choice."""
        cur = self.source.currentData()
        self.run_times = {}
        self.source.blockSignals(True)
        self.source.clear()
        self.source.addItem(CURRENT, None)
        for r in db.list_runs(limit=100):
            if r["ok"] + r["warn"] + r["fail"] + r["error"]:      # skip empty runs
                self.run_times[r["id"]] = r["started_at"]
                self.source.addItem(
                    f"{r['started_at']}  —  OK {r['ok']}, WARN {r['warn']}, "
                    f"FAIL {r['fail']}, ERROR {r['error']}", r["id"])
        self.source.setCurrentIndex(max(0, self.source.findData(cur)))
        self.source.blockSignals(False)
        self.load_source()

    def load_source(self):
        data = self.source.currentData()
        if data is None:
            self.base = list(self.get_current())
        else:
            self.base = [Result(r["device"], r["check_name"], r["status"], r["value"] or "",
                                r["message"] or "") for r in db.run_results(data)]
        self.base.sort(key=lambda r: (-SEVERITY[r.status], r.device, r.check))
        self._loc = {id(r): db.location_of(r.device) or NO_LOCATION for r in self.base}
        found = sorted(set(self._loc.values()), key=lambda s: (s == NO_LOCATION, s.lower()))
        self.locations.set_labels(found)                 # keeps ticks that still apply
        self.show_preview()

    def selected_results(self):
        picked = set(self.locations.selected())
        return [r for r in self.base if not picked or self._loc[id(r)] in picked]

    def scope_text(self):
        picked = self.locations.selected()
        return "Locations: " + ", ".join(picked) if picked else ""

    def report_date(self):
        return self.run_times.get(self.source.currentData())    # None = now

    # ---------- preview ----------
    def show_preview(self):
        rows = self.selected_results()
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            for j, v in enumerate(reports._row(r)):
                self.table.setItem(i, j, QTableWidgetItem(v))
        self.table.resizeColumnsToContents()
        n = lambda s: sum(r.status == s for r in rows)
        self.info.setText(f"{len(rows)} results  |  OK {n('OK')}  WARN {n('WARN')}  "
                          f"FAIL {n('FAIL')}  ERROR {n('ERROR')}")

    # ---------- export ----------
    def _export(self, title, pattern, fn, open_after=False):
        rows = self.selected_results()
        if not rows:
            QMessageBox.information(self, "Nothing to export",
                                    "No results to export. Run the checks, or pick a past run.")
            return
        ext = pattern.split("*")[-1].rstrip(")")
        folder = db.get_setting("report_folder")
        start = os.path.join(folder, f"Toner-{datetime.now():%Y-%m-%d_%H%M}{ext}") \
            if folder and os.path.isdir(folder) else ""
        path, _ = QFileDialog.getSaveFileName(self, title, start, pattern)
        if path:
            fn(rows, path, scope=self.scope_text(), when=self.report_date())
            if open_after:
                QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def export_csv(self):
        self._export("Export CSV", "CSV (*.csv)", reports.to_csv)

    def export_html(self):
        self._export("HTML report", "HTML (*.html)", reports.save_html, True)

    def export_pdf(self):
        self._export("PDF report", "PDF (*.pdf)", reports.save_pdf, True)

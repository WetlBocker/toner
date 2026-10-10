import os
from datetime import datetime

from PySide6.QtCore import QUrl
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QFileDialog, QHBoxLayout, QLabel,
                               QMessageBox, QPushButton, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)
from core import alerts, db, display, reports
from drivers.base import SEVERITY, Result
from ui.widgets import FilterButton, StatusDelegate

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
        self.filter = FilterButton("Filter by status, location, vendor or tag")
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
        top.addWidget(self.info, 1)
        buttons = QHBoxLayout()
        for text, fn in (("Export CSV", self.export_csv), ("HTML report", self.export_html),
                         ("PDF report", self.export_pdf)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            buttons.addWidget(b)
        buttons.addStretch()
        buttons.addWidget(self.filter)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addLayout(buttons)
        lay.addWidget(self.table)

        self.source.currentIndexChanged.connect(lambda _: self.load_source())
        self.filter.changed.connect(self.show_preview)
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
        devices = {d["name"]: d for d in db.list_devices()}
        self._meta = {}
        for r in self.base:
            d = devices.get(alerts.base(r.device), {})
            self._meta[id(r)] = {"Status": r.status, "Location": d.get("location") or NO_LOCATION,
                                 "Vendor": d.get("vendor") or "", "Tag": {x.lower() for x in db.split_tags(d.get("tags"))}}
        self.filter.set_sections(self._sections())          # keeps ticks that still apply
        self.show_preview()

    def _sections(self):
        m = self._meta.values()
        statuses = sorted({x["Status"] for x in m}, key=lambda s: -SEVERITY[s])        # worst first
        places = sorted({x["Location"] for x in m}, key=lambda s: (s == NO_LOCATION, s.lower()))
        vendors_ = sorted({x["Vendor"] for x in m if x["Vendor"]}, key=lambda v: display.vendor_name(v).lower())
        tags = sorted({t for x in m for t in x["Tag"]})
        return {"Status": [(s, s) for s in statuses], "Location": [(p, p) for p in places],
                "Vendor": [(display.vendor_name(v), v) for v in vendors_], "Tag": [(t, t) for t in tags]}

    def selected_results(self):
        """Any of the ticked values in a submenu, and all the submenus that have something ticked."""
        want = {t: self.filter.selected(t) for t in ("Status", "Location", "Vendor", "Tag")}

        def keep(r):
            m = self._meta[id(r)]
            return all(not want[t] or m[t] in want[t] for t in ("Status", "Location", "Vendor")) and \
                (not want["Tag"] or bool(want["Tag"] & m["Tag"]))
        return [r for r in self.base if keep(r)]

    def scope_text(self):
        return self.filter.describe()

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

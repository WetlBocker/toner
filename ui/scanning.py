"""The Scanning section: known vulnerabilities of each device's software version (core/advisories), laid out like Results, with
one row per device and the checks underneath, a Scan button for the devices shown, and Export (CSV, HTML, PDF) of what is shown."""
import os
from datetime import datetime

from PySide6.QtCore import QThread, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QFileDialog, QMenu, QPushButton

from core import advisories, db, reports
from ui.results import ResultsTab
from ui.toast import toast

REPORT_TITLE = "Toner Vulnerability Report"


class ScanWorker(QThread):
    batch = Signal(list)

    def __init__(self, devices):
        super().__init__()
        self.devices = devices

    def run(self):
        advisories.scan_all(self.devices, on_rows=self.batch.emit)


class ScanningTab(ResultsTab):
    TITLE, RUN, RUN_TIP, COLUMNS_KEY = "Scanning", "Scan", "Looks up known vulnerabilities for the devices shown", "scanning_columns"
    HINT = ("No scans yet", "Choose devices and press Scan")
    LATEST, FRESH = "Latest scan of", "Scan again for fresh ones."

    def __init__(self):
        super().__init__()
        self.schedule_note.hide()
        self.export_btn = QPushButton("Export...")
        menu = QMenu(self.export_btn)
        for text, pattern, fn, open_after in (("CSV", "CSV (*.csv)", reports.to_csv, False), ("HTML report", "HTML (*.html)", reports.save_html, True),
                                              ("PDF report", "PDF (*.pdf)", reports.save_pdf, True)):
            menu.addAction(text, lambda _=False, t=text, p=pattern, f=fn, o=open_after: self.export(t, p, f, o))
        self.export_btn.setMenu(menu)
        self.bar.addWidget(self.export_btn)
        self.table.itemDoubleClicked.connect(lambda item, _col: self.open_link(item))
        self._vendors = {}

    def link_for(self, r):
        if r.device not in self._vendors:
            self._vendors[r.device] = (db.find_device(r.device) or {}).get("vendor") or ""
        return advisories.advisory_url(r.check, self._vendors[r.device])

    def repopulate(self):
        self._vendors = {}
        super().repopulate()

    def _enter(self):
        if not self.open_link(self.table.currentItem()):
            super()._enter()

    def _stored(self):
        return db.latest_scan_results()

    def _worker(self, devices):
        return ScanWorker(devices)

    def _save(self):
        db.save_scan(self.results)

    def shown_rows(self):
        """The rows on screen, device by device, worst first: what an export holds."""
        out = []
        for rows in self._searched(self._group()).values():
            for r in self._rows_for(rows)[1]:
                copy = type(r)(**{**r.__dict__, "device": db.label_org(r.device)})
                copy.url = self.link_for(r)                        # the report links an advisory id to its page
                out.append(copy)
        return out

    def export(self, title, pattern, fn, open_after):
        rows = self.shown_rows()
        if not rows:
            toast(self, "No scan results to export. Scan some devices first.")
            return
        ext = pattern.split("*")[-1].rstrip(")")
        folder = db.get_setting("report_folder")
        start = os.path.join(folder, f"Toner-scan-{datetime.now():%Y-%m-%d_%H%M}{ext}") if folder and os.path.isdir(folder) else ""
        path, _ = QFileDialog.getSaveFileName(self, title, start, pattern)
        if path:
            fn(rows, path, scope=db.org_name(db.home()), title=REPORT_TITLE, kind=reports.SCAN)
            if open_after:
                QDesktopServices.openUrl(QUrl.fromLocalFile(path))

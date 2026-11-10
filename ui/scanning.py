"""The Scanning section: known vulnerabilities of each device's software version (core/advisories), laid out like Results, with
one row per device and the checks underneath, a Scan button for the devices shown, and Export (CSV, HTML, PDF) of what is shown."""
import os
import re
from datetime import datetime

from PySide6.QtCore import QThread, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QMenu, QPushButton, QTreeWidgetItem, QWidget

from core import advisories, db, reports
from ui import chartspec
from drivers.base import SEVERITY
from ui.results import ROLE, ResultsTab
from ui.toast import toast
from ui.vulntab import band_slices
from ui.webchart import ChartView

REPORT_TITLE = "Toner Vulnerability Report"
FIXED_BUILD = re.compile(r" Fixed in build (\S+?)\.\s*$")


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
    CHIP_NOUN = ""
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
        # Two charts over the list, from the rows shown: advisories by vendor (how bad), and the CVSS scores (how many at each level).
        self.charts_btn = QPushButton("Charts")
        self.charts_btn.setCheckable(True)
        self.charts_btn.setChecked(bool(db.get_setting("scanning_charts")))
        self.charts_btn.setToolTip("Show or hide the charts over the list")
        self.charts_btn.toggled.connect(self._toggle_charts)
        self.bar.addWidget(self.charts_btn)
        self.vendor_chart = ChartView(min_height=230)
        self.vendor_chart.setAccessibleName("Advisories by vendor")
        self.vendor_chart.clicked.connect(self._vendor_clicked)
        self.cvss_chart = ChartView(min_height=230)
        self.cvss_chart.setAccessibleName("CVSS scores")
        self.charts = QWidget()
        cl = QHBoxLayout(self.charts)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(12)
        cl.addWidget(self.vendor_chart, 1)
        cl.addWidget(self.cvss_chart, 1)
        lay = self.layout()
        lay.insertWidget(lay.indexOf(self.table), self.charts)
        self.charts.setVisible(self.charts_btn.isChecked())
        self.draw_charts()
        self.table.itemExpanded.connect(self._open_group)

    _vendors = {}                                   # device key -> vendor, read once per repopulate (a lookup per row loads every device)

    def link_for(self, r):
        return advisories.advisory_url(r.check, self._vendors.get(r.device) or self._vendors.get(r.device.split("@@")[0], ""))

    def repopulate(self):
        with db.including_archived():
            devs = db.list_devices()
        self._vendors = {d["key"]: d.get("vendor") or "" for d in devs}
        self._vendors.update({d["name"]: d.get("vendor") or "" for d in devs if d["name"] not in self._vendors})
        self._lazy = {}
        super().repopulate()
        self.draw_charts()

    # ---------- a Windows device's CVEs, one line per fixed build (thousands of rows would make the list unusable); a line's CVEs are built when it is opened
    _lazy = {}                                      # group key -> its rows
    _expanding_all = False

    def _add_checks(self, parent, rows, key):
        if self._vendors.get(key) != "windows":
            return super()._add_checks(parent, rows, key)
        fixed, groups, rest = {advisories.SOFTWARE, advisories.ADVISORIES, advisories.KEV}, {}, []
        for r in rows:
            if r.check not in fixed and (advisories.cvss_of(r.value) is not None or advisories.is_unscored(r.value)):
                m = FIXED_BUILD.search(r.message)
                groups.setdefault(m.group(1) if m else None, []).append(r)
            else:
                rest.append(r)
        super()._add_checks(parent, rest, key)
        for build in sorted(groups, key=lambda b: b is None):               # the CVEs with no fix go last
            cves = groups[build]
            if len(cves) == 1:
                parent.addChild(self._check_row(cves[0]))
                continue
            text = f"{len(cves)} CVEs, " + (f"fixed in build {build}" if build else "no fix stated")
            node = QTreeWidgetItem(["", text, max(cves, key=lambda r: SEVERITY.get(r.status, 0)).status, "", "", ""])
            gkey = f"{key}\x00{text}"
            node.setData(0, ROLE, gkey)
            node.setData(1, ROLE, "device")                                  # not a check: the right-click menu looks for no raw output
            node.setChildIndicatorPolicy(QTreeWidgetItem.ChildIndicatorPolicy.ShowIndicator)
            self._lazy[gkey] = cves
            parent.addChild(node)
            node.setExpanded(gkey in self.expanded)

    def _open_group(self, item):
        cves = self._lazy.get(item.data(0, ROLE))
        if cves is not None and not item.childCount() and not self._expanding_all:
            item.addChildren([self._check_row(r) for r in cves])
            self._fit()

    def expand_all(self):
        """Opens every device, but not the CVE lines: they would build every row."""
        self._expanding_all = True
        try:
            self.table.expandAll()
        finally:
            self._expanding_all = False
        for i in range(self.table.topLevelItemCount()):
            top = self.table.topLevelItem(i)
            for j in range(top.childCount()):
                kid = top.child(j)
                if kid.data(0, ROLE) in self._lazy and not kid.childCount():
                    kid.setExpanded(False)

    # ---------- the charts
    def _toggle_charts(self, on):
        self.charts.setVisible(on)
        db.set_setting("scanning_charts", bool(on))
        if on:
            self.draw_charts()

    def restyle(self):
        self.vendor_chart.restyle()
        self.cvss_chart.restyle()

    def _advisory_rows(self):
        """The advisory rows among what is shown: a check that is neither a fixed row nor a hardening rule, with a CVSS score (or "CVSS not given") in its value."""
        fixed = {advisories.SOFTWARE, advisories.ADVISORIES, advisories.KEV}
        out = []
        for r in self.shown_rows():
            if r.check in fixed:
                continue
            score = advisories.cvss_of(r.value)
            if score is not None or advisories.is_unscored(r.value):
                out.append((r, score))
        return out

    def draw_charts(self):
        if not getattr(self, "charts", None) or not self.charts.isVisible():
            return
        from core import display
        rows = self._advisory_rows()
        if not rows:
            note = "No advisories in the rows shown" if self.results else "Scan the devices to see advisories by vendor and their scores"
            self.vendor_chart.draw(lambda p: chartspec.empty(note))
            self.cvss_chart.draw(lambda p: chartspec.empty(""))
            return
        by_vendor = {}
        for r, _score in rows:
            key = r.device.split("@@")[0]
            vendor = display.vendor_name(self._vendors.get(r.device) or self._vendors.get(key) or "") or "(no vendor)"
            by_vendor.setdefault(vendor, {"FAIL": 0, "WARN": 0, "OK": 0})
            by_vendor[vendor][r.status if r.status in ("FAIL", "WARN") else "OK"] += 1
        vendors_ = sorted(by_vendor, key=lambda v: (-sum(by_vendor[v].values()), v.lower()))
        series = [(st, [by_vendor[v][st] for v in vendors_]) for st in ("FAIL", "WARN", "OK")]
        self.vendor_chart.draw(lambda p: chartspec.grouped_bars(p, vendors_, series, title="Advisories by vendor", stacked=True))
        scores = [sc for _r, sc in rows]
        self.cvss_chart.draw(lambda p: chartspec.pie(p, band_slices(p, scores), title="CVSS scores"))

    def _vendor_clicked(self, hit):
        """A vendor's bar: the search box narrows the list to that vendor (its name is in every device's search text)."""
        name = hit.get("name")
        if name and name != "(no vendor)":
            self.find.setText(name)

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

"""The device page's Vulnerabilities tab: the device's advisories in its latest scan as a pie by CVSS severity; selecting a slice
lists those advisories underneath. The Scanning page's pie uses the same bands (band_slices)."""
from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from core import advisories, db
from ui import chartspec
from ui.detaillist import DetailList
from ui.webchart import ChartView

NO_SCAN = "No scan yet. Scan this device on the Scanning page to see its advisories."
NONE = "No advisories for this version"
COLUMNS = [("id", "Advisory"), ("title", "Title"), ("cvss", "CVSS"), ("exploited", "Exploited"), ("link", "Link")]
BAND_STATUS = {"Low": "OK", "Medium": "OK", "High": "WARN", "Critical": "FAIL"}          # the colours the Scanning page has used


def band_of(score):
    return next((name for name, lo, hi in advisories.SEVERITY_BANDS if lo <= score < hi), None)


def band_slices(p, scores):
    """The pie's slices [(severity, how many, colour)] for CVSS scores."""
    return [(name, sum(lo <= s < hi for s in scores), chartspec.status_color(p, BAND_STATUS[name])) for name, lo, hi in advisories.SEVERITY_BANDS]


class VulnTab(QWidget):
    def __init__(self):
        super().__init__()
        self.rows = []
        self.empty = QLabel()
        self.empty.setProperty("muted", True)
        self.empty.setWordWrap(True)
        self.chart = ChartView(min_height=240)
        self.chart.setAccessibleName("Vulnerabilities")
        self.chart.clicked.connect(self._slice)
        self.detail = DetailList()
        self.detail.setMinimumHeight(160)
        self.detail.doubleClicked.connect(self._open)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 8, 0, 0)
        lay.addWidget(self.empty)
        lay.addWidget(self.chart, 1)
        lay.addWidget(self.detail, 1)

    def show_device(self, dev):
        """The device's rows in the latest scan: its advisories (rows with a CVSS score) by severity, or why there are none."""
        key, org = db.key_of(dev), dev.get("org") or None
        mine = [r for r in db.latest_scan_results()[0] if r["device"] == key and (r["org"] or None) == org]
        kev = next((r["message"] or "" for r in mine if r["check_name"] == advisories.KEV), "")
        self.rows = []
        for r in mine:
            score = advisories.cvss_of(r["value"]) if r["check_name"] not in (advisories.SOFTWARE, advisories.ADVISORIES, advisories.KEV) else None
            if score is not None:
                # shortcut: a Cisco advisory's CVEs are not stored with its row, so only an advisory named by its CVE can show Yes
                self.rows.append({"id": r["check_name"], "title": (r["message"] or "").partition(" Fixed in ")[0].strip(), "cvss": score,
                                  "exploited": "Yes" if r["check_name"] in kev else "No", "link": advisories.advisory_url(r["check_name"], dev.get("vendor") or "")})
        self.empty.setText(NONE if mine else NO_SCAN)
        self.empty.setVisible(not self.rows)
        self.chart.setVisible(bool(self.rows))
        self.detail.hide()
        if self.rows:
            scores = [r["cvss"] for r in self.rows]
            self.chart.draw(lambda p: chartspec.pie(p, band_slices(p, scores)))

    def _slice(self, hit):
        """A severity was selected: its advisories, highest score first."""
        name = hit.get("name") if hit.get("kind") == "series" else None
        if name not in BAND_STATUS:
            return
        self.detail.show_rows(sorted((r for r in self.rows if band_of(r["cvss"]) == name), key=lambda r: -r["cvss"]), COLUMNS)
        self.detail.show()

    def _open(self, index):
        r = self.detail.row_at(index)
        if r and r["link"]:
            QDesktopServices.openUrl(QUrl(r["link"]))

    def restyle(self):
        self.chart.restyle()

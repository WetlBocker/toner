"""The device page's Vulnerabilities tab: the device's advisories in its latest scan as a pie by CVSS severity; selecting a slice
lists those advisories underneath. The Scanning page's pie uses the same bands (band_slices)."""
import re

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from core import advisories, db
from ui import chartspec, themes
from ui.detaillist import DetailList
from ui.webchart import ChartView

NO_SCAN = "No scan yet. Scan this device on the Scanning page to see its advisories."
NONE = "No advisories for this version"
COLUMNS = [("id", "Advisory"), ("title", "Title"), ("cvss", "CVSS"), ("exploited", "Exploited"), ("link", "Link")]
CVE = r"CVE-\d{4}-\d+"
BAND_STATUS = {"Low": "OK", "Medium": "OK", "High": "WARN", "Critical": "FAIL", advisories.UNSCORED: "N/A"}          # the colours the Scanning page has used


def band_of(score):
    if score is None:
        return advisories.UNSCORED
    return next((name for name, lo, hi in advisories.SEVERITY_BANDS if lo <= score < hi), None)


def exploited(r, score, on_list):
    """'Yes' or 'No' for an advisory row, or '' when it cannot be told. A row is FAIL exactly when its CVSS is 9 or more or one of its
    CVEs is on CISA's list (advisories.status_of); a row named by its CVE is looked up in the list itself."""
    if r["status"] != "FAIL":
        return "No"
    if (score or 0) < 9:
        return "Yes"
    if re.fullmatch(CVE, r["check_name"]):
        return "Yes" if r["check_name"] in on_list else "No"
    return ""                                       # FAIL for its score alone or for the list too: the row does not say


def band_slices(p, scores):
    """The pie's slices [(severity, how many, colour)] for CVSS scores; None (not given) adds its own slice at the end."""
    colour = lambda name: (themes.mix(chartspec.status_color(p, "OK"), chartspec.status_color(p, "WARN"), 0.5) if name == "Medium"   # its own, between Low and High
                           else chartspec.status_color(p, BAND_STATUS[name]))
    out = [(name, sum(s is not None and lo <= s < hi for s in scores), colour(name)) for name, lo, hi in advisories.SEVERITY_BANDS]
    if None in scores:
        out.append((advisories.UNSCORED, scores.count(None), chartspec.status_color(p, BAND_STATUS[advisories.UNSCORED])))
    return out


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
        on_list = set(re.findall(CVE, next((r["message"] or "" for r in mine if r["check_name"] == advisories.KEV), "")))
        software = next((r for r in mine if r["check_name"] == advisories.SOFTWARE), None)
        self.rows = []
        for r in mine:
            advisory = r["check_name"] not in (advisories.SOFTWARE, advisories.ADVISORIES, advisories.KEV)
            score = advisories.cvss_of(r["value"]) if advisory else None
            if score is not None or (advisory and advisories.is_unscored(r["value"])):
                self.rows.append({"id": r["check_name"], "title": (r["message"] or "").partition(" Fixed in ")[0].strip(), "cvss": score,
                                  "exploited": exploited(r, score, on_list), "link": advisories.advisory_url(r["check_name"], dev.get("vendor") or "")})
        # nothing looked up (no source, lookups off, no version, the source refused): the version row says why
        looked = software is None or software["status"] not in ("N/A", "ERROR")
        self.empty.setText(NO_SCAN if not mine else NONE if looked else software["message"] or "")
        self.empty.setVisible(not self.rows)
        self.chart.setVisible(bool(self.rows))
        self.detail.hide()
        if self.rows:
            scores = [r["cvss"] for r in self.rows]
            self.chart.draw(lambda p: chartspec.pie(p, band_slices(p, scores), counts=True))

    def _slice(self, hit):
        """A severity was selected: its advisories, highest score first."""
        name = hit.get("name") if hit.get("kind") == "series" else None
        if name not in BAND_STATUS:
            return
        self.detail.show_rows(sorted((r for r in self.rows if band_of(r["cvss"]) == name), key=lambda r: -(r["cvss"] or 0)), COLUMNS)
        self.detail.show()

    def _open(self, index):
        r = self.detail.row_at(index)
        if r and r["link"]:
            QDesktopServices.openUrl(QUrl(r["link"]))

    def restyle(self):
        self.chart.restyle()

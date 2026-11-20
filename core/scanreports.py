"""The vulnerability and hardening reports (Settings > Reports): the latest scan's rows of one kind, made with the Scanning page's
report writer, on a schedule of their own or sent now. In Global they cover every organization's devices, in an organization its own."""
import os
import shutil
import tempfile
from datetime import datetime

from core import db, hardening, notify, periods, reports, trends
from drivers.base import Result

FMT = periods.FMT
# the settings prefix -> (its row in Settings > Reports, the report's title, the file name's word)
KINDS = {"vuln_report": ("Vulnerability report", "Toner Vulnerability Report", "vulnerability"),
         "hardening_report": ("Hardening report", "Toner Hardening Report", "hardening")}
NO_SCAN = "No scan yet. Scan on the Scanning page first."


def _hardening(check):
    return check == hardening.PREFIX.rstrip(": ") or check.startswith(hardening.PREFIX)


def rows(report):
    """The latest scan's rows for this report, as the Scanning page loads its latest scan: hardening rules for the hardening report,
    the version lookups (version, advisories, CISA) for the vulnerability report."""
    want = report == "hardening_report"
    return [Result(db.label_org(r["device"]), r["check_name"], r["status"], r["value"] or "", r["message"] or "", org=r["org"])
            for r in db.latest_scan_results()[0] if _hardening(r["check_name"]) == want]


def make(report, folder, now):
    """Save the report into `folder` (a PDF from the window, HTML from the service). Returns its path, or '' when there is no scan yet."""
    found = rows(report)
    if not found:
        return ""
    pdf = trends.pdf_ok()
    path = os.path.join(folder, f"Toner-{KINDS[report][2]}-{now:%Y-%m-%d}") + (".pdf" if pdf else ".html")
    (reports.save_pdf if pdf else reports.save_html)(found, path, scope=db.org_name(db.target()), title=KINDS[report][1], kind=reports.SCAN)
    return path


def due(report, now=None):
    return periods.is_due(db.get_setting(f"{report}_schedule"), db.get_setting(f"{report}_last"), now)


def generate_scheduled(report, now=None):
    """Make the report into the default folder and mail it to its addresses, as the trend report is. Returns the path, or '' when there is
    nowhere to put it or no scan yet (then the time is not stored, so it is made once there is one)."""
    folder = db.get_setting("report_folder")
    if not folder or not os.path.isdir(folder):
        return ""
    now = now or datetime.now()
    path = make(report, folder, now)
    if not path:
        return ""
    db.set_setting(f"{report}_last", now.strftime(FMT))        # (before the mail: a server that refuses must not make it again each minute)
    to = db.get_setting(f"{report}_email")
    if to:
        trends.mail(KINDS[report][0], db.get_setting(f"{report}_schedule"), to, [path], now)
    return path


def send_now(report, kind, to, now=None):
    """Settings > Reports, Send now: make the report ("trend" or a KINDS key) for schedule `kind` and mail it to `to`, leaving its last
    time alone. Made in the default folder, else in a temporary one removed afterwards. Returns the text shown beside the button."""
    now = now or datetime.now()
    folder = db.get_setting("report_folder")
    temp = None if folder and os.path.isdir(folder) else tempfile.mkdtemp(prefix="toner-report-")
    try:
        if report == "trend":
            files, label = trends.make(temp or folder, kind, now), "Trend report"
        else:
            path, label = make(report, temp or folder, now), KINDS[report][0]
            if not path:
                return NO_SCAN
            files = [path]
        sent, detail = trends.mail(label, kind, to, files, now)
    finally:
        if temp:
            shutil.rmtree(temp, ignore_errors=True)
    n = len(notify.addresses(to))
    return (f"Sent to {n} address." if n == 1 else f"Sent to {n} addresses.") if sent else f"Couldn't send the report: {detail}"

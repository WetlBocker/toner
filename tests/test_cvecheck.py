# Run directly (python tests/test_cvecheck.py) or all together (python tests/run_all.py). Its own throw-away database, fake sources.
# Check CVEs on the Scanning page (core.advisories.check_all, ui.cvecheck) and the severity ring's counts, total and Medium colour.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "cvecheck%d.db" % int(time.time())); os.environ["APPDATA"] = SP
from core import db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtWidgets import QApplication
app = QApplication([])
from core import advisories as A

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

print("== picking CVE IDs out of pasted text")
check("each ID once, upper-cased, in order; a malformed one is left out",
      A.cve_ids("see cve-2024-55591, CVE-2024-55591 and CVE-2023-20198; CVE-21-1") == ["CVE-2024-55591", "CVE-2023-20198"])
check("nothing that looks like a CVE gives none", A.cve_ids("FG-IR-24-535 and some words") == [])

# ---------------------------------------------------------------- fake NVD, PSIRT, Fortinet feed and CISA list
def cfg(*criteria):
    return [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": c, **extra} for c, extra in criteria]}]}]
RECORDS = {
    "CVE-2024-55591": {"id": "CVE-2024-55591", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.6}}]},
                       "configurations": cfg(("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", {"versionStartIncluding": "7.0.0", "versionEndExcluding": "7.0.17"}))},
    "CVE-2026-1000": {"id": "CVE-2026-1000"},                                                   # published, not analysed
    "CVE-2020-3452": {"id": "CVE-2020-3452", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]},
                      "configurations": cfg(("cpe:2.3:a:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*", {"versionEndExcluding": "9.12.4.2"}))},
    "CVE-2025-9999": {"id": "CVE-2025-9999", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.8}}]},
                      "configurations": cfg(("cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:x64:*", {"versionEndExcluding": "10.0.20348.5761"}))},
}
AFFECTS = {("CVE-2024-55591", "cpe:2.3:o:fortinet:fortios:7.0.10:*"), ("CVE-2020-3452", "cpe:2.3:a:cisco:adaptive_security_appliance_software:9.12.1:*"),
           ("CVE-2025-9999", "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.5760:*")}
asked, nvd_state = [], {"code": 200}
class Resp:
    def __init__(self, code, body): self.status_code, self._body = code, body
    def json(self): return self._body
def fake_get(url, host, params=None, headers=None, **kw):
    asked.append(dict(params or {}))
    if nvd_state["code"] != 200:
        return Resp(nvd_state["code"], {})
    cve, cpe = params.get("cveId"), params.get("virtualMatchString")
    hit = cve in RECORDS and (cpe is None or (cve, cpe) in AFFECTS)
    return Resp(200, {"totalResults": int(hit), "vulnerabilities": [{"cve": RECORDS[cve]}] if hit else []})
A._get = fake_get
psirt_state = {"down": False}
def fake_psirt(os_, version, *a):
    if psirt_state["down"]:
        raise A.LookupError_("Cisco PSIRT: no client id and secret. Check Settings > Scanning.")
    return [{"id": "cisco-sa-iosxe-webui", "title": "", "cves": ["CVE-2023-20198"], "cvss": 10.0, "sir": "", "fixed": ["17.9.4a"],
             "url": "https://sec.cloudapps.cisco.com/x"}] if version == "17.9.4" else []
A.psirt = fake_psirt
A.fortinet_feed = lambda version: [{"id": "FG-IR-26-182", "title": "", "summary": "", "cves": ["CVE-2026-1000"], "cvss": 2.1, "sir": "", "fixed": ["7.6.9"],
                                    "url": "https://fortiguard.com/psirt/FG-IR-26-182"}] if version.lstrip("v").startswith("7.6") else []
A.kev = lambda: {"CVE-2023-20198": "Cisco IOS XE Web UI Privilege Escalation Vulnerability"}
db.set_setting("scan_enabled", True)

def dev(name, vendor, version="", platform=""):
    d = {"name": name, "vendor": vendor, "host": f"10.0.0.{len(db.list_devices()) + 1}", "platform": platform, "enabled": 1}
    d["id"] = db.save_device(d)
    if version:
        db.set_software(d, {"version": version})
    return next(x for x in db.list_devices() if x["name"] == name)
fg_old, fg_new, fg_76 = dev("fg-old", "fortinet", "v7.0.10"), dev("fg-new", "fortinet", "v7.0.17"), dev("fg-76", "fortinet", "v7.6.3")
pa = dev("pa", "paloalto", "11.1.4")
xe, xe_clean, asa = dev("xe", "cisco", "17.09.04", "cisco_xe"), dev("xe-clean", "cisco", "17.12.1", "cisco_xe"), dev("asa", "cisco", "9.12(1)", "cisco_asa")
win = dev("win", "windows", "Microsoft Windows Server 2022 Standard (build 20348.5760)")
blank = dev("blank", "fortinet")

def one(d, cve):
    rows = A.check_all([d], [cve])
    return (rows[0]["status"], rows[0]["details"], rows[0]["link"]) if len(rows) == 1 else rows

print("== NVD first")
check("a version inside the range is affected, FAIL at CVSS 9 or more, with the fix and the CVE's NVD page",
      one(fg_old, "CVE-2024-55591") == ("FAIL", "Affected: FortiOS 7.0.10. CVSS 9.6, fixed in 7.0.17.", "https://nvd.nist.gov/vuln/detail/CVE-2024-55591"), one(fg_old, "CVE-2024-55591"))
check("the fixed version is outside the affected versions", one(fg_new, "CVE-2024-55591")[:2] == ("OK", "Not affected: FortiOS 7.0.17 is outside the affected versions."))
check("a CVE that does not name the product is not affected, without asking about the version",
      one(pa, "CVE-2024-55591")[:2] == ("OK", "Not affected: CVE-2024-55591 does not list PAN-OS.") and "virtualMatchString" not in asked[-1])
check("a CVE NVD has not analysed cannot be told, never 'not affected'", one(pa, "CVE-2026-1000")[:2] == ("N/A", "Cannot tell: NVD has not analysed CVE-2026-1000 yet."))
check("an ID NVD does not know says so", one(pa, "CVE-2026-99999")[:2] == ("N/A", "NVD has no record of CVE-2026-99999."))
check("...Fortinet then asks its feed, which can say affected (WARN even at a low score, never OK; the FortiGuard page)",
      one(fg_76, "CVE-2026-1000") == ("WARN","Affected: FortiOS 7.6.3. CVSS 2.1, fixed in 7.6.9.", "https://fortiguard.com/psirt/FG-IR-26-182"), one(fg_76, "CVE-2026-1000"))
check("...and when the feed has nothing either, it still cannot tell", one(fg_old, "CVE-2026-1000")[0] == "N/A")
asked.clear(); one(asa, "CVE-2020-3452")
psirt_state["down"] = True
asa_row = one(asa, "CVE-2020-3452")
psirt_state["down"] = False
check("a product NVD lists as an application is asked about as one (ASA)", asa_row[0] == "WARN" and any(p.get("virtualMatchString", "").startswith("cpe:2.3:a:cisco:adaptive") for p in asked)
      and "fixed in 9.12.4.2" in asa_row[1], (asa_row, asked))
check("Windows is asked by its exact build, and the fix is a build", one(win, "CVE-2025-9999")[:2] == ("WARN", "Affected: Windows Server 2022 10.0.20348.5760. CVSS 7.8, fixed in build 10.0.20348.5761."),
      one(win, "CVE-2025-9999"))

print("== Cisco: PSIRT first")
check("PSIRT's advisory for the version: affected, FAIL when exploited, with Cisco's page",
      one(xe, "CVE-2023-20198") == ("FAIL", "Affected: IOS XE 17.9.4. CVSS 10, fixed in 17.9.4a.", "https://sec.cloudapps.cisco.com/x"), one(xe, "CVE-2023-20198"))
check("PSIRT answers for the version without it: outside the affected versions", one(xe_clean, "CVE-2023-20198")[:2] == ("OK", "Not affected: IOS XE 17.12.1 is outside the affected versions."))
check("...or, when NVD's record names other products only, not listed", one(xe_clean, "CVE-2024-55591")[:2] == ("OK", "Not affected: CVE-2024-55591 does not list IOS XE."))

print("== many devices, many CVEs")
asked.clear()
rows = A.check_all([fg_old, fg_new, pa, blank], ["CVE-2024-55591", "CVE-2026-1000"])
records = [p for p in asked if "virtualMatchString" not in p]
check("a row per device and CVE, in order", [(r["device"], r["cve"]) for r in rows] == [(d, c) for d in ("fg-old", "fg-new", "pa", "blank") for c in ("CVE-2024-55591", "CVE-2026-1000")])
check("NVD is asked about each CVE once, whatever the number of devices", sorted(p["cveId"] for p in records) == ["CVE-2024-55591", "CVE-2026-1000"], records)
check("a device with no version says why, for every CVE, as Scan does", [r["details"] for r in rows if r["device"] == "blank"] == [A.NO_VERSION] * 2)
got = []
A.check_all([fg_old, pa], ["CVE-2024-55591"], on_rows=got.append)
check("rows are handed over a device at a time", [len(b) for b in got] == [1, 1])
nvd_state["code"] = 403
lim = one(pa, "CVE-2024-55591")
nvd_state["code"] = 200
check("NVD's rate limit is an ERROR row that says so", lim[0] == "ERROR" and "rate limit" in lim[1], lim)
A.db.set_setting("scan_enabled", False)
check("lookups off: every row says so", one(pa, "CVE-2024-55591")[:2] == ("N/A", A.OFF))
A.db.set_setting("scan_enabled", True)

print("== Scan's rows are unchanged by the shared preparation")
check("a device with no version still gives Scan's one row", [(r.check, r.status, r.message) for r in A.versions(blank)] == [(A.SOFTWARE, "N/A", A.NO_VERSION)])

print("== the Scanning page")
from ui import cvecheck
from ui.scanning import ScanningTab
tab = ScanningTab()
check("Check CVEs sits right after Scan, with its tooltip", tab.bar.indexOf(tab.cve_btn) == tab.bar.indexOf(tab.run_btn) + 1 and tab.cve_btn.text() == "Check CVEs"
      and tab.cve_btn.toolTip() == "Checks whether the devices shown are affected by the CVEs you enter")
tab.check_cves()
dlg = tab.cve_dialog
check("the dialog opens with its title and prompt", dlg.isVisible() and dlg.windowTitle() == "Check CVEs")
dlg.check()
check("nothing entered says so", dlg.info.text() == "No CVE IDs found in what you entered.")
dlg.devices_shown = lambda: []
dlg.box.setPlainText("CVE-2024-55591")
dlg.check()
check("no devices shown says so", dlg.info.text() == "No enabled devices are shown.")
dlg.devices_shown = lambda: [fg_old, pa]
dlg.check()
check("while it runs: what it is checking, and Check waits", dlg.info.text() == "Checking 1 CVE on 2 devices..." and not dlg.go.isEnabled(), dlg.info.text())
end = time.time() + 10
while dlg.worker.isRunning() and time.time() < end:
    app.processEvents(); time.sleep(0.02)
app.processEvents()
m = dlg.table.model()
check("the answers fill the table: Device, CVE, Status, Details", [m.headerData(i, __import__("PySide6.QtCore", fromlist=["Qt"]).Qt.Orientation.Horizontal) for i in range(4)]
      == ["Device", "CVE", "Status", "Details"] and m.rowCount() == 2 and [r["status"] for r in dlg.rows] == ["FAIL", "OK"])
check("then Check is ready again", dlg.go.isEnabled() and dlg.info.text() == "")
check("the status line counts in plural", cvecheck.checking(["a", "b"], [1, 2, 3]) == "Checking 2 CVEs on 3 devices...")
tab.check_cves()
check("pressing the button again shows the same dialog", tab.cve_dialog is dlg)
dlg.close()

print("== the severity ring")
from ui import chartspec
from ui.vulntab import band_slices
p = chartspec.palette()
sl = band_slices(p, [2.0, 5.0, 5.5, 7.5, 9.8, None])
colours = {n: c for n, _v, c in sl}
check("Medium has its own colour, between Low's and High's", len({colours["Low"], colours["Medium"], colours["High"]}) == 3)
opt = chartspec.pie(p, sl, title="CVSS scores", counts=True)
ser = opt["series"][0]
check("each slice shows its count, inside it", ser["label"]["show"] and ser["label"]["position"] == "inside" and ser["label"]["formatter"] == "{c}")
check("a slice too thin for its count shows none", ser["minShowLabelAngle"] > 0)
check("the count is white or near-black, whichever reads on the slice", {d["label"]["color"] for d in ser["data"]} <= {"#ffffff", "#111111"})
check("the middle shows the total, with 'total' under it", opt["title"][1]["text"] == "6" and opt["title"][1]["subtext"] == "total" and opt["title"][0]["text"] == "CVSS scores")

print(f"\n{ok} passed, {bad} failed")
sys_exit = __import__("sys").exit
sys_exit(1 if bad else 0)

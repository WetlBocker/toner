# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The Scanning section: lookups at fake PSIRT, NVD, CISA and EPSS servers, the rows a scan makes, the cache, storage per
# organization, the tab, its export, the Inventory menu, Settings > Scanning, the Assistant's tool, the README and the version.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, json, threading
import http.server as _hs
from urllib.parse import parse_qs, urlparse
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\scan%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db, orgs
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtWidgets import QApplication
app = QApplication([])
from core import advisories as A
from drivers.base import Result

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

# ---------------------------------------------------------------- the fake sources
hits = []
PSIRT = {"advisories": [
    {"advisoryId": "cisco-sa-iosxe-webui-privesc-j22SaA4z", "advisoryTitle": "Cisco IOS XE Software Web UI Privilege Escalation Vulnerability",
     "cves": ["CVE-2023-20198"], "cvssBaseScore": "10.0", "sir": "Critical", "firstFixed": ["17.9.4a"], "publicationUrl": "https://sec.cloudapps.cisco.com/x"},
    {"advisoryId": "cisco-sa-dhcp-dos-abc", "advisoryTitle": "Cisco IOS XE DHCP Snooping Denial of Service", "cves": ["CVE-2024-20259"],
     "cvssBaseScore": "8.6", "sir": "High", "firstFixed": ["17.9.5"], "publicationUrl": ""},
    {"advisoryId": "cisco-sa-low-thing", "advisoryTitle": "Cisco IOS XE Information Disclosure", "cves": ["CVE-2024-99999"],
     "cvssBaseScore": "4.3", "sir": "Medium", "firstFixed": ["NA"], "publicationUrl": ""}]}
NVD = {"resultsPerPage": 1, "totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2024-1111", "descriptions": [
    {"lang": "en", "value": "A heap-based buffer overflow in FortiOS SSL-VPN. An attacker may run code."}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]}}}]}
class Sources(_hs.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body):
        data = json.dumps(body).encode(); self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        form = parse_qs(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode())
        hits.append(("token", form.get("client_id", [""])[0]))
        if (form.get("client_id"), form.get("client_secret"), form.get("grant_type")) == (["cid-1"], ["sec-1"], ["client_credentials"]):
            self._send(200, {"access_token": "tok-1", "expires_in": 3599})
        else:
            self._send(401, {"error": "invalid_client"})
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query); hits.append((u.path, q))
        if u.path.startswith("/psirt/"):
            if self.headers.get("Authorization") != "Bearer tok-1":
                return self._send(401, {"error": "bad token"})
            os_, version = u.path.split("/")[2], q.get("version", [""])[0]
            return self._send(200, PSIRT) if (os_, version) == ("iosxe", "17.9.4a") else self._send(406, {"errorCode": "NOT_FOUND", "errorMessage": "No data found"})
        if u.path == "/nvd":
            self.server.nvd_keys.append(self.headers.get("apiKey"))
            return self._send(200, NVD if q.get("virtualMatchString") == ["cpe:2.3:o:fortinet:fortios:7.2.5:*"] else {"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []})
        if u.path == "/kev":
            return self._send(200, {"vulnerabilities": [{"cveID": "CVE-2023-20198"}, {"cveID": "CVE-2021-44228"}]})
        if u.path == "/epss":
            asked = q.get("cve", [""])[0].split(",")
            return self._send(200, {"data": [{"cve": c, "epss": "0.9432"} for c in asked if c == "CVE-2023-20198"] + [{"cve": c, "epss": "0.0071"} for c in asked if c == "CVE-2024-1111"]})
        self._send(404, {})
web = _hs.ThreadingHTTPServer(("127.0.0.1", 0), Sources); web.nvd_keys = []; threading.Thread(target=web.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{web.server_address[1]}"
A.TOKEN_URL, A.PSIRT_URL, A.NVD_URL, A.KEV_URL, A.EPSS_URL = base + "/token", base + "/psirt/{os}?version={version}", base + "/nvd", base + "/kev", base + "/epss"

# ---------------------------------------------------------------- devices: Global's and one organization's
def dev(name, vendor, version="", platform="", org=None, folder=None):
    d = {"name": name, "vendor": vendor, "host": f"10.0.0.{len(db.list_devices()) + 1}", "platform": platform, "folder_id": folder, "org": org, "enabled": 1}
    with db.within(org):
        d["id"] = db.save_device(d)
    if version:
        db.set_software(d, {"version": version})
    return d
acme = orgs.create("Acme Charter", "ACME")
core = db.create_folder("Core")
c9300 = dev("c9300", "cisco", "17.09.04a", "cisco_xe", folder=core)
old = dev("old-rtr", "cisco", "15.2(4)M7")
fw = dev("edge-fw", "fortinet", "v7.2.5")
mt = dev("mt", "mikrotik")
pc = dev("pc", "windows", "10.0.19045")
a_sw = dev("acme-sw", "cisco", "17.09.04a", "cisco_xe", org=acme)
A.set_secret("psirt_id", "cid-1"); A.set_secret("psirt_secret", "sec-1")

print("== the version each source is asked about")
check("a Catalyst's 17.09.04a is asked for as 17.9.4a; 15.2(4)M7 stays", A.cisco_version("17.09.04a") == "17.9.4a" and A.cisco_version("15.2(4)M7") == "15.2(4)M7")
check("a Cisco device without a platform: IOS XE for 16 and 17, else IOS, and it says so", A.cisco_os(c9300) == ("iosxe", False) and A.cisco_os(old) == ("ios", True)
      and A.cisco_os({"vendor": "cisco", "sw_version": "17.3.5"}) == ("iosxe", True))
check("CPE parts: FortiOS loses its v, Junos splits at R and drops the build", A.cpe_version("fortinet", "v7.2.5") == ("7.2.5", "*")
      and A.cpe_version("juniper", "22.4R3-S2.1") == ("22.4", "r3-s2") and A.cpe_version("mikrotik", "7.12 (stable)") == ("7.12", "*"))
check("statuses: KEV or 9+ fails, 7 to 8.9 warns, below is OK", A.status_of({"cvss": 4.3, "cves": ["CVE-2023-20198"]}, {"CVE-2023-20198"}) == "FAIL"
      and A.status_of({"cvss": 9.0, "cves": []}, set()) == "FAIL" and A.status_of({"cvss": 8.6, "cves": ["x"]}, set()) == "WARN" and A.status_of({"cvss": 6.9, "cves": []}, set()) == "OK")

print("== one device's rows")
rows = A.scan(db.find_device("c9300"))
by = {r.check: r for r in rows}
check("software version row OK, naming the OS, version and read date", by[A.SOFTWARE].status == "OK" and by[A.SOFTWARE].value == "17.09.04a" and by[A.SOFTWARE].message.startswith("IOS XE 17.9.4a, read 20"), by[A.SOFTWARE])
check("one row per advisory, worst first, with CVSS and EPSS and the fix", [r.check for r in rows[1:4]] == ["cisco-sa-iosxe-webui-privesc-j22SaA4z", "cisco-sa-dhcp-dos-abc", "cisco-sa-low-thing"]
      and rows[1].status == "FAIL" and rows[1].value == "CVSS 10 · EPSS 94%" and rows[1].message == "Cisco IOS XE Software Web UI Privilege Escalation Vulnerability Fixed in 17.9.4a."
      and rows[2].status == "WARN" and rows[2].value == "CVSS 8.6" and rows[3].status == "OK" and rows[3].message == "Cisco IOS XE Information Disclosure", [(r.check, r.status, r.value, r.message) for r in rows])
check("the CISA row fails, naming the exploited CVE", by[A.KEV].status == "FAIL" and by[A.KEV].message == "CVE-2023-20198 on CISA's known exploited list", by[A.KEV])
check("no 'advisories' row when some were found", A.ADVISORIES not in by and len(rows) == 6)
rows = A.scan(db.find_device("old-rtr")); by = {r.check: r for r in rows}
check("a version with nothing published: software OK (platform assumed), 'No known advisories', CISA OK", by[A.SOFTWARE].message.startswith("IOS 15.2(4)M7 (platform assumed from the version), read 20")
      and by[A.ADVISORIES].status == "OK" and by[A.ADVISORIES].message == A.NONE_FOUND and by[A.KEV].status == "OK" and by[A.KEV].message == A.NONE_KEV, [(r.check, r.status, r.message) for r in rows])
rows = A.scan(db.find_device("edge-fw")); by = {r.check: r for r in rows}
check("a Fortinet goes to NVD: one row per CVE, the first sentence as its title, WARN at 7.5", by["CVE-2024-1111"].status == "WARN" and by["CVE-2024-1111"].value == "CVSS 7.5 · EPSS 1%"
      and by["CVE-2024-1111"].message == "A heap-based buffer overflow in FortiOS SSL-VPN" and by[A.SOFTWARE].message.startswith("fortios 7.2.5, read 20"), [(r.check, r.status, r.value, r.message) for r in rows])
from core import backup
fg2 = dev("fg2", "fortinet"); pa2 = dev("pa2", "paloalto"); jn = dev("jn", "juniper")
backup.store("fg2", "#config-version=FGVM64-8.0.0-FW-build0167-260420:opmode=0:vdom=0:user=api-admin\n#conf_file_ver=2\nconfig system global\n    set alias \"FortiG8\"\nend\n", mask=False)
backup.store("pa2", '<config version="11.1.0" urldb="paloaltonetworks" detail-version="11.1.4"><mgt-config/></config>', mask=False)
backup.store("jn", "## Last commit: 2026-10-28 by admin\nversion 22.4R3-S2.1;\nsystem {\n    host-name jn;\n}\n", mask=False)
for d, want, what in ((fg2, "8.0.0", "fortios 8.0.0"), (pa2, "11.1.4", "pan-os 11.1.4"), (jn, "22.4R3-S2.1", "junos 22.4 r3-s2")):
    r = A.scan(db.find_device(d["name"]))[0]
    check(f"no version from the checks: {d['vendor']} takes it from the newest backup", r.check == A.SOFTWARE and r.status == "OK" and r.value == want
          and r.message.startswith(f"{what}, from the configuration backup of 20"), (r.value, r.message))
backup.store("pa2", '<config version="11.1.0"><mgt-config/></config>', mask=False)
check("PAN-OS without a detail-version: the version attribute", A.version_from_backup(db.find_device("pa2"))[0] == "11.1.0")
check("a backup with no version line, or none at all: nothing", A.version_from_backup({"name": "c9300", "vendor": "cisco"}) == ("", "") and A.version_from_backup(db.find_device("mt")) == ("", ""))
for d in (fg2, pa2, jn):
    db.delete_device(d["id"])                             # the later counts are of the six devices above
check("no version yet: one N/A row saying to run the checks", [(r.check, r.status, r.message) for r in A.scan(db.find_device("mt"))] == [(A.SOFTWARE, "N/A", A.NO_VERSION), ("Hardening", "N/A", "No hardening rules for this vendor yet.")])
check("a vendor with no source: one N/A row saying so", [(r.check, r.status, r.message) for r in A.scan(db.find_device("pc"))] == [(A.SOFTWARE, "N/A", A.NO_SOURCE), ("Hardening", "N/A", "No hardening rules for this vendor yet.")])
n = len(hits); A.scan(db.find_device("c9300")); A.scan(db.find_device("edge-fw"))
check("a second scan of the same versions asks the sources nothing (a day's cache in the Global file)", len(hits) == n, hits[n:])
A.forget_cache(); A.set_secret("psirt_secret", "wrong")
rows = A.scan(db.find_device("c9300"))
check("a rejected sign-in: one ERROR row with Cisco's words and the app type to register", len(rows) == 2 and rows[0].status == "ERROR" and rows[0].message == f"17.09.04a: Cisco PSIRT: sign-in rejected (invalid_client). {A.APP_TYPE}", rows)
A.set_secret("psirt_secret", ""); A._token.clear()
check("no account: one ERROR row saying so", A.scan(db.find_device("c9300"))[0].message.endswith(f"Cisco PSIRT: no client id and secret. {A.CHECK_SETTINGS}"))
A.set_secret("psirt_secret", "sec-1")
check("the NVD key is sent when there is one", web.nvd_keys and web.nvd_keys[-1] is None and (A.set_secret("nvd_key", "nvd-k"), A.forget_cache(), A.scan(db.find_device("edge-fw"))) and web.nvd_keys[-1] == "nvd-k", web.nvd_keys)
check("Test says what Cisco and NVD answered", A.test("cid-1", "sec-1", "nvd-k") == "Cisco PSIRT answered: 3 advisories for IOS XE 17.9.4a. NVD answered: 1 CVE for FortiOS 7.2.5."
      and A.test("cid-1", "bad", "") == f"Cisco PSIRT: sign-in rejected (invalid_client). {A.APP_TYPE}", A.test("cid-1", "sec-1", "nvd-k"))

print("== stored per organization, read like results")
db.set_home(db.GLOBAL)
all_rows = A.scan_all(db.list_devices())
sid = db.save_scan(all_rows)
stored, at = db.latest_scan_results()
check("Global's latest scan holds every device of the view, keyed by organization", {r["device"] for r in stored} == {"c9300", "old-rtr", "edge-fw", "mt", "pc", db.dkey("acme-sw", acme)} and at[:2] == "20", {r["device"] for r in stored})
with db.within(acme):
    with db.connect() as c:
        own = c.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
with db.connect() as c:
    here = c.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
check("the organization's rows went to its own file, Global's to Global's", own == 6 and here == len(all_rows) - 6, (own, here))
db.save_run([Result("c9300", "cpu", "OK", "3%")])
check("health views do not see scan rows", all(r["check_name"] == "cpu" for r in db.latest_results()[0] if r["device"] == "c9300"))
db.set_home(acme)
check("seen from the organization: only its own", {r["device"] for r in db.latest_scan_results()[0]} == {"acme-sw"})
db.set_home(db.GLOBAL)

print("== the Scanning tab")
import ui.scanning as S
tab = S.ScanningTab(); tab.resize(1000, 600); tab.show(); app.processEvents()
check("laid out like Results, with its own words", tab.header.title.text() == "Scanning" and tab.run_btn.text() == "Scan" and tab.export_btn.text() == "Export..."
      and [a.text() for a in tab.export_btn.menu().actions()] == ["CSV", "HTML report", "PDF report"] and not tab.schedule_note.isVisible())
check("it opens on the latest stored scan", tab.stored and tab.summary.text().startswith("Latest scan of 6 devices") and tab.summary.text().endswith("Scan again for fresh ones."), tab.summary.text())
tab.run_devices(["c9300", "edge-fw"])
t0 = time.time()
while tab.running() and time.time() - t0 < 30: app.processEvents(); time.sleep(0.02)
app.processEvents()
check("Scan runs just those devices and shows their rows", not tab.running() and tab.summary.text() == "2 devices, 10 checks" and tab.table.topLevelItemCount() == 2, tab.summary.text())
top = next(tab.table.topLevelItem(i) for i in range(tab.table.topLevelItemCount()) if tab.table.topLevelItem(i).text(0) == "c9300")
check("the device row says the worst, and the advisory rows sit under it", top.text(2) == "FAIL" and top.text(1) == "6 checks" and "cisco-sa-iosxe-webui" in top.text(4)
      and {top.child(k).text(1) for k in range(top.childCount())} >= {"software version", "known exploited (CISA)", "cisco-sa-dhcp-dos-abc"}, (top.text(1), top.text(2), top.text(4)))
with db.connect() as c:
    newest = c.execute("SELECT MAX(id) FROM scans").fetchone()[0]
    just = {r[0] for r in c.execute("SELECT device FROM scan_results WHERE scan_id=?", (newest,))}
    n_scans = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
check("the run was stored as a scan of its own", n_scans == 2 and just == {"c9300", "edge-fw"}, (n_scans, just))
out = os.path.join(SP, "scan.html"); S.QFileDialog.getSaveFileName = lambda *a, **k: (out, "")
S.QDesktopServices.openUrl = lambda *a: None
tab.export("HTML report", "HTML (*.html)", S.reports.save_html, True)
html = open(out, encoding="utf-8").read()
check("Export writes what is shown, under its own title", "<h1>Toner Vulnerability Report</h1>" in html and "cisco-sa-iosxe-webui-privesc-j22SaA4z" in html and "CVE-2024-1111" in html and "Global" in html)
check("the first page lists every device as a link to its section, then a page break before Needs attention", '<a href="#dev-c9300">c9300</a>' in html and '<a href="#dev-edge-fw">edge-fw</a>' in html
      and '<a name="dev-c9300"' in html and 'page-break-before: always">Needs attention' in html and html.index("#dev-c9300") < html.index("Needs attention") < html.index('name="dev-c9300"'))
check("each device's section starts with its version, advisories and CISA line", "<p>Version 17.09.04a · 3 advisories (1 FAIL, 1 WARN) · on CISA&#x27;s known exploited list</p>" in html
      and "<p>Version v7.2.5 · 1 advisory (1 WARN)</p>" in html, [l[:80] for l in html.split("<p>") if l.startswith("Version")])
check("...and the hardening part once rules ran", S.reports._scan_line([Result("x", "Hardening: Telnet allowed on VTY lines", "FAIL", "", "m"), Result("x", "Hardening: No NTP server", "OK", "", "not found")]) == "Version unknown · hardening: 1 of 2 rules flagged")
check("only the Status cell is coloured, and Message gets the widest column", html.count('bgcolor="#ffcdd2"') == html.count("<b>FAIL</b>") and '<th width="42%"' in html and '<td bgcolor' not in html.replace('<td bgcolor="#ffcdd2"><font', "").replace('<td bgcolor="#fff3b0"><font', "").replace('<td bgcolor="#c8e6c9"><font', "").replace('<td bgcolor="#e0e0e0"><font', ""))
pdf = os.path.join(SP, "scan.pdf")
S.reports.save_pdf(tab.shown_rows(), pdf, scope="Global", title="Toner Vulnerability Report", kind=S.reports.SCAN)
raw = open(pdf, "rb").read()
check("the PDF is landscape with clickable links to named destinations", b"/MediaBox [0 0 842" in raw and raw.count(b"/Subtype /Link") >= 2 and b"/Dests" in raw, (len(raw), raw.count(b"/Subtype /Link")))
out2 = os.path.join(SP, "scan.csv"); S.QFileDialog.getSaveFileName = lambda *a, **k: (out2, "")
tab.export("CSV", "CSV (*.csv)", S.reports.to_csv, False)
csv_text = open(out2, encoding="utf-8").read()
check("...and CSV, one line per check with its result", csv_text.startswith("Device,Check,Status,Value,Message") and csv_text.count("\n") == 11 and "edge-fw,CVE-2024-1111,WARN,CVSS 7.5" in csv_text, csv_text)
tab.results = []; tab.last_ran = []; tab.repopulate()
check("the empty hint says Scan", tab.hint.isVisible() and tab.hint.head.text() == "No scans yet" and tab.hint.sub.text() == "Choose devices and press Scan")
from ui.results import ResultsTab
r = ResultsTab()
check("Results itself is unchanged", r.header.title.text() == "Results" and r.run_btn.text() == "Run checks" and not hasattr(r, "export_btn"))

print("== Inventory > right-click > Scan for vulnerabilities")
import ui.inventory as INV
inv = INV.InventoryTab(); inv.resize(900, 600); inv.show(); inv.refresh(); app.processEvents()
captured = {}
class FakeMenu(INV.QMenu):
    def exec(self, *a):
        captured.update(actions=[x.text() for x in self.actions() if x.text()], menu=self); return None
INV.QMenu = FakeMenu
asked = []; inv.scan_vulns.connect(asked.append)
def item_named(text):
    found = []
    def walk(it):
        if it.text(0) == text or it.text(0).startswith(text + "  ("): found.append(it)
        for k in range(it.childCount()): walk(it.child(k))
    for i in range(inv.table.topLevelItemCount()): walk(inv.table.topLevelItem(i))
    return found[0]
inv.table.expandAll(); inv.table.clearSelection(); it = item_named("edge-fw"); it.setSelected(True); inv.table.setCurrentItem(it)
inv.show_menu(inv.table.visualItemRect(it).center())
check("a device offers it, after Run Checks", captured["actions"].index("Scan for vulnerabilities") > captured["actions"].index("Run Checks"), captured["actions"])
next(x for x in captured["menu"].actions() if x.text() == "Scan for vulnerabilities").trigger()
check("...and asks for that device", asked == [["edge-fw"]], asked)
inv.table.clearSelection(); it = item_named("Core"); it.setSelected(True); inv.table.setCurrentItem(it); inv.show_menu(inv.table.visualItemRect(it).center())
asked.clear(); next(x for x in captured["menu"].actions() if x.text() == "Scan for vulnerabilities").trigger()
check("a folder offers it for the devices in it", asked == [["c9300"]], asked)
inv.table.clearSelection(); it = item_named("Acme Charter"); it.setSelected(True); inv.table.setCurrentItem(it); inv.show_menu(inv.table.visualItemRect(it).center())
asked.clear(); next(x for x in captured["menu"].actions() if x.text() == "Scan for vulnerabilities").trigger()
check("an organization's branch offers it for every device of the organization", asked == [[db.dkey("acme-sw", acme)]], asked)

print("== Settings > Scanning")
from ui.settings_pages.scanning import ScanningPage
import ui.settings as SET
pg = ScanningPage(); pg.load()
check("the page: the box, the Cisco account and the NVD key, saved values shown as such", pg.enabled.isChecked() and pg.enabled.text() == "Look up known vulnerabilities for each device's software version"
      and pg.cisco_id.placeholderText() == "saved; leave blank to keep" and pg.cisco_secret.placeholderText() == "saved; leave blank to keep" and pg.cisco_id.text() == "")
check("installation-wide, listed among the pages", "Scanning" in SET.GLOBAL_PAGES and any(isinstance(p, ScanningPage) for p in SET.SettingsTab().pages))
pg.cisco_secret.setText("sec-2"); pg.enabled.setChecked(False); pg.save()
check("saving keeps the setting and writes only what was typed to the vault", db.get_setting("scan_enabled") is False and A.get_secret("psirt_secret") == "sec-2" and A.get_secret("psirt_id") == "cid-1" and pg.cisco_secret.text() == "")
A.set_secret("psirt_secret", "sec-1"); db.set_setting("scan_enabled", True)
got = []; pg.tested.connect(got.append); pg.cisco_secret.setText(""); pg.test()
t0 = time.time()
while not got and time.time() - t0 < 15: app.processEvents(); time.sleep(0.02)
check("Test asks Cisco with the saved account and reports", got == ["Cisco PSIRT answered: 3 advisories for IOS XE 17.9.4a. NVD answered: 1 CVE for FortiOS 7.2.5."] and pg.result.text() == got[0] and pg.test_btn.isEnabled(), got)
pg.cisco_id.setText(""); A.set_secret("psirt_id", ""); pg.test()
check("without an account, Test says what to enter", pg.result.text() == "Enter the Cisco PSIRT client ID and secret first.")
A.set_secret("psirt_id", "cid-1")

print("== the Assistant's tool, the README, the version")
from core.assistant import tools as T
tool = T.BY_NAME["vulnerabilities"]
r = tool.fn({"device": "c9300"})
check("vulnerabilities(device) hands over the stored rows, problems first", r["count"] == 6 and r["results"][0]["check"] == "cisco-sa-iosxe-webui-privesc-j22SaA4z" and r["results"][0]["status"] == "FAIL", r)
r = tool.fn({})
check("...and every device's without one", r["count"] >= 8 and {x["device"] for x in r["results"]} >= {"c9300", "edge-fw", "pc"}, r["count"])
check("it is named among what the Assistant reads", any("vulnerability" in s for s in T.WHAT_THEY_READ))
readme = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "README.md"), encoding="utf-8").read()
check("the README has a Scanning row", "| **Scanning** |" in readme and "Scan for vulnerabilities" in readme and "Settings > Scanning" in readme)
from core.version import VERSION
check("version 1.11.4", VERSION == "1.11.4")

web.shutdown()
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

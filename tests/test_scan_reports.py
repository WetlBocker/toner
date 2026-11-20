# Run directly (python tests/test_scan_reports.py). Settings > Reports: the trend, vulnerability and hardening reports, each on its own
# schedule with its own addresses, and Send now. The mail goes through fakes (notify.mail_files, or a fake SMTP class); no real server.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, threading, time, types
from datetime import datetime, timedelta
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "sr%d.db" % int(time.time())); os.environ["APPDATA"] = SP
from core import audit, db, notify, periods, service, trends
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def attempt(fn, *a, **k):
    """fn(*a, **k), or the exception it raised (so a missing function fails its own check, not the whole file)."""
    try:
        return fn(*a, **k)
    except Exception as e:
        return e
try:
    from core import scanreports
except ImportError:
    scanreports = types.SimpleNamespace()
SR = lambda name: getattr(scanreports, name, None) or (lambda *a, **k: (_ for _ in ()).throw(AttributeError(name)))
from drivers.base import Result

F = periods.FMT
NOW = datetime(2026, 6, 15, 12, 0, 0)
folder = os.path.join(SP, "reports"); os.makedirs(folder)
def gs(key): return attempt(db.get_setting, key)              # a setting not yet known fails its check, not the file
def last_audit():return ([(r["action"], r["detail"]) for r in audit.recent(1)] or [("", "")])[0]
def dev(name):
    db.save_device(dict(name=name, vendor="cisco", host=name, port=0, platform="cisco_ios", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))
def scan_rows(name, org=None):
    return [Result(name, "Software version", "OK", "17.3.1", "", org=org), Result(name, "cisco-sa-test-1", "FAIL", "CVSS 9.8", "bad bug", org=org),
            Result(name, "Hardening: Telnet allowed on VTY lines", "FAIL", "", "telnet on", org=org),
            Result(name, "Hardening: HTTP server", "OK", "", "", org=org)]
def no_scans(org=None):
    with db.within(org):
        with db.connect() as c: c.execute("DELETE FROM scan_results"); c.execute("DELETE FROM scans")

print("== the trend report's period")
check("the trend report covers 7, 14, 30 or 90 days by its schedule (weekly and monthly as before)",
      [attempt(getattr(trends, "window", lambda k: None), k) for k in ("weekly", "biweekly", "monthly", "quarterly")] == [7, 14, 30, 90])
seen_days = []
real_compute = trends.compute
trends.compute = lambda days=7, now=None: (seen_days.append(days), real_compute(days, now))[1]
db.set_setting("report_folder", folder)
for kind in ("biweekly", "quarterly"):
    db.set_setting("trend_schedule", kind); db.set_setting("trend_last", "")
    attempt(trends.generate_scheduled, NOW)
check("a bi-weekly and a quarterly scheduled trend report are made over 14 and 90 days", seen_days[-2:] == [14, 90], seen_days)
trends.compute = real_compute
db.set_setting("trend_schedule", "biweekly"); db.set_setting("trend_last", (NOW - timedelta(days=14)).strftime(F))
check("bi-weekly trend: due at 14 days, not a minute before", trends.due(NOW) and not trends.due(NOW - timedelta(minutes=1)))
db.set_setting("trend_schedule", ""); db.set_setting("trend_last", "")

print("== which rows each report holds")
dev("gw"); dev("sw")
db.save_scan(scan_rows("gw") + scan_rows("sw"))
vuln = attempt(SR("rows"), "vuln_report"); hard = attempt(SR("rows"), "hardening_report")
vuln = vuln if isinstance(vuln, list) else []; hard = hard if isinstance(hard, list) else []
check("the vulnerability report holds the latest scan's version and advisory rows only", sorted((r.device, r.check) for r in vuln)
      == [("gw", "Software version"), ("gw", "cisco-sa-test-1"), ("sw", "Software version"), ("sw", "cisco-sa-test-1")], [(r.device, r.check) for r in vuln])
check("the hardening report holds its hardening rows only", sorted((r.device, r.check) for r in hard)
      == sorted((d, c) for d in ("gw", "sw") for c in ("Hardening: Telnet allowed on VTY lines", "Hardening: HTTP server")), [(r.device, r.check) for r in hard])
db.save_scan([Result("gw", "Hardening", "N/A", "", "No configuration backup to read. Configs > Back up now reads one.")])
hard = attempt(SR("rows"), "hardening_report"); hard = hard if isinstance(hard, list) else []
check("a device's plain 'Hardening' row (no rules, no backup) is a hardening row, and only the newest scan of a device counts",
      [(r.device, r.check) for r in hard if r.device == "gw"] == [("gw", "Hardening")] and len([r for r in hard if r.device == "sw"]) == 2, [(r.device, r.check) for r in hard])
vuln = attempt(SR("rows"), "vuln_report"); vuln = vuln if isinstance(vuln, list) else []
check("...and gw's newest scan has no vulnerability rows", not [r for r in vuln if r.device == "gw"], [(r.device, r.check) for r in vuln])
db.save_scan(scan_rows("gw"))

print("== Global and an organization")
from core import orgs
acme = orgs.create("Acme", "ACME")
with db.within(acme):
    dev("a1")
db.save_scan(scan_rows("a1", org=acme))
got = attempt(SR("rows"), "vuln_report"); got = got if isinstance(got, list) else []
check("in Global the report covers every organization's devices, labelled with their organization", sorted({r.device for r in got}) == sorted({"gw", "sw", db.label_org(db.dkey("a1", acme))}), sorted({r.device for r in got}))
db.set_home(acme)
got = attempt(SR("rows"), "vuln_report"); got = got if isinstance(got, list) else []
check("in an organization, only that organization's devices", sorted({r.device for r in got}) == ["a1"], sorted({r.device for r in got}))
db.set_home(db.GLOBAL)

print("== the files")
path = attempt(SR("make"), "vuln_report", folder, NOW)
check("the vulnerability report is saved as Toner-vulnerability-YYYY-MM-DD, HTML without a window", path == os.path.join(folder, "Toner-vulnerability-2026-06-15.html"), path)
html = open(path, encoding="utf-8").read() if isinstance(path, str) and os.path.exists(path) else ""
check("...made with the Scanning page's writer: its title, the scope, a line per device, no hardening rows",
      "<h1>Toner Vulnerability Report</h1>" in html and "Global" in html and "cisco-sa-test-1" in html and "Version 17.3.1" in html and "Telnet" not in html, html[:300])
path = attempt(SR("make"), "hardening_report", folder, NOW)
html = open(path, encoding="utf-8").read() if isinstance(path, str) and os.path.exists(path) else ""
check("the hardening report: Toner-hardening-YYYY-MM-DD, titled Toner Hardening Report, hardening rows only",
      path == os.path.join(folder, "Toner-hardening-2026-06-15.html") and "<h1>Toner Hardening Report</h1>" in html and "Telnet" in html and "cisco-sa-test-1" not in html, path)

print("== on a schedule")
for rep in ("vuln_report", "hardening_report"):
    check(f"{rep}: off by default, never due", gs(f"{rep}_schedule") == "" and attempt(SR("due"), rep, NOW) is False)
    db.set_setting(f"{rep}_schedule", "quarterly"); db.set_setting(f"{rep}_last", (NOW - timedelta(days=91)).strftime(F))
    check(f"{rep}: quarterly, due at 91 days and not a minute before", attempt(SR("due"), rep, NOW) is True and attempt(SR("due"), rep, NOW - timedelta(minutes=1)) is False)
    db.set_setting(f"{rep}_schedule", "")
    check(f"{rep}_last is the organization's own, as trend_last is", f"{rep}_last" in db.ORG_LOCAL)
calls = []
real_mail = notify.mail_files
def fake_mail(to, subject, body, files):
    calls.append(dict(to=to, subject=subject, body=body, files=list(files), thread=threading.get_ident(),
                      sizes=[os.path.getsize(f) for f in files if os.path.exists(f)]))
    return fake_mail.reply
fake_mail.reply = (True, "sent to 2 recipient(s)")
notify.mail_files = fake_mail
db.set_setting("vuln_report_schedule", "weekly"); db.set_setting("vuln_report_last", ""); db.set_setting("vuln_report_email", "boss@example.com, ops@example.com")
path = attempt(SR("generate_scheduled"), "vuln_report", NOW)
check("on schedule: saved to the default folder and mailed to that report's addresses", path == os.path.join(folder, "Toner-vulnerability-2026-06-15.html")
      and calls and calls[-1]["to"] == "boss@example.com, ops@example.com" and calls[-1]["files"] == [path], (path, calls[-1:]))
check("the subject and body follow the trend report's", calls and calls[-1]["subject"] == "Vulnerability report, 2026-06-08 to 2026-06-15"
      and calls[-1]["body"] == "The weekly vulnerability report from Toner is attached.", calls[-1:])
check("vuln_report_last is stored and it is not due a minute later", gs("vuln_report_last") == NOW.strftime(F) and attempt(SR("due"), "vuln_report", NOW + timedelta(minutes=1)) is False)
check("the audit log says it was emailed", last_audit() == ("vulnerability report emailed", "sent to 2 recipient(s)"), last_audit())
db.set_setting("hardening_report_schedule", "biweekly"); db.set_setting("hardening_report_last", ""); db.set_setting("hardening_report_email", "sec@example.com")
path = attempt(SR("generate_scheduled"), "hardening_report", NOW)
check("the hardening report goes to its own addresses, with its own name and period", calls and calls[-1]["to"] == "sec@example.com"
      and calls[-1]["subject"] == "Hardening report, 2026-06-01 to 2026-06-15" and calls[-1]["body"] == "The bi-weekly hardening report from Toner is attached.", calls[-1:])
n = len(calls); no_scans(); no_scans(acme); db.set_setting("vuln_report_last", "")
for f in os.listdir(folder): os.remove(os.path.join(folder, f))
path = attempt(SR("generate_scheduled"), "vuln_report", NOW)
check("with no scan yet nothing is made or sent, and vuln_report_last is not stored", path == "" and len(calls) == n and not os.listdir(folder) and gs("vuln_report_last") == "", (path, os.listdir(folder)))
db.set_setting("report_folder", "")
db.save_scan(scan_rows("gw"))
check("with no default folder nothing is made", attempt(SR("generate_scheduled"), "vuln_report", NOW) == "" and gs("vuln_report_last") == "")
db.set_setting("report_folder", folder)
notify.mail_files = real_mail
class FakeSMTP:
    def __init__(self, host, port, timeout=None, **k): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def ehlo(self): pass
    def starttls(self, context=None): pass
    def login(self, user, password): raise RuntimeError("535 bad login for hunter2-secret")
notify._SMTP = notify._SMTP_SSL = FakeSMTP
ch = notify.new_channel("email"); ch.update(smtp_host="mail.example.com", from_addr="toner@example.com", to_addrs="alerts@example.com", username="mailer")
notify.save_channels([ch]); notify.set_secrets(ch, {"password": "hunter2-secret"})
db.set_setting("vuln_report_last", "")
path = attempt(SR("generate_scheduled"), "vuln_report", NOW)
check("a refusing mail server leaves the file saved and vuln_report_last set", isinstance(path, str) and os.path.exists(path) and gs("vuln_report_last") == NOW.strftime(F), path)
check("...and an audit line that says why, without the password", last_audit()[0] == "vulnerability report not emailed" and "535" in last_audit()[1] and "hunter2" not in last_audit()[1], last_audit())
notify.mail_files = fake_mail

print("== the service's tick and the window's hook")
for rep in ("vuln_report", "hardening_report"): db.set_setting(f"{rep}_last", "")
db.set_setting("hardening_report_schedule", "weekly")
did = service.Daemon(log=lambda m: None).tick(NOW)
check("the service makes both when due", ("vulnerability report", os.path.join(folder, "Toner-vulnerability-2026-06-15.html")) in did
      and ("hardening report", os.path.join(folder, "Toner-hardening-2026-06-15.html")) in did, did)
did = service.Daemon(log=lambda m: None).tick(NOW + timedelta(minutes=1))
check("and not again a minute later", not any(k in ("vulnerability report", "hardening report") for k, *_ in did), did)
import app as A, logging
class Catch(logging.Handler):
    def __init__(self): super().__init__(); self.lines = []
    def emit(self, r): self.lines.append(r.getMessage())
def housekeeping():
    """Main.do_housekeeping on a stand-in window (it only needs .scanning); returns what it did and what it logged."""
    did, catch = [], Catch()
    real = (A.scheduler.start_scan, A.agents.running, A.agents.check_cert)
    A.scheduler.start_scan = lambda tab: did.append("scan"); A.agents.running = lambda: True; A.agents.check_cert = lambda: did.append("cert")
    A.log.addHandler(catch)
    try:
        attempt(A.Main.do_housekeeping, types.SimpleNamespace(scanning=None))
    finally:
        A.log.removeHandler(catch); A.scheduler.start_scan, A.agents.running, A.agents.check_cert = real
    return did, catch.lines
for k in ("trend", "vuln_report", "hardening_report"): db.set_setting(f"{k}_schedule", "weekly"); db.set_setting(f"{k}_last", "")
made = []
real_make, real_tmake = scanreports.make, trends.make
def failing(report, folder, now):
    made.append(report)
    if report == "vuln_report": raise PermissionError("the report folder is read-only")
    return real_make(report, folder, now)
def failing_trend(folder, kind, now):
    made.append("trend"); raise OSError("disk full")
scanreports.make, trends.make = failing, failing_trend
did, lines = housekeeping()
scanreports.make, trends.make = real_make, real_tmake
check("the window's hook: a trend report and a vulnerability report that fail do not stop the hardening report", made == ["trend", "vuln_report", "hardening_report"]
      and gs("hardening_report_last") != "" and gs("vuln_report_last") == "", made)
check("...nor the scheduled scan and the certificate check", did == ["scan", "cert"], did)
check("...and each failure is logged once, by name", lines == ["trend report failed", "vulnerability report failed"], lines)
hard_last = gs("hardening_report_last")
did, lines = housekeeping()
check("next time the failed ones are tried again and made (the window's housekeeping runs every 30 minutes); the one made is not due", not lines
      and gs("trend_last") != "" and gs("vuln_report_last") != "" and gs("hardening_report_last") == hard_last and did == ["scan", "cert"], (lines, gs("trend_last"), gs("vuln_report_last")))
for rep in ("trend", "vuln_report", "hardening_report"): db.set_setting(f"{rep}_schedule", ""); db.set_setting(f"{rep}_last", "")

print("== Send now (the core)")
calls.clear(); fake_mail.reply = (True, "sent to 1 recipient(s)")
db.set_setting("vuln_report_last", "")
text = attempt(SR("send_now"), "vuln_report", "", "boss@example.com", NOW)
check("one address: 'Sent to 1 address.'", text == "Sent to 1 address.", text)
check("it mails the report it made, and leaves vuln_report_last alone", calls and calls[-1]["to"] == "boss@example.com" and calls[-1]["sizes"] and calls[-1]["sizes"][0] > 500
      and gs("vuln_report_last") == "", calls[-1:])
check("with the schedule Off the mail says so without a period", calls and calls[-1]["subject"] == "Vulnerability report, 2026-06-15"
      and calls[-1]["body"] == "The vulnerability report from Toner is attached.", calls[-1:])
fake_mail.reply = (True, "sent to 3 recipient(s)")
check("several: 'Sent to 3 addresses.'", attempt(SR("send_now"), "hardening_report", "monthly", "a@example.com; b@example.com, c@example.com", NOW) == "Sent to 3 addresses.")
check("...over the schedule's period", calls and calls[-1]["subject"] == "Hardening report, 2026-05-16 to 2026-06-15" and calls[-1]["body"] == "The monthly hardening report from Toner is attached.", calls[-1:])
fake_mail.reply = (False, "SMTPAuthenticationError: 535 bad login")
check("a refusal: 'Couldn't send the report: {reason}'", attempt(SR("send_now"), "trend", "weekly", "boss@example.com", NOW) == "Couldn't send the report: SMTPAuthenticationError: 535 bad login")
check("the trend report is sent over its period, with trend_last left alone", calls and calls[-1]["subject"] == "Trend report, 2026-06-08 to 2026-06-15" and gs("trend_last") == "", calls[-1:])
db.set_setting("report_folder", ""); fake_mail.reply = (True, "")
kept = []
real_rm = __import__("shutil").rmtree
import shutil; shutil.rmtree = lambda p, *a, **k: (kept.append(p), real_rm(p, *a, **k))
attempt(SR("send_now"), "vuln_report", "", "boss@example.com", NOW)
shutil.rmtree = real_rm
check("with no default folder it is made in a temporary folder that is removed afterwards", calls and kept and os.path.dirname(calls[-1]["files"][0]) == kept[-1]
      and not os.path.exists(kept[-1]) and calls[-1]["sizes"], (kept, calls[-1:]))
db.set_setting("report_folder", folder)
n = len(calls); no_scans(); no_scans(acme)
check("no scan: 'No scan yet. Scan on the Scanning page first.' and nothing sent", attempt(SR("send_now"), "hardening_report", "", "boss@example.com", NOW)
      == "No scan yet. Scan on the Scanning page first." and len(calls) == n)
db.save_scan(scan_rows("gw"))

print("== Settings > Reports")
from PySide6.QtWidgets import QApplication, QLabel, QPushButton
app = QApplication([])
A.apply_look(app)
from ui.settings_pages.appearance import ReportsPage
import ui.settings as ST
db.set_setting("trend_schedule", "monthly"); db.set_setting("vuln_report_schedule", "weekly"); db.set_setting("hardening_report_schedule", "quarterly")
from PySide6.QtWidgets import QComboBox, QLineEdit
REPS = ("trend", "vuln_report", "hardening_report")
def parts(p):
    """The page's drop-downs, address boxes, Send now buttons and result labels by report; stand-ins where it has none (so each check fails on its own)."""
    return [getattr(p, attr, None) or {r: make() for r in REPS} for attr, make in (("schedule", QComboBox), ("email", QLineEdit), ("send", QPushButton), ("result", QLabel))]
page = ReportsPage(); page.load()
boxes, emails, buttons, results = parts(page)
lab = lambda w: page.form.labelForField(w).text() if w is not None and page.form.labelForField(w) else ""
labels = [lab(b) for b in boxes.values()]
check("three report rows: Trend report, Vulnerability report, Hardening report", labels == ["Trend report", "Vulnerability report", "Hardening report"], labels)
check("each drop-down is Off, Weekly, Bi-Weekly, Monthly, Quarterly, stored as '', weekly, biweekly, monthly, quarterly",
      len(boxes) == 3 and all([b.itemText(i) for i in range(b.count())] == ["Off", "Weekly", "Bi-Weekly", "Monthly", "Quarterly"]
                              and [b.itemData(i) for i in range(b.count())] == ["", "weekly", "biweekly", "monthly", "quarterly"] for b in boxes.values()))
check("stored values load: the old 'monthly' as Monthly, weekly, quarterly", [b.currentText() for b in boxes.values()] == ["Monthly", "Weekly", "Quarterly"], [b.currentText() for b in boxes.values()])
db.set_setting("trend_schedule", "weekly"); page.load()
check("...and the old 'weekly' as Weekly", page.trend.currentText() == "Weekly")
check("each is followed by its own 'Email it to' row with a Send now button",
      all(lab(e.parentWidget()) == "Email it to" for e in emails.values())
      and all(b.text() == "Send now" and b.parentWidget() is e.parentWidget() for b, e in zip(buttons.values(), emails.values())))
note = "Each report is saved to the default folder and emailed to its addresses through the first Email channel in Settings > Notifications. The vulnerability and hardening reports use the latest scan."
texts = [l.text() for l in page.findChildren(QLabel)]
check("the approved note replaces the old one", note in texts and "Sent through the first Email channel in Settings > Notifications, to these addresses only." not in texts)
check("'Also one report per organization' stays with the trend report", page.per_org.text() == "Also one report per organization")
for rep, b in buttons.items():
    emails[rep].setText("")
check("Send now is disabled while its box is empty", not any(b.isEnabled() for b in buttons.values()))
emails["vuln_report"].setText("boss@example.com")
check("...and enabled once it has an address", buttons["vuln_report"].isEnabled() and not buttons["trend"].isEnabled())
for rep, sched in (("vuln_report", "weekly"), ("hardening_report", "monthly")):
    db.set_setting(f"{rep}_email", "x@example.com"); db.set_setting(f"{rep}_schedule", sched)
page.load()
check("the addresses are loaded", [emails[r].text() for r in ("vuln_report", "hardening_report")] == ["x@example.com"] * 2)

print("== Settings > Reports: validation and saving")
for rep, name in (("vuln_report", "vulnerability report"), ("hardening_report", "hardening report")):
    for r in boxes: boxes[r].setCurrentIndex(0); emails[r].setText("")
    page.folder.setText(""); boxes[rep].setCurrentIndex(boxes[rep].findData("weekly"))
    check(f"{name}: a schedule needs the default folder", page.validate() == [f"Reports: choose a default folder to save the scheduled {name} into."], page.validate())
    page.folder.setText(folder); emails[rep].setText("ok@example.com, not an address")
    check(f"{name}: addresses must be valid", page.validate() == ["Reports: 'not an address' is not a valid email address."], page.validate())
    notify.save_channels([]); emails[rep].setText("ok@example.com")
    check(f"{name}: addresses need an Email channel", page.validate() == [f"Reports: add an Email channel in Settings > Notifications before emailing the {name}."], page.validate())
    notify.save_channels([ch])
    check(f"{name}: with all three it is fine", page.validate() == [], page.validate())
boxes["trend"].setCurrentIndex(boxes["trend"].findData("biweekly")); emails["trend"].setText("t@example.com")
boxes["vuln_report"].setCurrentIndex(boxes["vuln_report"].findData("quarterly")); emails["vuln_report"].setText("v@example.com")
page.save()
check("all six are saved under their keys", [gs(k) for k in ("trend_schedule", "trend_email", "vuln_report_schedule", "vuln_report_email", "hardening_report_schedule", "hardening_report_email")]
      == ["biweekly", "t@example.com", "quarterly", "v@example.com", "weekly", "ok@example.com"])
check("the labels of the two new schedules", ST.KEY_LABELS.get("vuln_report_schedule") == "Vulnerability report" and ST.KEY_LABELS.get("hardening_report_schedule") == "Hardening report")

print("== Settings > Reports: Send now on a worker thread")
held = threading.Event(); main = threading.get_ident(); calls.clear()
def held_mail(to, subject, body, files):
    held.wait(10)
    return fake_mail(to, subject, body, files)
notify.mail_files = held_mail; fake_mail.reply = (True, "")
db.set_setting("vuln_report_last", ""); db.set_setting("report_folder", folder)
emails["vuln_report"].setText("a@example.com, b@example.com")
buttons["vuln_report"].click(); app.processEvents()
check("while it sends, the page is usable and the button is disabled", not buttons["vuln_report"].isEnabled() and not calls and page.isEnabled())
emails["vuln_report"].setText("a@example.com"); app.processEvents()
check("...and stays disabled when the box changes", not buttons["vuln_report"].isEnabled())
held.set(); t0 = time.time()
while results["vuln_report"].text() in ("", ) and time.time() - t0 < 15: app.processEvents(); time.sleep(0.02)
check("the result appears beside the button", results["vuln_report"].text() == "Sent to 2 addresses." and results["vuln_report"].parentWidget() is buttons["vuln_report"].parentWidget(), results["vuln_report"].text())
check("it ran off the UI thread, to the box's text at the click, and left vuln_report_last alone", calls and calls[-1]["thread"] != main and calls[-1]["to"] == "a@example.com, b@example.com"
      and gs("vuln_report_last") == "", calls[-1:])
check("a PDF is made from the window, on the worker thread", calls and calls[-1]["files"][0].endswith(".pdf") and open(calls[-1]["files"][0], "rb").read(5) == b"%PDF-", calls[-1:])
check("the button is enabled again afterwards", buttons["vuln_report"].isEnabled())
emails["hardening_report"].setText("bad address")
buttons["hardening_report"].click(); app.processEvents()
check("addresses are validated as on save, and nothing is sent", results["hardening_report"].text() == "Reports: 'bad address' is not a valid email address."
      and len(calls) == 1 and buttons["hardening_report"].isEnabled(), results["hardening_report"].text())

print("== Settings > Reports: leaving while a send runs")
errors = []; threading.excepthook = lambda a: errors.append(a.exc_value)
held.clear(); n = len(calls)
S = ST.SettingsTab(); S.resize(1200, 800); S.show(); app.processEvents()
S.select_page("Reports"); app.processEvents(); time.sleep(0.2); app.processEvents(); S.check_dirty()
rp = S.pages[S.stack.currentIndex()]; i = S.stack.currentIndex()
r_boxes, r_emails, r_buttons, _r = parts(rp)
check("opened, the page is not dirty", not S._dirty.get(i))
for rep in REPS:
    rp.load(); S.check_dirty(); r_boxes[rep].setCurrentIndex((r_boxes[rep].currentIndex() + 1) % 5); S.check_dirty()
    check(f"a changed {rep} schedule is tracked as an unsaved edit", S._dirty.get(i))
    rp.load(); S.check_dirty(); r_emails[rep].setText("new@example.com"); S.check_dirty()
    check(f"a changed {rep} address box is tracked too", S._dirty.get(i))
rp.load(); S.check_dirty()                          # (trend_email is t@example.com, saved above)
r_buttons["trend"].click(); app.processEvents(); S.check_dirty()
check("Send now and its result are not edits; the button waits for the send", not S._dirty.get(i) and not r_buttons["trend"].isEnabled())
S.select_page("Appearance"); app.processEvents()
rp.deleteLater(); S.deleteLater(); app.processEvents()
held.set(); t0 = time.time()
while len(calls) == n and time.time() - t0 < 15: app.processEvents(); time.sleep(0.02)
time.sleep(0.3); app.processEvents()
check("leaving the page and closing Settings while it sends does not crash; the send finishes", len(calls) == n + 1 and not errors, (len(calls), errors))
notify.mail_files = real_mail
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

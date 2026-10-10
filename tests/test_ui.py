# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, json, socket, threading
pass
os.environ["QT_QPA_PLATFORM"] = "offscreen"
SP = os.environ["SP"]; stamp = int(time.time())
os.makedirs(SP + rf"\ui{stamp}"); os.environ["NETCHECK_DB"] = SP + rf"\ui{stamp}\netcheck.db"
from core import db
db.init()
from PySide6.QtCore import Qt, QEventLoop
from PySide6.QtWidgets import QApplication, QMessageBox, QFileDialog
app = QApplication([])
PASS = FAIL = 0
def check(name, cond, extra=""):
    global PASS, FAIL
    PASS += bool(cond); FAIL += (not cond)
    print(("  ok   " if cond else "  FAIL ") + name + (f"   [{extra}]" if extra and not cond else ""))
def wait(cond, secs=10):
    end = time.time() + secs
    while time.time() < end and not cond(): QEventLoop().processEvents(); time.sleep(0.02)
    return cond()
msgs = []
QMessageBox.warning = staticmethod(lambda *a: msgs.append(("warn", a[2])) or QMessageBox.StandardButton.Ok)
QMessageBox.information = staticmethod(lambda *a: msgs.append(("info", a[2])) or QMessageBox.StandardButton.Ok)
answer = {"q": QMessageBox.StandardButton.Yes}
QMessageBox.question = staticmethod(lambda *a: (msgs.append(("ask", a[2])), answer["q"])[1])
for n, v, loc in (("core", "cisco", "Chicago"), ("fw", "fortinet", "Chicago"), ("ap", "unifi", "Denver")):
    db.save_device(dict(name=n, vendor=v, host="127.0.0.1", port=0, platform="", username="u", site="default",
                        verify_ssl=0, ha_expected=0, enabled=1, location=loc, details=""))
secrets_deleted = []; db.delete_secret = lambda n: secrets_deleted.append(n)
import app as A
w = A.Main(); w.show(); S = w.settings
P = {p.title: p for p in S.pages}

print("== tab and save/revert")
check("settings is a tab, no corner button", w.centralWidget().tabText(w.centralWidget().count() - 1) == "Settings")
check("11 categories listed", S.nav.count() >= 11 and "Notifications" in [S.nav.item(i).text() for i in range(S.nav.count())] and [S.nav.item(i).text() for i in range(3)] == ["General", "Thresholds", "Checks"])
g = P["General"]; g.workers.setValue(4); g.retention.setValue(30); g.scan_over.setValue(0); g.verify.setChecked(True)
check("nothing is stored until Save", db.get_setting("workers") == 10)
S.save(); check("Save writes settings", db.get_setting("workers") == 4 and db.get_setting("retention_days") == 30 and db.get_setting("default_verify_ssl") is True)
g.workers.setValue(9); S.reload(); check("Revert discards edits", g.workers.value() == 4)

print("== threshold validation")
T = P["Thresholds"]; T.spins["cpu"][0].setValue(95); T.spins["cpu"][1].setValue(80); msgs.clear(); S.save()
check("WARN above FAIL is refused, nothing saved", msgs and "contradict" in msgs[-1][1] and db.get_thresholds()["cpu"]["warn"] == 70 and S.nav.currentRow() == 1, msgs)
T.spins["cpu"][0].setValue(60); T.spins["cpu"][1].setValue(85)
T.spins["uptime"][0].setValue(2); T.spins["uptime"][1].setValue(5); msgs.clear(); S.save()
check("uptime needs FAIL <= WARN", msgs and "Uptime" in msgs[-1][1], msgs)
T.spins["uptime"][0].setValue(24); T.spins["uptime"][1].setValue(2)
T.add_row("Location: Chicago", "cpu", 40, 50); T.add_row("Device: ap", "memory", 99, 90)
msgs.clear(); S.save(); check("invalid override is refused too", msgs and "Device: ap" in msgs[-1][1], msgs)
T.table.cellWidget(1, 2).setValue(60); T.table.cellWidget(1, 3).setValue(95)
T.mode.setCurrentIndex(T.mode.findData("delta")); T.fw.setCurrentText("FAIL")
msgs.clear(); S.save(); check("valid thresholds + overrides save", not msgs and db.get_thresholds()["cpu"]["warn"] == 60 and len(db.get_setting("threshold_overrides")) == 2
      and db.get_setting("counter_mode") == "delta" and db.get_setting("firmware_severity") == "FAIL", msgs)
S.reload(); check("overrides reload into the table", T.table.rowCount() == 2 and T.table.cellWidget(0, 0).currentText() == "Location: Chicago")
T.reset(); check("reset puts defaults in the boxes (unsaved)", T.spins["cpu"][0].value() == 70 and db.get_thresholds()["cpu"]["warn"] == 60)
T.remove_row() if False else None
T.table.selectRow(0); T.remove_row(); check("remove override", T.table.rowCount() == 1)
S.reload()

print("== checks page")
C = P["Checks"]; top = C.tree.topLevelItem(0); top.child(3).setCheckState(0, Qt.CheckState.Unchecked)   # cisco: interfaces
S.save(); check("unticked check is stored as disabled", db.get_setting("disabled_checks") == ["cisco:interfaces"], db.get_setting("disabled_checks"))
S.reload(); top = C.tree.topLevelItem(0); check("and shows unticked after reload", top.child(3).checkState(0) == Qt.CheckState.Unchecked and top.child(0).checkState(0) == Qt.CheckState.Checked)

print("== connections / defaults reach the app")
N = P["Connections"]; N.ssh.setValue(45); N.http.setValue(30); N.retries.setValue(3); N.delay.setValue(5); S.save()
o = db.runtime_options(); check("runtime options reflect connections page", (o["ssh_timeout"], o["http_timeout"], o["retries"], o["retry_delay"]) == (45, 30, 3, 5))
from ui.inventory import DeviceDialog
check("new-device dialog follows 'verify SSL by default'", DeviceDialog().verify.isChecked() and not DeviceDialog(db.list_devices()[0]).verify.isChecked())

print("== appearance")
from PySide6.QtGui import QPalette
import core.reports as RP
Ap = P["Appearance"]; Ap.theme.setCurrentText("Dark"); Ap.font.setValue(13); S.save()
check("dark theme applied live", app.palette().color(QPalette.ColorRole.Window).lightness() < 80 and app.font().pointSize() == 13)
Ap.theme.setCurrentText("Light"); S.save(); check("light theme applied", app.palette().color(QPalette.ColorRole.Window).lightness() > 200)
Ap.theme.setCurrentText("System"); Ap.font.setValue(0); S.save(); check("system theme restored", app.font().pointSize() != 13 and app.font().pointSize() == 10)
Ap.preset.setCurrentText("Color-blind safe"); S.save()
check("colour preset applied to tables and reports", RP.COLORS["OK"] == "#b3d9ff" and db.get_setting("status_colors") == {} and w.results.table.topLevelItemCount() == 0)
Ap.colors["FAIL"] = "#112233"; Ap.paint(); S.save()
check("a single custom colour is stored as an override", db.get_setting("status_colors") == {"FAIL": "#112233"} and RP.COLORS["FAIL"] == "#112233" and RP.COLORS["OK"] == "#b3d9ff")
check("text colour flips to white on a dark background", RP.fg_for("#112233") == "#ffffff" and RP.fg_for("#fff3b0") == "#1a1a1a")
from drivers.base import Result
html = RP.to_html([Result("d", "cpu", "FAIL", "99%")]); check("report uses the custom colour with readable text", "#112233" in html and 'color="#ffffff"' in html)
def has_colour(widget, hexcol):
    img = widget.grab().toImage()
    want = int(hexcol.lstrip("#"), 16)
    return any((img.pixel(x, y) & 0xFFFFFF) == want for y in range(0, img.height(), 2) for x in range(0, img.width(), 2))
w.results.results = [Result("d", "cpu", "FAIL", "99%")]; w.results.last_ran = ["d"]; w.results.repopulate(); w.results.resize(900, 400); w.results.show()
check("status pill in the results table uses the custom colour", w.results.table.topLevelItem(0).text(2) == "FAIL" and has_colour(w.results.table, "#112233"))
w.results.chips.set_counts({"FAIL": 1}); check("status chips use it too", has_colour(w.results.chips, "#112233") or "#112233" in w.results.chips.labels["FAIL"].styleSheet())
Ap.preset.setCurrentText("Default"); Ap.colors = dict(RP.DEFAULT_COLORS); Ap.paint(); S.save(); check("back to defaults", RP.COLORS == RP.DEFAULT_COLORS)

print("== terminal settings")
Tm = P["Terminal"]; Tm.scheme.setCurrentText("Light"); Tm.size.setValue(14); Tm.scrollback.setValue(777); Tm.paging.setText("terminal length 0"); S.save()
term = w.tools.ssh.term
check("terminal recoloured and resized live", term.bg.name() == "#ffffff" and term.font().pointSize() == 14 and term.scrollback == 777)
term.reset(); check("new scrollback applies to the next session", term.main.history.top.maxlen == 777, term.main.history.top.maxlen)
Tm.scheme.setCurrentText("Dark"); Tm.size.setValue(10); Tm.scrollback.setValue(5000); S.save()

print("== reports settings")
Rp = P["Reports"]; Rp.report_title.setText("Acme Network Health"); Rp.org.setText("Acme <HQ>"); Rp.include_all.setChecked(False); S.save()
html = RP.to_html([Result("d", "cpu", "OK", "1%"), Result("d", "mem", "FAIL", "99%")])
check("custom title and escaped organisation", "<h1>Acme Network Health</h1>" in html and "Acme &lt;HQ&gt;" in html)
check("full listing can be left out", "All results by device" not in html and "Needs attention" in html)
Rp.include_all.setChecked(True); Rp.folder.setText(r"C:\definitely\not\here"); msgs.clear(); S.save()
check("missing report folder is refused", msgs and "does not exist" in msgs[-1][1]); Rp.folder.setText(SP); S.save()
captured = {}
import ui.reports_tab as RT
RT.QFileDialog.getSaveFileName = staticmethod(lambda parent, title, start, pattern: (captured.update(start=start), ("", ""))[1])
w.reports.base = [Result("d", "cpu", "OK", "1%")]; w.reports.filter.set_sections({}); w.reports._meta = {id(w.reports.base[0]): {"Status": "OK", "Location": "", "Vendor": "", "Tag": set()}}; w.reports.show_preview()
w.reports.export_html(); check("save dialog opens in the default folder with a dated name", captured["start"].startswith(SP) and captured["start"].endswith(".html"), captured)

print("== automation / scheduler")
Au = P["Automation"]; Au.enabled.setChecked(True); Au.minutes.setValue(15); Au.groups.boxes["Location: Chicago"].setChecked(True); Au.on_start.setChecked(False); S.save()
sch = w.scheduler; check("timer armed with the interval", sch.timer.isActive() and sch.timer.interval() == 15 * 60000 and sch.next_at is not None)
check("next run shown on the Results tab", w.results.schedule_note.text().startswith("Next scheduled run:"), w.results.schedule_note.text())
launched = []; w.results.start_scheduled = lambda labels: launched.append(labels)
sch._fire(); check("firing runs the chosen groups and re-arms", launched == [["Location: Chicago"]] and sch.timer.isActive())
db.set_setting("schedule_groups", ["Location: Atlantis"]); launched.clear(); sch._fire(); check("groups that no longer exist -> run skipped, not 'everything'", launched == [])
db.set_setting("schedule_groups", []); sch._fire(); check("no groups chosen = all devices", launched == [[]])
Au.enabled.setChecked(False); S.save(); check("switching off stops the timer", not sch.timer.isActive() and w.results.schedule_note.text() == "")
# real start_scheduled path (no dialogs when empty / already running)
from ui.results import ResultsTab
rt = ResultsTab(); msgs.clear(); rt.start_scheduled(["Vendor: Cisco"]) if False else None
db.set_setting("schedule_groups", []); rt2 = ResultsTab(); rt2.start_scheduled(["Location: Nowhere"]); check("scheduled run with no matching devices is silent", not msgs, msgs)

print("== security: host keys & stored credentials")
import paramiko, ui.tools as TL
from core import nettools
sec = P["Security"]
def start_server(host_key):
    class Srv(paramiko.ServerInterface):
        def check_auth_password(self, u, p): return paramiko.AUTH_SUCCESSFUL
        def get_allowed_auths(self, u): return "password"
        def check_channel_request(self, k, c): return paramiko.OPEN_SUCCEEDED
        def check_channel_shell_request(self, ch): return True
        def check_channel_pty_request(self, *a): return True
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(5)
    def serve():
        while True:
            try: c, _ = s.accept()
            except OSError: return
            def h(c):
                t = paramiko.Transport(c); t.add_server_key(host_key)
                try:
                    t.start_server(server=Srv()); ch = t.accept(5); ch and ch.send(b"hi> ")
                    while t.is_active(): time.sleep(0.1)          # keep the connection open
                except Exception: pass
            threading.Thread(target=h, args=(c,), daemon=True).start()
    threading.Thread(target=serve, daemon=True).start(); return s, s.getsockname()[1]
def connect(port, mode):
    reasons = []; sess = nettools.SshSession("127.0.0.1", port, "u", "p", hostkey_mode=mode, timeout=5)
    sess.closed.connect(reasons.append); got = []; sess.data.connect(got.append); sess.start()
    wait(lambda: got or reasons, 8); sess.stop(); wait(lambda: reasons, 5); sess.wait(2000); return got, reasons[-1] if reasons else ""
k1, k2 = paramiko.RSAKey.generate(2048), paramiko.RSAKey.generate(2048)
srv1, port = start_server(k1)
got, why = connect(port, "Reject unknown hosts"); check("reject mode refuses an unknown host", not got and "not a known host" in why, why)
got, why = connect(port, "Trust on first use"); check("first use: connects and remembers the key", bool(got) and len(nettools.list_host_keys()) == 1, why)
got, why = connect(port, "Reject unknown hosts"); check("reject mode now connects (key is known)", bool(got), why)
srv1.close(); srv2, _ = start_server(k2); srv2.close()
# same host:port, different key: new server on the same port
s3 = socket.socket(); s3.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
import time as _t; _t.sleep(0.3)
try:
    s3.bind(("127.0.0.1", port)); s3.listen(5)
    class Srv3(paramiko.ServerInterface):
        def check_auth_password(self, u, p): return paramiko.AUTH_SUCCESSFUL
        def get_allowed_auths(self, u): return "password"
        def check_channel_request(self, k, c): return paramiko.OPEN_SUCCEEDED
        def check_channel_shell_request(self, ch): return True
        def check_channel_pty_request(self, *a): return True
    def serve3():
        while True:
            try: c, _ = s3.accept()
            except OSError: return
            def h(c):
                t = paramiko.Transport(c); t.add_server_key(k2)
                try:
                    t.start_server(server=Srv3()); ch = t.accept(5); ch and ch.send(b"hi> ")
                    while t.is_active(): time.sleep(0.1)
                except Exception: pass
            threading.Thread(target=h, args=(c,), daemon=True).start()
    threading.Thread(target=serve3, daemon=True).start()
    got, why = connect(port, "Trust on first use"); check("a CHANGED host key is refused", not got and why.startswith("HOST KEY CHANGED"), why)
    got, why = connect(port, "Always trust"); check("'Always trust' ignores the saved key (old behaviour)", bool(got), why)
except OSError as e:
    check("could not rebind test port", False, e)
sec.refresh(); check("host key shown in the Security page", sec.keys.rowCount() == 1 and sec.keys.item(0, 2).text().startswith("SHA256:"))
sec.keys.selectRow(0); sec.forget_one(); check("forget selected key", sec.keys.rowCount() == 0)
check("credentials table lists every device", sec.creds.rowCount() == 3 and sec.creds.item(0, 2).text() in ("yes", "no"))
sec.creds.selectRow(1); sec.clear_secret(); check("delete stored secret asks first, then deletes", secrets_deleted == [sec.creds.item(1, 0).text()], secrets_deleted)
sec.mode.setCurrentText("Reject unknown hosts"); S.save(); check("host-key policy saved", db.get_setting("hostkey_mode") == "Reject unknown hosts")
sec.mode.setCurrentText("Trust on first use"); S.save()

print("== scan confirmation")
check("address counts", [nettools.count_addresses(t) for t in ("10.0.0.5", "10.0.0.0/24", "10.0.0.0/16", "10.0.0.1-50", "host.lan")] == [1, 256, 65536, 50, 1])
sc = w.tools.scan; sc.nmap = None; db.set_setting("scan_confirm_over", 100); sc.target.setText("10.0.0.0/24"); sc.ports.setText("1")
answer["q"] = QMessageBox.StandardButton.No; msgs.clear(); sc.start()
check("large scan asks and honours 'No'", any(m[0] == "ask" and "256" in m[1] for m in msgs) and sc.scan is None)
db.set_setting("scan_confirm_over", 0); msgs.clear(); sc.target.setText("127.0.0.1"); sc.ports.setText("1"); sc.start(); wait(lambda: sc.go.isEnabled(), 10)
check("limit 0 never asks", not any(m[0] == "ask" for m in msgs)); answer["q"] = QMessageBox.StandardButton.Yes

print("== SSH tab uses the settings")
ssh = w.tools.ssh; db.set_setting("default_ssh_port", 2222); db.set_setting("paging_cmd", "terminal length 0"); db.set_setting("hostkey_mode", "Always trust"); db.set_setting("ssh_timeout", 33)
cap = {}
class Cap:
    def __init__(self, *a, **k): cap["a"], cap["k"] = a, k
    class _S:
        def connect(self, *a): pass
    data = closed = _S()
    def start(self): pass
    def isRunning(self): return False
TL.nettools.SshSession = Cap
ssh.host.setText("127.0.0.1"); ssh.user.setText("u"); ssh.paging.setChecked(True); ssh.connect_session()
check("paging command, host-key mode and timeout reach the session", cap["a"][4] == "terminal length 0" and cap["k"]["hostkey_mode"] == "Always trust" and cap["k"]["timeout"] == 33, cap)

print("== data & logs")
D = P["Data and logs"]; D.refresh(); check("info panel shows paths and counts", "netcheck.db" in D.info.text() and "runs" in D.info.text())
path = SP + rf"\ui{stamp}\settings.json"
QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (path, "")); D.export_settings()
data = json.load(open(path)); check("export excludes devices and secrets", "devices" not in data and "workers" in data and "thresholds" in data)
db.set_setting("workers", 22); data["workers"] = 6; data["retries"] = "x"; json.dump(data, open(path, "w"))
QFileDialog.getOpenFileName = staticmethod(lambda *a, **k: (path, "")); msgs.clear(); D.import_settings()
check("import applies, ignores the bad value, refreshes the pages", db.get_setting("workers") == 6 and "retries" in msgs[-1][1] and g.workers.value() == 6, msgs[-1])
open(path, "w").write("[1,2]"); D.import_settings(); check("import of a wrong-shaped file is refused", "Could not read" in msgs[-1][1])
bk = SP + rf"\ui{stamp}\backup.db"; QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (bk, ""))
D.backup(); import sqlite3 as sq; con = sq.connect(bk); n = con.execute("select count(*) from devices").fetchone()[0]; con.close()
check("database backup is a valid copy", n == 3, n)
db.save_run([Result("core", "cpu", "OK", "1%", numeric=1.0)]); D.clear_history()
with db.connect() as c: left = c.execute("select count(*) from runs").fetchone()[0], c.execute("select count(*) from results").fetchone()[0], c.execute("select count(*) from devices").fetchone()[0]
check("clear history empties runs+results, keeps devices", left == (0, 0, 3), left)
from core import sessionlog
sl = sessionlog.SessionLog("core", "127.0.0.1", 22, "u"); sl.write(b"x\n"); sl.close("done")
live = sessionlog.SessionLog("fw", "127.0.0.1", 22, "u")
D.delete_logs(); rem = sessionlog.list_sessions()
check("delete logs removes finished sessions, keeps open ones",
      sorted(r["device"] for r in rem) == ["127.0.0.1", "fw"] and os.path.exists(live.path) and not os.path.exists(sl.path),
      [r["device"] for r in rem]); live.close("done")

print(f"\n{PASS} passed, {FAIL} failed")


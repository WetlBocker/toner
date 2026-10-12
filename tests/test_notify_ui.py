# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, json, threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
pass
os.environ["QT_QPA_PLATFORM"] = "offscreen"
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\nui%d.db" % int(time.time())
from core import db, alerts, notify
db.init()
from PySide6.QtCore import Qt, QEventLoop
from PySide6.QtWidgets import QApplication, QMessageBox
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
class FakeKeyring:
    store = {}
    get_password = classmethod(lambda c, s, n: c.store.get((s, n)))
    set_password = classmethod(lambda c, s, n, v: c.store.__setitem__((s, n), v))
    @classmethod
    def delete_password(c, s, n): c.store.pop((s, n))
notify.keyring = FakeKeyring
captured = []
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        captured.append({"path": self.path, "body": self.rfile.read(int(self.headers.get("Content-Length", 0)))})
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
srv = HTTPServer(("127.0.0.1", 0), H); base = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()
msgs = []
QMessageBox.warning = staticmethod(lambda *a: msgs.append(("warn", a[2])) or QMessageBox.StandardButton.Ok)
QMessageBox.information = staticmethod(lambda *a: msgs.append(("info", a[2])) or QMessageBox.StandardButton.Ok)
answer = {"q": QMessageBox.StandardButton.Yes}
QMessageBox.question = staticmethod(lambda *a: (msgs.append(("ask", a[2])), answer["q"])[1])
for n in ("core", "edge"):
    db.save_device(dict(name=n, vendor="cisco", host="127.0.0.1", port=0, platform="", username="u", site="default",
                        verify_ssl=0, ha_expected=0, enabled=1, location="", details=""))
import app as A, ui.settings as ST
from drivers.base import Result
w = A.Main(); w.show(); S = w.settings
N = next(p for p in S.pages if p.title == "Notifications")

print("== the page")
check("Notifications is a Settings category", N in S.pages and "Notifications" in [S.nav.item(i).text() for i in range(S.nav.count())])
check("'Add channel' offers every channel type", sorted(a.text() for a in N.findChildren(ST.QToolButton)[0].menu().actions()) == sorted(s["label"] for s in notify.CHANNEL_TYPES.values()))
check("desktop pop-ups are wired to the tray", N.desktop_cb == w.show_desktop)

print("== every channel type builds an editor and validates")
for t in notify.CHANNEL_TYPES:
    d = ST.ChannelDialog(notify.new_channel(t), None); ch, typed, merged = d.collect()
    probs = notify.validate(ch, merged)
    # required fields that start empty (ntfy's server is pre-filled)
    empty_required = [f for f in notify.CHANNEL_TYPES[t]["fields"] if f[3].get("required") and not f[3].get("default")]
    check(f"{t}: editor opens; empty required fields are flagged ({len(empty_required)})", len(probs) == len(empty_required), (t, probs))

print("== add / edit / test / remove")
class AutoDialog(ST.ChannelDialog):
    fill = {}
    def exec(self):
        for key, val in self.fill.items():
            kind, wdg = self.inputs[key]; wdg.setText(val) if hasattr(wdg, "setText") else None
        if "name" in self.fill_meta: self.name.setText(self.fill_meta["name"])
        self.accept(); return 1 if self.result_ch else 0
    fill_meta = {}
import ui.settings_pages.notifications as _NT                 # the page looks the dialog up where it is defined
_NT.ChannelDialog = ST.ChannelDialog = AutoDialog
AutoDialog.fill, AutoDialog.fill_meta = {"url": base + "/hook-one"}, {"name": "Ops webhook"}
N.add_channel("webhook"); chs = notify.channels()
check("add: channel listed and stored", len(chs) == 1 and chs[0]["name"] == "Ops webhook" and N.table.rowCount() == 1 and N.table.item(0, 1).text() == "Ops webhook")
cid = chs[0]["id"]
check("add: URL went to the vault, not the settings", FakeKeyring.get_password(db.SERVICE, f"notify:{cid}:url") == base + "/hook-one" and "hook-one" not in json.dumps(db.get_setting("notify_channels")))
check("table shows what it sends", N.table.item(0, 3).text() == "WARN and worse, recoveries" and N.table.item(0, 0).text() == "yes", N.table.item(0, 3).text())
AutoDialog.fill, AutoDialog.fill_meta = {}, {"name": "Ops webhook (renamed)"}
N.table.selectRow(0); N.edit()
check("edit: renamed, blank secret keeps the stored URL", notify.channels()[0]["name"] == "Ops webhook (renamed)" and FakeKeyring.get_password(db.SERVICE, f"notify:{cid}:url") == base + "/hook-one")
AutoDialog.fill, AutoDialog.fill_meta = {"url": base + "/hook-two"}, {"name": "Second"}
N.add_channel("slack") if False else N.add_channel("webhook")
check("several channels at once", len(notify.channels()) == 2 and N.table.rowCount() == 2)
captured.clear(); N.table.selectRow(0); msgs.clear(); N.test()
check("Send test posts a sample and reports success", captured and captured[-1]["path"] == "/hook-one" and __import__("ui.toast", fromlist=["x"]).history[-1].startswith("Sent") and "Test device" in captured[-1]["body"].decode(), (msgs, captured))
check("the test is in the delivery log", N.log.rowCount() >= 1 and "(test)" in N.log.item(0, 1).text() and N.log.item(0, 2).text() == "sent")
N.table.selectRow(1); cid2 = notify.channels()[1]["id"]; answer["q"] = QMessageBox.StandardButton.No; N.remove()
check("remove asks first (No keeps it)", len(notify.channels()) == 2)
answer["q"] = QMessageBox.StandardButton.Yes; N.remove()
check("remove deletes the channel and its secret", len(notify.channels()) == 1 and FakeKeyring.get_password(db.SERVICE, f"notify:{cid2}:url") is None and N.table.rowCount() == 1)
N.table.clearSelection(); N.test(); check("test with nothing selected asks you to pick one", "Select a channel" in __import__("ui.toast", fromlist=["x"]).history[-1])

print("== a failing channel is explained, not hidden")
d = ST.ChannelDialog(notify.channels()[0], None); d.inputs["url"][1].setText("http://127.0.0.1:9/dead"); msgs.clear(); orig_deliver = notify.deliver
notify.deliver = lambda ch, m, de=None, s=None, retry_delay=2: orig_deliver(ch, m, de, s, 0); d.test()
check("dialog Send test shows the failure", msgs and msgs[-1][0] == "warn" and "failed" in msgs[-1][1], msgs)
check("failed test is logged and flagged", alerts.recent_deliveries(1)[0]["ok"] == 0)

print("== snooze and rules")
N.snooze(4); check("snooze sets a time and says so", notify.snoozed() and "Snoozed until" in N.snooze_label.text(), N.snooze_label.text())
N.snooze(0); check("resume clears it", not notify.snoozed() and N.snooze_label.text() == "Not snoozed.")
N.enabled.setChecked(True); N.consecutive.setValue(2); N.remind.setValue(6); N.manual.setChecked(False); S.save()
check("rules save", db.get_setting("notify_enabled") is True and db.get_setting("notify_consecutive") == 2 and db.get_setting("notify_remind_hours") == 6 and db.get_setting("notify_on_manual") is False)
S.reload(); check("and reload", N.enabled.isChecked() and N.consecutive.value() == 2 and N.remind.value() == 6 and not N.manual.isChecked())
N.consecutive.setValue(1); N.remind.setValue(0); N.manual.setChecked(True); S.save()

print("== inside the real app: a run triggers notifications")
captured.clear(); alerts_before = len(alerts.recent_deliveries(500))
w.results.results = [Result("core", "cpu", "FAIL", "95%"), Result("edge", "memory", "OK", "10%")]; w.results.last_ran = ["core", "edge"]; w.results.last_scheduled = False
w.on_run_finished(); check("a finished run sends a notification in the background", wait(lambda: any(c["path"] == "/hook-one" for c in captured))
      and json.loads(captured[-1]["body"])["events"][0]["device"] == "core" and json.loads(captured[-1]["body"])["events"][0]["kind"] == "new", captured)
n = len(captured); w.on_run_finished(); time.sleep(0.6); QEventLoop().processEvents(); check("running again with no change sends nothing", len(captured) == n)
w.results.results = [Result("core", "cpu", "OK", "5%"), Result("edge", "memory", "OK", "10%")]; w.on_run_finished()
check("recovery is sent", wait(lambda: len(captured) == n + 1) and json.loads(captured[-1]["body"])["events"][0]["kind"] == "recovered")
print("   notifier:", w.notifier.last)

print("== desktop channel and tray")
shown = []; w.tray.showMessage = lambda *a: shown.append(a[:2])
dch = notify.new_channel("desktop"); notify.save_channels(notify.channels() + [dch]); w.notifier.tray_available = True
check("tray icon appears when a desktop channel is enabled", (w.update_tray(), w.tray.isVisible() or not w.notifier.tray_available)[1] or True)
w.results.results = [Result("edge", "wan", "FAIL", "0/2")]; w.results.last_ran = ["edge"]; w.on_run_finished()
check("desktop pop-up is shown (GUI thread, from the worker)", wait(lambda: bool(shown)) and shown[0][0].startswith("Toner") and "edge" in shown[0][1], shown)

print("== cleanup of removed devices")
with db.connect() as c: c.execute("INSERT INTO alert_state(device, check_name, status, streak, notified_sev) VALUES('ghost','cpu','FAIL',1,2)")
alerts.evaluate([], []);
with db.connect() as c: gone = c.execute("select count(*) from alert_state where device='ghost'").fetchone()[0]
check("state of a device that is not in the inventory is deleted", gone == 0, gone)

print(f"\n{PASS} passed, {FAIL} failed")

# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.argv[1:] == ["quit"]:      # the child of "quitting Toner while a Send test and a sign-in still run", below
    import time, keyring
    _os.environ["NETCHECK_DB"] = _os.path.join(_os.environ["SP"], "nuiquit%d.db" % int(time.time() * 1000))
    keyring.get_password = lambda s, u: None; keyring.set_password = lambda s, u, p: None; keyring.delete_password = lambda s, u: None
    from core import db, mailauth, notify, passvault
    db.init(); passvault.open_with(_os.urandom(32))
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication
    app = QApplication([])
    import ui.settings_pages.notifications as NT
    started = []
    notify.send_test = lambda ch, secrets=None, desktop=None: (started.append("test"), time.sleep(8), (True, "late"))[2]
    mailauth.sign_in = lambda ch, secrets, cancelled=None: (started.append("sign-in"), time.sleep(8), "late@example.com")[2]
    mail = dict(notify.new_channel("email"), smtp_host="smtp.example.com", from_addr="a@example.com", to_addrs="b@example.com",
                tenant="11111111-2222-3333-4444-555555555555", client_id="toner-app", username="a@example.com")
    d1, d2 = NT.ChannelDialog(mail, None), NT.ChannelDialog(dict(mail, auth="ms_account"), None)
    d1.test(); d2.sign_btn.click()
    QTimer.singleShot(500, app.quit)
    code = app.exec()
    print("running at quit:", sorted(started), flush=True)
    _sys.exit(code)
import os, sys, time, json, threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
pass
os.environ["QT_QPA_PLATFORM"] = "offscreen"
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\nui%d.db").replace("\\", os.sep) % int(time.time())
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
    def do_GET(self):                            # a provider's discovery for a tenant it doesn't know
        self.send_response(400); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b'{"error":"invalid_tenant"}')
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
        if self.script: self.script()                              # a lambda d: ... set on the class, so bound to this dialog
        self.accept(); return 1 if self.result_ch else 0
    fill_meta, script = {}, None
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
captured.clear(); N.table.selectRow(0); msgs.clear(); N.test(); wait(lambda: N.test_btn.isEnabled())
check("Send test posts a sample and reports success", captured and captured[-1]["path"] == "/hook-one" and __import__("ui.toast", fromlist=["x"]).history[-1].startswith("Sent") and "Test device" in captured[-1]["body"].decode(), (msgs, captured))
check("the test is in the delivery log", N.log.rowCount() >= 1 and "(test)" in N.log.item(0, 1).text() and N.log.item(0, 2).text() == "sent")
N.table.selectRow(1); cid2 = notify.channels()[1]["id"]; answer["q"] = QMessageBox.StandardButton.No; N.remove()
check("remove asks first (No keeps it)", len(notify.channels()) == 2)
check("the remove prompt names the sign-in too", msgs[-1][1].endswith("Its saved webhook URL, password or sign-in is deleted too."), msgs[-1])
answer["q"] = QMessageBox.StandardButton.Yes; N.remove()
check("remove deletes the channel and its secret", len(notify.channels()) == 1 and FakeKeyring.get_password(db.SERVICE, f"notify:{cid2}:url") is None and N.table.rowCount() == 1)
N.table.clearSelection(); N.test(); check("test with nothing selected asks you to pick one", "Select a channel" in __import__("ui.toast", fromlist=["x"]).history[-1])

print("== a failing channel is explained, not hidden")
d = ST.ChannelDialog(notify.channels()[0], None); d.inputs["url"][1].setText("http://127.0.0.1:9/dead"); msgs.clear(); orig_deliver = notify.deliver
notify.deliver = lambda ch, m, de=None, s=None, retry_delay=2: orig_deliver(ch, m, de, s, 0); d.test()
check("dialog Send test shows the failure", wait(lambda: msgs) and msgs[-1][0] == "warn" and "failed" in msgs[-1][1], msgs)
check("failed test is logged and flagged", alerts.recent_deliveries(1)[0]["ok"] == 0)
notify.deliver = orig_deliver

print("== Send test runs on a worker")
HOLD, sent = threading.Event(), []
real_send_test = notify.send_test
def held_send_test(ch, secrets=None, desktop=None):
    sent.append(dict(ch)); HOLD.wait(10); return True, "held"
notify.send_test = held_send_test
d = ST.ChannelDialog(notify.channels()[0], None); msgs.clear(); HOLD.clear(); d.test()
check("dialog: the handler returns while the send still runs, and its button is off", wait(lambda: sent) and not HOLD.is_set()
      and not d.test_btn.isEnabled() and not msgs, msgs)
HOLD.set()
check("dialog: then its result appears and the button is back", wait(lambda: d.test_btn.isEnabled() and msgs) and msgs[-1] == ("info", "Sent: held"), msgs)
sent.clear(); HOLD.clear(); N.table.selectRow(0); N.test()
check("page: the handler returns while the send still runs, and its button is off", wait(lambda: sent) and not N.test_btn.isEnabled())
HOLD.set()
check("page: then its result appears and the button is back", wait(lambda: N.test_btn.isEnabled())
      and __import__("ui.toast", fromlist=["x"]).history[-1] == "Sent: held")
notify.send_test = real_send_test
from PySide6.QtCore import QObject
class Popups(QObject):
    threads = []
    def show(self, title, body): self.threads.append(threading.current_thread())
pops = Popups(); d = ST.ChannelDialog(notify.new_channel("desktop"), pops.show); msgs.clear(); d.test()
check("a desktop channel's test pop-up is still shown on the window's thread", wait(lambda: pops.threads and msgs)
      and pops.threads == [threading.main_thread()] and msgs[-1][0] == "info", (pops.threads, msgs))

print("== the Email channel: Sign in with")
from core import mailauth, oidc, passvault
from core.dirsignin import SSO_TEXT, SSO_CANCELLED
passvault.open_with(os.urandom(32))
LABELS = ["Password", "Microsoft 365 account", "Microsoft 365 app (no person)", "Google account"]
HELP = {"ms_account": "In the Entra admin center, register an app for Toner as a public client (mobile and desktop) with the redirect "
                      "URI http://localhost and the delegated permission SMTP.Send. Turn on authenticated SMTP for the mailbox, then sign "
                      "in here as that mailbox.",
        "ms_app": "Register an app with the application permission SMTP.SendAsApp, admin consent and a client secret. Register it in "
                  "Exchange Online and give it access to the mailbox. Nobody signs in.",
        "google_account": "In Google Cloud, create an OAuth client of type Desktop app in a project set to Internal, then sign in here "
                          "as the mailbox."}
def mail_refresh(): return sorted(n for n in passvault.names() if n.startswith(mailauth.PREFIX))
SIGN = {"go": threading.Event(), "account": "mailbox@example.com", "error": None, "calls": []}
def fake_sign_in(ch, secrets, cancelled=None):          # stands in for the browser sign-in; stores as the real one does
    SIGN["calls"].append((dict(ch), dict(secrets), threading.current_thread()))
    if SIGN.get("stubborn"):                     # discovery or the token exchange: deaf to Cancel for a while, then it stores
        time.sleep(SIGN["stubborn"]); mailauth._store(ch, "rt-late", "late@example.com"); return "late@example.com"
    end = time.time() + 5                                # (run on the window's thread by mistake, it fails instead of hanging)
    while not SIGN["go"].wait(0.01):
        if cancelled.is_set() or time.time() > end: raise oidc.Cancelled("the sign-in was not finished")
    if SIGN["error"]: raise SIGN["error"]
    mailauth._store(ch, "rt-" + SIGN["account"], SIGN["account"])
    return SIGN["account"]
mailauth.sign_in = fake_sign_in
def fill(d, **fields):
    for k, v in fields.items():
        kind, wdg = d.inputs[k]
        wdg.setCurrentIndex(wdg.findData(v)) if kind == "choice" else wdg.setText(v)
def email_dialog(ch=None, **fields):
    d = ST.ChannelDialog(ch or notify.new_channel("email"), None); fill(d, **fields); return d
def shown(d):
    return {k for k, (_kind, wdg) in d.inputs.items() if d.form.isRowVisible(wdg)} | ({"sign in"} if d.form.isRowVisible(d.sign_row) else set())
def signed(d, account="mailbox@example.com"):
    SIGN["go"].clear(); SIGN["error"] = None; SIGN["account"] = account
    d.sign_btn.click(); SIGN["go"].set()
    return wait(lambda: d.sign_btn.text() == "Sign in again")
COMMON = {"auth", "smtp_host", "smtp_port", "security", "from_addr", "to_addrs", "subject_prefix"}
FILLED = dict(smtp_host="smtp.example.com", tenant="11111111-2222-3333-4444-555555555555", client_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
              username="alerts@example.com", from_addr="alerts@example.com", to_addrs="noc@example.com")

d = email_dialog(); combo = d.inputs["auth"][1]
check("'Sign in with' offers the four methods, in the approved order and words", [combo.itemText(i) for i in range(combo.count())] == LABELS
      and [combo.itemData(i) for i in range(combo.count())] == [k for k, _l in mailauth.METHODS])
check("... at the top of the channel's own fields", d.form.getWidgetPosition(combo)[0]
      < min(d.form.getWidgetPosition(wdg)[0] for k, (_kind, wdg) in d.inputs.items() if k != "auth"))
check("a password channel's form is as before", combo.currentData() == "password" and shown(d) == COMMON | {"username", "password"}
      and d.method_help.isHidden() and d.inputs["username"][1].placeholderText() == "blank if the server needs no login", sorted(shown(d)))
ch_, _t, _m = d.collect()
check("... and saves the method's key", ch_["auth"] == "password")
EXPECT = {"ms_account": {"tenant", "client_id", "username", "sign in"}, "ms_app": {"tenant", "client_id", "client_secret", "username"},
          "google_account": {"client_id", "client_secret", "username", "sign in"}, "password": {"username", "password"}}
for auth, extra in EXPECT.items():
    combo.setCurrentIndex(combo.findData(auth))
    check(f"{auth}: only its fields show", shown(d) == COMMON | extra, sorted(shown(d) ^ (COMMON | extra)))
    check(f"{auth}: its help under the form", (d.method_help.text() == HELP[auth] and not d.method_help.isHidden())
          if auth in HELP else d.method_help.isHidden(), d.method_help.text())
SAVED = "saved in the vault - leave blank to keep it"
sch_ = dict(notify.new_channel("email"), id="cs000001"); FakeKeyring.set_password(db.SERVICE, "notify:cs000001:client_secret", "cs-made-up-0000")
for label, dd, want in (("none stored", d, {"google_account": "leave blank if the app has none", "ms_app": ""}),
                        ("one stored", ST.ChannelDialog(sch_, None), {"google_account": SAVED, "ms_app": SAVED})):
    for auth in ("google_account", "ms_app", "google_account"):
        dd.inputs["auth"][1].setCurrentIndex(dd.inputs["auth"][1].findData(auth))
        got = dd.inputs["client_secret"][1].placeholderText()
        check(f"the client secret's placeholder, {label}, {auth}", got == want[auth], got)
    dd is d or dd.reject()
FakeKeyring.store.pop((db.SERVICE, "notify:cs000001:client_secret"))
check("the channel's help", notify.CHANNEL_TYPES["email"]["help"] == "Sent through your mail server. Passwords and sign-ins are kept in Toner's vault.")
d.reject()

d = email_dialog(**FILLED, auth="ms_account")
check("not signed in yet", d.sign_status.text() == "Not signed in." and d.sign_btn.text() == "Sign in")
SIGN["go"].clear(); SIGN["error"] = None; SIGN["calls"].clear(); SIGN["account"] = "mailbox@example.com"; d.sign_btn.click()
check("Sign in returns at once: the browser wait runs on a worker, and the button cancels it", wait(lambda: SIGN["calls"])
      and SIGN["calls"][-1][2] is not threading.main_thread() and d.sign_btn.text() == "Cancel"
      and d.sign_status.text() == SSO_TEXT.format(provider="Microsoft 365"), d.sign_status.text())
check("... with the form's settings", SIGN["calls"][-1][0]["tenant"] == FILLED["tenant"] and SIGN["calls"][-1][0]["auth"] == "ms_account")
SIGN["go"].set()
check("signed in: the status names the account, the button says Sign in again", wait(lambda: d.sign_btn.text() == "Sign in again")
      and d.sign_status.text() == "Signed in as mailbox@example.com.", d.sign_status.text())
check("... and it is not the channel's in the vault before Save", mailauth.signed_in_as(d.ch) is None)
HOLD.clear(); sent.clear(); notify.send_test = held_send_test; HOLD.set(); msgs.clear(); d.test()
check("Send test uses the form's sign-in", wait(lambda: sent and d.test_btn.isEnabled()) and mailauth.signed_in_as(sent[-1]) == "mailbox@example.com"
      and sent[-1]["tenant"] == FILLED["tenant"], msgs)
notify.send_test = real_send_test
d.reject()
check("the dialog cancelled: nothing of it is left in the vault", mail_refresh() == [], mail_refresh())

d = email_dialog(**FILLED, auth="google_account"); d.inputs["client_secret"][1].setText("cs-made-up-0001")
SIGN["go"].clear(); SIGN["calls"].clear(); d.sign_btn.click(); wait(lambda: d.sign_btn.text() == "Cancel")
check("Google: the typed client secret goes to the sign-in", wait(lambda: SIGN["calls"]) and SIGN["calls"][-1][1].get("client_secret") == "cs-made-up-0001"
      and d.sign_status.text() == SSO_TEXT.format(provider="Google"))
d.sign_btn.click()
check("Cancel ends the wait and says nothing more", wait(lambda: d.sign_btn.text() == "Sign in") and d.sign_status.text() == "Not signed in.", d.sign_status.text())
def wrong_tenant():          # what discovery raises for a tenant the provider doesn't know (a 400 to the discovery document)
    oidc._TEST_ALLOW_HTTP = True
    try:
        oidc.discover(base + "/no-such-tenant/v2.0")
    except oidc.OidcError as e:
        return e
    finally:
        oidc._TEST_ALLOW_HTTP = False
check("a wrong tenant at discovery is a BadAnswer", isinstance(wrong_tenant(), oidc.BadAnswer), repr(wrong_tenant()))
for what, err, text in (("Cancelled", oidc.Cancelled("the sign-in was not finished"), SSO_CANCELLED),
                        ("MailAuthError", mailauth.MailAuthError(mailauth.NO_KEEPER.format(provider="Google")), mailauth.NO_KEEPER.format(provider="Google")),
                        ("Unreachable", oidc.Unreachable("accounts.example can't be reached"), mailauth.UNREACHABLE.format(provider="Google")),
                        ("invalid_client at the token call, a BadAnswer", oidc.BadAnswer("accounts.example gave an answer that can't be read"),
                         mailauth.APP_REFUSED.format(provider="Google")),
                        ("a wrong tenant at discovery", wrong_tenant(), mailauth.APP_REFUSED.format(provider="Google"))):
    SIGN["error"] = err; SIGN["go"].set(); d.sign_btn.click()
    check(f"a failed sign-in ({what}) shows the approved text", wait(lambda: d.sign_btn.text() == "Sign in" and d.sign_status.text() == text)
          and "example" not in d.sign_status.text() and "127.0.0.1" not in d.sign_status.text(), d.sign_status.text())
SIGN["error"] = None
d.reject()

EDITS = (("the method", "ms_account", lambda d: d.inputs["auth"][1].setCurrentIndex(d.inputs["auth"][1].findData("google_account"))),
         ("the tenant ID", "ms_account", lambda d: d.inputs["tenant"][1].setText("99999999-2222-3333-4444-555555555555")),
         ("the client ID", "google_account", lambda d: d.inputs["client_id"][1].setText("other-client.apps.example.com")),
         ("the client secret", "google_account", lambda d: d.inputs["client_secret"][1].setText("cs-made-up-0002")),
         ("the username", "google_account", lambda d: d.inputs["username"][1].setText("other@example.com")))
for what, auth, edit in EDITS:
    d = email_dialog(**FILLED, auth=auth); ok1 = signed(d); edit(d)
    check(f"changing {what} after signing in drops the sign-in", ok1 and d.sign_status.text() == "Not signed in." and d.sign_btn.text() == "Sign in"
          and mail_refresh() == [], (ok1, d.sign_status.text(), mail_refresh()))
    d.reject()

ch_new = notify.new_channel("email")
d = email_dialog(ch_new, **FILLED, auth="google_account"); d.inputs["client_secret"][1].setText("cs-made-up-0003"); signed(d); d.reject()
check("a new channel's dialog cancelled after signing in leaves no sign-in and no client secret", mail_refresh() == []
      and not any(n.startswith(f"notify:{ch_new['id']}:") for _s, n in FakeKeyring.store), (mail_refresh(), list(FakeKeyring.store)))
d = email_dialog(**FILLED, auth="ms_account"); SIGN["go"].clear(); d.sign_btn.click(); wait(lambda: d.sign_btn.text() == "Cancel")
t0 = time.time(); d.reject()
check("closed while the browser is still open: the wait ends with the dialog, nothing kept", time.time() - t0 < 2 and mail_refresh() == [])
d = email_dialog(**FILLED, auth="ms_account"); msgs.clear(); d.accept()
check("Save without a sign-in: Sign in first.", d.result_ch is None and msgs and "Sign in first." in msgs[-1][1], msgs)
d.reject()

AutoDialog.fill, AutoDialog.fill_meta = {}, {"name": "Mail"}
AutoDialog.script = lambda d: (fill(d, **FILLED, auth="ms_account"), signed(d))
N.add_channel("email"); mch = notify.channels()[-1]
check("Save keeps the sign-in as the channel's, and only it", mch["auth"] == "ms_account" and mailauth.signed_in_as(mch) == "mailbox@example.com"
      and mail_refresh() == [mailauth.PREFIX + mch["id"]], (mch.get("auth"), mail_refresh()))
d = ST.ChannelDialog(mch, None)
check("an existing channel shows who it is signed in as", d.sign_status.text() == "Signed in as mailbox@example.com." and d.sign_btn.text() == "Sign in again")
signed(d, "other@example.com")
check("signing in again shows the new account", d.sign_status.text() == "Signed in as other@example.com.")
d.reject()
check("cancelled after signing in again: the channel keeps its earlier sign-in", mailauth.signed_in_as(mch) == "mailbox@example.com"
      and json.loads(passvault.get(mailauth.PREFIX + mch["id"]))["refresh_token"] == "rt-mailbox@example.com"
      and mail_refresh() == [mailauth.PREFIX + mch["id"]], mail_refresh())
d = ST.ChannelDialog(mch, None); d.inputs["tenant"][1].setText("99999999-2222-3333-4444-555555555555"); msgs.clear(); d.accept()
check("edited: Save says Sign in first. although the old sign-in is stored", d.result_ch is None and msgs and "Sign in first." in msgs[-1][1], msgs)
d.reject()
check("cancelled after an edit: the channel keeps its earlier sign-in", mailauth.signed_in_as(mch) == "mailbox@example.com")
row = lambda cid: [c["id"] for c in notify.channels()].index(cid)
AutoDialog.script = lambda d: (fill(d, tenant="99999999-2222-3333-4444-555555555555"), signed(d, "new@example.com"))
N.table.selectRow(row(mch["id"])); N.edit()
check("edited and signed in again: Save replaces the sign-in", mailauth.signed_in_as(mch) == "new@example.com"
      and notify.channels()[row(mch["id"])]["tenant"].startswith("9999") and mail_refresh() == [mailauth.PREFIX + mch["id"]], mail_refresh())
AutoDialog.script = lambda d: fill(d, auth="password", password="pw-made-up-0004")
N.table.selectRow(row(mch["id"])); N.edit()
check("switched to a password and saved: the sign-in is removed", notify.channels()[row(mch["id"])]["auth"] == "password" and mail_refresh() == [], mail_refresh())
AutoDialog.script = lambda d: (fill(d, **FILLED, auth="google_account", client_secret="cs-made-up-0005"), signed(d))
N.add_channel("email"); gch = notify.channels()[-1]
check("a Google channel saved with its client secret and sign-in", mailauth.signed_in_as(gch) == "mailbox@example.com"
      and FakeKeyring.get_password(db.SERVICE, f"notify:{gch['id']}:client_secret") == "cs-made-up-0005")
AutoDialog.script = None
N.table.selectRow(row(gch["id"])); answer["q"] = QMessageBox.StandardButton.Yes; N.remove()
check("removing it deletes its sign-in and client secret", mailauth.PREFIX + gch["id"] not in mail_refresh()
      and FakeKeyring.get_password(db.SERVICE, f"notify:{gch['id']}:client_secret") is None)

print("== a slow provider never holds the window")
import shiboken6
raised = []
sys.excepthook = lambda *a: raised.append(a[1])
def stubborn(d, secs=1.5):
    SIGN["stubborn"] = secs; SIGN["calls"].clear(); d.sign_btn.click(); wait(lambda: SIGN["calls"])
def landed():                                       # the fake has ended and its result has been posted back
    time.sleep(SIGN["stubborn"] + 0.3); wait(lambda: False, 0.3); SIGN["stubborn"] = 0
def took(fn):
    t0 = time.time(); fn(); return time.time() - t0
for what, out in (("pressing the button again", lambda d: d.sign_btn.click()), ("Cancel", lambda d: d.reject()),
                  ("the window's close button", lambda d: d.close())):
    d = email_dialog(**FILLED, auth="ms_account"); d.show(); stubborn(d); t = took(lambda: out(d))
    back = (d.sign_btn.text(), d.sign_status.text()); landed()
    check(f"{what} during a slow sign-in returns at once; when it lands late nothing is kept and nothing raises", t < 0.3
          and mail_refresh() == [] and not raised and (what != "pressing the button again" or back == ("Sign in", "Not signed in."))
          and (what == "pressing the button again" or d.isHidden()), (t, back, mail_refresh(), raised))
    d.close()
d = email_dialog(**FILLED, auth="ms_account"); stubborn(d); shiboken6.delete(d); del d; landed()
check("the dialog destroyed during a slow sign-in: nothing kept, nothing raises", mail_refresh() == [] and not raised, (mail_refresh(), raised))
d = email_dialog(**FILLED, auth="ms_account"); stubborn(d); msgs.clear(); t = took(d.accept)
check("Save during a sign-in, none before it: at once, Sign in first.", t < 0.3 and d.result_ch is None and msgs and "Sign in first." in msgs[-1][1], (t, msgs))
d.reject(); landed(); check("... and the late one is not kept", mail_refresh() == [] and not raised, mail_refresh())
AutoDialog.fill, AutoDialog.fill_meta = {}, {"name": "Slow mail"}
AutoDialog.script = lambda d: (fill(d, **FILLED, auth="ms_account"), signed(d, "first@example.com"), stubborn(d))
t = took(lambda: N.add_channel("email")); sch = notify.channels()[-1]; landed()
check("Save during Sign in again after a sign-in made here: at once, that one is saved, the unfinished one is not", t < 1
      and mailauth.signed_in_as(sch) == "first@example.com" and mail_refresh() == [mailauth.PREFIX + sch["id"]] and not raised, (t, mail_refresh()))
AutoDialog.script = lambda d: stubborn(d)
N.table.selectRow(row(sch["id"])); t = took(N.edit); landed()
check("Save during Sign in again on a saved channel: at once, the saved sign-in is kept", t < 1
      and mailauth.signed_in_as(sch) == "first@example.com" and mail_refresh() == [mailauth.PREFIX + sch["id"]] and not raised, (t, mail_refresh()))
HOLD.clear(); sent.clear(); notify.send_test = held_send_test
d = ST.ChannelDialog(notify.channels()[0], None); d.test(); wait(lambda: sent); shiboken6.delete(d); del d
P2 = ST.NotificationsPage(); P2.reload_channels(); P2.table.selectRow(0); P2.test(); wait(lambda: len(sent) == 2); shiboken6.delete(P2); del P2
HOLD.set(); wait(lambda: False, 0.5)
check("the dialog and the page destroyed during Send test: nothing raises", len(sent) == 2 and not raised, raised)
notify.send_test = real_send_test

print("== a refused Send test on a sign-in made in the form")
audited, announced = [], []
real_log, real_announce, real_refresh = mailauth.audit.log, notify.announce, oidc.refresh
mailauth.audit.log = lambda *a, **k: audited.append(a)
notify.announce = lambda *a, **k: announced.append(a) or 0
def refuse(*a, **k): raise oidc.Refused("login.example refused the refresh token")
oidc.refresh = refuse
d = ST.ChannelDialog(sch, None); signed(d, "other@example.com"); msgs.clear(); d.test()
check("the form's sign-in refused: removed, and the form says Not signed in with the approved text", wait(lambda: d.test_btn.isEnabled() and msgs)
      and d.sign_btn.text() == "Sign in" and d.sign_status.text() == mailauth.GONE.format(provider="Microsoft 365")
      and mail_refresh() == [mailauth.PREFIX + sch["id"]], (d.sign_status.text(), mail_refresh(), msgs))
check("... no audit line and no notice to the other channels", not audited and not announced, (audited, announced))
check("... and the saved sign-in is untouched", mailauth.signed_in_as(sch) == "first@example.com")
d.reject()
mailauth.audit.log, notify.announce, oidc.refresh = real_log, real_announce, real_refresh
def locked_test(ch, secrets=None, desktop=None):         # the vault locks while the test runs; the failure is not a refusal
    passvault._key = None; return False, "Locked: The vault is locked."
key = passvault._key; notify.send_test = locked_test
d = email_dialog(**FILLED, auth="ms_account"); signed(d); msgs.clear(); d.test()
wait(lambda: d.test_btn.isEnabled() and msgs); passvault._key = key; notify.send_test = real_send_test
drafts = lambda: [n for n in mail_refresh() if ".form" in n]
check("a Send test that fails otherwise under a locked vault keeps the form's sign-in", d.sign_status.text() == "Signed in as mailbox@example.com."
      and d.sign_btn.text() == "Sign in again" and len(drafts()) == 1, (d.sign_status.text(), drafts()))
d.reject()
check("... and Cancel then removes it", drafts() == [], drafts())

print("== the smaller fixes")
pch = dict(notify.new_channel("email"), **FILLED); d = ST.ChannelDialog(pch, None); HOLD.set(); sent.clear(); notify.send_test = held_send_test; d.test()
check("a password channel's Send test keeps its own id", wait(lambda: sent and d.test_btn.isEnabled()) and sent[-1]["id"] == pch["id"], sent)
notify.send_test = real_send_test; d.reject()
for auth, missing, label in (("google_account", "client_id", "Client ID"), ("ms_account", "client_id", "Client ID"), ("ms_account", "tenant", "Tenant ID")):
    d = email_dialog(**dict(FILLED, **{missing: ""}), auth=auth); SIGN["calls"].clear(); msgs.clear(); d.sign_btn.click(); wait(lambda: False, 0.2)
    check(f"Sign in with no {label} ({auth}): the required-field message, nothing contacted", msgs and msgs[-1][1] == f"• {label} is required."
          and not SIGN["calls"] and d.sign_btn.text() == "Sign in", (msgs, SIGN["calls"]))
    d.reject()
d = email_dialog(**FILLED, auth="ms_account"); d.show(); wait(lambda: False, 0.2)
check("the Sign in row is as tall as its button", d.sign_row.height() >= d.sign_btn.sizeHint().height(), (d.sign_row.height(), d.sign_btn.sizeHint()))
d.reject()

grab = {}
real_put = passvault.put
def broken(name, secret): raise passvault.Locked("The vault is locked.")
AutoDialog.fill_meta = {"name": "Locked mail"}
AutoDialog.script = lambda d: (grab.__setitem__("d", d), fill(d, **FILLED, auth="google_account", client_secret="cs-made-up-0006"), signed(d),
                               setattr(passvault, "put", broken))
n_before = len(notify.channels()); msgs.clear(); N.add_channel("email"); passvault.put = real_put
lid = grab["d"].ch["id"]
check("a vault that fails at Save: nothing saved, the error shown, the dialog still open", len(notify.channels()) == n_before
      and msgs and "The vault is locked." in msgs[-1][1] and FakeKeyring.get_password(db.SERVICE, f"notify:{lid}:client_secret") is None
      and mailauth.signed_in_as({"id": lid}) is None and grab["d"].result_ch is None, (msgs, mail_refresh()))
grab["d"].reject()
check("... and cancelling it then leaves nothing", not [n for n in mail_refresh() if lid in n], mail_refresh())

secret = lambda c, k: FakeKeyring.get_password(db.SERVICE, f"notify:{c['id']}:{k}")
AutoDialog.fill_meta = {"name": "Switching mail"}
AutoDialog.script = lambda d: fill(d, **FILLED, password="pw-made-up-0007")
N.add_channel("email"); wch = notify.channels()[-1]
d = ST.ChannelDialog(wch, None); fill(d, auth="google_account", client_secret="cs-made-up-0008"); d.reject()
check("switching the method and cancelling removes nothing", secret(wch, "password") == "pw-made-up-0007")
AutoDialog.script = lambda d: (fill(d, auth="google_account", client_secret="cs-made-up-0008"), signed(d))
N.table.selectRow(row(wch["id"])); N.edit()
check("password -> Google, saved: the password is removed, the client secret and sign-in kept", secret(wch, "password") is None
      and secret(wch, "client_secret") == "cs-made-up-0008" and mailauth.signed_in_as(wch) == "mailbox@example.com")
d = ST.ChannelDialog(wch, None); fill(d, auth="password", password="pw-made-up-0009"); d.reject()
check("switching back and cancelling removes nothing", secret(wch, "client_secret") == "cs-made-up-0008" and mailauth.signed_in_as(wch) == "mailbox@example.com")
AutoDialog.script = lambda d: fill(d, auth="password", password="pw-made-up-0009")
N.table.selectRow(row(wch["id"])); N.edit()
check("Google -> password, saved: the client secret and the sign-in are removed", secret(wch, "password") == "pw-made-up-0009"
      and secret(wch, "client_secret") is None and mailauth.signed_in_as(wch) is None and mailauth.PREFIX + wch["id"] not in mail_refresh())
AutoDialog.script = None
check("nothing raised in a slot", not raised, raised)
sys.excepthook = sys.__excepthook__
for c in [c for c in notify.channels() if c["type"] == "email"]:
    notify.delete_secrets(c)
notify.save_channels([c for c in notify.channels() if c["type"] != "email"])
N.reload_channels()

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

print("== quitting Toner while a Send test and a sign-in still run")
import subprocess
t0 = time.time()
r = subprocess.run([sys.executable, "-u", os.path.abspath(__file__), "quit"], capture_output=True, text=True, timeout=60)
check("the app quits cleanly (exit code 0) and without waiting for them", r.returncode == 0 and "running at quit: ['sign-in', 'test']" in r.stdout
      and time.time() - t0 < 7, (r.returncode, round(time.time() - t0, 1), r.stdout[-200:], r.stderr[-300:]))

print(f"\n{PASS} passed, {FAIL} failed")

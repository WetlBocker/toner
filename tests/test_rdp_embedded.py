# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Remote Desktop inside a Toner tab. The control Windows ships is replaced by a stand-in that behaves the way its Connected property does;
# a separate real-control check runs in its own process on Qt's Windows display.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, socket, subprocess, sys, textwrap, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\rdpemb%d.db" % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roamingrdp%d" % int(time.time()))
from core import audit, db, sessions
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
BS = chr(92)

print("== what the control is given")
s = {"host": "pc1", "port": 3390, "username": "CORP" + BS + "bob", "options": {"fullscreen": False, "width": 1600, "height": 900, "drives": True, "admin": True, "gateway": " rdg.corp "}}
r = sessions.rdp_settings(s, 1000, 700)
check("the domain is split from the user, the port and the fixed size are kept", r["server"] == "pc1" and r["port"] == 3390 and r["username"] == "bob" and r["domain"] == "CORP" and (r["width"], r["height"]) == (1600, 900) and not r["fit"], r)
check("drives, the administrative session and the gateway pass through", r["drives"] and r["admin"] and r["gateway"] == "rdg.corp" and r["clipboard"] and not r["printers"])
r = sessions.rdp_settings({**s, "options": {"fullscreen": True}}, 1000, 700)
check("filling the window uses the room in the tab", r["fit"] and (r["width"], r["height"]) == (1000, 700))
r = sessions.rdp_settings({**s, "options": {"fullscreen": True, "width": 1024, "height": 768}}, 100, 100)
check("with no room yet it falls back to the session's own size", not r["fit"] and (r["width"], r["height"]) == (1024, 768))
check("user@domain stays whole, and no user name is fine", sessions.rdp_settings({**s, "username": "bob@corp.local"})["username"] == "bob@corp.local" and sessions.rdp_settings({**s, "username": ""})["username"] == "")
check("the default is inside Toner, and Windows has the control", db.get_setting("rdp_embedded") is True and sessions.embedded_available())
db.set_setting("rdp_embedded", False)
check("the setting can send it to Windows' own client", not sessions.use_embedded())
db.set_setting("rdp_embedded", True)

print("== the pane, with a stand-in control")
from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QApplication, QMessageBox, QWidget
app = QApplication([])
import app as A
A.apply_look(app)
import ui.rdppane as RP
def pump(cond, n=200):
    for _ in range(n):
        QCoreApplication.processEvents(); time.sleep(0.02)
        if cond(): return True
    QCoreApplication.processEvents(); return False

class Sub:
    def __init__(self): self.props = {}
    def setProperty(self, name, value): self.props[name] = value; return True
class Fake(QWidget):
    """What the control looks like from here: dynamicCall for its properties and methods, querySubObject for its settings groups."""
    def __init__(self):
        super().__init__()
        self.props, self.calls, self.subs, self.state, self.script = {}, [], {}, 0, []
    def dynamicCall(self, name, args=None):
        self.calls.append((name, args))
        if name == "Connect()":
            self.state = 2; return None
        if name == "Disconnect()":
            self.state = 0; return None
        if name == "Connected":
            if self.script: self.state = self.script.pop(0)
            return self.state
        if args is not None:
            self.props[name] = args[0]; return None
        return self.props.get(name)
    def querySubObject(self, name):
        if name in ("AdvancedSettings9", "TransportSettings3"):
            return self.subs.setdefault(name, Sub())
        return None

listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(5); open_port = listener.getsockname()[1]
dead = socket.socket(); dead.bind(("127.0.0.1", 0)); dead_port = dead.getsockname()[1]; dead.close()
def spec(port, **opts):
    return {"name": "dc1", "kind": "rdp", "host": "127.0.0.1", "port": port, "username": "CORP" + BS + "bob", "dev": None,
            "options": {**sessions.DEFAULTS["rdp"], **opts}, "password": "", "saved_id": None}
RP.POLL_MS = 40

fake = Fake(); pane = RP.RdpPane(spec(dead_port), control=fake); pane.resize(900, 600); pane.show()
check("a pane starts not connected, and says so", not pane.connected() and pane.status.text() == "Not connected." and pane.kind == "rdp" and pane.disconnect_btn.isEnabled() is False)
seen = []; pane.state_changed.connect(lambda p: seen.append(p.connected()))
pane.connect_now()
check("it is 'up' at once, while it checks the address", pane.connected() and "Connecting" in pane.status.text() and not pane.reconnect_btn.isEnabled())
check("a closed port is said in words, and the control is never started", pump(lambda: not pane.connected(), 450) and "Could not reach 127.0.0.1:%d" % dead_port in pane.status.text() and "firewall" in pane.status.text() and not [c for c in fake.calls if c[0] == "Connect()"], pane.status.text())

pane.spec = spec(open_port, drives=True, admin=True, gateway="rdg.corp", clipboard=False)
fake.script = [2, 2, 1, 1]
pane.connect_now()
check("an answering port starts the control", pump(lambda: any(c[0] == "Connect()" for c in fake.calls)))
adv, gw = fake.subs["AdvancedSettings9"].props, fake.subs["TransportSettings3"].props
check("it was given the server, the user (domain apart) and the size before connecting", fake.props["Server"] == "127.0.0.1" and fake.props["UserName"] == "bob" and fake.props["Domain"] == "CORP"
      and fake.props["DesktopWidth"] == 1280 and fake.props["DesktopHeight"] == 800 and fake.props["ColorDepth"] == 32, fake.props)
check("and the port, sign-in and sharing options", adv["RDPPort"] == open_port and adv["EnableCredSspSupport"] is True and adv["RedirectDrives"] is True and adv["RedirectClipboard"] is False
      and adv["RedirectPrinters"] is False and adv["ConnectToAdministerServer"] is True and adv["DisplayConnectionBar"] is False and adv["SmartSizing"] is True, adv)
check("the gateway is set when there is one", gw["GatewayHostname"] == "rdg.corp" and gw["GatewayUsageMethod"] == 1)
g = fake.geometry(); st_ = pane.stage
check("a fixed-size desktop is scaled to the tab with its own shape, centred, not stretched", abs(g.width() / g.height() - 1280 / 800) < 0.03 and g.width() <= st_.width() and g.height() <= st_.height()
      and (g.width() == st_.width() or g.height() == st_.height()) and abs(g.center().x() - st_.width() // 2) <= 2 and abs(g.center().y() - st_.height() // 2) <= 2, (g, st_.size()))
check("the tab says whether it fills the window, from the session's setting (off here)", pane.fill.text() == "Fill the window" and not pane.fill.isChecked())
check("no password is ever handed to the control (Windows asks for it)", not any("assword" in c[0] for c in fake.calls) and not any("assword" in k for k in fake.props))
check("it reports connected once the control does, and the tab's dot comes on", pump(lambda: "Connected to 127.0.0.1" in pane.status.text()) and pane.connected())
fake.script = [0]
check("when the control reports the end, the pane says disconnected and can reconnect", pump(lambda: not pane.connected()) and pane.status.text() == "Disconnected from 127.0.0.1." and pane.reconnect_btn.isEnabled())
check("state changes were announced", True in seen and seen[-1] is False)

fake.calls.clear(); fake.script = [2, 0]
pane.connect_now()
check("a connection that never gets made is explained with the usual causes", pump(lambda: not pane.connected() and "was not made" in pane.status.text()) and "network level authentication" in pane.status.text(), pane.status.text())

fake.script = []; pane.connect_now(); pump(lambda: fake.state == 2); fake.state = 1; pump(lambda: "Connected to" in pane.status.text())
fake.calls.clear(); pane.disconnect_now()
check("Disconnect asks the control to end it", ("Disconnect()", None) in fake.calls and "Disconnecting" in pane.status.text())
check("and the pane follows when it has", pump(lambda: not pane.connected()))

print("== filling the window")
fake2 = Fake(); p2 = RP.RdpPane(spec(open_port, fullscreen=True), control=fake2); p2.resize(1000, 700); p2.show(); QCoreApplication.processEvents()
fake2.script = [1]; p2.connect_now(); pump(lambda: "Connected to" in p2.status.text())
a2 = fake2.subs["AdvancedSettings9"].props
check("the desktop is the size of the tab, and the picture scales to fit", a2["SmartSizing"] is True and fake2.props["DesktopWidth"] >= 900 and fake2.props["DesktopHeight"] >= 500, (fake2.props, a2))
fake2.calls.clear(); p2.resize(1200, 800); pump(lambda: any(c[0].startswith("UpdateSessionDisplaySettings") for c in fake2.calls), 80)
upd = [c for c in fake2.calls if c[0].startswith("UpdateSessionDisplaySettings")]
check("resizing the window asks the server for a desktop to match", upd and upd[-1][1][0] >= 1000 and upd[-1][1][1] >= 600, fake2.calls)
check("a fixed-size desktop is asked for at 100% scale", fake.subs["AdvancedSettings9"].props["DesktopScaleFactor"] == 100)
check("a desktop that fills the tab is asked for at the display's scale (100% on this test screen, a multiple of 25 otherwise)", a2["DesktopScaleFactor"] >= 100 and a2["DesktopScaleFactor"] % 25 == 0, a2)
p2.stage.devicePixelRatioF = lambda: 1.5
fake2.calls.clear(); p2._resize_session()
upd = [c for c in fake2.calls if c[0].startswith("UpdateSessionDisplaySettings")]
check("on a 150% display, the resize carries 150 as the scale", upd and upd[-1][1][5] == 150 and upd[-1][1][0] >= 1500, upd)
p2._apply(); check("and so does the first connection (width in real pixels)", fake2.subs["AdvancedSettings9"].props["DesktopScaleFactor"] == 150 and fake2.props["DesktopWidth"] >= 1300, (fake2.props["DesktopWidth"], fake2.subs["AdvancedSettings9"].props["DesktopScaleFactor"]))
g2 = fake2.geometry()
check("filling the window gives the control the whole tab", p2.fill.isChecked() and g2.width() == p2.stage.width() and g2.height() == p2.stage.height(), (g2, p2.stage.size()))
fake2.calls.clear(); p2.fill.setChecked(False)
sent = [c for c in fake2.calls if c[0].startswith("UpdateSessionDisplaySettings")]
check("turning it off on the tab goes back to the session's size at once, scaled to fit", sent and sent[-1][1][:2] == [1280, 800] and abs(fake2.geometry().width() / fake2.geometry().height() - 1.6) < 0.03, (sent, fake2.geometry()))
fake2.calls.clear(); p2.fill.setChecked(True)
sent = [c for c in fake2.calls if c[0].startswith("UpdateSessionDisplaySettings")]
check("and turning it on asks for the tab's size and fills it", sent and sent[-1][1][0] >= 900 and fake2.geometry().width() == p2.stage.width(), (sent, fake2.geometry()))
fake2.calls.clear(); p2.shutdown()
check("closing the pane disconnects first", ("Disconnect()", None) in fake2.calls and not p2.connected())
p3 = RP.RdpPane(spec(open_port), control=Fake()); p3.resize(900, 600); p3.show(); p3.connect_now(); p3.disconnect_now()
check("Disconnect while still checking the address just stops", not p3.connected() and p3.status.text() == "Not connected.")
p3.shutdown()

print("== a real control that is missing")
class Gone(Exception): pass
try:
    RP.make_control(); check("the offscreen display cannot host it, and says why", False)
except RP.RdpUnavailable as e:
    check("the offscreen display cannot host it, and says why", "Windows display" in str(e), e)

print("== inside the Sessions section")
import ui.sessions as S
warned = []
QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2]))
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
w = A.Main(); w.resize(1240, 760); w.show(); st = w.sessions
made = []
def factory():
    f = Fake(); made.append(f); f.script = [1]; return f
real_make = RP.make_control; RP.make_control = factory
real_begin = RP.RdpPane._begin_probe
RP.RdpPane._begin_probe = lambda self: self._start_control()               # the device tabs use port 3389, which nothing here listens on
launched = []; real_launch = sessions.launch_rdp
sessions.launch_rdp = lambda s: (launched.append(s), sessions.rdp_path(s))[1]
win = db.save_device({"name": "dc-1", "vendor": "windows", "host": "127.0.0.1", "port": 0, "platform": "agent", "username": "", "site": "default", "verify_ssl": 0,
                      "ha_expected": 0, "enabled": 1, "location": "", "details": "", "folder_id": None})
dev = db.get_device(win)
spec_saved = st._spec({"name": "Jump", "kind": "rdp", "host": "127.0.0.1", "port": open_port, "username": "", "options": {}})
st.open_spec(spec_saved)
pane = st.tabs.currentWidget()
check("a Remote Desktop session opens as a tab, not in Windows' own client", isinstance(pane, RP.RdpPane) and st.tabs.count() == 1 and not launched and st.stack.currentWidget() is st.tabs)
check("it connects on its own and the tab shows it is live", pump(lambda: pane.connected() and "Connected to" in pane.status.text()) and st.tabs.tabText(0).startswith("● "), st.tabs.tabText(0))
check("it is counted as a live session and audited", st.live_count() == 1 if hasattr(st, "live_count") else True)
check("opening a device's Remote Desktop gives it its own tab", st.open_rdp_device(dev) is not pane and st.tabs.count() == 2)
check("and asking again goes to that tab instead of making another", st.open_rdp_device(dev) is st.tabs.currentWidget() and st.tabs.count() == 2)
check("the device's address is used", made[-1].props["Server"] == "127.0.0.1" and st.tabs.currentWidget().spec["options"]["fullscreen"] is True)
st.close_tab(1)
check("closing a tab ends the session and removes it", st.tabs.count() == 1 and ("Disconnect()", None) in made[1].calls)
db.set_setting("rdp_embedded", False)
st.open_spec(spec_saved)
check("with the setting off, Windows' own client is used and no tab is added", len(launched) == 1 and st.tabs.count() == 1)
db.set_setting("rdp_embedded", True)
RP.make_control = real_make; RP.RdpPane._begin_probe = real_begin
st.open_spec(spec_saved)
check("when the control cannot be hosted, Windows' own client is used and the page says why", len(launched) == 2 and st.tabs.count() == 1 and "Started Remote Desktop" in st.note.text())

print("== from the rest of Toner")
RP.make_control = factory; RP.RdpPane._begin_probe = lambda self: self._start_control()
w.open_rdp_console(dev)
check("the main window's Remote Desktop action opens the Sessions section on the device's tab", w.tabs.currentWidget() is st and st.tabs.currentWidget().spec["name"] == "dc-1" and st.tabs.count() == 2)
w.inventory.open_rdp_tab.emit(dev); w.inventory.refresh()
check("the Inventory and the device window ask for the same thing", st.tabs.count() == 2 and hasattr(w.inventory, "open_rdp_tab"))
w.open_device_view(dev)
view = w.views.get("dc-1")
before = st.tabs.count()
for i in range(st.tabs.count() - 1, -1, -1): st.close_tab(i)
view.act("rdp")
check("the device window's Remote Desktop button opens the tab", view is not None and st.tabs.count() == 1 and st.tabs.currentWidget().spec["name"] == "dc-1" and w.tabs.currentWidget() is st)
check("and the details page closes itself, so it is not left in front of the session", not view.isVisible() and "dc-1" not in w.views)
check("the session starts at once (it is connecting, not just opened)", pump(lambda: st.tabs.currentWidget().connected(), 50))
w.open_device_view(dev); view2 = w.views.get("dc-1"); view2.show()
check("asking for the details again gives a fresh page", view2 is not view and view2.isVisible())
pings = []
real_start_ping, real_running = w.tools.liveping.start, w.tools.liveping.running
w.tools.liveping.start = lambda: pings.append(w.tools.liveping.host.text())
w.tools.liveping.running = lambda: False
view2.act("ping")
check("Ping closes the details page too, opens the Tools section on the Live Ping tool, and starts pinging that computer", not view2.isVisible() and "dc-1" not in w.views
      and w.tabs.currentWidget() is w.tools and w.tools.tabs.currentWidget() is w.tools.liveping and pings == [dev["host"]], (pings, dev["host"]))
w.open_device_view(dev); view3 = w.views.get("dc-1"); view3.show()
w.tools.liveping.running = lambda: True; halted = []; real_halt = w.tools.liveping.halt; w.tools.liveping.halt = lambda: (halted.append(1), setattr(w.tools.liveping, "running", lambda: False))
pings.clear(); view3.act("ping")
check("a ping already running is stopped first, so the new one starts", halted == [1] and len(pings) == 1)
w.tools.liveping.start, w.tools.liveping.running, w.tools.liveping.halt = real_start_ping, real_running, real_halt
w.open_device_view(dev); view4 = w.views.get("dc-1"); view4.show()
view4.buttons["snmp"].setEnabled(True); view4.act("snmp")
check("SNMP closes it as well (it opens the SNMP tool)", not view4.isVisible() and w.tools.tabs.currentWidget() is w.tools.snmp)
w.open_device_view(dev); view5 = w.views.get("dc-1"); view5.show()
edited = []; real_edit = w.inventory.edit_device; w.inventory.edit_device = lambda d: edited.append(d["name"])
view5.act("edit")
w.inventory.edit_device = real_edit
check("Edit keeps the page (it is not leaving the window)", view5.isVisible() and edited == ["dc-1"])
view5.close()
w.open_palette()
labels = [e[0] for e in w.palette.entries]
check("the palette offers Remote Desktop to Windows computers", "Remote Desktop to dc-1" in labels, [l for l in labels if "dc-1" in l])
w.palette.close()
w.tabs.setCurrentWidget(w.dashboard)
[fn for l, _h, fn in w.palette.entries if l == "Remote Desktop to dc-1"][0]()
check("and choosing it opens the tab", w.tabs.currentWidget() is st and st.tabs.count() == 1)
st.open_rdp_device(dev); st.close_tab(0); st.open_rdp_device(dev)
db.set_setting("rdp_embedded", False)
w.open_rdp_console(dev)
check("with the setting off the main window uses Windows' own client", len(launched) == 3 and st.tabs.count() == 1)
db.set_setting("rdp_embedded", True)
for i in range(st.tabs.count() - 1, -1, -1): st.close_tab(i)
sessions.launch_rdp = real_launch; RP.make_control = real_make; RP.RdpPane._begin_probe = real_begin

print("== Settings > Terminal")
from ui.settings_pages.appearance import TerminalPage
pg = TerminalPage(); pg.load()
check("it offers inside Toner or Windows' own window, inside by default", pg.rdp.count() == 2 and pg.rdp.currentIndex() == 0)
pg.rdp.setCurrentIndex(1); pg.save()
check("the choice is saved", db.get_setting("rdp_embedded") is False and not sessions.use_embedded())
pg.load(); check("and shown again", pg.rdp.currentIndex() == 1)
db.set_setting("rdp_embedded", True)

print("== the real control, in its own process")
code = textwrap.dedent('''
    import os, sys
    os.environ["QT_QPA_PLATFORM"] = "windows"
    from PySide6.QtWidgets import QApplication
    app = QApplication([])
    sys.path.insert(0, %r)
    import ui.rdppane as RP
    try:
        ax = RP.make_control()
    except RP.RdpUnavailable as e:
        print("UNAVAILABLE", e); sys.exit(77)
    pane = RP.RdpPane({"name": "x", "kind": "rdp", "host": "127.0.0.1", "port": 1, "username": "u", "dev": None, "options": {}}, control=ax)
    pane.resize(800, 600); pane.show(); app.processEvents()
    pane._apply()
    print("server", repr(ax.dynamicCall("Server")), "user", repr(ax.dynamicCall("UserName")), "width", ax.dynamicCall("DesktopWidth"),
          "port", ax.querySubObject("AdvancedSettings9").property("RDPPort"), "state", pane._state())
    pane.shutdown()
''' % os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=90, env={**os.environ, "QT_QPA_PLATFORM": "windows"})
if res.returncode == 77:
    check("(no Windows display or control here: the real-control check is skipped)", True)
else:
    check("Windows' real control accepts the settings the pane gives it", res.returncode == 0 and "server '127.0.0.1' user 'u' width 1280 port 1 state 0" in res.stdout, (res.stdout, res.stderr[-300:]))

print(f"\n{ok} passed, {bad} failed")
listener.close()
sys.exit(1 if bad else 0)

# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The search box and funnel every list uses, as on Inventory.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\fi%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db, sessions
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtCore import QCoreApplication, Qt
from PySide6.QtWidgets import QApplication, QCheckBox, QWidgetAction
app = QApplication([])
import app as A
A.apply_look(app)
from ui import finder as F
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

chi = db.ensure_folder_path("Chicago"); core_f = db.ensure_folder_path("Chicago/Core"); acme = db.ensure_folder_path("Acme")
def add(name, vendor, host, folder, location="", tags=""):
    db.save_device(dict(name=name, vendor=vendor, host=host, port=0, platform="", username="u", site="default", verify_ssl=0, ha_expected=0,
                        enabled=1, location=location, details="", folder_id=folder, tags=tags))
add("core-sw1", "cisco", "10.0.0.1", core_f, "Chicago", "core")
add("fw1", "fortinet", "10.0.0.2", chi, "Chicago")
add("acme-sw", "cisco", "10.9.0.1", acme, "Dallas", "branch")
STORE[("netcheck", "core-sw1")] = STORE[("netcheck", "acme-sw")] = "pw"

def ticks(fb):
    """{section title: {text: ticked}} from the funnel's menu, as a person sees it."""
    fb.build()
    out = {}
    for act in fb.menu_.actions():
        sub = act.menu()
        if sub:
            out[act.text()] = {a.defaultWidget().text(): a.defaultWidget().isChecked() for a in sub.actions() if isinstance(a, QWidgetAction)}
    return out
def tick(fb, title, text, on=True):
    fb.build()
    sub = next(a.menu() for a in fb.menu_.actions() if a.menu() and a.text() == title)
    next(a.defaultWidget() for a in sub.actions() if isinstance(a, QWidgetAction) and a.defaultWidget().text() == text).setChecked(on)

print("== the parts")
box = F.SearchBox("Search devices")
check("the search box says what it searches and that Ctrl+F reaches it", box.placeholderText() == "Search devices  (Ctrl+F)" and box.isClearButtonEnabled())
box.setText("core 10.0")
check("several words must all match", box.matches("core-sw1", "10.0.0.1") and not box.matches("core-sw1", "192.168.1.1"))
fb = F.FilterButton(lambda: F.device_sections(db.list_devices()))
check("the funnel is an icon with the Inventory tooltip", fb.toolTip() == "Filter by vendor, location, folder or tag" and fb.text() == "")
menu = ticks(fb)
check("its menus: Vendor, Location, Folder (with the folders above), Tag", list(menu) == ["Vendor", "Location", "Folder", "Tag"]
      and set(menu["Folder"]) == {"Acme", "Chicago", "Chicago/Core"} and set(menu["Vendor"]) == {"Cisco", "Fortinet"}, menu)
tick(fb, "Vendor", "Cisco"); tick(fb, "Location", "Chicago")
check("ticks show as a count and in the tooltip", fb.text() == " 2" and fb.toolTip() == "Filter: Cisco, Chicago", (fb.text(), fb.toolTip()))
box.clear()
check("Vendor AND Location; several ticks in one menu are either", [d["name"] for d in F.shown_devices(db.list_devices(), box, fb)] == ["core-sw1"])
fb.clear(); tick(fb, "Folder", "Chicago")
check("a folder includes the folders under it", sorted(d["name"] for d in F.shown_devices(db.list_devices(), box, fb)) == ["core-sw1", "fw1"])
fb.clear()
check("Clear filter empties it", not fb.active() and fb.text() == "")
ex = F.FilterButton(lambda: [F.Section("status", "Status", [("All results", 0), ("Problems only", 1), ("Failing", 3)], exclusive=True)])
check("a one-choice menu starts on its first entry", ticks(ex)["Status"] == {"All results": True, "Problems only": False, "Failing": False})
tick(ex, "Status", "Failing")
check("choosing another moves the tick", ticks(ex)["Status"] == {"All results": False, "Problems only": False, "Failing": True} and ex.selected("status") == {3})
tick(ex, "Status", "All results")
check("and the first entry means no filter", not ex.active())

print("== Configs")
w = A.Main()
c = w.configs
check("the All devices drop-down is gone; Search devices and the funnel are there", not hasattr(c, "group") and c.find.placeholderText() == "Search devices  (Ctrl+F)")
c.find.setText("acme")
check("the list follows the search", c.names == ["acme-sw"], c.names)
c.find.clear(); tick(c.funnel, "Vendor", "Cisco")
check("and the funnel", sorted(c.names) == ["acme-sw", "core-sw1"], c.names)
started = []
c._start = lambda labels, scheduled, only=None, among=None: started.append(among)
c.start()
check("Back up now backs up the devices shown", started == [{"acme-sw", "core-sw1"}], started)
c.funnel.clear()
c.__dict__.pop("_start")

print("== Results")
from drivers.base import Result
r = w.results
r.results = [Result("core-sw1", "cpu", "OK", "3%"), Result("core-sw1", "bgp", "FAIL", "0/1", "down: 10.1.1.1"), Result("acme-sw", "cpu", "OK", "2%"),
             Result("fw1", "resources", "WARN", "85%")]
r.last_ran, r.stored = [], False
r.repopulate()
tops = lambda: sorted(r.table.topLevelItem(i).text(0) for i in range(r.table.topLevelItemCount()))
check("Status is a menu in the funnel, with the five choices", list(ticks(r.funnel)["Status"]) == ["All results", "Problems only", "Warnings", "Failing", "Healthy devices"])
r.show_filter("fail")
check("an Overview card still opens it filtered", tops() == ["core-sw1"] and r.funnel.selected("status") == {3}, tops())
r.show_filter("all"); r.find.setText("bgp")
check("the search matches checks and messages too", tops() == ["core-sw1"], tops())
r.find.setText("dallas")
check("and the device's own details (its location)", tops() == ["acme-sw"], tops())
ran = []
r._start = lambda picked, scheduled, label=None, none_shown=False: ran.append((sorted(picked), label))
r.start()
check("Run checks runs the devices shown", ran == [(["Device: acme-sw"], "the devices shown")], ran)
r.find.clear(); ran.clear(); r.start()
check("with no search or filter it runs everything, as before", ran == [([], None)], ran)
r.__dict__.pop("_start")
r.show_filter("problems"); tick(r.funnel, "Vendor", "Fortinet")
check("the device menus and Status work together", tops() == ["fw1"], tops())
r.show_all()
check("Show all results clears the search and the funnel", not r.funnel.active() and not r.find.text())

print("== History")
h = w.history
h.find.setText("acme")
check("History's search narrows the devices it charts", h._group_names() == {"acme-sw"})
h.find.clear(); tick(h.funnel, "Location", "Chicago")
check("and its funnel", h._group_names() == {"core-sw1", "fw1"})
h.funnel.clear()
check("with neither, every device", h._group_names() is None)

print("== Tools and Automation")
from ui.tools2 import CommandRunnerTab, TopologyTab, ListenersTab
from ui.automation import PlaybooksPage
run = CommandRunnerTab()
check("Command Runner: search and funnel where the drop-down was", not hasattr(run, "group") and run.find.placeholderText() == "Search devices  (Ctrl+F)")
run.find.setText("core"); check("its device list follows them", [d["name"] for d in run.candidates()] == ["core-sw1"], run.candidates())
pb = PlaybooksPage()
pb.find.setText("acme"); check("Playbooks the same", not hasattr(pb, "group") and [d["name"] for d in pb.candidates()] == ["acme-sw"])
topo = TopologyTab()
check("Topology: search and funnel, and Discover asks the devices shown", not hasattr(topo, "group") and topo.go.toolTip() == "Asks the devices shown that have SNMP settings")
lt = ListenersTab()
msgs = [{"time": "1", "type": "syslog", "source": "10.0.0.1", "device": "core-sw1", "severity": "error", "severity_no": 3, "text": "link down Gi0/1"},
        {"time": "2", "type": "syslog", "source": "10.0.0.2", "device": "fw1", "severity": "info", "severity_no": 6, "text": "admin login"},
        {"time": "3", "type": "trap", "source": "10.9.9.9", "device": "", "severity": "", "severity_no": 6, "text": "linkDown", "trap": "IF-MIB"}]
lt.rows = msgs
check("Listeners: Search messages, and a funnel with Kind, Severity and Device", lt.filter.placeholderText() == "Search messages  (Ctrl+F)"
      and list(ticks(lt.funnel)) == ["Kind", "Severity", "Device"] and set(ticks(lt.funnel)["Device"]) == {"core-sw1", "fw1", "(not in the inventory)"})
tick(lt.funnel, "Device", "core-sw1")
check("by device", [m["time"] for m in msgs if lt.wanted(m)] == ["1"])
lt.funnel.clear(); tick(lt.funnel, "Kind", "Traps")
check("by kind", [m["time"] for m in msgs if lt.wanted(m)] == ["3"])
lt.funnel.clear(); tick(lt.funnel, "Severity", "error and worse")
check("by severity, as before", [m["time"] for m in msgs if lt.wanted(m)] == ["1", "3"], [m["time"] for m in msgs if lt.wanted(m)])
lt.funnel.clear(); lt.filter.setText("login")
check("and the search", [m["time"] for m in msgs if lt.wanted(m)] == ["2"])

print("== Sessions")
st = w.sessions
s1 = sessions.save({"kind": "ssh", "name": "core ssh", "host": "10.0.0.1", "username": "u"})
s2 = sessions.save({"kind": "rdp", "name": "jump box", "host": "10.5.5.5", "username": "u"})
s3 = sessions.save({"kind": "ssh", "name": "fw cli", "host": "10.0.0.99", "username": "u", "device": "fw1"})
st.refresh()
def names_shown():
    out, stack = [], [st.tree.topLevelItem(i) for i in range(st.tree.topLevelItemCount())]
    while stack:
        it = stack.pop()
        if st.kind_of(it)[0] == "session":
            out.append(it.text(0))
        stack += [it.child(i) for i in range(it.childCount())]
    return sorted(out)
check("Sessions: the funnel is next to the search box, with Type and Device", st.search.placeholderText() == "Search sessions  (Ctrl+F)"
      and list(ticks(st.funnel)) == ["Type", "Device"] and set(ticks(st.funnel)["Device"]) == {"core-sw1", "fw1"}, ticks(st.funnel))
tick(st.funnel, "Type", "Remote Desktop (RDP)")
check("by type", names_shown() == ["jump box"], names_shown())
st.funnel.clear(); tick(st.funnel, "Device", "core-sw1")
check("by device: a session at the device's address belongs to it", names_shown() == ["core ssh"], names_shown())
st.funnel.clear(); tick(st.funnel, "Device", "fw1")
check("...and so does one linked to it", names_shown() == ["fw cli"], names_shown())
st.funnel.clear()

print("== Settings, Wi-Fi and the choosers")
S = w.settings
check("Settings: Search settings (Ctrl+F)", S.search.placeholderText() == "Search settings  (Ctrl+F)")
audit_i = next(i for i, p in enumerate(S.pages) if type(p).__name__ == "AuditPage")
check("the audit log: Search the audit log (Ctrl+F), on the right", S.pages[audit_i].search.placeholderText() == "Search the audit log  (Ctrl+F)")
from ui.tools3 import WifiTab
check("Wi-Fi: Search networks (Ctrl+F)", WifiTab().filter.placeholderText() == "Search networks  (Ctrl+F)")
from ui.interfacepicker import InterfacePicker
from ui.servicepicker import ServicePicker
check("the interface and service choosers", InterfacePicker([("Gi0/1", "up")], []).search.placeholderText() == "Search interfaces  (Ctrl+F)"
      and ServicePicker([{"name": "Spooler", "display": "Print Spooler", "state": "Running", "start": "Auto"}], [], "Services", "").search.placeholderText()
      == "Search services  (Ctrl+F)")

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

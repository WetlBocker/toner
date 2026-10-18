# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Choosing which interfaces a device checks, and a down interface being a FAIL: the shared row, the stored choice, the dialogs.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\ifchoice%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roamingif%d" % int(time.time()))
from core import checks, db, ifaces
from drivers.base import Driver
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

print("== the stored choice")
check("it is kept, cleaned, next to the other own settings", db.normalize_checkopts({"interfaces": ["port1", " port1 ", "", "wan1"], "checks": ["cpu"]}) == {"checks": ["cpu"], "interfaces": ["port1", "wan1"]})
check("an empty or wrong list means every interface", db.normalize_checkopts({"interfaces": []}) == {} and db.normalize_checkopts({"interfaces": "port1"}) == {} and db.normalize_checkopts('{"interfaces": [""]}') == {})
check("it is stored as JSON on the device and comes back", db.normalize_checkopts(json.dumps(db.normalize_checkopts({"interfaces": ["a", "b"]}))) == {"interfaces": ["a", "b"]})

print("== the row every driver shares")
def row(states, chosen=None):
    d = Driver({"name": "t", "vendor": "cisco", "host": "x", "checkopts": json.dumps({"interfaces": chosen}) if chosen else ""}, db.get_thresholds(), {})
    return d.interfaces_row(states)
S = [("a", "up"), ("b", "down"), ("c", "off"), ("d", "up"), ("e", "errdisabled")]
r = row(S)
check("any interface down is a FAIL", r.status == "FAIL" and r.value == "2/4 up" and r.message == "down: b; err-disabled: e", r)
check("all up is OK, with nothing to say", row([("a", "up"), ("b", "up")]).status == "OK" and row([("a", "up")]).message == "")
check("an interface in a bad state other than down (err-disabled) is a WARN", row([("a", "up"), ("e", "errdisabled")]).status == "WARN")
check("the ones an administrator switched off are not counted", row([("c", "off"), ("a", "up")]).value == "1/1 up")
check("nothing but switched-off ports: no row", row([("c", "off")]) == [] and row([]) == [])
r = row(S, ["a", "d"])
check("with a list only those count", r.status == "OK" and r.value == "2/2 up" and r.message == "", r)
check("names match in any case", row(S, ["A", "B"]).status == "FAIL" and row(S, ["A", "B"]).message == "down: b")
check("a chosen port that is switched off should be up, so it is down", row(S, ["c"]).status == "FAIL" and row(S, ["c"]).message == "down: c")
r = row(S, ["a", "zz"])
check("a chosen one the device does not have is a WARN", r.status == "WARN" and r.message == "not found on the device: zz", r)
check("... and a down one outranks it", row(S, ["b", "zz"]).status == "FAIL" and "zz" in row(S, ["b", "zz"]).message)
check("only missing ones: still a row, so it is noticed", row([("a", "up")], ["zz"]).status == "WARN" and row([("a", "up")], ["zz"]).value == "0/0 up")
many = [(f"p{i}", "down") for i in range(9)]
check("a long list is cut short, with the count", row(many).message == "down: p0, p1, p2, p3, p4, p5 (+3 more)")
d = Driver({"name": "t", "vendor": "cisco", "host": "x", "checkopts": json.dumps({"interfaces": ["a"]})}, db.get_thresholds(), {})
check("error counters are read only for the chosen ones", d.error_counter_rows("interface errors", {"a": 3, "b": 9}).value == "1" and "b" not in d.error_counter_rows("interface errors", {"a": 3, "b": 9}).message
      and d.error_counter_rows("interface errors", {"b": 9}) is None)
d2 = Driver({"name": "t", "vendor": "cisco", "host": "x"}, db.get_thresholds(), {})
check("with no list they are all read, as before", d2.error_counter_rows("interface errors", {"a": 3, "b": 9}).value == "2")
check("a driver without interfaces says so", not ifaces.available("windows") and ifaces.available("fortinet") and ifaces.available("snmp") and ifaces.available("cisco"))
try:
    Driver({"name": "t", "vendor": "x", "host": "x"}, {}, {}).list_interfaces(); check("no list from a driver without one", False)
except NotImplementedError:
    check("no list from a driver without one", True)

print("== asking a device for its list")
import drivers.fortinet as FG
class Resp:
    status_code = 200
    def raise_for_status(self): pass
    def json(self): return {"results": {"port1": {"type": "physical", "link": True}, "port2": {"type": "physical", "link": False, "status": "up", "role": "wan"},
                                         "port3": {"type": "physical", "link": False, "status": "down"}, "ssl.root": {"type": "tunnel"}}}
FG.requests.get = lambda *a, **k: Resp()
got = ifaces.listing({"name": "fw", "vendor": "fortinet", "host": "10.0.0.1", "password": "TOK", "verify_ssl": 0, "port": 0})
check("the list has each name with its state in words", got == [("port1", "Up"), ("port2", "Down"), ("port3", "Switched off")], got)
try:
    ifaces.listing({"name": "x", "vendor": "windows", "host": "h"}); check("a Windows computer has none to list", False)
except ValueError as e:
    check("a Windows computer has none to list", "no list of interfaces" in str(e))

print("== the picker")
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtCore import Qt
app = QApplication([])
import app as A
A.apply_look(app)
from ui.interfacepicker import InterfacePicker
from ui.devicechecks import DeviceChecks
warned = []
QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2]))
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
LIST = [("port1", "Up"), ("port2", "Down"), ("port3", "Switched off"), ("lan", "Up")]
pk = InterfacePicker(LIST, ["port2", "old9"])
check("what was chosen is ticked, and one the device no longer has stays in the list", pk.selected() == ["old9", "port2"] and pk.rows[0] == ("old9", "Not on the device now"), pk.selected())
pk.search.setText("port"); app.processEvents()
check("the filter hides the rest", [pk.table.isRowHidden(i) for i in range(pk.table.rowCount())] == [True, False, False, False, True] and "3 of 5 interfaces shown" in pk.count.text(), pk.count.text())
pk.shown_btn.click()
check("'Tick all shown' ticks only those", sorted(pk.selected()) == ["old9", "port1", "port2", "port3"], pk.selected())
pk.none_btn.click(); pk.search.setText(""); pk.up_btn.click()
check("'Tick the ones that are up' picks by state, and 'Clear all' clears", sorted(pk.selected()) == ["lan", "port1"] and pk.count.text().startswith("2 chosen"), (pk.selected(), pk.count.text()))

print("== Edit device > Checks")
w = DeviceChecks(); w.set_vendor("fortinet"); w.load(None)
w.show(); app.processEvents()
check("a firewall shows the choice; nothing is chosen, so everything is checked", w.if_box.isVisibleTo(w) and not w.pick_ifs.isChecked() and w.values() == {} and "All interfaces" in w.if_summary.text() and not w.if_choose.isEnabled())
w.set_vendor("windows")
check("a kind of device with no interfaces check does not show it", not w.if_box.isVisibleTo(w))
w.set_vendor("snmp")
check("a plain SNMP device does", w.if_box.isVisibleTo(w))
w.set_vendor("fortinet")
asked = []
w.fetch_interfaces = lambda: (asked.append(1), LIST)[1]
InterfacePicker.exec = lambda self: (self.none_btn.click(), self.shown_btn.click(), 0)[2]                  # cancelled
w.pick_ifs.setChecked(True)
check("ticking the box asks the device, and cancelling puts it back to 'all'", asked == [1] and not w.pick_ifs.isChecked() and w.values() == {})
def accept(names):
    def go(self):
        self.none_btn.click()
        for i, (n, _s) in enumerate(self.rows):
            if n in names: self.table.item(i, 0).setCheckState(Qt.CheckState.Checked)
        return 1
    return go
InterfacePicker.exec = accept(["port1", "lan"])
w.pick_ifs.setChecked(True); app.processEvents()
check("choosing some saves them, and the summary names them", w.pick_ifs.isChecked() and w.values() == {"interfaces": ["port1", "lan"]} and "2 chosen: port1, lan" in w.if_summary.text() and w.if_choose.isEnabled(), (w.values(), w.if_summary.text()))
InterfacePicker.exec = accept(["port1", "lan", "port2"])
w.if_choose.click()
check("the Choose button reopens it with the choice, and keeps the new one", w.values()["interfaces"] == ["port1", "port2", "lan"] and asked == [1, 1, 1], (w.values(), asked))
w2 = DeviceChecks(); w2.set_vendor("fortinet"); w2.load(w.values())
check("a saved choice loads back ticked", w2.pick_ifs.isChecked() and w2.values() == w.values() and "3 chosen" in w2.if_summary.text())
w2.pick_ifs.setChecked(False)
check("unticking means every interface again (the list is not kept)", w2.values() == {})
w.reset()
check("'use the global settings for everything' clears it too", w.values() == {} and not w.pick_ifs.isChecked())
first = checks.CATALOG["fortinet"][0][0]
w.load({"checks": [first], "interfaces": ["port1"], "thresholds": {"memory": {"warn": 50, "fail": 60}}})
check("it travels with the other own settings", w.values() == {"checks": [first], "interfaces": ["port1"], "thresholds": {"memory": {"warn": 50.0, "fail": 60.0}}}, w.values())
w.set_vendor("windows")
check("a list kept from before is dropped if the device became a kind with no interfaces", "interfaces" not in w.values())
w.fetch_interfaces = lambda: (_ for _ in ()).throw(RuntimeError("the switch did not answer"))
w.set_vendor("fortinet"); warned.clear(); w.if_choose.click()
check("when the device cannot be reached, the reason is shown and nothing changes", warned and "the switch did not answer" in warned[-1] and w.values()["interfaces"] == ["port1"], warned)

print("== the device dialog")
import ui.inventory as I
saved = db.get_device(db.save_device({"name": "fw-1", "vendor": "fortinet", "host": "10.9.9.9", "port": 0, "platform": "", "username": "", "site": "default",
                                       "verify_ssl": 0, "ha_expected": 0, "enabled": 1, "location": "", "details": "", "folder_id": None,
                                       "checkopts": {"interfaces": ["port2"]}}))
dlg = I.DeviceDialog(saved)
check("an existing choice shows in the dialog", dlg.checks_tab.pick_ifs.isChecked() and dlg.values()["checkopts"] == {"interfaces": ["port2"]})
seen = []
real_listing = ifaces.listing
ifaces.listing = lambda d, opts=None: (seen.append(d), LIST)[1]
InterfacePicker.exec = accept(["port1", "port2"])
dlg.secret.setText("typed-token"); dlg.host.setText("10.9.9.10")
dlg.checks_tab.if_choose.click()
check("the list is asked for with what is typed in the dialog, saved or not", seen and seen[0]["host"] == "10.9.9.10" and seen[0]["password"] == "typed-token" and seen[0]["vendor"] == "fortinet" and seen[0]["name"] == "fw-1", seen)
check("and the choice is part of what the dialog saves", dlg.values()["checkopts"] == {"interfaces": ["port1", "port2"]})
dlg.host.setText(""); warned.clear(); dlg.checks_tab.if_choose.click()
check("with no address it says so", warned and "address" in warned[-1], warned)
ifaces.listing = real_listing
dlg.reject()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

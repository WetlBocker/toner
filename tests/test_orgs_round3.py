# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Organizations, round 3: folders imported as new organizations, the Remove button greyed out, agent sign-up per organization,
# and Settings asking before it is left with unsaved changes (Cancel drops them without asking).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, io, json, zipfile
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\orgr3%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import agents, audit, db, orgs, vault
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication.instance() or QApplication([])
import app as A
A.apply_look(app)
QMessageBox.warning = staticmethod(lambda *a, **k: None)
QMessageBox.information = staticmethod(lambda *a, **k: None)

print("== folders imported as organizations")
from ui import orgassign
rows = [("sw1", ["Acme", "Core"], "Device"), ("sw2", ["acme"], "Device"), ("fw", ["Beta"], "Device"), ("top", [], "Device"),
        ("g1", ["Global"], "Device"), ("s1", ["Shared"], "Device")]
check("with no organizations yet, the step is still asked when the import has folders", db.everything() and not db.several())
od = orgassign.OrgAssignDialog(rows)
check("the drop-down offers New Organization", od.pick.findText("New Organization") >= 0 and od.pick.itemData(od.pick.findText("New Organization")) == orgassign.NEW)
check("the button is called Import All Folders as New Organizations", od.all_new.text() == "Import All Folders as New Organizations" and od.all_new.isEnabled())
od.tree.topLevelItem(2).setSelected(True)                  # Beta
od.pick.setCurrentIndex(od.pick.findText("New Organization")); od.apply()
check("New Organization for a folder shows it as new", od.tree.topLevelItem(2).text(1) == "Beta (new)" and od.picks()[2] == "beta", od.picks())
od.tree.clearSelection(); od.tree.topLevelItem(3).setSelected(True); od.apply()
check("rows with no folder stay where they were", od.picks()[3] == 0)
od.apply_all_new()
p = od.picks()
check("every folder goes to an organization named after it; folders differing only in capitals share one", p[0] == p[1] == "acme" and p[2] == "beta", p)
check("Global, Shared and rows with no folder are not made into organizations", p[3] == 0 and p[4] == 0 and p[5] == 0, p)
check("the folder's own spelling is used", od.tree.topLevelItem(0).text(1) == "Acme (new)", od.tree.topLevelItem(0).text(1))
check("nothing is created before Import", orgs.list_orgs() == [])
ids = od.resolve()
made = {o["name"]: o["id"] for o in orgs.list_orgs()}
check("Import creates them", set(made) == {"Acme", "Beta"} and od.created == ["Acme", "Beta"], made)
check("...and each row gets the new organization's id", ids == [made["Acme"], made["Acme"], made["Beta"], 0, 0, 0], ids)
check("each new organization has a code and a colour", all(o["code"] and o["colour"] for o in orgs.list_orgs()))
check("the top folder is dropped inside the new organization", orgassign.strip_top(["Acme", "Core"], made["Acme"]) == ["Core"])
check("the toast says what was made", orgassign.created_text(["Acme", "Beta", "Contoso"]) == "Created 3 organizations: Acme, Beta, Contoso."
      and orgassign.created_text(["Acme"]) == "Created 1 organization: Acme.")
od2 = orgassign.OrgAssignDialog([("x", ["acme"], "Device"), ("y", ["Gamma"], "Device")])
check("a folder named like an existing organization starts there", od2.picks()[0] == made["Acme"])
od2.apply_all_new()
check("...and New Organization keeps it there instead of making a second one", od2.picks() == [made["Acme"], "gamma"], od2.picks())
orgs.set_archived(made["Beta"], True)
od3 = orgassign.OrgAssignDialog([("z", ["Beta"], "Device")])
od3.apply_all_new()
check("a folder named like an archived organization is not made into a new one", od3.picks() == [0], od3.picks())
orgs.set_archived(made["Beta"], False)
db.set_home(made["Acme"])
check("inside an organization no step is asked", orgassign.choose(rows) == [None] * len(rows))
db.set_home(0)

print("== importing through the Inventory")
import ui.inventory as INV
inv = INV.InventoryTab()
csv = os.path.join(SP, "orgr3_import.csv")
with open(csv, "w", encoding="utf-8") as f:
    f.write("name,vendor,host,folder\nd1,cisco,10.9.0.1,Delta/Core\nd2,cisco,10.9.0.2,Delta\nd3,cisco,10.9.0.3,\n")
real_exec = orgassign.OrgAssignDialog.exec
def import_all_new(self):
    self.apply_all_new(); return True
orgassign.OrgAssignDialog.exec = import_all_new
fired = []
inv.orgs_created.connect(lambda: fired.append(1))
import PySide6.QtWidgets as QW
QW.QFileDialog.getOpenFileName = staticmethod(lambda *a, **k: (csv, ""))
toasts = []
INV.toast = lambda w, text, *a, **k: toasts.append(text)
inv.import_file()
delta = next((o["id"] for o in orgs.list_orgs() if o["name"] == "Delta"), None)
check("the import made the Delta organization", delta is not None, [o["name"] for o in orgs.list_orgs()])
with db.within(delta):
    here = {d["name"]: db.path_of(d) for d in db.list_devices() if d["org"] == delta}
check("its devices went there, without the Delta folder", here == {"d1": "Core", "d2": ""}, here)
with db.within(0):
    check("the device with no folder stayed in Global", any(d["name"] == "d3" and d["org"] == 0 for d in db.list_devices()))
check("the window is told (the switcher reloads) and a toast says so", fired and toasts and toasts[-1] == "Created 1 organization: Delta.", (fired, toasts))
orgassign.OrgAssignDialog.exec = real_exec

print("== right-click an organization in Global's Inventory: Add Device")
from PySide6.QtWidgets import QMenu
inv.resize(1200, 700); inv.show(); inv.refresh(); app.processEvents()
menus = []
class FakeMenu(QMenu):
    def exec(self, *a):
        menus.append([x.text() for x in self.actions() if x.text()])
real_menu = INV.QMenu; INV.QMenu = FakeMenu
opened = []
class FakeDeviceDialog:
    def __init__(self, *a, **k): opened.append(k)
    def exec(self): return False
real_dd = INV.DeviceDialog; INV.DeviceDialog = FakeDeviceDialog
def right_click(match):
    it = next(inv.table.topLevelItem(i) for i in range(inv.table.topLevelItemCount()) if inv.table.topLevelItem(i).text(0).startswith(match))
    inv.table.clearSelection(); it.setSelected(True); inv.table.setCurrentItem(it)
    inv.show_menu(inv.table.visualItemRect(it).center()); return it
right_click("Delta")
check("the organization's menu starts with Add Device", menus and menus[-1][0] == "Add Device", menus[-1:])
inv.add()
check("Add Device opens with that organization chosen", opened and opened[-1].get("org") == delta, opened[-1:])
right_click("Global")
check("on the Global branch too", menus[-1][0] == "Add Device")
inv.add()
check("...with Global chosen", opened[-1].get("org") == INV.GLOBAL_ONLY_CHOICE, opened[-1:])
dl = right_click("Delta"); dl.setExpanded(True); app.processEvents()
core = next(dl.child(i) for i in range(dl.childCount()) if dl.child(i).text(0).startswith("Core"))
inv.table.clearSelection(); core.setSelected(True); inv.table.setCurrentItem(core)
inv.show_menu(inv.table.visualItemRect(core).center())
inv.add()
with db.within(delta):
    core_id = db.ensure_folder_path("Core")
check("on a folder inside an organization: that organization and that folder", menus[-1][0] == "Add Device" and opened[-1].get("org") == delta
      and opened[-1].get("folder_id") == core_id, (menus[-1], opened[-1:]))
dev_item = next(core.child(i) for i in range(core.childCount())) if core.childCount() else None
if dev_item is not None:
    inv.table.clearSelection(); dev_item.setSelected(True); inv.show_menu(inv.table.visualItemRect(dev_item).center())
    check("a device's own menu does not offer it", "Add Device" not in menus[-1], menus[-1])
INV.DeviceDialog = real_dd
INV.QMenu = real_menu
empty = orgs.create("Empty Org", "EMPTY"); inv.refresh(); app.processEvents()
for org, pre in ((empty, empty), (delta, delta), (db.GLOBAL, INV.GLOBAL_ONLY_CHOICE)):
    real = INV.DeviceDialog(parent=inv, org=pre)
    check(f"the real Add device window opens with {db.org_name(org)} chosen", real.org_pick.currentData() == pre, (real.org_pick.currentText(), pre))
with db.within(delta):
    real = INV.DeviceDialog(parent=inv, folder_id=core_id, org=delta)
check("...and that folder", real.folder.currentData() == core_id, real.folder.currentText())
orgs.remove(empty)

print("== Remove organization: the button looks greyed out")
import ui.settings_pages.orgs as OP
acme = made["Acme"]
dlg = OP.RemoveDialog(orgs.get(acme)); dlg.resize(460, 220); dlg.show(); app.processEvents()
check("it starts disabled", not dlg.ok.isEnabled())
check("the style sheet greys out a disabled default button", "QPushButton:default:disabled" in app.styleSheet())
def middle(btn):
    img = btn.grab().toImage()
    return img.pixelColor(img.width() // 2, 3).name()
off = middle(dlg.ok)
dlg.confirm.setText("Acme"); app.processEvents()
on = middle(dlg.ok)
check("disabled and enabled look different", dlg.ok.isEnabled() and off != on, (off, on))
dlg.confirm.setText("acme"); app.processEvents()
check("the name has to match exactly, capitals included", not dlg.ok.isEnabled())
dlg.close()

print("== agent sign-up per organization")
beta = made["Beta"]
gkey = agents.enroll_key()
with db.within(acme):
    akey = agents.enroll_key()
with db.within(beta):
    bkey = agents.enroll_key()
check("each organization has its own sign-up key", len({gkey, akey, bkey}) == 3)
check("Global's key keeps its old name in Credential Manager; an organization's starts with its number",
      STORE.get((db.SERVICE, "service:agent-enroll")) == gkey and STORE.get((db.SERVICE, f"org{acme}/service:agent-enroll")) == akey)
db.set_setting("agent_enroll", True)
with db.within(beta):
    db.set_setting("agent_enroll", False)
code, ans = agents.enroll("ACME-PC1", akey, "10.0.0.60")
check("Acme's package signs a computer up to Acme", code == 200 and ans["name"] == "ACME-PC1", (code, ans))
with db.within(acme):
    check("...it is in Acme's inventory", any(d["name"] == "ACME-PC1" for d in db.list_devices()))
    check("...and Acme's audit log", any(r["action"] == "agent signed up" for r in audit.recent()))
with db.within(0):
    check("...not in Global's own devices", not any(d["name"] == "ACME-PC1" and d["org"] == 0 for d in db.list_devices()))
check("its token reports into Acme", agents.token_owner(ans["token"]) == ("ACME-PC1", acme))
code, ans = agents.enroll("GLOBAL-PC1", gkey, "10.0.0.61")
check("Global's package still signs computers up to Global", code == 200 and agents.token_owner(ans["token"]) == ("GLOBAL-PC1", 0), (code, ans))
code, ans = agents.enroll("BETA-PC1", bkey, "10.0.0.62")
check("an organization with sign-up off turns computers away", code == 403, (code, ans))
code, ans = agents.enroll("NOPE", "wrong-key", "10.0.0.63")
check("a wrong key is refused", code == 401, (code, ans))
orgs.set_archived(acme, True)
code, ans = agents.enroll("ACME-PC2", akey, "10.0.0.64")
check("an archived organization's key is refused", code == 401, (code, ans))
orgs.set_archived(acme, False)
with db.within(acme):
    data = agents.package_bytes(7)
cfg = json.loads(zipfile.ZipFile(io.BytesIO(data)).read("toner-agent/agent.json"))
check("a package made in Acme carries Acme's key", cfg["key"] == akey and cfg["minutes"] == 7)
check("sign-up, its interval and pushing it are each organization's own; the receiver is Global's",
      {"agent_enroll", "agent_minutes", "agent_push_minutes"}.isdisjoint(db.GLOBAL_ONLY) and {"agent_enabled", "agent_port", "agent_bind", "agent_address", "agent_token_days"} <= db.GLOBAL_ONLY)
check("the credentials backup knows each organization's key", f"org{acme}/service:agent-enroll" in vault.known_names() and "service:agent-enroll" in vault.known_names())
gamma = orgs.create("Gamma", "GAMMA")
with db.within(gamma):
    gk = agents.enroll_key()
orgs.remove(gamma)
check("removing an organization deletes its key", (db.SERVICE, f"org{gamma}/service:agent-enroll") not in STORE and agents.key_owner(gk) is None)

print("== Settings > Agents in an organization")
import ui.settings as ST
S = ST.SettingsTab(); S.resize(1200, 800); S.show(); app.processEvents()
ai = next(i for i, p in enumerate(S.pages) if p.title == "Agents")
ag = S.pages[ai]
check("in Global the package has a 'Signs computers up to:' choice listing the organizations",
      ag.dest_label.text() == "Signs computers up to:" and ag.dest.isVisibleTo(ag) and [ag.dest.itemText(i) for i in range(ag.dest.count())][:1] == ["Global"]
      and ag.dest.findText("Acme") > 0)
check("that choice is not a setting (it never marks the page unsaved)", ag.dest.property("notSetting") and (ag.dest.setCurrentIndex(1), S.check_dirty(True), S.dirty_pages())[2] == [])
saved = []
QW.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (saved.append(a[2]) or os.path.join(SP, "orgr3_pkg.zip"), ""))
ag.dest.setCurrentIndex(ag.dest.findText("Acme")); ag._download()
cfg = json.loads(zipfile.ZipFile(os.path.join(SP, "orgr3_pkg.zip")).read("toner-agent/agent.json"))
check("downloading for Acme from Global uses Acme's key and names the file after it", cfg["key"] == akey and saved[-1] == "Toner-Agent-Acme.zip", saved)
ag.dest.setCurrentIndex(0); ag._download()
check("Global's package keeps its old name", saved[-1] == "Toner-Agent.zip")
db.set_home(acme); S.reload(); S.select_page("Agents"); app.processEvents()
check("the Agents page is not managed by Global as a whole any more", ag.isEnabled() and ai not in S.managed)
check("the receiver's settings are, one by one", all(not w.isEnabled() and w.toolTip() == "Managed by Global" for w in (ag.enabled, ag.port, ag.bind, ag.address, ag.renew, ag.token_days)))
check("sign-up, the key, the interval and the package are Acme's own", all(w.isEnabled() for w in (ag.enroll, ag.newkey, ag.minutes, ag.push, ag.download)))
check("the sign-up box names the organization", ag.enroll.text() == "Let computers sign themselves up to Acme with the agent package", ag.enroll.text())
check("the key shown is Acme's", ag.key.text() == akey)
check("no organization choice inside an organization", not ag.dest.isVisibleTo(ag))
ag.minutes.setValue(12); S.ask_save = S.save; S.save()
with db.within(acme):
    check("Acme's interval is its own", db.get_setting("agent_minutes") == 12 and db.overridden("agent_minutes"))
with db.within(0):
    check("...Global's is unchanged", db.get_setting("agent_minutes") == 5)
S.show_own(); app.processEvents()
check("and it has a Reset to Global line", "Agent report interval" in S.own_lines[ai].text(), S.own_lines[ai].text())
ag._download()
cfg = json.loads(zipfile.ZipFile(os.path.join(SP, "orgr3_pkg.zip")).read("toner-agent/agent.json"))
check("a package downloaded inside Acme is Acme's", cfg["key"] == akey and cfg["minutes"] == 12 and saved[-1] == "Toner-Agent-Acme.zip", (saved[-1], cfg["minutes"]))
db.set_home(0); S.reload()
del S.ask_save

print("== Settings: Cancel, and leaving with unsaved changes")
gen = next(p for p in S.pages if p.title == "General")
spin = [w for w in gen.findChildren(ST.QSpinBox)][0]
was = spin.value()
check("the button is called Cancel", S.cancel_btn.text() == "Cancel")
S.select_page("General"); spin.setValue(was + 3)
asked = []
QMessageBox.question = staticmethod(lambda *a, **k: asked.append(a) or QMessageBox.StandardButton.Yes)
S.cancel_btn.click(); app.processEvents()
check("Cancel drops the edit without asking", spin.value() == was and not asked and S.unsaved_count() == 0)

answer = {"button": None}
shown = []
def fake_exec(self):
    shown.append({"title": self.windowTitle(), "text": self.text(), "buttons": [b.text() for b in self.buttons()]})
    want = next(b for b in self.buttons() if b.text() == answer["button"])
    self._clicked = want
    return 0
QMessageBox.exec = fake_exec
QMessageBox.clickedButton = lambda self: getattr(self, "_clicked", None)
check("with nothing edited, leaving asks nothing", S.confirm_leave() and not shown)
spin.setValue(was + 1)
answer["button"] = "Stay in Settings"
check("Stay in Settings keeps you there with the edit", not S.confirm_leave() and spin.value() == was + 1)
check("the pop-up says how many pages and asks to save before leaving", shown and shown[-1]["title"] == "Unsaved settings"
      and shown[-1]["text"] == "You have unsaved changes on 1 page.\nSave them before leaving Settings?", shown[-1:])
check("its buttons are Save changes, Discard changes and Stay in Settings", shown[-1]["buttons"] == ["Save changes", "Discard changes", "Stay in Settings"], shown[-1]["buttons"])
answer["button"] = "Discard changes"
check("Discard changes lets you go and drops the edit", S.confirm_leave() and spin.value() == was and S.unsaved_count() == 0)
from ui import settings_diff as SD
confirmed = []
SD.ConfirmChanges.exec = lambda self: confirmed.append(self.windowTitle()) or True
spin.setValue(was + 2)
answer["button"] = "Save changes"
check("Save changes goes through the usual Save (its list and question) and then lets you go",
      S.confirm_leave() and confirmed == ["Save changes"] and int(db.get_setting(next(k for k in ("retention_days",)))) >= 0 and S.unsaved_count() == 0, confirmed)
spin.setValue(was + 4); confirmed.clear()
SD.ConfirmChanges.exec = lambda self: confirmed.append(self.windowTitle()) or False
check("answering Keep editing in Save's list keeps you in Settings", not S.confirm_leave() and S.unsaved_count() == 1)
S.cancel()
S.close()

print("== the main window asks when you leave Settings")
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
w = A.Main(); w.resize(1400, 860); w.show(); app.processEvents()
w.go("Settings"); app.processEvents()
gen = next(p for p in w.settings.pages if p.title == "General")
w.settings.select_page("General")
spin = [x for x in gen.findChildren(ST.QSpinBox)][0]
was = spin.value(); spin.setValue(was + 5); shown.clear()
answer["button"] = "Stay in Settings"
w.go("Inventory"); app.processEvents()
check("clicking another section with unsaved changes asks, and Stay in Settings stays", shown and w.tabs.currentWidget() is w.settings
      and w.tabs.list.currentRow() == w.tabs.indexOf(w.settings), [s["text"] for s in shown])
answer["button"] = "Discard changes"
w.go("Inventory"); app.processEvents()
check("Discard changes moves on and drops the edit", w.tabs.currentWidget() is w.inventory and spin.value() == was)
shown.clear(); w.go("Settings"); w.go("Overview"); app.processEvents()
check("leaving with nothing edited asks nothing", not shown and w.tabs.currentWidget() is w.dashboard)
w.go("Settings"); spin.setValue(was + 6); shown.clear()
answer["button"] = "Stay in Settings"
w.set_org(acme); app.processEvents()
check("switching organization asks the same, worded for switching", shown and shown[-1]["text"].endswith("Save them before switching organization?") and db.home() == 0,
      shown[-1:])
answer["button"] = "Discard changes"
w.set_org(acme); app.processEvents()
check("...and Discard changes switches", db.home() == acme and spin.value() == was)
w.set_org(0); app.processEvents()
spin.setValue(was + 7); shown.clear()
answer["button"] = "Stay in Settings"
w._quitting = True
w.background_mode = lambda: False
from PySide6.QtGui import QCloseEvent
ev = QCloseEvent(); w.closeEvent(ev)
check("closing Toner asks too, and Stay in Settings keeps it open", shown and shown[-1]["text"].endswith("Save them before closing Toner?") and not ev.isAccepted(), shown[-1:])
w.settings.cancel()
from core import extstore as ES
real_unsent, real_active = ES.unsent, ES.active
ES.unsent, ES.active = (lambda: 2), (lambda: "bitwarden")
said = []
QMessageBox.question = staticmethod(lambda *a, **k: said.append(a[2]) or QMessageBox.StandardButton.No)
w._quitting = True; ev = QCloseEvent(); w.closeEvent(ev)
check("closing with changes that haven't reached the password manager asks, in the agreed words; No keeps Toner open",
      said and said[-1] == "2 changes haven't reached Bitwarden yet and will be lost if Toner closes. Close anyway?" and not ev.isAccepted(), said)
ES.unsent = lambda: 1
w._quitting = True; ev = QCloseEvent(); w.closeEvent(ev)
check("...one change", said[-1] == "1 change hasn't reached Bitwarden yet and will be lost if Toner closes. Close anyway?", said[-1:])
ES.unsent, ES.active = real_unsent, real_active
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

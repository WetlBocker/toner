# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, json, faulthandler
pass      # if anything blocks, print where and quit
pass
os.environ["QT_QPA_PLATFORM"] = "offscreen"
SP = os.environ["SP"]; stamp = int(time.time())
os.makedirs(SP + (rf"\fold{stamp}").replace("\\", os.sep)); os.environ["NETCHECK_DB"] = SP + (rf"\fold{stamp}\netcheck.db").replace("\\", os.sep)
from core import db
db.init()
PASS = FAIL = 0
def check(name, cond, extra=""):
    global PASS, FAIL
    PASS += bool(cond); FAIL += (not cond)
    print(("  ok   " if cond else "  FAIL ") + name + (f"   [{extra}]" if extra and not cond else ""))
def dev(name, vendor="cisco", loc="", fid=None, **kw):
    d = dict(name=name, vendor=vendor, host="127.0.0.1", port=0, platform="", username="u", site="default", verify_ssl=0,
             ha_expected=0, enabled=1, location=loc, details="", folder_id=fid); d.update(kw); return d

print("== database: folders")
chi = db.create_folder("Chicago"); core = db.create_folder("Core", chi); edge = db.create_folder("Edge", chi); den = db.create_folder("Denver")
check("nested paths", db.folder_paths() == {chi: "Chicago", core: "Chicago/Core", edge: "Chicago/Edge", den: "Denver"}, db.folder_paths())
for bad in ("", "  ", ".", "..", "a/b", "a\\b"):
    try: db.create_folder(bad); ok = False
    except ValueError: ok = True
    check(f"rejects folder name {bad!r}", ok)
try: db.create_folder("chicago"); ok = False
except ValueError as e: ok = "already exists" in str(e)
check("sibling names are unique, ignoring case", ok)
check("the same name is fine under a different parent", db.create_folder("Core", den) > 0)
for n, f in (("sw1", core), ("sw2", core), ("fw1", edge), ("ap1", den), ("loose", None)):
    db.save_device(dev(n, fid=f))
check("devices keep their folder", {d["name"]: d["folder_id"] for d in db.list_devices()}["sw1"] == core)
try: db.move_folder(chi, core); ok = False
except ValueError as e: ok = "into itself" in str(e)
check("a folder cannot move into its own subfolder", ok)
try: db.move_folder(chi, chi); ok = False
except ValueError: ok = True
check("...or into itself", ok)
try: db.move_folder(core, den); ok = False
except ValueError as e: ok = "already exists" in str(e)
check("moving into a place with the same name is refused", ok)
db.rename_folder(den, "Denver DC"); check("rename", db.folder_paths()[den] == "Denver DC")
_i = db.ensure_folder_path("HQ/Floor 2/IDF"); check("ensure_folder_path creates every level", db.folder_paths()[_i] == "HQ/Floor 2/IDF")
check("...and reuses what exists, ignoring case", db.ensure_folder_path("chicago/core") == core and db.ensure_folder_path("") is None)
_i = db.ensure_folder_path("HQ\\Floor 2"); check("path with backslashes", db.folder_paths()[_i] == "HQ/Floor 2")
check("descendants include self and everything below", db.folder_descendants(chi) == {chi, core, edge})

print("== groups use folders")
labels = db.group_labels()
check("folders with devices are offered as groups, with their parents", [l for l in labels if l.startswith("Folder:")] == ["Folder: Chicago", "Folder: Chicago/Core", "Folder: Chicago/Edge", "Folder: Denver DC"], [l for l in labels if l.startswith("Folder")])
ds = {d["name"]: d for d in db.list_devices()}
check("a folder group includes its subfolders", {n for n, d in ds.items() if db.in_group(d, "Folder: Chicago")} == {"sw1", "sw2", "fw1"})
check("a subfolder group is just that folder", {n for n, d in ds.items() if db.in_group(d, "Folder: Chicago/Core")} == {"sw1", "sw2"})
check("'Chicago' does not match 'Chicago2'", not db.in_group(dev("x", fid=db.create_folder("Chicago2")), "Folder: Chicago"))
check("devices at top level are in no folder group", not db.in_group(ds["loose"], "Folder: Chicago"))
check("group_device_names works with folders", db.group_device_names(["Folder: Denver DC"]) == {"ap1"})
rules = [{"scope": "Folder: Chicago", "check": "cpu", "warn": 50, "fail": 60}, {"scope": "Folder: Chicago/Core", "check": "cpu", "warn": 40, "fail": 55},
         {"scope": "Location: X", "check": "cpu", "warn": 1, "fail": 2}]
check("threshold override: deeper folder beats shallower", db.thresholds_for(ds["sw1"], None, rules)["cpu"] == {"warn": 40, "fail": 55})
check("...and the shallower applies to the rest", db.thresholds_for(ds["fw1"], None, rules)["cpu"] == {"warn": 50, "fail": 60})
check("override scopes list folders", "Folder: Chicago/Core" in db.override_scopes())
check("folders are not part of exported settings / imports", "inventory_expanded" not in db.export_settings())

print("== deleting a folder never deletes devices")
db.delete_folder(core)
ds = {d["name"]: d for d in db.list_devices()}
check("its devices moved up one level", ds["sw1"]["folder_id"] == chi and ds["sw2"]["folder_id"] == chi and len(ds) == 5, {n: d["folder_id"] for n, d in ds.items()})
sub = db.create_folder("Sub", edge); db.save_device({**ds["fw1"], "id": ds["fw1"]["id"]}); db.delete_folder(edge)
check("subfolders move up too", dict((f["name"], f["parent_id"]) for f in db.list_folders())["Sub"] == chi)
a = db.create_folder("Dup", chi); b = db.create_folder("Mid", chi); inner = db.create_folder("Dup", b)
try: db.delete_folder(b); ok = False
except ValueError as e: ok = "clash" in str(e)
check("a delete that would create a name clash is refused, nothing lost", ok and any(f["id"] == b for f in db.list_folders()) and any(f["id"] == inner for f in db.list_folders()))

print("== import creates folders")
from core import importer
dev1, _ = importer.normalize({"Name": "imp1", "Type": "cisco", "IP": "10.0.0.5", "Folder": "Branch \\ Austin / Core "})
check("folder column accepted (any slashes, trimmed)", dev1["folder"] == "Branch/Austin/Core", dev1["folder"])
try: importer.normalize({"name": "x", "vendor": "cisco", "host": "1.1.1.1", "folder": "a/../b"}); ok = False
except ValueError as e: ok = "'..'" in str(e)
check("'..' in a folder path is rejected", ok)

print("== the tree")
from PySide6.QtCore import Qt, QPoint, QPointF, QMimeData
from PySide6.QtGui import QDropEvent
from PySide6.QtWidgets import QApplication, QMessageBox, QInputDialog, QFileDialog
app = QApplication([])
from ui import orgassign as _oa
_oa.OrgAssignDialog.exec = lambda self: True     # the import step (asked when an import has folders): keep its starting choices
msgs = []
QMessageBox.warning = staticmethod(lambda *a: msgs.append(("warn", a[2])) or QMessageBox.StandardButton.Ok)
QMessageBox.information = staticmethod(lambda *a: msgs.append(("info", a[2])) or QMessageBox.StandardButton.Ok)
answer = {"q": QMessageBox.StandardButton.Yes}
QMessageBox.question = staticmethod(lambda *a: (msgs.append(("ask", a[2])), answer["q"])[1])
typed = {"text": None}
QInputDialog.getText = staticmethod(lambda *a, **k: (typed["text"] or "", typed["text"] is not None))
import ui.inventory as INV
import app as A
w = A.Main(); w.show(); inv = w.inventory
def tree():
    out = []
    def walk(it, depth):
        out.append("  " * depth + it.text(0))
        for i in range(it.childCount()): walk(it.child(i), depth + 1)
    for i in range(inv.table.topLevelItemCount()): walk(inv.table.topLevelItem(i), 0)
    return out
def find(kind, ident):
    for it in inv._all_items():
        if inv.kind_of(it) == (kind, ident): return it
def find_dev(name):
    return next(it for it in inv._all_items() if inv.kind_of(it)[0] == "device" and it.text(0) == name)
def find_folder(path):
    return next(it for it in inv._all_items() if inv.kind_of(it)[0] == "folder" and db.folder_paths()[inv.kind_of(it)[1]] == path)
def pick(*items):
    inv.table.clearSelection()
    for it in items: it.setSelected(True)
inv.table.expandAll()
print("   " + " | ".join(tree()[:6]))
check("folders first, counts shown", tree()[0].startswith("Branch") or tree()[0].startswith("Chicago"), tree()[:3])
check("device rows keep all their columns", find_dev("sw1").text(1) == "Cisco" and find_dev("sw1").text(4) == "127.0.0.1")
check("top-level device is listed after the folders", tree()[-1].strip() == "loose" or "loose" in tree()[-3:], tree()[-3:])

print("== folder actions in the UI")
pick(); typed["text"] = "Projects"; inv.new_folder()
check("New folder at top level", any(f["name"] == "Projects" and f["parent_id"] is None for f in db.list_folders()))
pf = next(f["id"] for f in db.list_folders() if f["name"] == "Projects")
pick(find("folder", pf)); typed["text"] = "2026"; inv.new_folder()
check("New folder inside the selected folder, and it is opened", any(f["name"] == "2026" and f["parent_id"] == pf for f in db.list_folders()) and find("folder", pf).isExpanded())
msgs.clear(); typed["text"] = "2026"; pick(find("folder", pf)); inv.new_folder(); check("duplicate name is refused with a message", msgs and "already exists" in msgs[-1][1], msgs)
pick(find("folder", pf)); typed["text"] = "Projects 2"; inv.rename_folder(); check("rename (F2)", db.folder_paths()[pf] == "Projects 2")
pick(find_dev("sw1")); check("Edit is enabled only for one device", inv.buttons["Edit"].isEnabled()); pick(find_dev("sw1"), find_dev("sw2")); check("Edit off for two, Delete on", not inv.buttons["Edit"].isEnabled() and inv.buttons["Delete"].isEnabled())
pick(find("folder", pf)); check("a folder selected: Edit off, Delete (folder) on", not inv.buttons["Edit"].isEnabled() and inv.buttons["Delete"].isEnabled())
inv.table.clearSelection(); check("nothing selected: Edit and Delete off", not inv.buttons["Edit"].isEnabled() and not inv.buttons["Delete"].isEnabled())

print("== moving things")
sw1, sw2 = find_dev("sw1"), find_dev("sw2")
pick(sw1, sw2); inv.move_selected_to(pf)
ds = {d["name"]: d for d in db.list_devices()}; check("move devices via the menu action", ds["sw1"]["folder_id"] == pf and ds["sw2"]["folder_id"] == pf)
check("target folder is opened and counted", find("folder", pf).isExpanded() and "(2)" in find("folder", pf).text(0) or "(2" in find("folder", pf).text(0), find("folder", pf).text(0))
# real drag-and-drop event onto a folder row
def drop_on(item, selected):
    pick(*selected); vp = inv.table.viewport(); rect = inv.table.visualItemRect(item) if item is not None else None
    pos = QPointF(rect.center()) if rect else QPointF(vp.width() - 5, vp.height() - 5)
    ev = QDropEvent(pos, Qt.DropAction.MoveAction, QMimeData(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
    inv.table.dropEvent(ev); return ev
den_item = find_folder("Denver DC"); drop_on(den_item, [find_dev("sw1")])
check("DRAG a device onto a folder", {d["name"]: d["folder_id"] for d in db.list_devices()}["sw1"] == den)
drop_on(None, [find_dev("sw1")]); check("drag onto empty space = top level", {d["name"]: d["folder_id"] for d in db.list_devices()}["sw1"] is None)
chi_item = find_folder("Chicago"); drop_on(find_folder("Projects 2"), [chi_item])
check("DRAG a folder into another", dict((f["name"], f["parent_id"]) for f in db.list_folders())["Chicago"] == pf)
msgs.clear(); drop_on(find_folder("Projects 2/Chicago"), [find_folder("Projects 2")])
check("dragging a folder into its own child is refused and nothing changes", msgs and "into itself" in msgs[-1][1] and dict((f["name"], f["parent_id"]) for f in db.list_folders())["Projects 2"] is None, msgs)
drop_on(find_folder("Denver DC"), [find_folder("Projects 2/Chicago"), find_dev("ap1")]) ; ds = {d["name"]: d for d in db.list_devices()}
check("a mixed selection (folder + device) moves together", dict((f["name"], f["parent_id"]) for f in db.list_folders())["Chicago"] == den and ds["ap1"]["folder_id"] == den)
check("tree stays consistent after drops", find_folder("Denver DC/Chicago") is not None)

print("== right-click menu content")
from PySide6.QtWidgets import QMenu
captured = {}
class FakeMenu(QMenu):
    def exec(self, *a):
        captured.update(actions=[x.text() for x in self.actions() if x.text()], menu=self); return None
INV.QMenu = FakeMenu
vp = inv.table.viewport()
pick(); inv.show_menu(QPoint(vp.width() - 5, vp.height() - 5)); check("empty space: Add Device / New folder / Expand / Collapse", captured["actions"] == ["Add Device", "New folder...", "Expand all", "Collapse all"], captured["actions"])
it = find_dev("loose"); inv.show_menu(inv.table.visualItemRect(it).center()); a = captured["actions"]
check("a device: Edit, SSH, Move, Delete", a[:3] == ["Details...", "Edit...", "Open SSH session"] and "Move to folder" in a and a[-3] == "Delete..." and a[-2:] == ["Expand all", "Collapse all"], a)
move = next(x for x in captured["menu"].actions() if x.text() == "Move to folder").menu()
check("'Move to folder' lists top level and every folder", move.actions()[0].text() == "(top level)" and "Denver DC/Chicago" in [x.text() for x in move.actions()])
it = find_folder("Denver DC"); inv.show_menu(inv.table.visualItemRect(it).center()); a = captured["actions"]
check("a folder: add device, subfolder, rename, move, delete", a[:3] == ["Add Device", "New subfolder...", "Rename..."] and "Move to folder" in a and a[-3] == "Delete folder..." and a[-2:] == ["Expand all", "Collapse all"], a)
move = next(x for x in captured["menu"].actions() if x.text() == "Move to folder").menu()
check("a folder cannot be moved into itself or its children", not any(x.text().startswith("Denver DC") for x in move.actions()), [x.text() for x in move.actions()])
INV.QMenu = QMenu

print("== deleting from the UI")
pick(find_folder("Denver DC")); answer["q"] = QMessageBox.StandardButton.No; inv.delete(); check("declining keeps the folder", "Denver DC" in db.folder_paths().values())
answer["q"] = QMessageBox.StandardButton.Yes; msgs.clear(); n_dev = len(db.list_devices()); inv.delete()
check("deleting a folder: devices survive, contents move up, user told", len(db.list_devices()) == n_dev and "Denver DC" not in db.folder_paths().values() and "No device is deleted" in [m for m in msgs if m[0] == "ask"][-1][1])
pick(find_dev("ap1"), find_dev("loose")); inv.delete(); check("delete several devices at once", {d["name"] for d in db.list_devices()}.isdisjoint({"ap1", "loose"}))

print("== persistence and other views")
fid = next(f["id"] for f in db.list_folders() if f["name"] == "Projects 2")
inv.expanded.discard(fid); find("folder", fid).setExpanded(True); check("opening a folder is remembered", fid in db.get_setting("inventory_expanded"))
inv2 = INV.InventoryTab(); check("...and survives a restart", find_folder.__name__ and any(inv2.kind_of(i) == ("folder", fid) and i.isExpanded() for i in inv2._all_items()))
inv.set_filter("vendor_sel","cisco"); inv._build_filter_menu(); assert inv.filter_btn.toolTip().startswith("Filter: Cisco"); alld=[inv.kind_of(i) for i in inv._all_items()]; check("vendor filter keeps folder tree, drag on, only cisco shown", inv.table.dragEnabled() and inv.buttons["New folder"].isEnabled() and all(inv.payload["device:%d"%i]["vendor"]=="cisco" for k,i in alld if k=="device") and any(k=="folder" for k,_ in alld))
inv.set_filter(None, None); inv.set_filter(None, None); xs=[dev("zz-u","unifi","Austin"),dev("zz-f","fortinet","Chicago"),dev("zz-c","cisco","Chicago"),dev("zz-k","cisco","Denver")]; [db.save_device(d) for d in xs]; inv.refresh(); inv.toggle_filter("vendor_sel","cisco",True); inv.toggle_filter("vendor_sel","unifi",True); check("two vendors ticked at once", {inv.payload[k]["vendor"] for k in inv.payload if k.startswith("device:")}=={"cisco","unifi"} and inv.filter_btn.text().strip()=="2"); inv.toggle_filter("location_sel","Austin",True); check("vendors AND locations combine", {inv.payload[k]["location"] for k in inv.payload if k.startswith("device:")}=={"Austin"}); inv.toggle_filter("location_sel","Chicago",True); check("several locations", {inv.payload[k]["location"] for k in inv.payload if k.startswith("device:")}=={"Austin","Chicago"}); inv.set_filter(None, None); [db.delete_device(d["id"]) for d in db.list_devices() if d["name"].startswith("zz-")]; inv.refresh(); check("filters reset to everything", len([1 for i in inv._all_items() if inv.kind_of(i)[0]=="device"]) == len(db.list_devices()))
inv.collapse_all(); check("collapse all", not any(i.isExpanded() for i in inv._all_items())); inv.expand_all(); check("expand all", all(i.isExpanded() for i in inv._all_items() if i.childCount()))


print("== device dialog and SSH hand-off")
fdlg = INV.DeviceDialog(None, None, folder_id=pf); check("new device starts in the chosen folder", fdlg.values()["folder_id"] == pf and fdlg.folder.currentText() == "Projects 2")
d0 = db.list_devices()[0]; ed = INV.DeviceDialog(d0, None); check("editing shows the device's folder", ed.values()["folder_id"] == d0["folder_id"])
fdlg.folder.setCurrentIndex(0); check("...and can be set to top level", fdlg.values()["folder_id"] is None)
shown = []; w.sessions.open_device = lambda d: shown.append(d["name"]) or True
dsel = db.list_devices()[0]; inv.refresh(); inv.select_device(dsel["id"]); inv.open_in_ssh()
check("Open SSH session passes the device on, and the app switches to Sessions", shown == [dsel["name"]] and w.tabs.currentWidget() is w.sessions)
del w.sessions.open_device
check("device pickers show the folder", any("[" in w.tools.diag.picker.itemText(i) for i in range(1, w.tools.diag.picker.count())) or all(d.get("folder_id") is None for d in db.list_devices()))

print("== import with folders")
import ui.inventory as INV2
csv = SP + (rf"\fold{stamp}\imp.csv").replace("\\", os.sep)
open(csv, "w", encoding="utf-8").write("name,vendor,host,folder\ni1,cisco,10.1.1.1,Branch/Austin/Core\ni2,cisco,10.1.1.2,Branch/Austin/Core\ni3,fortinet,10.1.1.3,Branch/Austin/Edge\ni4,unifi,10.1.1.4,\ni1,cisco,10.1.1.9,Branch/Dup\nbad,cisco,https://x/,Branch/Bad\n")
QFileDialog.getOpenFileName = staticmethod(lambda *a, **k: (csv, "")); msgs.clear(); inv.import_file()
paths = set(db.folder_paths().values())
check("import creates the folders and files devices in them", {"Branch", "Branch/Austin", "Branch/Austin/Core", "Branch/Austin/Edge"} <= paths and {d["name"]: d["folder_id"] for d in db.list_devices()}["i2"] == db.ensure_folder_path("Branch/Austin/Core"))
check("no stray folders for duplicates or bad rows", "Branch/Dup" not in paths and "Branch/Bad" not in paths, sorted(paths))
check("summary mentions the duplicate and the bad row", "i1" in msgs[-1][1] and "bad" in msgs[-1][1], msgs[-1])

print(f"\n{PASS} passed, {FAIL} failed")







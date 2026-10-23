# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Settings > Organizations with several rows selected: archive, restore and remove them together (1.6.10).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "orgbulk%d.db" % int(time.time())); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import audit, db, orgs, sessions
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

from PySide6.QtWidgets import QAbstractItemView, QApplication, QMessageBox
app = QApplication.instance() or QApplication([])
import app as A
A.apply_look(app)
import ui.settings_pages.orgs as OP
warned, asked, toasts, fired = [], [], [], []
QMessageBox.warning = staticmethod(lambda *a, **k: warned.append((a[1], a[2])))
QMessageBox.question = staticmethod(lambda *a, **k: asked.append((a[1], a[2])) or QMessageBox.StandardButton.Yes)
OP.toast = lambda w, t: toasts.append(t)


def dev(name):
    return dict(name=name, vendor="cisco", host="10.0.0.1", port=0, platform="", username="u", site="default", verify_ssl=0, ha_expected=0,
                enabled=1, location="", details="", folder_id=None)


def names():
    return [o["name"] for o in orgs.list_orgs()]


def audit_rows():
    """Every organization's audit lines (an action is logged in the file of the organization being looked at)."""
    db.set_home(0)
    with db.including_archived(True):
        return [f"{r['action']} {r['detail']}" for r in audit.recent(500)]


page = OP.OrganizationsPage()
page.changed_orgs.connect(lambda: fired.append(1))
acme, beta, con, delta = orgs.create("Acme", "ACME"), orgs.create("Beta", "BETA"), orgs.create("Contoso", "CON"), orgs.create("Delta", "DELTA")
page.load()

print("== selecting several rows")
check("the table allows several rows to be selected", page.table.selectionMode() == QAbstractItemView.SelectionMode.ExtendedSelection)
page.select_ids({acme, beta, con})
check("selected_ids lists them in the order of the list", page.selected_ids() == [acme, beta, con], page.selected_ids())
check("Rename needs exactly one organization", not page.rename_btn.isEnabled())
check("Archive and Remove work on all of them", page.archive_btn.isEnabled() and page.archive_btn.text() == "Archive" and page.remove_btn.isEnabled())
page.select_ids({acme})
check("one selected: Rename is back", page.rename_btn.isEnabled() and page.selected() == acme)
page.select_ids(set())
check("nothing selected: the three are off", not any(b.isEnabled() for b in (page.rename_btn, page.archive_btn, page.remove_btn)))
orgs.set_archived(delta, True); page.load()
page.select_ids({acme, delta})
check("an active and an archived one together: Archive is off, with the agreed tooltip",
      not page.archive_btn.isEnabled() and page.archive_btn.toolTip() == "Select only active or only archived organizations." and page.remove_btn.isEnabled())
page.select_ids({delta})
check("only archived ones: the button reads Restore", page.archive_btn.isEnabled() and page.archive_btn.text() == "Restore" and page.archive_btn.toolTip() == "")
check("clicking a cell selects its whole row for the buttons", (page.table.item(0, 1).setSelected(True), page.selected_ids() == [acme, delta])[1], page.selected_ids())

print("== archiving several")
orgs.set_current(beta)
page.select_ids({acme, beta, con}); page.toggle_archive()
check("asks once, in the agreed words", asked and asked[-1] == ("Archive organizations",
      "Archive 3 organizations? Acme, Beta and Contoso. Their devices and history stay saved but are hidden, their schedules and alerts stop, "
      "and they can only be viewed in the Global context. Restore them any time in Global from Settings > Organizations."), asked[-1:])
check("...and archives all three", all(orgs.get(o)["archived"] for o in (acme, beta, con)))
check("the one picked in the sidebar switches to Global", db.home() == 0 and orgs.current() == 0)
check("the window is told once", fired == [1], fired)
check("one audit line per organization", sum(1 for r in audit_rows() if "organization archived" in r) == 3)
check("the rows stay selected and the button now reads Restore", page.selected_ids() == [acme, beta, con] and page.archive_btn.text() == "Restore")
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.No)
orgs.set_archived(delta, False); page.load(); page.select_ids({delta}); page.toggle_archive()
check("No leaves them as they are", not orgs.get(delta)["archived"])
QMessageBox.question = staticmethod(lambda *a, **k: asked.append((a[1], a[2])) or QMessageBox.StandardButton.Yes)
page.select_ids({delta}); page.toggle_archive()
check("one organization still asks in its own words", asked[-1] == ("Archive organization",
      "Archive Delta? Its devices and history stay saved but are hidden, its schedules and alerts stop, and it can only be viewed in the Global "
      "context. Restore it any time in Global from Settings > Organizations.") and orgs.get(delta)["archived"], asked[-1:])

print("== restoring several")
n_asked = len(asked)
page.select_ids({acme, beta, con}); page.toggle_archive()
check("Restore asks nothing and restores all three", not any(orgs.get(o)["archived"] for o in (acme, beta, con)) and len(asked) == n_asked)
check("...with a toast counting them", toasts[-1] == "3 organizations restored.", toasts[-1:])
check("...and an audit line each", sum(1 for r in audit_rows() if "organization restored" in r) == 3)
page.select_ids({delta}); page.toggle_archive()
check("one restored: the toast names it", toasts[-1] == "Delta restored." and not orgs.get(delta)["archived"])

print("== the Remove dialog for several")
dlg = OP.RemoveDialog([orgs.get(acme), orgs.get(beta)])
check("title and names", dlg.windowTitle() == "Remove organizations" and dlg.names.text() == "Acme, Beta")
check("the choices are worded for several", dlg.move.text() == "Move their devices, sessions and history to:" and dlg.delete.text() == "Delete them permanently")
dests = [dlg.dest.itemText(i) for i in range(dlg.dest.count())]
check("the destinations leave out the selected ones", dests == ["Global", "Contoso", "Delta"], dests)
check("Remove waits for REMOVE", not dlg.ok.isEnabled() and dlg.confirm.placeholderText() == "REMOVE")
dlg.confirm.setText("Acme"); check("a name is not enough", not dlg.ok.isEnabled())
dlg.confirm.setText("remove"); check("lower case is not enough", not dlg.ok.isEnabled())
dlg.confirm.setText("REMOVE"); check("REMOVE enables it", dlg.ok.isEnabled())
check("moving to Global is the default", dlg.destination() == 0)
one = OP.RemoveDialog(orgs.get(acme))
check("one organization keeps its own dialog: its name confirms", one.windowTitle() == "Remove organization" and one.confirm.placeholderText() == "Acme"
      and one.move.text() == "Move its devices, sessions and history to:")
one.confirm.setText("Acme"); check("...and enables Remove", one.ok.isEnabled())

print("== removing several, moving everything to Contoso")
for org, n in ((acme, "acme-sw1"), (beta, "beta-sw1")):
    with db.within(org):
        db.save_device(dev(n))
        sessions.save({"name": n + "-ssh", "kind": "ssh", "host": "10.0.0.1", "port": 22, "username": "u", "folder_id": None, "options": {}})
real_exec = OP.RemoveDialog.exec
def exec_move(self):
    self.dest.setCurrentIndex(self.dest.findData(con)); self.confirm.setText("REMOVE"); return True
OP.RemoveDialog.exec = exec_move
orgs.set_current(acme); fired.clear()
page.load(); page.select_ids({acme, beta}); page.remove()
check("both are gone", names() == ["Contoso", "Delta"], names())
with db.within(con):
    moved = sorted(d["name"] for d in db.list_devices() if d["org"] == con)
    sess = sorted(s["name"] for s in sessions.list_sessions() if s["org"] == con)
check("their devices and sessions are in Contoso", moved == ["acme-sw1", "beta-sw1"] and sess == ["acme-sw1-ssh", "beta-sw1-ssh"], (moved, sess))
check("the one picked in the sidebar switches to Global", db.home() == 0)
check("their files are gone", not db.org_path(acme).exists() and not db.org_path(beta).exists())
check("the toast counts them", toasts[-1] == "2 organizations removed.", toasts[-1:])
check("an audit line each, saying where things went", sum(1 for r in audit_rows() if "organization removed" in r and "(moved to Contoso)" in r) == 2, audit_rows()[-3:])
check("the window is told once", fired == [1])

print("== a name clash stops the whole removal")
e1, e2 = orgs.create("Echo", "ECHO"), orgs.create("Foxtrot", "FOX")
with db.within(e1):
    db.save_device(dev("shared-name")); db.save_device(dev("beta-sw1"))        # beta-sw1 is in Contoso already
with db.within(e2):
    db.save_device(dev("Shared-Name"))
try:
    orgs.remove_many([e1, e2], move_to=con)
    check("remove_many refuses", False)
except ValueError as e:
    check("remove_many refuses with one line per clash and says nothing was removed", str(e) ==
          "A device named beta-sw1 already exists in Contoso.\nA device named Shared-Name already exists in Echo.\n\nNothing was removed.", str(e))
check("...and both are still there", set(names()) >= {"Echo", "Foxtrot"})
page.load(); page.select_ids({e1, e2}); page.remove()
check("the page shows that under the dialog's title", warned and warned[-1][0] == "Remove organizations" and warned[-1][1].endswith("Nothing was removed.")
      and set(names()) >= {"Echo", "Foxtrot"}, warned[-1:])
try:
    orgs.remove_many([e1, e2], move_to=e1)
    check("moving into one of the selected is refused", False)
except ValueError as e:
    check("moving into one of the selected is refused", str(e) == "Pick another organization to move them to.")

print("== deleting several permanently")
def exec_delete(self):
    self.delete.setChecked(True); self.confirm.setText("REMOVE"); return True
OP.RemoveDialog.exec = exec_delete
paths = [db.org_path(e1), db.org_path(e2)]
page.select_ids({e1, e2}); page.remove()
check("both are gone, with their files", names() == ["Contoso", "Delta"] and not any(p.exists() for p in paths), names())
with db.within(con):
    check("Contoso kept only what it had", sorted(d["name"] for d in db.list_devices() if d["org"] == con) == ["acme-sw1", "beta-sw1"])
check("audit says deleted", sum(1 for r in audit_rows() if "organization removed" in r and "(deleted)" in r) == 2)
OP.RemoveDialog.exec = real_exec

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

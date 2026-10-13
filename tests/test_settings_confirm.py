# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Settings > Save changes and Revert: each lists what will change, with the old and the new value, and asks first.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "setconf%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingsetconf%d" % int(time.time()))
from core import db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
from PySide6.QtWidgets import QApplication, QLineEdit, QMessageBox
from PySide6.QtCore import Qt
app = QApplication([])
import app as A
A.apply_look(app)
import ui.settings as ST
from ui import settings_diff as SD, toast as T

S = ST.SettingsTab(); S.resize(1200, 800); S.show(); app.processEvents()
page = lambda title: next(p for p in S.pages if p.title == title)
seen = []
def answer(accept):
    """Stand in for the confirmation window: record what it lists, then say yes or no."""
    def fake(self):
        seen.append({"title": self.windowTitle(), "intro": self.findChildren(__import__("PySide6.QtWidgets", fromlist=["x"]).QLabel)[0].text(),
                     "head": [self.tree.headerItem().text(i) for i in range(3)],
                     "rows": [(self.tree.topLevelItem(i).text(0), [tuple(self.tree.topLevelItem(i).child(j).text(k) for k in range(3)) for j in range(self.tree.topLevelItem(i).childCount())])
                              for i in range(self.tree.topLevelItemCount())],
                     "go": self.go.text()})
        return accept
    SD.ConfirmChanges.exec = fake
warned = []
QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2]))

print("== reading a page in words")
snap = SD.snapshot(page("General"))
check("each setting is named by its label, with the value as shown", snap.get("Keep run history") == "90 days" and "Devices checked in parallel" in snap, list(snap)[:5])
check("a tick box is named by its own words, and says on or off", any("system tray" in k and v == "off" for k, v in snap.items()), snap)
check("the audit log's filter box is not a setting", SD.snapshot(page("Audit log")) == {} and ST.signature(page("Audit log")) == ())
check("the read-only boxes (the agent key, the certificate) are not settings", "Sign-up key" not in SD.snapshot(page("Agents")) and "Certificate" not in SD.snapshot(page("Agents")))
from ui.settings_base import Page
pw = Page(); pw.form.addRow("Secret", QLineEdit()); pw.form.itemAt(0, ST.QFormLayout.ItemRole.FieldRole).widget().setEchoMode(QLineEdit.EchoMode.Password)
check("a password is never shown, only whether there is one", SD.snapshot(pw) == {"Secret": "(empty)"} and (pw.form.itemAt(0, ST.QFormLayout.ItemRole.FieldRole).widget().setText("hunter2") or SD.snapshot(pw) == {"Secret": "(set)"}))
check("the checks page lists every check, on or off", SD.snapshot(page("Checks")).get("Cisco: CPU") == "on")
check("the difference between two readings is old and new, with additions and removals said", SD.changes({"a": "1", "b": "2"}, {"a": "1", "b": "3", "c": "4"}) == [("b", "2", "3"), ("c", "(not set)", "4")]
      and SD.changes({"a": "1"}, {}) == [("a", "1", "(removed)")])

print("== opening a folded section is not a change")
from ui.settings_base import Collapsible
ag = page("Agents"); folds = ag.findChildren(Collapsible)
before_sig, before_snap = ST.signature(ag), SD.snapshot(ag)
check("the Agents page has folded sections", len(folds) >= 2 and not any(f.toggle.isChecked() for f in folds))
for f in folds:
    f.toggle.setChecked(True)
app.processEvents()
check("opening every one changes neither what is compared nor what is listed", ST.signature(ag) == before_sig and SD.snapshot(ag) == before_snap and not any("Advanced" in k or "How agents" in k for k in SD.snapshot(ag)), SD.snapshot(ag))
check("so no change is pending and no page is marked", S.pending_changes() == [])
for f in folds:
    f.toggle.setChecked(False)
all_folds = [(p.title, f) for p in S.pages for f in p.findChildren(Collapsible)]
for _t, f in all_folds:
    f.toggle.setChecked(True)
app.processEvents()
check("on any page", S.pending_changes() == [] and len(all_folds) >= 2, [t for t, _f in all_folds])
for _t, f in all_folds:
    f.toggle.setChecked(False)

print("== nothing changed")
check("freshly loaded, there is nothing to list", S.pending_changes() == [])
T.history.clear(); seen.clear(); answer(True)
S.ask_revert()
check("Revert with nothing edited just says so, and shows no window", not seen and "Nothing to revert" in T.history[-1], T.history)
S.ask_save()
check("Save with nothing edited saves as before, with no window", not seen and S.status.text().startswith("Saved"), S.status.text())

print("== Save lists what changes")
gen, th, ap = page("General"), page("Thresholds"), page("Appearance")
sp = [w for w in gen.findChildren(ST.QSpinBox)][0]; old_days = sp.value(); sp.setValue(old_days - 30)
tray = next(c for c in gen.findChildren(ST.QCheckBox) if "tray" in c.text()); tray.setChecked(True)
th.spins["cpu"][0].setValue(55)
ap.theme.setCurrentIndex((ap.theme.currentIndex() + 1) % ap.theme.count()); old_theme = db.get_setting("theme")
seen.clear(); answer(False)
S.ask_save()
check("a window opens, titled and worded for saving, with Now and Will become", seen and seen[0]["title"] == "Save changes" and seen[0]["head"] == ["Setting", "Now", "Will become"] and "4 settings" in seen[0]["intro"] and seen[0]["go"] == "Save changes", seen[:1])
rows = dict(seen[0]["rows"][i][0].split("  (")[0] and (seen[0]["rows"][i][0].split("  (")[0], seen[0]["rows"][i][1]) for i in range(len(seen[0]["rows"])))
check("the changes are grouped by page", set(rows) == {"General", "Thresholds", "Appearance"}, list(rows))
flat = {r[0]: r for rs in rows.values() for r in rs}
check("a number says what it was and what it becomes", flat["Keep run history"][1:] == (f"{old_days} days", f"{old_days - 30} days"), flat.get("Keep run history"))
check("a tick box says off and on", [r for r in rows["General"] if "tray" in r[0]][0][1:] == ("off", "on"))
check("a threshold shows both limits", flat["CPU %"][1:] == ("WARN at 70 / FAIL at 90", "WARN at 55 / FAIL at 90"), flat.get("CPU %"))
check("a drop-down shows the two choices", flat["Theme"][1] != flat["Theme"][2])
check("answering no changes nothing: the edits stay and nothing is stored", db.get_setting("theme") == old_theme and int(db.get_setting("retention_days")) == old_days and sp.value() == old_days - 30
      and (S.stack.setCurrentIndex(S.pages.index(gen)), S.check_dirty(), S.dirty_pages())[2] != [])
check("(nothing was stored)", int(db.get_setting("retention_days")) == old_days and db.get_thresholds()["cpu"]["warn"] == 70)
seen.clear(); answer(True)
S.ask_save()
check("answering yes saves them all", int(db.get_setting("retention_days")) == old_days - 30 and db.get_thresholds()["cpu"]["warn"] == 55 and bool(db.get_setting("run_in_background")) and db.get_setting("theme") != old_theme)
check("and the page is clean again, so the next Save has nothing to list", S.pending_changes() == [] and S.dirty_pages() == [] and S.status.text().startswith("Saved"))

print("== a problem is reported before any window")
th.spins["cpu"][0].setValue(99); th.spins["cpu"][1].setValue(50)
seen.clear(); warned.clear()
S.ask_save()
check("contradicting limits give the usual warning and no confirmation window", warned and "contradict" in warned[-1] and not seen, (warned, seen))
th.spins["cpu"][0].setValue(55); th.spins["cpu"][1].setValue(90)

print("== Revert lists what goes back")
sp.setValue(7); th.spins["memory"][1].setValue(95); S.search.setText("")
# an override row in the table is described too
th.add_row("Vendor: Cisco", "cpu", 40, 60)
seen.clear(); answer(False)
S.ask_revert()
flat = {r[0]: r for _t, rs in seen[0]["rows"] for r in rs}
check("it says your edit and what it goes back to", seen[0]["title"] == "Revert changes" and seen[0]["head"] == ["Setting", "Your edit", "Goes back to"] and seen[0]["go"] == "Revert", seen[0]["head"])
check("each edited setting shows the edit first, then the saved value", flat["Keep run history"][1:] == ("7 days", f"{old_days - 30} days") and flat["Memory %"][1:] == ("WARN at 80 / FAIL at 95", "WARN at 80 / FAIL at 90"), flat)
check("a new override row is listed and goes back to (not set)", flat["Override: Vendor: Cisco / CPU %"][1:] == ("WARN 40 / FAIL 60", "(not set)"), [k for k in flat if "Override" in k])
check("answering no keeps the edits", sp.value() == 7 and th.table.rowCount() == 1)
seen.clear(); answer(True)
S.ask_revert()
check("answering yes puts everything back as saved", sp.value() == old_days - 30 and th.spins["memory"][1].value() == 90 and th.table.rowCount() == 0 and S.pending_changes() == [])
check("and nothing was written by a revert", int(db.get_setting("retention_days")) == old_days - 30)

print("== the checks page and the unsaved marks")
ck = page("Checks"); top = ck.tree.topLevelItem(0); first = top.child(0); first.setCheckState(0, Qt.CheckState.Unchecked)
S.stack.setCurrentIndex(S.pages.index(ck)); S.check_dirty()
check("switching a check off marks the page unsaved (it used to be missed)", S.dirty_pages() == [S.pages.index(ck)], S.dirty_pages())
seen.clear(); answer(False); S.ask_save()
flat = {r[0]: r for _t, rs in seen[0]["rows"] for r in rs}
check("and the list names the check", flat[f"{top.text(0)}: {first.text(0)}"][1:] == ("on", "off"), list(flat))
first.setCheckState(0, Qt.CheckState.Checked)

print("== the buttons")
check("the buttons ask first (they are wired to the asking versions)", S.save_btn.text() == "Save changes" and S.revert_btn.text() == "Revert")
sp.setValue(11); seen.clear(); answer(False)
S.revert_btn.click()
check("the Revert button opens the list", seen and seen[0]["title"] == "Revert changes")
seen.clear(); S.save_btn.click()
check("the Save button opens the list", seen and seen[0]["title"] == "Save changes")
check("the confirmation window really exists and is not a plain message box", SD.ConfirmChanges.__mro__[1].__name__ == "QDialog")

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

# Run directly (python tests/test_settings_dirty.py). The unsaved-changes dot: none when a page is opened and nothing changes,
# none when a value is changed and put back.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "dirty%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingdirty%d" % int(time.time()))
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
from PySide6.QtWidgets import QApplication, QCheckBox, QSpinBox
app = QApplication([])
import app as A
A.apply_look(app)
import ui.settings as ST

S = ST.SettingsTab(); S.resize(1200, 800); S.show(); app.processEvents()
def settle():
    app.processEvents(); time.sleep(0.2); app.processEvents()
page = lambda title: next(p for p in S.pages if p.title == title)

print("== every page, opened, nothing changed")
for title in list(S.page_titles()):
    S.select_page(title); settle()
    S.check_dirty(); S.check_dirty()
    i = S.stack.currentIndex()
    now, was = ST.signature(S.pages[i]), S.baseline[i]
    check(f"{title}: not dirty", not S._dirty.get(i), [(a, b) for a, b in zip(was, now) if a != b][:3] or (len(was), len(now)))
check("no page marked, no line", S.dirty_pages() == [] and S.unsaved.text() == "", (S.dirty_pages(), S.unsaved.text()))

print("== changed and changed back")
for title in ("General", "Accounts", "Security"):
    S.select_page(title); settle()
    i = S.stack.currentIndex(); p = S.pages[i]
    box = next((w for w in p.findChildren(QCheckBox) if w.isEnabled() and not w.property("notSetting")), None)
    if box is not None:
        was = box.isChecked(); box.setChecked(not was); settle(); S.check_dirty()
        check(f"{title}: a tick shows", S._dirty.get(i))
        box.setChecked(was); settle(); S.check_dirty()
        check(f"{title}: ticked back, not dirty", not S._dirty.get(i) and S.unsaved.text() == "")
    else:
        sp = next(w for w in p.findChildren(QSpinBox) if w.isEnabled() and not w.property("notSetting"))
        was = sp.value(); sp.setValue(was + 1 if was < sp.maximum() else was - 1); settle(); S.check_dirty()
        check(f"{title}: a number shows", S._dirty.get(i))
        sp.setValue(was); settle(); S.check_dirty()
        check(f"{title}: number put back, not dirty", not S._dirty.get(i) and S.unsaved.text() == "")

print("== a read-only box that follows something else is not an edit")
S.select_page("Agents"); settle()
ag, i = page("Agents"), S.stack.currentIndex()
port = ag.port.value()
ag.port.setValue(port + 1); S.refresh_dynamic(); ag.port.setValue(port); settle(); S.check_dirty()    # (the window refreshes the pages whenever the inventory changes)
check("Agents: port edited, a refresh in between, port put back: not dirty", not S._dirty.get(i) and S.unsaved.text() == "", S.unsaved.text())
S.select_page("Demarc"); settle()
dm, j = page("Demarc"), S.stack.currentIndex()
dm.cert.setText("a pin that arrived while the page was open"); S.check_dirty()                          # (its status timer does this when the sender connects)
check("Demarc: its certificate box changing by itself is not an edit", not S._dirty.get(j) and S.unsaved.text() == "")
print("== a model list refilled after load")
S.select_page("AI"); settle()
ai, k = page("AI"), S.stack.currentIndex()
base = ai.chosen_model(); pid = ai.chosen_provider()
ai._models[pid] = [("zz-other", "Other"), (base, base)]; ai._fill_models(pid, keep=base); settle(); S.check_dirty()   # (what Test does when it lists the models)
check("AI: the same model moved to another row", ai.model.currentIndex() == 1 and ai.chosen_model() == base, ai.model.currentIndex())
check("AI: not dirty and nothing pending", not S._dirty.get(k) and S.pending_changes() == [], S.pending_changes())
ai.model.setCurrentIndex(ai.model.findData("zz-other")); S.check_dirty()
check("AI: another model picked: dirty", S._dirty.get(k))
ai.model.setCurrentIndex(ai.model.findData(base)); S.check_dirty()
check("AI: the original picked again: clean", not S._dirty.get(k) and S.pending_changes() == [])
print("== the Save list shows a drop-down's label, not its key")
from PySide6.QtWidgets import QComboBox
from ui import settings_diff as SD
an = page("Ansible")
check("Ansible's 'where' reads as its label", SD._value(an.where) == an.where.currentText() and SD._value(an.where) not in ("wsl", "server"), SD._value(an.where))
org = QComboBox(); org.addItem("Global", 0); org.addItem("Acme", 7); org.setCurrentIndex(1)
check("an organization drop-down reads as the name", SD._value(org) == "Acme")
print(f"\n{ok} ok, {bad} failed"); sys.exit(1 if bad else 0)

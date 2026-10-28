# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Settings > Appearance > Style: the Standard look and the denser, flatter Ops console look.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\ops%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roamingops%d" % int(time.time()))
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
from drivers.base import Result
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox, QTableWidget, QTableWidgetItem
app = QApplication([])
import app as A
from ui import nav, theme, widgets
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)

print("== the colours")
std_l, std_d = theme.tokens(False), theme.tokens(True)
ops_l, ops_d = theme.tokens(False, theme.OPS), theme.tokens(True, theme.OPS)
check("Standard is the default style", std_d == theme.tokens(True, "Standard") and std_d["ops"] is False and std_l["surface"] == "#ffffff")
check("the console look has its own dark and light palettes", ops_d["bg"] == "#050e17" and ops_d["surface"] == "#08141f" and ops_l["bg"] == "#e8eef3"
      and ops_l["surface"] == "#ffffff" and ops_d["bg"] != std_d["bg"] and ops_d["ops"] and ops_l["ops"])
check("and the Toner theme's accent, the same as Standard", ops_d["accent"] == std_d["accent"] == theme.ACCENT[1] and ops_l["accent"] == theme.ACCENT[0])
check("rows are tinted with a solid colour in both", ops_d["select"].startswith("#") and ops_l["select"].startswith("#") and ops_d["select"] != ops_d["surface"])
ss_std, ss_ops = theme.stylesheet(std_d), theme.stylesheet(ops_d)
check("only the console look has the compact rules", "Cascadia Mono" not in ss_std and "Cascadia Mono" in ss_ops and "padding: 1px 6px" in ss_ops)

print("== the setting")
check("Standard is the default, so nothing changes for anyone until they choose", db.get_setting("ui_style") == "Standard" and theme.STYLES == ["Standard", "Ops console"])

acme = db.create_folder("Acme")
for i, (n, v) in enumerate((("sw1", "cisco"), ("fw1", "fortinet"), ("dc1", "windows"))):
    db.save_device(dict(name=n, vendor=v, host=f"10.0.0.{i + 1}", port=0, platform="", username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=acme, tags="", fields=""))
db.save_run([Result("sw1", "cpu", "OK", "5%"), Result("fw1", "wan links", "FAIL", "1/2", "down: wan2"), Result("dc1", "disk C:", "WARN", "86% used", "high"), Result("dc1", "cpu", "OK", "5%")])
A.apply_look(app)
w = A.Main(); w.resize(1300, 820); w.show(); app.processEvents()
check("the window starts in the standard look", not theme.is_ops() and w.tabs.side.maximumHeight() == nav.BAR_HEIGHT and w.tabs.list.item(0).sizeHint().height() == nav.BAR_HEIGHT - 1)
w.go("Inventory"); w.inventory.table.expandAll(); app.processEvents()
dev_item = next(it for it in w.inventory._all_items() if w.inventory.kind_of(it)[0] == "device")
h_std = w.inventory.table.visualItemRect(dev_item).height()
font_std = app.font().pointSize()

print("== choosing it in Settings > Appearance")
w.go("Settings"); w.settings.select_page("Appearance"); app.processEvents()
page = next(p for p in w.settings.pages if p.title == "Appearance")
check("the page offers a Style box, on Standard", page.ui_style.count() == 2 and page.ui_style.currentText() == "Standard" and page.ui_style.itemText(1) == "Ops console")
page.ui_style.setCurrentText("Ops console"); w.settings.check_dirty()
names = [n for t, rows in w.settings.pending_changes() if t == "Appearance" for n, _a, _b in rows]
check("the change shows in the list of what will be saved", any(n == "Style" for n in names), names)
w.settings.save(); app.processEvents()
check("saving applies it at once, with no restart", db.get_setting("ui_style") == "Ops console" and theme.is_ops() and "Cascadia Mono" in app.styleSheet())
check("the top bar is lower in the console style", w.tabs.side.maximumHeight() == nav.BAR_HEIGHT_OPS and w.tabs.list.item(0).sizeHint().height() == nav.BAR_HEIGHT_OPS - 1, (w.tabs.side.maximumHeight(), w.tabs.list.item(0).sizeHint().height()))
check("the text is a point smaller", app.font().pointSize() == font_std - 1, (font_std, app.font().pointSize()))
w.go("Inventory"); w.inventory.table.expandAll(); app.processEvents()
dev_item = next(it for it in w.inventory._all_items() if w.inventory.kind_of(it)[0] == "device")
h_ops = w.inventory.table.visualItemRect(dev_item).height()
check("a row in the Inventory is shorter", h_ops < h_std, (h_std, h_ops))
w.go("Overview"); w.dashboard.refresh(); app.processEvents()
card = w.dashboard.cards["devices"]
check("the number cards on the Overview carry a smaller number", abs(card.value.font().pointSizeF() / app.font().pointSizeF() - 2.2) < 0.15, (card.value.font().pointSizeF(), app.font().pointSizeF()))

print("== every section draws in the console look, light and dark")
errors = []
for mode in ("Dark", "Light"):
    db.set_setting("theme", mode); w.settings_applied()
    for sec in ("Overview", "Results", "Inventory", "Configs", "Scanning", "History", "Reports", "Tools", "Sessions", "Automation/AI", "Settings", "About"):
        try:
            w.go(sec); app.processEvents(); w.grab()
        except Exception as e:
            errors.append((mode, sec, repr(e)))
    check(f"{mode}: no section fails to draw", not errors, errors)
    check(f"{mode}: the console palette is in use", theme.current()["bg"] == (ops_d["bg"] if mode == "Dark" else ops_l["bg"]), theme.current()["bg"])

print("== the status pill")
t = QTableWidget(2, 1); t.resize(220, 90)
for r, s in enumerate(("FAIL", "OK")): t.setItem(r, 0, QTableWidgetItem(s))
t.setItemDelegateForColumn(0, widgets.StatusDelegate(t)); t.show(); app.processEvents()
db.set_setting("theme", "Dark"); w.settings_applied(); app.processEvents()
img_ops = t.grab().toImage()
db.set_setting("ui_style", "Standard"); w.settings_applied(); app.processEvents()
img_std = t.grab().toImage()
check("it is drawn differently in the two looks (a flat tag, not a round pill)", img_ops != img_std and not theme.is_ops())
check("and switching back restores the standard top bar", w.tabs.side.maximumHeight() == nav.BAR_HEIGHT and w.tabs.list.item(0).sizeHint().height() == nav.BAR_HEIGHT - 1 and app.font().pointSize() == font_std)

print("== from the search (Ctrl+K)")
w.open_palette(); ents = {e[0]: e[2] for e in w.palette.entries}; w.palette.close()
check("it offers the other style", "Style: Ops console" in ents and "Style: Standard" not in ents)
ents["Style: Ops console"](); app.processEvents()
check("choosing it switches at once and the Settings page follows", theme.is_ops() and db.get_setting("ui_style") == "Ops console" and next(p for p in w.settings.pages if p.title == "Appearance").ui_style.currentText() == "Ops console")
w.open_palette(); ents = {e[0]: e[2] for e in w.palette.entries}; w.palette.close()
check("and then offers the way back", "Style: Standard" in ents and "Style: Ops console" not in ents)
ents["Style: Standard"](); app.processEvents()
check("which restores the standard look", not theme.is_ops() and w.tabs.side.maximumHeight() == nav.BAR_HEIGHT)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

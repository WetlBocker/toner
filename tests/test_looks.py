# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Settings > Appearance > Look: Standard, Soft, Sharp and Terminal (the former Ops console) on top of any theme.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\looks%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roaminglooks%d" % int(time.time()))
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
from ui import nav, theme, themes, widgets
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)

print("== the tokens of each look")
std, soft, sharp, term = (theme.tokens(dict(theme="Midnight", look=l)) for l in themes.LOOKS)
check("Standard is the default look", db.get_setting("look") == "Standard" and themes.LOOKS == ["Standard", "Soft", "Sharp", "Terminal"] and not std["terminal"])
check("the four looks share the theme's colours", std["bg"] == soft["bg"] == sharp["bg"] == term["bg"] and std["accent"] == term["accent"] == "#22d3ee")
check("Soft rounds every corner, Sharp squares them, Terminal has none", soft["r_btn"] > std["r_btn"] > sharp["r_btn"] > term["r_btn"] == 0 and soft["r_card"] == 14 and sharp["r_card"] == 2)
check("Terminal is the former Ops console: monospace data, tight rows, small-capital headers, a point smaller",
      "Cascadia Mono" in term["data_font"] and term["pad_row"] == "1px 6px" and "8pt" in term["header_font"] and term["point_delta"] == -1 and term["terminal"] and term["ops"])
check("rows are tinted with a solid colour in every look", all(t["select"].startswith("#") and t["select"] != t["surface"] for t in (std, soft, sharp, term)))
from PySide6.QtGui import QColor as _QC
far = lambda a, b: sum(abs(x - y) for x, y in zip(_QC(a).getRgb()[:3], _QC(b).getRgb()[:3]))
check("a row under the mouse is tinted, but nearer the background than a selected row, so it never looks selected", all(
      0 < far(t["row_hover"], t["surface"]) < far(t["row_hover"], t["select"]) for t in (std, soft, sharp, term)),
      [(t["row_hover"], t["select"]) for t in (std, soft, sharp, term)])
ss_std, ss_term = theme.stylesheet(std), theme.stylesheet(term)
check("...and that is the colour rows get under the mouse", f"QListView::item:hover {{ background: {std['row_hover']}; }}" in ss_std)
check("only the Terminal look has the compact rules", "Cascadia Mono" not in ss_std and "Cascadia Mono" in ss_term and "padding: 1px 6px" in ss_term)
check("the knobs are independent of the theme", theme.tokens(dict(theme="Linen", look="Terminal"))["terminal"] and theme.tokens(dict(theme="Linen", look="Terminal"))["bg"] == themes.FIXED["Linen"]["bg"])

acme = db.create_folder("Acme")
for i, (n, v) in enumerate((("sw1", "cisco"), ("fw1", "fortinet"), ("dc1", "windows"))):
    db.save_device(dict(name=n, vendor=v, host=f"10.0.0.{i + 1}", port=0, platform="", username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=acme, tags="", fields=""))
db.save_run([Result("sw1", "cpu", "OK", "5%"), Result("fw1", "wan links", "FAIL", "1/2", "down: wan2"), Result("dc1", "disk C:", "WARN", "86% used", "high"), Result("dc1", "cpu", "OK", "5%")])
A.apply_look(app)
w = A.Main(); w.resize(1300, 820); w.show(); app.processEvents()
check("the window starts in the standard look", not theme.is_terminal() and w.tabs.side.maximumHeight() == nav.BAR_HEIGHT)
w.go("Inventory"); w.inventory.table.expandAll(); app.processEvents()
dev_item = next(it for it in w.inventory._all_items() if w.inventory.kind_of(it)[0] == "device")
h_std = w.inventory.table.visualItemRect(dev_item).height()
font_std = app.font().pointSize()

print("== choosing a look in Settings > Appearance")
w.go("Settings"); w.settings.select_page("Appearance"); app.processEvents()
page = next(p for p in w.settings.pages if p.title == "Appearance")
check("the page offers a Look box, on Standard", [page.look.itemText(i) for i in range(page.look.count())] == themes.LOOKS and page.look.currentText() == "Standard")
page.look.setCurrentText("Terminal"); w.settings.check_dirty()
names = [n for t, rows in w.settings.pending_changes() if t == "Appearance" for n, _a, _b in rows]
check("the change shows in the list of what will be saved", any(n == "Look" for n in names), names)
w.settings.save(); app.processEvents()
check("saving applies it at once, with no restart", db.get_setting("look") == "Terminal" and theme.is_terminal() and "Cascadia Mono" in app.styleSheet())
check("the top bar is lower in the Terminal look", w.tabs.side.maximumHeight() == nav.BAR_HEIGHT_OPS, w.tabs.side.maximumHeight())
check("the text is a point smaller", app.font().pointSize() == font_std - 1, (font_std, app.font().pointSize()))
w.go("Inventory"); w.inventory.table.expandAll(); app.processEvents()
dev_item = next(it for it in w.inventory._all_items() if w.inventory.kind_of(it)[0] == "device")
h_term = w.inventory.table.visualItemRect(dev_item).height()
check("a row in the Inventory is shorter", h_term < h_std, (h_std, h_term))
w.go("Overview"); w.dashboard.refresh(); app.processEvents()
card = w.dashboard.cards["devices"]
check("the number cards on the Overview carry a smaller number", abs(card.value.font().pointSizeF() / app.font().pointSizeF() - 2.2) < 0.15, (card.value.font().pointSizeF(), app.font().pointSizeF()))

print("== every section draws in the Terminal look, light and dark")
errors = []
for mode in ("Midnight", "Linen"):
    db.set_setting("theme", mode); w.settings_applied()
    for sec in ("Overview", "Results", "Inventory", "Configs", "Scanning", "History", "Reports", "Tools", "Sessions", "Automation/AI", "Settings", "About"):
        try:
            w.go(sec); app.processEvents(); w.grab()
        except Exception as e:
            errors.append((mode, sec, repr(e)))
    check(f"{mode}: no section fails to draw", not errors, errors)
    check(f"{mode}: the theme's palette is in use", theme.current()["bg"] == themes.FIXED[mode]["bg"], theme.current()["bg"])

print("== the status chip")
t = QTableWidget(2, 1); t.resize(220, 90)
for r, s in enumerate(("FAIL", "OK")): t.setItem(r, 0, QTableWidgetItem(s))
t.setItemDelegateForColumn(0, widgets.StatusDelegate(t)); t.show(); app.processEvents()
db.set_setting("theme", "Midnight"); w.settings_applied(); app.processEvents()
img_term = t.grab().toImage()
db.set_setting("look", "Standard"); w.settings_applied(); app.processEvents()
img_std = t.grab().toImage()
check("it is drawn differently in the two looks (square in Terminal, a pill elsewhere)", img_term != img_std and not theme.is_terminal())
check("and switching back restores the standard top bar", w.tabs.side.maximumHeight() == nav.BAR_HEIGHT and app.font().pointSize() == font_std)

print("== from the search (Ctrl+K)")
w.open_palette(); ents = {e[0]: e[2] for e in w.palette.entries}; w.palette.close()
check("it offers the other looks", {"Look: Soft", "Look: Sharp", "Look: Terminal"} <= set(ents) and "Look: Standard" not in ents)
ents["Look: Terminal"](); app.processEvents()
check("choosing one switches at once and the Settings page follows", theme.is_terminal() and db.get_setting("look") == "Terminal" and next(p for p in w.settings.pages if p.title == "Appearance").look.currentText() == "Terminal")
w.open_palette(); ents = {e[0]: e[2] for e in w.palette.entries}; w.palette.close()
check("and then offers the way back", "Look: Standard" in ents and "Look: Terminal" not in ents)
ents["Look: Standard"](); app.processEvents()
check("which restores the standard look", not theme.is_terminal() and w.tabs.side.maximumHeight() == nav.BAR_HEIGHT)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

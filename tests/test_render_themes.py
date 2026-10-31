# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Every theme, look and panel style makes a stylesheet Qt accepts, and the window draws in each one. Set TONER_RENDER_DIR to a folder to
# keep a picture of every theme on the Overview, Results, Inventory and Settings (the offscreen render step before a commit).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_os.environ.setdefault("QT_QPA_FONTDIR", r"C:\Windows\Fonts")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "render%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingrender%d" % int(time.time()))
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
from PySide6.QtCore import QtMsgType, qInstallMessageHandler
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
import app as A
from ui import theme, themes

print("== every stylesheet parses")
complaints = []
qInstallMessageHandler(lambda kind, ctx, msg: complaints.append(msg) if "stylesheet" in msg.lower() or "Could not parse" in msg else None)
for name in themes.NAMES:
    for look in themes.LOOKS:
        for panels in themes.PANELS:
            app.setStyleSheet(theme.stylesheet(theme.tokens(dict(theme=name, look=look, panels=panels))))
app.processEvents()
check(f"{len(themes.NAMES) * len(themes.LOOKS) * len(themes.PANELS)} stylesheets, none Qt complained about", not complaints, complaints[:3])

for i, (n, v) in enumerate((("core-sw1", "cisco"), ("edge-fw", "fortinet"), ("udm-pro", "unifi"), ("dist-sw2", "cisco"))):
    db.save_device(dict(name=n, vendor=v, host=f"10.0.0.{i + 1}", port=0, platform="cisco_ios" if v == "cisco" else "", username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="Chicago", details="", folder_id=None))
db.save_run([Result("core-sw1", "cpu", "OK", "12%", numeric=12.0), Result("core-sw1", "memory", "WARN", "86%", numeric=86.0), Result("edge-fw", "wan links", "OK", "2/2"),
             Result("udm-pro", "uptime", "OK", "41d"), Result("dist-sw2", "connection", "ERROR", "", "timeout")])
A.apply_look(app)
w = A.Main(); w.resize(1240, 760); w.show(); app.processEvents()
out = os.environ.get("TONER_RENDER_DIR")
if out:
    os.makedirs(out, exist_ok=True)

def shot(label, sec):
    w.go(sec); app.processEvents()
    img = w.grab().toImage()
    if out:
        img.save(os.path.join(out, f"{label.replace(' ', '_').replace('/', '-')}-{sec.replace('/', '-')}.png"))
    return img

print("== every theme draws the main sections")
errors = []
for name in themes.NAMES:
    db.set_setting("theme", name); w.settings_applied(); app.processEvents()
    try:
        for sec in ("Overview", "Results", "Inventory", "Settings"):
            img = shot(name, sec)
        bg = QColor(theme.current()["bg"])
        px = QColor(img.pixel(w.width() - 3, w.height() // 2))          # the page's right margin, where only the backdrop is
        if theme.current().get("glow"):
            near = abs(px.lightness() - bg.lightness()) < 40
        else:
            near = px == bg
        if not near:
            errors.append((name, "margin colour", px.name(), bg.name()))
    except Exception as e:
        errors.append((name, repr(e)))
    check(f"{name}: draws, in its own colours", not [e for e in errors if e[0] == name], [e for e in errors if e[0] == name])

print("== every section, in a few themes and every look")
for name, look in (("Aurora", "Standard"), ("Linen", "Soft"), ("High contrast", "Sharp"), ("Midnight", "Terminal")):
    db.set_setting("theme", name); db.set_setting("look", look); w.settings_applied(); app.processEvents()
    errs = []
    for sec in ("Overview", "Results", "Inventory", "Configs", "Scanning", "History", "Reports", "Tools", "Sessions", "Automation/AI", "Settings", "About"):
        try:
            shot(f"{name} {look}", sec)
        except Exception as e:
            errs.append((sec, repr(e)))
    check(f"{name}, {look}: all 12 sections draw", not errs, errs)
db.set_setting("look", "Standard")
for panels in themes.PANELS:
    db.set_setting("panels", panels); w.settings_applied(); app.processEvents()
    try:
        shot(f"Aurora {panels}", "Overview"); good = True
    except Exception as e:
        good = repr(e)
    check(f"Panels {panels}: the Overview draws", good is True, good)
db.set_setting("panels", "Bordered"); db.set_setting("theme", "System"); w.settings_applied()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

# The sign-in window (and the setup and lock windows) wear Toner's theme. The name is kept in a tiny plain file beside netcheck.keys,
# because the setting itself is in the encrypted database, which is not open yet.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import json, os, time
SP = os.environ["SP"]; os.environ["APPDATA"] = SP
os.environ["NETCHECK_DB"] = os.path.join(SP, f"theme{int(time.time())}.db")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import datakey, db, lockdown, passvault, session
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
from ui import theme, themes
from ui.signinwindow import SignInWindow
P = db.base_path().with_suffix(".theme")
def shown(name):
    return themes.resolve(dict(themes.DEFAULT_LOOK, theme=name), dict(system_dark=False))["bg"]
def bg_now():
    A.plain_look(app); w = SignInWindow(); w.close(); return theme.current()["bg"]

print("== the plain copy")
check("it sits beside netcheck.keys", theme.plain_path().parent == datakey.path().parent)
theme.write_plain("Nebula")
check("writing it gives the name and nothing else", json.loads(P.read_text(encoding="utf-8")) == {"theme": "Nebula"})
check("no temp file left", not P.with_name(P.name + ".tmp").exists())

print("== a new sign-in window uses it")
check("Nebula", bg_now() == shown("Nebula"))
theme.write_plain("Linen")
check("Linen", bg_now() == shown("Linen") and bg_now() != shown("Nebula"))

print("== missing, damaged or unknown: the default")
default_bg = shown(themes.DEFAULT_THEME)
P.unlink()
check("missing", bg_now() == default_bg)
for label, text in (("damaged", "{not json"), ("not an object", "[1]"), ("unknown name", '{"theme": "Nope"}'), ("not a name", '{"theme": 5}'),
                    ("Your colour (needs the database)", '{"theme": "Your colour"}')):
    P.write_text(text, encoding="utf-8"); check(label, bg_now() == default_bg)

print("== a crafted file")
P.write_text("[" * 200000 + "]" * 200000, encoding="utf-8"); check("200,000 deep", bg_now() == default_bg)
P.write_text('{"theme": "Linen", "pad": "' + "x" * 2_000_000 + '"}', encoding="utf-8"); check("2 MB", bg_now() == default_bg)
_r = os.replace
os.replace = lambda a, b: (_ for _ in ()).throw(OSError("no"))
P.unlink(); theme.write_plain("Nebula"); os.replace = _r
check("failed write leaves no temp", not P.with_name(P.name + ".tmp").exists() and not P.exists())

print("== only the name is taken from it")
P.write_text(json.dumps({"theme": "Linen", "look": "Terminal", "panel_opacity": 50, "custom_accent": "#ff0000"}), encoding="utf-8")
l = theme.plain_look()
check("the rest stays default", l == dict(themes.DEFAULT_LOOK, theme="Linen"))

print("== the Appearance page writes it; lockdown leaves it plain")
from ui.settings_pages.appearance import AppearancePage
P.unlink()
db.init()
pg = AppearancePage(); pg.grid.set_current("Tide")
check("grid has Tide", pg.grid.current() == "Tide")
pg.save()
check("save wrote it", json.loads(P.read_text(encoding="utf-8")) == {"theme": "Tide"})
before = P.read_bytes()
check("not pending for lockdown", P not in lockdown.pending())
print(f"\n{ok} passed, {bad} failed")
sys_exit = _sys.exit(1 if bad else 0)

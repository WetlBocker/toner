# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The themes themselves: every one reads, the knobs do what they say, the interactive ones follow their input, old settings migrate,
# and motion is still when it should be.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sqlite3, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "themes%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingthemes%d" % int(time.time()))
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
from ui import themes

print("== every theme reads")
HEX = lambda s: isinstance(s, str) and len(s) == 7 and s[0] == "#" and all(c in "0123456789abcdef" for c in s[1:])
for name, p in themes.FIXED.items():
    missing = [k for k in themes.BASE_KEYS if not HEX(p.get(k, ""))]
    check(f"{name}: every colour is there, as lower-case hex", not missing, missing)
    check(f"{name}: dark says what the page colour says", p["dark"] == (themes.luminance(p["bg"]) < 0.3), themes.luminance(p["bg"]))
    floor_text = 14 if name == "High contrast" else 7
    check(f"{name}: text on the page reads easily ({floor_text}:1)", themes.contrast(p["text"], p["bg"]) >= floor_text and themes.contrast(p["text"], p["surface"]) >= floor_text,
          (round(themes.contrast(p["text"], p["bg"]), 1), round(themes.contrast(p["text"], p["surface"]), 1)))
    check(f"{name}: muted text reads (4:1)", themes.contrast(p["muted"], p["bg"]) >= 4 and themes.contrast(p["muted"], p["surface"]) >= 4,
          (round(themes.contrast(p["muted"], p["bg"]), 1), round(themes.contrast(p["muted"], p["surface"]), 1)))
    check(f"{name}: the word on a primary button reads (4.5:1)", themes.contrast(p["accent"], p["accent_text"]) >= 4.5, round(themes.contrast(p["accent"], p["accent_text"]), 1))
    check(f"{name}: has a one-line description", len(themes.note(name)) > 10)
check("the groups list every fixed theme once, and the interactive ones", sorted(n for _g, ns in themes.GROUPS for n in ns) == sorted(list(themes.FIXED) + list(themes.INTERACTIVE))
      and themes.NAMES[0] == "System" and len(themes.NAMES) == 25)
check("kinds", themes.kind("Aurora") == "dark" and themes.kind("Linen") == "light" and themes.kind("Time of day") == "interactive" and themes.kind("System") == "follows Windows")
check("old names map", themes.legacy_name("Dark") == "Midnight" and themes.legacy_name("Light") == "Daylight" and themes.legacy_name("System") == "System"
      and themes.legacy_name("Ember") == "Ember" and themes.legacy_name("Nope") == "System")

print("== the knobs")
base = themes.resolve(dict(theme="Harbor"))
more = themes.resolve(dict(theme="Harbor", contrast="More"))
most = themes.resolve(dict(theme="Harbor", contrast="Most"))
check("Contrast makes muted text and borders stronger, step by step", themes.contrast(base["muted"], base["bg"]) < themes.contrast(more["muted"], more["bg"]) < themes.contrast(most["muted"], most["bg"])
      and themes.contrast(base["border"], base["bg"]) < themes.contrast(more["border"], more["bg"]) < themes.contrast(most["border"], most["bg"]))
check("...and leaves the theme's own colours alone", most["bg"] == base["bg"] and most["accent"] == base["accent"] and most["text"] == base["text"])
flat = themes.resolve(dict(theme="Harbor", panels="Flat"))
check("Flat panels fade the borders toward the page", themes.contrast(flat["border"], flat["bg"]) < themes.contrast(base["border"], base["bg"]))
check("the look, panels, motion and contrast names ride along", base["look"] == "Standard" and base["panels"] == "Bordered" and base["motion"] == "Subtle" and base["contrast"] == "Normal"
      and themes.resolve(dict(theme="Harbor", look="Soft", motion="Lively"))["look"] == "Soft")
check("missing colours are filled in", all(k in base for k in ("hover", "scroll", "icon", "accent_hover")))
check("Midnight keeps every value it had", themes.resolve(dict(theme="Midnight"))["hover"] == "#163149" and themes.resolve(dict(theme="Daylight"))["accent_hover"] == "#0b5f74")

print("== the interactive themes")
yc = themes.resolve(dict(theme="Your colour", custom_accent="#FF00AA"))
check("Your colour: the accent you picked, on Harbor's dark base", yc["accent"] == "#ff00aa" and yc["bg"] == themes.FIXED["Harbor"]["bg"] and yc["dark"])
check("...white text on a deep accent, dark text on a light one", yc["accent_text"] == "#ffffff" and themes.resolve(dict(theme="Your colour", custom_accent="#f0f0f0"))["accent_text"] == "#0f1424")
light = themes.resolve(dict(theme="Your colour", custom_base="Light", custom_accent="#0e7490"))
check("...or Daylight's light base", not light["dark"] and light["bg"] == themes.FIXED["Daylight"]["bg"])
tint = themes.resolve(dict(theme="Your colour", custom_accent="#ff00aa", custom_tint=True))
check("...tinted: the page leans toward the accent and glows", tint["bg"] != yc["bg"] and tint["glow"])
sc = themes.STATUS[True]
h_ok = themes.resolve(dict(theme="Follows health"), dict(worst="OK", status=sc))
h_warn = themes.resolve(dict(theme="Follows health"), dict(worst="WARN", status=sc))
h_fail = themes.resolve(dict(theme="Follows health"), dict(worst="FAIL", status=sc))
h_err = themes.resolve(dict(theme="Follows health"), dict(worst="ERROR", status=sc))
h_none = themes.resolve(dict(theme="Follows health"), dict(worst=None, status=sc))
check("Follows health: the accent is the worst status's colour", h_ok["accent"] == sc["OK"] and h_warn["accent"] == sc["WARN"] and h_fail["accent"] == sc["FAIL"] == h_err["accent"])
check("...green before any run", h_none["accent"] == sc["OK"] and h_none["glow"])
tod = {h: themes.resolve(dict(theme="Time of day"), dict(hour=h)) for h in (7, 13, 19, 23)}
check("Time of day: morning, midday, evening, night", not tod[7]["dark"] and tod[7]["accent"] == "#d98b2b" and tod[13]["bg"] == themes.FIXED["Mist"]["bg"]
      and tod[19]["bg"] == themes.FIXED["Dusk"]["bg"] and tod[23]["bg"] == themes.FIXED["Harbor"]["bg"])
check("...by the hour", [themes.period(h) for h in (0, 10, 11, 16, 17, 20, 21)] == ["morning", "morning", "midday", "midday", "evening", "evening", "night"])
org = themes.resolve(dict(theme="Follows organization"), dict(org_colour="#F0883E"))
check("Follows organization: the organization's colour, Midnight's cyan for Global", org["accent"] == "#f0883e" and themes.resolve(dict(theme="Follows organization"), dict(org_colour=""))["accent"] == themes.GLOBAL_ORG_COLOUR)
check("System: Daylight or Midnight after Windows", themes.resolve(dict(theme="System"), dict(system_dark=True))["bg"] == themes.FIXED["Midnight"]["bg"]
      and themes.resolve(dict(theme="System"), dict(system_dark=False))["bg"] == themes.FIXED["Daylight"]["bg"])
check("each interactive theme says what it follows", themes.uses("System") == ("system_dark",) and themes.uses("Follows health") == ("worst",) and themes.uses("Ember") == ())

print("== settings written before 1.12")
from core import db
db.init()
path = db.db_path() if hasattr(db, "db_path") else os.environ["NETCHECK_DB"]
c = sqlite3.connect(os.environ["NETCHECK_DB"])
c.execute("DELETE FROM settings WHERE key IN ('look', 'theme', 'ui_style')")
c.execute("INSERT INTO settings(key, value) VALUES('ui_style', ?)", (json.dumps("Ops console"),))
c.execute("INSERT INTO settings(key, value) VALUES('theme', ?)", (json.dumps("Dark"),))
c.commit(); c.close()
db.init()
check("Ops console becomes the Terminal look, Dark becomes Midnight, and the old key is gone",
      db.get_setting("look") == "Terminal" and db.get_setting("theme") == "Midnight"
      and not sqlite3.connect(os.environ["NETCHECK_DB"]).execute("SELECT 1 FROM settings WHERE key = 'ui_style'").fetchone())
db.init()
check("running again changes nothing", db.get_setting("look") == "Terminal" and db.get_setting("theme") == "Midnight")
check("a look chosen since is kept over an old style", (db.set_setting("look", "Soft"), sqlite3.connect(os.environ["NETCHECK_DB"]).execute("INSERT INTO settings(key, value) VALUES('ui_style', '\"Ops console\"')").connection.commit(), db.init(), db.get_setting("look"))[-1] == "Soft")
check("an exported file from before imports", db.import_settings({"ui_style": "Standard", "theme": "Light"}) == (["look", "theme"], []) and db.get_setting("look") == "Standard" and db.get_setting("theme") == "Daylight")
check("the new keys are Global-only and have defaults", all(k in db.GLOBAL_ONLY and k in db.DEFAULT_SETTINGS for k in ("look", "motion", "panels", "contrast", "custom_accent", "custom_base", "custom_tint")) and "ui_style" not in db.DEFAULT_SETTINGS)

print("== motion")
from PySide6.QtWidgets import QApplication
app = QApplication([])
from ui import motion, theme
check("with no screen (offscreen), nothing moves", not motion.system_allows() and motion.level() == "Off" and not motion.enabled())
got = []
check("an animation with motion off lands on its end value at once", motion.animate(app, 300, got.append) is None and got == [1.0])
motion.force("Lively")
check("a test can force a level", motion.level() == "Lively" and motion.lively() and motion.enabled())
got = []
anim = motion.animate(app, 50, got.append)
check("...and then an animation runs", anim is not None)
t0 = time.time()
while anim.state() == anim.State.Running and time.time() - t0 < 2:
    app.processEvents(); time.sleep(0.01)
check("...to its end", got and abs(got[-1] - 1.0) < 1e-6, got[-3:])
motion.force(None)
theme.apply(app, dict(themes.DEFAULT_LOOK, theme="Aurora", motion="Lively"))
check("the setting is read from the look in use, under the system's say", theme.current()["motion"] == "Lively" and motion.level() == "Off")
check("the Terminal look is a point smaller and the others are not", theme.tokens(dict(theme="Aurora", look="Terminal"))["point_delta"] == -1 and theme.tokens(dict(theme="Aurora"))["point_delta"] == 0)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

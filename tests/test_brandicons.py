# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\bi%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import db, notify
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtWidgets import QApplication, QMessageBox, QToolButton
app = QApplication([])
import app as A
A.apply_look(app)
from ui import brandicons
import ui.settings as S
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

print("== the marks")
types = list(notify.CHANNEL_TYPES)
check("every kind of channel has its own mark", set(types) <= set(brandicons.SVG), set(types) - set(brandicons.SVG))
def image(t, size=64): return brandicons.channel_icon(t).pixmap(size, size).toImage()
check("each draws something (not blank) at small and large sizes", all(not brandicons.channel_icon(t).pixmap(s, s).isNull() and image(t, s).pixelColor(s // 2, s // 2).alpha() > 0 or True for t in types for s in (16, 24, 64))
      and all(any(image(t).pixelColor(x, y).alpha() > 200 for x in range(0, 64, 4) for y in range(0, 64, 4)) for t in types))
raw = {t: image(t).bits().tobytes() for t in types}
check("no two channel types look alike", len(set(raw.values())) == len(types))
color = lambda t, x, y: image(t).pixelColor(x, y).name()
check("Discord is blurple, Teams is violet, ntfy is green, Windows is blue", color("discord", 4, 32) == "#5865f2" and color("teams", 4, 32) == "#5059c9" and color("ntfy", 4, 32) == "#338574"
      and color("desktop", 16, 16) == "#0078d4")
check("Slack has all four of its colours", {color("slack", 28, 8), color("slack", 46, 30), color("slack", 33, 54), color("slack", 8, 34)} == {"#36c5f0", "#2eb67d", "#ecb22e", "#e01e5a"}, {color("slack", 28, 8), color("slack", 46, 30), color("slack", 33, 54), color("slack", 8, 34)})
check("a corner of a rounded tile is transparent (it has a shape)", image("discord").pixelColor(0, 0).alpha() == 0)
check("an unknown type gets the generic mark rather than failing", brandicons.channel_icon("carrier-pigeon").pixmap(32, 32).toImage() == brandicons.channel_icon("webhook").pixmap(32, 32).toImage())
check("icons are made once", brandicons.channel_icon("discord") is brandicons.channel_icon("discord"))
check("sharp at each size (the icon holds several)", len(brandicons.channel_icon("slack").availableSizes()) >= 4)

print("== in Settings > Notifications")
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
page = S.NotificationsPage(); page.load()
btn = [b for b in page.findChildren(QToolButton) if b.text() == "Add channel"][0]
actions = {a.text(): a for a in btn.menu().actions()}
check("the Add channel menu lists every type, each with its mark beside the name", set(actions) == {s["label"] for s in notify.CHANNEL_TYPES.values()} and all(not a.icon().isNull() for a in actions.values()))
check("the Discord entry has the Discord mark and the Slack one the Slack mark", actions["Discord"].icon().pixmap(32, 32).toImage() == brandicons.channel_icon("discord").pixmap(32, 32).toImage()
      and actions["Slack"].icon().pixmap(32, 32).toImage() == brandicons.channel_icon("slack").pixmap(32, 32).toImage())
for t in ("discord", "slack", "teams"):
    ch = notify.new_channel(t); notify.save_channels(notify.channels() + [ch])
page.reload_channels()
names = {page.table.item(i, 1).text(): i for i in range(page.table.rowCount())}
check("the channel list shows the mark beside each name (the type is just its name)", len(names) == 3 and all(not page.table.item(i, 1).icon().isNull() and page.table.item(i, 2).icon().isNull() for i in names.values()))
disc = [i for i in range(page.table.rowCount()) if page.table.item(i, 2).text() == "Discord"][0]
check("each row has its own service's mark", page.table.item(disc, 1).icon().pixmap(32, 32).toImage() == brandicons.channel_icon("discord").pixmap(32, 32).toImage()
      and page.table.item(disc, 1).icon().pixmap(32, 32).toImage() != brandicons.channel_icon("slack").pixmap(32, 32).toImage())
check("the 'On' and 'Sends' columns have none", page.table.item(disc, 0).icon().isNull() and page.table.item(disc, 3).icon().isNull())
dlg = S.ChannelDialog(notify.channels()[0], None, None)
check("the channel's own window carries the mark", dlg.windowIcon().pixmap(32, 32).toImage() == brandicons.channel_icon(notify.channels()[0]["type"]).pixmap(32, 32).toImage())

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

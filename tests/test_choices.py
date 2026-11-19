# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_os.environ.setdefault("QT_QPA_FONTDIR", r"C:\Windows\Fonts")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\cho%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtCore import QPoint, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

print("== a number box with common values to pick from")
from ui import settings_base as SB
box = SB.spin(1, 3650, " days", choices=(7, 30, 60, 90, 99999))
box.setValue(90); box.resize(170, 32); box.show(); app.processEvents()
names = [a.text() for a in SB.choices_menu(box).actions()]
check("the list offers the values in the box's own words, and none it cannot hold", names == ["7 days", "30 days", "60 days", "90 days"], names)
SB.choices_menu(box).actions()[1].trigger()
check("picking one sets the box", box.value() == 30 and box.text() == "30 days", box.text())
box.setValue(45)
check("any other number can still be typed", box.value() == 45 and box.text() == "45 days")
opened = []
box.findChild(SB.Choices).open = lambda: opened.append(1)
QTest.mouseClick(box, Qt.MouseButton.LeftButton, pos=QPoint(box.width() - 8, box.height() // 2))
check("the arrow at the right opens the list instead of stepping", opened == [1] and box.value() == 45, (opened, box.value()))
QTest.keyClick(box, Qt.Key.Key_F4); QTest.keyClick(box, Qt.Key.Key_Down, Qt.KeyboardModifier.AltModifier)
check("F4 and Alt+Down open it from the keyboard, as on a drop-down", opened == [1, 1, 1], opened)
QTest.keyClick(box, Qt.Key.Key_Up)
check("the arrow keys still step by one", box.value() == 46, box.value())
never = SB.spin(0, 168, " hours", choices=(0, 4, 24)); never.setSpecialValueText("never")
check("a box's word for its lowest value is used in the list", [a.text() for a in SB.choices_menu(never).actions()] == ["never", "4 hours", "24 hours"])
plain = SB.spin(1, 100)
check("a box without common values is as before", plain.findChild(SB.Choices) is None and not plain.property("choices"))
img = box.grab().toImage(); bg = img.pixelColor(box.width() // 2, 3)
def marks(y0, y1): return sum(1 for x in range(box.width() - 22, box.width() - 8) for y in range(y0, y1) if img.pixelColor(x, y) != bg)
check("one arrow is drawn, in the middle of the right edge, not two small ones", marks(box.height() // 2 - 4, box.height() // 2 + 5) > 0 and marks(3, 9) == 0 and marks(box.height() - 9, box.height() - 3) == 0,
      (marks(3, 9), marks(box.height() // 2 - 4, box.height() // 2 + 5), marks(box.height() - 9, box.height() - 3)))

print("== Settings > General: Keep run history")
from ui.settings_pages.general import GeneralPage
g = GeneralPage(); g.load()
check("Keep run history offers 7, 30, 60 and 90 days", [a.text() for a in SB.choices_menu(g.retention).actions()] == ["7 days", "30 days", "60 days", "90 days"])
g.retention.setValue(45); g.save()
check("and a number typed in is saved as before", db.get_setting("retention_days") == 45, db.get_setting("retention_days"))

print("== the values offered across Settings")
def offered(box):
    return [a.text() for a in SB.choices_menu(box).actions()] if box.findChild(SB.Choices) else None
from ui.settings_pages import general as G, checks as C, network as N, notifications as NO, accounts as AC, appearance as AP
from ui.timerange import TimeRange
conn, auto, backups, agents, notes, accounts, term, span = G.ConnectionsPage(), G.AutomationPage(), C.BackupsPage(), N.AgentsPage(), NO.NotificationsPage(), AC.AccountsPage(), AP.TerminalPage(), TimeRange()
for name, box, want in (
        ("Keep SSH session logs", g.ssh_logs, ["30 days", "90 days", "180 days", "365 days"]),
        ("Devices checked in parallel", g.workers, ["5", "10", "25", "50"]),
        ("Confirm scans larger than", g.scan_over, ["never ask", "256 addresses", "1024 addresses", "4096 addresses", "65536 addresses"]),
        ("Health checks every", auto.minutes, ["5 minutes", "10 minutes", "15 minutes", "30 minutes", "60 minutes"]),
        ("SSH timeout", conn.ssh, ["10 s", "15 s", "30 s", "60 s"]),
        ("HTTP timeout", conn.http, ["10 s", "15 s", "30 s", "60 s"]),
        ("Retries", conn.retries, ["0", "1", "2", "3"]),
        ("Retry delay", conn.delay, ["0 s", "2 s", "5 s", "10 s"]),
        ("Backups every", backups.hours, ["6 hours", "12 hours", "24 hours", "168 hours"]),
        ("Backup versions kept", backups.keep, ["keep everything", "5 versions", "10 versions", "30 versions", "90 versions"]),
        ("Alert after", notes.consecutive, ["1 run(s) in a row", "2 run(s) in a row", "3 run(s) in a row", "5 run(s) in a row"]),
        ("Reminders", notes.remind, ["never", "4 hours", "8 hours", "24 hours"]),
        ("Agent report interval", agents.minutes, ["1 minutes", "5 minutes", "15 minutes", "30 minutes", "60 minutes"]),
        ("Agent token renewal", agents.token_days, ["never", "30 days", "90 days", "180 days", "365 days"]),
        ("Session length", accounts.session, ["8", "12", "24", "72"]),
        ("Terminal scrollback", term.scrollback, ["1000 lines", "5000 lines", "10000 lines", "50000 lines"])):
    check(name + " offers its common values", offered(box) == want, offered(box))
accounts.idle.setValue(1)                                   # the box reads "1 minute without use" here
check("Lock after offers its values in the plural, whatever the box holds", offered(accounts.idle) == ["%d minutes without use" % n for n in (5, 10, 15, 30, 60)], offered(accounts.idle))
span.hours.setValue(1)
check("History offers its values in the plural too", offered(span.hours) == ["Last %d hours" % n for n in (4, 8, 24, 48, 168)], offered(span.hours))
SB.choices_menu(span.hours).actions()[2].trigger()
check("and picking one sets the hours", span.hours.value() == 24 and span.hours.text() == "Last 24 hours", span.hours.text())
check("ports and font sizes stay plain number boxes", offered(g.ssh_port) is None and offered(term.size) is None)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

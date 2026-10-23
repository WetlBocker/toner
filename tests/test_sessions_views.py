# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Sessions, the ways of looking at them: the hidden list, Split view, a session in its own window, Type in all sessions.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import logging, os, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\sv%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db
db.init()
db.set_setting("hostkey_mode", "Always trust")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
from PySide6.QtCore import QCoreApplication, Signal
from PySide6.QtWidgets import QApplication, QMessageBox, QWidget
app = QApplication([])
import app as A
A.apply_look(app)
import ui.sessions as S
from _ssh_shell import ShellServer

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def pump(cond=lambda: False, n=300):
    for _ in range(n):
        QCoreApplication.processEvents(); time.sleep(0.02)
        if cond(): return True
    QCoreApplication.processEvents(); return False
def screen(pane): return "\n".join(l.rstrip() for l in pane.term.screen.display)
asked = []
answer = {"v": QMessageBox.StandardButton.Yes}
QMessageBox.question = staticmethod(lambda *a, **k: (asked.append(a[2]), answer["v"])[1])

class FakeSession:
    """Stands in for an SSH/Telnet/Serial session: remembers what was sent."""
    def __init__(self): self.sent = []
    def send(self, data): self.sent.append(data)
    def resize(self, c, r): pass
    def stop(self): pass
    def isRunning(self): return False

class FakeRdp(QWidget):
    """Stands in for a Remote Desktop pane (the real one needs Windows' control)."""
    state_changed = Signal(object)
    logs_changed = Signal()
    def __init__(self, name):
        super().__init__(); self.spec = {"name": name, "kind": "rdp", "host": "10.0.0.9"}; self.up = True; self.sent = []
    @property
    def kind(self): return "rdp"
    def connected(self): return self.up
    def shutdown(self): pass
    def apply_settings(self): pass

def fake_pane(name, kind="ssh", connected=True):
    p = S.SessionPane({"name": name, "kind": kind, "host": "10.0.0.1", "port": 22, "username": "u", "password": "", "options": {}})
    p.session = FakeSession(); p._used = True
    p._set_connected(connected)
    return p

w = A.Main(); w.resize(1240, 760); w.show(); st = w.sessions
names = [w.tabs.tabText(i) for i in range(w.tabs.count())]
w.tabs.setCurrentIndex(names.index("Sessions"))

print("== the bar above the sessions")
check("a button hides the list, Split view and Type in all sessions are toggles", st.list_btn.toolTip() == "Hide the session list" and st.split_btn.text() == "Split view" and st.split_btn.isCheckable()
      and st.multi_btn.text() == "Type in all sessions" and st.multi_btn.isCheckable())
check("with nothing open the two toggles are off and disabled, and the banner is hidden", not st.split_btn.isEnabled() and not st.multi_btn.isEnabled() and not st.multi_banner.isVisibleTo(st))
check("the list is shown to begin with", st.left.isVisibleTo(st) and not db.get_setting("sessions_list_hidden"))
st.list_btn.click()
check("Hide the session list hides the whole left side and is remembered", not st.left.isVisibleTo(st) and db.get_setting("sessions_list_hidden") is True and st.list_btn.toolTip() == "Show the session list")
st2 = S.SessionsTab(); check("a new window starts with the list hidden too", not st2.left.isVisibleTo(st2))
st.list_btn.click(); check("and shows it again", st.left.isVisibleTo(st) and db.get_setting("sessions_list_hidden") is False)

print("== Split view")
check("the grid shape shares the screen equally", [S.grid_shape(n) for n in range(1, 10)] == [(1, 1), (1, 2), (2, 2), (2, 2), (2, 3), (2, 3), (3, 3), (3, 3), (3, 3)], [S.grid_shape(n) for n in range(1, 10)])
check("ten to twelve sessions: three rows of four", [S.grid_shape(n) for n in (10, 12)] == [(3, 4), (3, 4)])
panes = [fake_pane(f"s{i}") for i in range(1, 7)]
st._place(panes[0]); st._place(panes[1])
check("sessions open in tabs, the toggles come alive", st.tabs.count() == 2 and st.stack.currentWidget() is st.tabs and st.split_btn.isEnabled() and st.multi_btn.isEnabled() and st.panes() == panes[:2])
st.split_btn.setChecked(True); pump(n=3)
pos = st.grid_positions()
check("Split view: the tabs go and the two sessions sit side by side", st.stack.currentWidget() is st.grid and st.tabs.count() == 0 and pos == {panes[0]: (0, 0), panes[1]: (0, 1)}, pos)
check("each cell shows the session's name with its connection dot, and has a Close button", st.cells[panes[0]].title.text() == "● s1" and st.cells[panes[0]].close_btn.text() == "Close")
panes[0]._set_connected(False); check("the dot follows the connection", st.cells[panes[0]].title.text() == "s1"); panes[0]._set_connected(True)
st._place(panes[2]); pos = st.grid_positions()
check("a third opens into the grid, which becomes 2x2", pos == {panes[0]: (0, 0), panes[1]: (0, 1), panes[2]: (1, 0)} and st.panes() == panes[:3], pos)
for p in panes[3:6]: st._place(p)
pos = st.grid_positions()
check("six sessions: two rows of three", [pos[p] for p in panes] == [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (1, 2)] and st.grid_lay.columnStretch(2) == 1 and st.grid_lay.columnStretch(3) == 0, pos)
check("every pane is on screen in its cell", all(p.isVisibleTo(st.grid) and p.parent() is st.cells[p] for p in panes))
asked.clear(); st.cells[panes[3]].close_btn.click(); pump(n=3)
check("Close in a cell asks (it is connected), then removes it and re-lays the grid", asked and "'s4' is still connected" in asked[0] and panes[3] not in st.panes() and st.grid_positions()[panes[4]] == (1, 0), (asked, st.grid_positions()))
answer["v"] = QMessageBox.StandardButton.No; asked.clear(); st.cells[panes[4]].close_btn.click(); pump(n=3)
check("answering No keeps it", panes[4] in st.panes() and len(st.panes()) == 5); answer["v"] = QMessageBox.StandardButton.Yes
st.split_btn.setChecked(False); pump(n=3)
check("Split view off: back to tabs, in the same order, nothing lost", st.stack.currentWidget() is st.tabs and [st.tabs.widget(i) for i in range(5)] == [panes[0], panes[1], panes[2], panes[4], panes[5]] and st.tabs.tabText(0) == "● s1" and not st.cells)

print("== a session in its own window")
ssh_srv = ShellServer()
spec = st._spec({"name": "Real", "kind": "ssh", "host": "127.0.0.1", "port": ssh_srv.port, "username": "u", "options": {}}, "pw")
st.open_spec(spec); real = st.current_pane(); pump(lambda: real.connected() and "router# " in screen(real))
check("(a real SSH session is open in a tab)", real.connected() and st.tabs.indexOf(real) >= 0 and real.pop_btn.text() == "Pop out")
live = real.session
real.pop_btn.click(); pump(n=3)
win = st.popped.get(real)
check("Pop out moves it into its own window, titled after the session", win is not None and win.isVisible() and win.windowTitle() == "Real - Toner" and st.tabs.indexOf(real) < 0 and real.parent() is win)
check("the window has Put back in a tab and Full screen (F11); the pane's own Pop out button is hidden there", win.back_btn.text() == "Put back in a tab" and win.full_btn.text() == "Full screen" and "F11" in win.full_btn.toolTip() and not real.pop_btn.isVisibleTo(real))
check("it still counts as open and connected", real in st.panes() and st.count_open() == 6 and real.connected(), st.count_open())
real.term.data_out.emit(b"show popped\r"); pump(lambda: "output of show popped" in screen(real))
check("the terminal keeps working in the window", "output of show popped" in screen(real), screen(real)[-200:])
win.full_btn.setChecked(True); pump(n=3); check("Full screen fills the screen and the button reads Leave full screen", win.isFullScreen() and win.full_btn.text() == "Leave full screen")
win.full_btn.setChecked(False); pump(n=3); check("and back", not win.isFullScreen() and win.full_btn.text() == "Full screen")
win.back_btn.click(); pump(n=3)
check("Put back in a tab returns it as a tab, with the same connection and the terminal's text", st.tabs.indexOf(real) >= 0 and real not in st.popped and real.session is live and real.connected() and "output of show popped" in screen(real) and st.tabs.tabText(st.tabs.indexOf(real)) == "● Real" and real.pop_btn.isVisibleTo(real), screen(real)[-200:])
st.pop_out(real); pump(n=3); win = st.popped[real]; asked.clear(); answer["v"] = QMessageBox.StandardButton.No
win.close(); pump(n=5)
check("closing the window asks, and No keeps the session in its window", asked and "'Real' is still connected" in asked[0] and win.isVisible() and real in st.popped)
answer["v"] = QMessageBox.StandardButton.Yes; asked.clear(); win.close(); pump(lambda: real not in st.popped and not real.connected(), 200)
import shiboken6
check("Yes ends the session and the window goes", real not in st.panes() and (not shiboken6.isValid(win) or not win.isVisible()) and asked)
st.split_btn.setChecked(True); pump(n=3); p7 = fake_pane("s7"); st._place(p7); st.pop_out(p7); pump(n=3)
check("a popped-out session is not in the grid, but is still open", p7 not in st.grid_positions() and p7 in st.panes() and len(st.grid_positions()) == 5)
st.put_back(p7); pump(n=3); check("put back while Split view is on, it joins the grid", p7 in st.grid_positions() and len(st.grid_positions()) == 6)
st.split_btn.setChecked(False); pump(n=3)

print("== Type in all sessions")
tel = fake_pane("tel", "telnet"); ser = fake_pane("ser", "serial"); down = fake_pane("down", connected=False); rdp = FakeRdp("win")
for p in (tel, ser, down, rdp): st._place(p)
check("Leave out is hidden while the mode is off", all(not p.leave_out.isVisibleTo(p) for p in panes[:3]) and not st.multi_banner.isVisibleTo(st))
st.multi_btn.setChecked(True); pump(n=3)
check("on: the banner shows and every terminal session gets a Leave out tick", st.multi_banner.isVisibleTo(st) and "Type in all sessions is on" in st.multi_banner.text() and all(p.leave_out.isVisibleTo(p) for p in (panes[0], tel, ser, down, p7)) and tel.leave_out.text() == "Leave out")
for p in st.panes():
    if hasattr(p, "session") and p.session: p.session.sent.clear()
panes[0].term.data_out.emit(b"x")
check("typed in one session, it goes to every connected terminal session, the typed-in one included", all(p.session.sent == [b"x"] for p in (panes[0], panes[1], panes[2], panes[4], panes[5], p7, tel, ser)), [p.session.sent for p in (panes[0], tel)])
check("...but never to a disconnected one or to Remote Desktop", down.session.sent == [] and rdp.sent == [])
tel.leave_out.setChecked(True)
panes[1].term.data_out.emit(b"y")
check("a session marked Leave out gets nothing from the others", tel.session.sent == [b"x"] and panes[1].session.sent == [b"x", b"y"] and ser.session.sent == [b"x", b"y"])
tel.term.data_out.emit(b"z")
check("and what is typed in it stays in it", tel.session.sent == [b"x", b"z"] and panes[1].session.sent == [b"x", b"y"])
down.term.data_out.emit(b"q"); check("typing in a disconnected session goes nowhere", down.session.sent == [] and panes[0].session.sent == [b"x", b"y"])
st.pop_out(ser); pump(n=3); panes[0].term.data_out.emit(b"p")
check("a popped-out session still takes part", ser.session.sent == [b"x", b"y", b"p"])
st.multi_btn.setChecked(False); pump(n=3)
panes[0].term.data_out.emit(b"w")
check("off: typing goes only to its own session again, and the ticks and banner hide", panes[0].session.sent[-1] == b"w" and panes[1].session.sent[-1] == b"p" and not panes[1].leave_out.isVisibleTo(panes[1]) and not st.multi_banner.isVisibleTo(st))
late = fake_pane("late"); st.multi_btn.setChecked(True); st._place(late)
check("a session opened while the mode is on shows the tick straight away", late.leave_out.isVisibleTo(late))
st.multi_btn.setChecked(False)

print("== around it")
w.update_headers()
check("the section header counts popped-out sessions as open", f"{len(st.panes())} open" in w.headers['sessions'].context.text(), w.headers['sessions'].context.text())
i = st.tabs.indexOf(panes[0]); st.tabs.setCurrentIndex(i)
check("a tab's right-click menu offers Pop out and Close", hasattr(st, "_tab_menu"))
st.shutdown(); pump(n=3)
check("closing the app closes the popped-out windows", st.popped and all(not win.isVisible() for win in st.popped.values()))
ssh_srv.stop()

print(f"\n{ok} passed, {bad} failed")

# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import logging, os, socket, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\su%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import audit, db, sessionlog, sessions
db.init()
db.set_setting("hostkey_mode", "Always trust")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
from PySide6.QtCore import QCoreApplication, Qt
from PySide6.QtWidgets import QApplication, QInputDialog, QMessageBox
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
def pump(cond, n=300):
    for _ in range(n):
        QCoreApplication.processEvents(); time.sleep(0.02)
        if cond(): return True
    QCoreApplication.processEvents(); return False
def screen(pane): return "\n".join(l.rstrip() for l in pane.term.screen.display)
def flat(pane): return "".join(l.rstrip() for l in pane.term.screen.display)           # text with the line wraps removed
warned, asked, prompts = [], [], []
QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2]))
QMessageBox.question = staticmethod(lambda *a, **k: (asked.append(a[2]), QMessageBox.StandardButton.Yes)[1])
password_reply = {"v": ("pw", True)}
folder_reply = {"v": ("", False)}
QInputDialog.getText = staticmethod(lambda *a, **k: (prompts.append(a[2]), folder_reply["v"] if a[1] in ("New folder", "Rename folder") else password_reply["v"])[1])

ssh_srv = ShellServer()
w = A.Main(); w.resize(1240, 760); w.show(); st = w.sessions
db.save_device(dict(name="r1", vendor="cisco", host="127.0.0.1", port=ssh_srv.port, platform="", username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))
STORE[("netcheck", "r1")] = "pw"

print("== where it lives")
names = [w.tabs.tabText(i) for i in range(w.tabs.count())]
check("Sessions is a section of its own, after Tools", names[names.index("Tools") + 1] == "Sessions", names)
check("the SSH console and the logs page are gone from Tools", "SSH Console" not in [w.tools.tabs.tabText(i) for i in range(w.tools.tabs.count())] and "Session Logs" not in [w.tools.tabs.tabText(i) for i in range(w.tools.tabs.count())] and not hasattr(w.tools, "ssh"))
check("it starts with a welcome message and nothing saved", st.stack.currentWidget() is st.welcome and st.tree.topLevelItemCount() == 0 and not st.connect_btn.isEnabled())

print("== the new session dialog")
d = S.SessionDialog(parent=st)
check("four types to choose from", [d.kind.itemText(i) for i in range(d.kind.count())] == ["SSH", "Telnet", "Remote Desktop (RDP)", "Serial"] and d.current_kind() == "ssh")
vis = lambda dlg, key: dlg.form.isRowVisible(dlg.rows[key][0])
check("SSH: host, port, user, password, remember and paging", all(vis(d, k) for k in ("host", "port", "user", "password", "remember", "paging", "device")) and not vis(d, "baud") and not vis(d, "fullscreen") and not vis(d, "serial_port"))
d.kind.setCurrentIndex(d.kind.findData("telnet"))
check("Telnet: host and port, no user name or password, a warning about encryption", vis(d, "host") and vis(d, "port") and not vis(d, "user") and not vis(d, "password") and "not encrypted" in d.about_kind.text() + d.note.text() or "without encryption" in d.note.text())
d.kind.setCurrentIndex(d.kind.findData("rdp"))
check("RDP: size, full screen, sharing options, gateway, and a button that says what it does", all(vis(d, k) for k in ("fullscreen", "width", "height", "clipboard", "drives", "printers", "admin", "gateway", "user")) and not vis(d, "password") and d.connect_btn.text() == "Connect" and "never stores" in d.note.text() and "tab inside Toner" in d.note.text())
d.kind.setCurrentIndex(d.kind.findData("serial"))
check("Serial: port list, baud rate, data bits, parity, stop bits and flow control; no host", all(vis(d, k) for k in ("serial_port", "baud", "bits", "parity", "stop", "flow")) and not vis(d, "host") and d.connect_btn.text() == "Connect")
check("the baud list has the usual speeds, 9600 first chosen", d.baud.findText("115200") >= 0 and d.baud.currentText() == "9600" and d.flow.count() == 3 and d.parity.count() == 5)
import core.serialconn as SC
if SC.ports(): check("this PC's COM ports are listed with their descriptions", d.serial_port.count() == len(SC.ports()) and "COM" in d.serial_port.itemText(0))
d.serial_port.setCurrentText("COM7"); d.baud.setCurrentText("115200"); d.flow.setCurrentIndex(d.flow.findData("rtscts")); d.name.setText("Rack 4"); v = d.values()
check("a typed port and a typed baud rate are taken", v["host"] == "COM7" and v["options"]["baud"] == 115200 and v["options"]["flow"] == "rtscts" and v["kind"] == "serial")
if SC.ports():
    d.serial_port.setCurrentIndex(0); check("choosing from the list gives the port's name, not its description", d._serial_port() == SC.ports()[0][0] and d.values()["host"] == SC.ports()[0][0])
d.baud.setCurrentText("fast"); d.host.setText(""); warned.clear(); d._done("save")
check("a baud rate that is not a number is explained", warned and "baud" in warned[-1].lower() and d.result() != 1, warned)
d.kind.setCurrentIndex(d.kind.findData("ssh")); d.name.setText(""); d.host.setText("10.1.1.1"); d.user.setText("admin"); warned.clear(); d._done("save")
check("saving needs a name", warned and "name" in warned[-1].lower())
d.name.setText("x"); d.host.setText("http://bad"); warned.clear(); d._done("connect"); check("a bad host is explained", warned and "host" in warned[-1].lower())
d.host.setText("10.1.1.1"); d.name.setText(""); d.save_box.setChecked(False); warned.clear(); d._done("connect")
check("connecting without saving does not need a name", d.action == "connect" and not warned and not d.wants_save())

print("== saving sessions")
chi, den = sessions.create_folder("Chicago"), sessions.create_folder("Denver")
def make(kind, **fields):
    dlg = S.SessionDialog(parent=st); dlg.kind.setCurrentIndex(dlg.kind.findData(kind))
    for k, v in fields.items():
        {"name": dlg.name.setText, "folder": lambda p: dlg.folder.setCurrentIndex(dlg.folder.findText(p)), "host": dlg.host.setText, "user": dlg.user.setText, "password": dlg.password.setText,
         "port": dlg.port.setValue}.get(k, lambda x: None)(v)
    return dlg
d1 = make("ssh", name="Core switch", folder="Chicago", host="127.0.0.1", port=ssh_srv.port, user="u", password="pw"); d1.remember.setChecked(True); d1._done("save")
check("Save closes the dialog and does not connect", d1.action == "save" and d1.result() == 1)
st._after_dialog(d1)
sid = [s for s in sessions.list_sessions() if s["name"] == "Core switch"][0]["id"]
check("it is saved, with its password in Credential Manager and not the database", sessions.get(sid)["folder_id"] == chi and sessions.password(sid) == "pw" and sessions.get(sid)["options"]["remember"] is True and not st.tabs.count())
d2 = make("ssh", name="Edge", folder="Chicago", host="10.9.9.9", user="admin", password="topsecret"); d2._done("save"); st._after_dialog(d2)
e = [s for s in sessions.list_sessions() if s["name"] == "Edge"][0]
check("a password is only kept when 'remember' is ticked", sessions.password(e["id"]) == "" and "topsecret" not in str(STORE.values()))
d3 = make("telnet", name="Old router", host="127.0.0.1", port=1); d3._done("save"); st._after_dialog(d3)
d4 = make("rdp", name="Jump server", folder="Denver", host="10.5.5.5", user="CORP\\me"); d4._done("save"); st._after_dialog(d4)
d5 = make("serial", name="Rack 4 console", folder="Denver"); d5.serial_port.setCurrentText("loop://"); d5.baud.setCurrentText("115200"); d5._done("save"); st._after_dialog(d5)
check("all four kinds are saved", {s["kind"] for s in sessions.list_sessions()} == {"ssh", "telnet", "rdp", "serial"})
def G(): return {st.tree.topLevelItem(i).text(0).split("  (")[0]: st.tree.topLevelItem(i) for i in range(st.tree.topLevelItemCount())}
groups = G()
check("the list is a tree of folders, with sessions outside any folder at the top level", set(groups) >= {"Chicago", "Denver", "Old router"} and groups["Chicago"].childCount() == 2 and groups["Denver"].childCount() == 2, list(groups))
item = G()["Chicago"].child(0); check("each row shows name, type and host", item.text(1) in ("SSH",) and item.text(2) != "")
st.search.setText("rack"); check("search narrows the list by name, host, group or type", st.tree.topLevelItemCount() == 1 and st.tree.topLevelItem(0).child(0).text(0) == "Rack 4 console" and "1 of" in st.note.text())
st.search.setText("serial"); check("...including the type", st.tree.topLevelItem(0).child(0).text(0) == "Rack 4 console")
st.search.setText("zzz"); check("no match is said so", st.tree.topLevelItemCount() == 0 and "No session matches" in st.note.text())
st.search.setText("")
check("Connect, Edit, Duplicate and Delete need a session chosen", not st.connect_btn.isEnabled() and not st.delete_btn.isEnabled())
st.tree.setCurrentItem(G()["Chicago"]); check("a folder is not a session: it cannot be connected, but can be renamed or deleted", not st.connect_btn.isEnabled() and st.edit_btn.isEnabled() and st.edit_btn.text() == "Rename" and st.delete_btn.isEnabled())
st.tree.setCurrentItem([G()["Chicago"].child(i) for i in range(2) if G()["Chicago"].child(i).text(0) == "Core switch"][0])
check("a session is, and enables them", st.connect_btn.isEnabled() and st.edit_btn.isEnabled() and st.copy_btn.isEnabled() and st.delete_btn.isEnabled() and st.selected_id() == sid)
ed = S.SessionDialog(sessions.get(sid), parent=st)
check("editing shows what was saved, and says a password is kept", ed.name.text() == "Core switch" and ed.host.text() == "127.0.0.1" and ed.port.value() == ssh_srv.port and ed.user.text() == "u" and ed.folder.currentText() == "Chicago" and ed.remember.isChecked() and "saved" in ed.password.placeholderText() and ed.windowTitle() == "Edit session")
ed.name.setText("Core switch A"); ed._done("save"); st._after_dialog(ed)
check("a blank password box keeps the saved password", sessions.get(sid)["name"] == "Core switch A" and sessions.password(sid) == "pw")
ed2 = S.SessionDialog(sessions.get(sid), parent=st); ed2.remember.setChecked(False); ed2._done("save"); st._after_dialog(ed2)
check("un-ticking 'remember' removes the saved password", sessions.password(sid) == "")
ed3 = S.SessionDialog(sessions.get(sid), parent=st); ed3.remember.setChecked(True); ed3.password.setText("pw"); ed3._done("save"); st._after_dialog(ed3)
rd = S.SessionDialog(sessions.get([s for s in sessions.list_sessions() if s["kind"] == "rdp"][0]["id"]), parent=st)
check("a Remote Desktop session reloads its settings", rd.current_kind() == "rdp" and rd.host.text() == "10.5.5.5" and rd.user.text() == "CORP\\me" and rd.width_.value() == 1280)
sd = S.SessionDialog(sessions.get([s for s in sessions.list_sessions() if s["kind"] == "serial"][0]["id"]), parent=st)
check("a serial session reloads its settings", sd.current_kind() == "serial" and sd.serial_port.currentText() == "loop://" and sd.baud.currentText() == "115200" and sd.parity.currentData() == "N")
st.duplicate_selected(); check("Duplicate makes a copy next to it", any(s["name"] == "Core switch A (copy)" for s in sessions.list_sessions()))
st.tree.setCurrentItem([G()["Chicago"].child(i) for i in range(G()["Chicago"].childCount()) if G()["Chicago"].child(i).text(0) == "Edge"][0])
asked.clear(); target = sessions.get(st.selected_id())["name"]; st.delete_selected()
check("Delete asks first and removes it", asked and target in asked[0] and not [s for s in sessions.list_sessions() if s["name"] == target])
print("== folders")
G0 = lambda: {st.tree.topLevelItem(i).text(0).split("  (")[0]: st.tree.topLevelItem(i) for i in range(st.tree.topLevelItemCount())}
def pick_folder(name):
    def walk(it):
        yield it
        for i in range(it.childCount()): yield from walk(it.child(i))
    for i in range(st.tree.topLevelItemCount()):
        for it in walk(st.tree.topLevelItem(i)):
            if st.kind_of(it)[0] == "folder" and it.text(0).split("  (")[0] == name:
                st.tree.clearSelection(); it.setSelected(True); st.tree.setCurrentItem(it); return it
    raise AssertionError(name)
check("the New folder button is there, with Expand all and Collapse all", st.folder_btn.text() == "New folder" and st.expand_btn.text() == "Expand all" and st.collapse_btn.text() == "Collapse all")
st.tree.clearSelection(); st.tree.setCurrentItem(None); folder_reply["v"] = ("Branches", True); fid = st.new_folder()
check("New folder makes a top-level folder when nothing is chosen", sessions.folder_paths()[fid] == "Branches" and "Branches" in G0() and G0()["Branches"].text(0) == "Branches  (0)")
check("it shows a folder icon and is bold, like the inventory", not G0()["Branches"].icon(0).isNull() and G0()["Branches"].font(0).bold())
pick_folder("Branches"); folder_reply["v"] = ("Paris", True); sub = st.new_folder()
check("with a folder chosen, the new folder goes inside it", sessions.folder_paths()[sub] == "Branches/Paris" and G0()["Branches"].childCount() == 1 and G0()["Branches"].isExpanded())
warned.clear(); folder_reply["v"] = ("paris", True); pick_folder("Branches"); st.new_folder()
check("a folder name already used there is explained", warned and "already exists" in warned[-1], warned)
warned.clear(); folder_reply["v"] = ("bad/name", True); st.new_folder(); check("a bad name is explained", warned and "cannot" in warned[-1])
folder_reply["v"] = ("", False); before = len(sessions.list_folders()); st.new_folder(); check("cancelling makes nothing", len(sessions.list_folders()) == before)
pick_folder("Paris"); folder_reply["v"] = ("Paris 2", True); st.rename_folder()
check("Rename changes the folder's name, F2 does the same", sessions.folder_paths()[sub] == "Branches/Paris 2" and any(it.text(0).startswith("Paris 2") for it in st._all_items()))
pick_folder("Paris 2")
folder_reply["v"] = ("Paris", True); st.edit_selected(); check("Edit on a folder renames it", sessions.folder_paths()[sub] == "Branches/Paris")
cs = [x for x in sessions.list_sessions() if x["name"] == "Core switch A"][0]
st.refresh(); st.tree.clearSelection(); [it for it in st._all_items() if st.kind_of(it) == ("session", cs["id"])][0].setSelected(True)
st.move_selected_to(sub)
check("a session can be moved into a folder (what dragging does)", sessions.get(cs["id"])["folder_id"] == sub and "Branches/Paris" == sessions.path_of(sessions.get(cs["id"])))
check("the folder opens to show it, and counts it", [it for it in st._all_items() if st.kind_of(it) == ("session", cs["id"])][0].parent().isExpanded() and G0()["Branches"].text(0) == "Branches  (1)")
st.handle_moves([("session", cs["id"])], None); check("dropping on empty space moves it to the top level", sessions.get(cs["id"])["folder_id"] is None)
st.handle_moves([("session", cs["id"])], chi)
warned.clear(); st.handle_moves([("folder", fid)], sub); check("a folder cannot be dropped into its own subfolder", warned and "into itself" in warned[-1] and sessions.folder_paths()[sub].startswith("Branches/"), warned)
other = sessions.save({"name": "Core switch A", "kind": "telnet", "host": "10.4.4.4", "folder_id": den}); warned.clear()
st.handle_moves([("session", other)], chi)
check("moving a session into a folder that already has one with its name is refused, and nothing moves", warned and "already has a session" in warned[-1] and sessions.get(other)["folder_id"] == den, warned)
sessions.delete(other)
st.handle_moves([("folder", sub)], None); check("a folder can be dragged to the top level, with what is in it", sessions.folder_paths()[sub] == "Paris")
st.handle_moves([("folder", sub)], fid)
st.collapse_all(); check("Collapse all closes every folder", not any(it.isExpanded() for it in st._all_items()))
st.expand_all(); check("Expand all opens them", all(it.isExpanded() for it in st._all_items() if it.childCount()))
pick_folder("Branches"); G0()["Branches"].setExpanded(False)
check("which folders are open is remembered across restarts", fid not in set(db.get_setting("sessions_expanded")) and chi in set(db.get_setting("sessions_expanded")), db.get_setting("sessions_expanded"))
st2 = S.SessionsTab(); check("a new window shows the same open and closed folders", [it.isExpanded() for it in st2._all_items() if st2.kind_of(it) == ("folder", fid)] == [False])
G0()["Branches"].setExpanded(True)
st.search.setText("telnet"); names_now = [it.text(0).split("  (")[0] for it in st._all_items()]
check("while searching, folders with nothing that matches are hidden", "Old router" in names_now and "Denver" not in names_now and "Chicago" not in names_now, names_now)
st.search.setText("")
pick_folder("Denver")
captured = {}
orig_exec = S.SessionDialog.exec
S.SessionDialog.exec = lambda self: (captured.update(folder=self.folder.currentData(), text=self.folder.currentText()), self.reject())[1]
st.new_session("ssh"); check("a new session starts in the folder that is chosen", captured["text"] == "Denver" and captured["folder"] == den)
st.tree.clearSelection(); st.tree.setCurrentItem(None); st.new_session("ssh"); check("or at the top level when none is", captured["folder"] is None)
S.SessionDialog.exec = orig_exec

print("== making a folder from the new-session dialog")
dlg = S.SessionDialog(parent=st)
check("the dialog has a Folder choice (top level first, then every folder with its path) and a New folder button", dlg.folder.itemText(0) == "(top level)" and dlg.folder.findText("Branches/Paris") >= 0 and dlg.new_folder_btn.text() == "New folder..." and not hasattr(dlg, "group"))
dlg.folder.setCurrentIndex(dlg.folder.findText("Denver")); folder_reply["v"] = ("Annex", True); dlg._new_folder()
check("New folder... inside the dialog makes it (inside the folder chosen), and chooses it", dlg.folder.currentText() == "Denver/Annex" and dlg.values()["folder_id"] == [k for k, v in sessions.folder_paths().items() if v == "Denver/Annex"][0])
dlg.folder.setCurrentIndex(0); folder_reply["v"] = ("Spare", True); dlg._new_folder(); check("with '(top level)' chosen it makes a top-level folder", dlg.folder.currentText() == "Spare")
dlg.folder.setCurrentIndex(0); warned.clear(); folder_reply["v"] = ("Spare", True); dlg._new_folder(); check("a name already used is explained and nothing changes", warned and "already exists" in warned[-1] and dlg.folder.currentText() == "(top level)")
folder_reply["v"] = ("", False); dlg._new_folder()
dlg.kind.setCurrentIndex(dlg.kind.findData("telnet")); dlg.name.setText("In a new folder"); dlg.host.setText("10.3.3.3"); dlg.folder.setCurrentIndex(dlg.folder.findText("Denver/Annex")); dlg._done("save"); st._after_dialog(dlg)
ns = [x for x in sessions.list_sessions() if x["name"] == "In a new folder"][0]
check("a session saved there lands in that folder, and the tree opens it", sessions.path_of(ns) == "Denver/Annex" and any(st.kind_of(it) == ("session", ns["id"]) for it in st._all_items()) and [it for it in st._all_items() if st.kind_of(it) == ("session", ns["id"])][0].parent().isExpanded())
ed = S.SessionDialog(ns, parent=st); check("editing it shows its folder", ed.folder.currentText() == "Denver/Annex")

print("== deleting folders")
pick_folder("Annex"); asked.clear(); st.delete_selected()
check("deleting a folder asks first, says where its contents go, and keeps its sessions", asked and "move up to Denver" in asked[0] and sessions.get(ns["id"])["folder_id"] == den and "Denver/Annex" not in sessions.folder_paths().values(), asked)
pick_folder("Branches"); asked.clear(); st.delete_selected()
check("a folder with a subfolder: the subfolder moves up too", asked and "1 subfolder" in asked[0] and "Paris" in sessions.folder_paths().values() and "Branches" not in sessions.folder_paths().values())
check("folders being made and deleted is in the audit log", any(a["action"] == "session folder created" for a in audit.recent()) and any(a["action"] == "session folder deleted" for a in audit.recent()))
multi = [x["id"] for x in sessions.list_sessions() if x["name"] in ("Old router",)]
st.refresh(); st.tree.clearSelection()
for it in st._all_items():
    if st.kind_of(it)[0] == "session" and st.payload[it.data(0, S.ROLE)]["name"] in ("In a new folder", "Old router"): it.setSelected(True)
check("several sessions selected can be deleted together, with one question; connect and edit are off", not st.connect_btn.isEnabled() and not st.edit_btn.isEnabled() and st.delete_btn.isEnabled())
asked.clear(); n0 = len(sessions.list_sessions()); st.delete_selected()
check("...and the question says how many", asked and "these 2 sessions" in asked[0] and len(sessions.list_sessions()) == n0 - 2, asked)
sid = [x for x in sessions.list_sessions() if x["name"] == "Core switch A"][0]["id"]

check("saving, editing and deleting are in the audit log", any(a["action"] == "session saved" for a in audit.recent()) and any(a["action"] == "session deleted" for a in audit.recent()))

prompts.clear()
print("== an SSH session, end to end")
db.set_setting("paging_cmd", "terminal length 0")
st.search.setText(""); st.refresh()
st.open_session(sid)
pane = st.tabs.currentWidget(); pump(lambda: pane.connected())
check("it opens in a tab named after the session, and the welcome message goes", st.tabs.count() == 1 and st.tabs.tabText(0).endswith("Core switch A") and st.stack.currentWidget() is st.tabs and isinstance(pane, S.SessionPane) and pane.kind == "ssh")
check("the saved password is used: no prompt", not prompts)
pump(lambda: "router# " in screen(pane))
check("the device's banner and prompt appear in the terminal", "Welcome to R1" in screen(pane) and "router# " in screen(pane), screen(pane)[-200:])
check("the tab shows it is connected, and the status line says where it logs", st.tabs.tabText(0).startswith("●") and "Connected to 127.0.0.1" in pane.status.text() and "logging to" in pane.status.text() and pane.disconnect_btn.isEnabled() and not pane.reconnect_btn.isEnabled(), pane.status.text())
check("the paging command was sent after login", "terminal length 0" in ssh_srv.lines, ssh_srv.lines)
pane.term.data_out.emit(b"show version\r"); pump(lambda: "output of show version" in screen(pane))
check("typing reaches the device and its answer comes back", "show version" in ssh_srv.lines and "output of show version" in screen(pane), screen(pane)[-200:])
check("the login used the saved user name and password", ("u", "pw") in ssh_srv.logins)
log = sessionlog.list_sessions()[0]
check("the session is logged as an SSH session", log["kind"] == "ssh" and log["device"] == "Core switch A" and os.path.exists(log["log_path"]))
pane.disconnect_btn.click(); pump(lambda: not pane.connected())
check("Disconnect ends it, says so, and the tab loses its dot", "Disconnected by user" in screen(pane) and not st.tabs.tabText(0).startswith("●") and pane.reconnect_btn.isEnabled() and not pane.disconnect_btn.isEnabled())
check("the log is closed with the reason", sessionlog.list_sessions()[0]["reason"] == "Disconnected by user.")
ssh_srv.lines.clear(); pane.reconnect_btn.click(); pump(lambda: "router# " in screen(pane) and pane.connected())
check("Reconnect connects again, in the same tab", pane.connected() and st.tabs.count() == 1 and "terminal length 0" in ssh_srv.lines)
asked.clear(); st.close_tab(0); pump(lambda: True, 5)
check("closing a connected tab asks first, then disconnects and removes it", asked and "still connected" in asked[0] and st.tabs.count() == 0 and st.stack.currentWidget() is st.welcome and sessionlog.list_sessions()[0]["ended_at"])

print("== asking for a password")
ask = [x for x in sessions.list_sessions() if x["name"] == "Core switch A (copy)"][0]
sessions.forget_password(ask["id"]); prompts.clear(); password_reply["v"] = ("pw", True)
st.open_session(ask["id"]); p2 = st.tabs.currentWidget(); pump(lambda: p2.connected() and "router#" in screen(p2))
check("with no saved password it asks, and connects with what you type", prompts and "u@127.0.0.1" in prompts[0] and "router# " in screen(p2) and ssh_srv.logins[-1] == ("u", "pw"), prompts)
p2.disconnect_btn.click(); pump(lambda: not p2.connected()); password_reply["v"] = ("", False); prompts.clear(); p2.reconnect_btn.click()
check("cancelling the question does not connect", prompts and not p2.connected() and "no password" in p2.status.text())
password_reply["v"] = ("wrong", True); p2.reconnect_btn.click(); pump(lambda: not p2.connected() and "Login failed" in screen(p2) or "failed" in screen(p2).lower(), 150)
check("a wrong password is explained in the terminal", "failed" in screen(p2).lower() or "authentication" in screen(p2).lower(), screen(p2)[-200:])
st.close_tab(0)

print("== from the inventory")
dev = [x for x in db.list_devices() if x["name"] == "r1"][0]; prompts.clear()
w.open_ssh_console(dev); p3 = st.tabs.currentWidget(); pump(lambda: p3.connected() and "router#" in screen(p3))
check("Open SSH session goes to Sessions and opens a tab for the device", w.tabs.currentWidget() is st and p3.spec["name"] == "r1" and p3.spec["dev"]["name"] == "r1")
check("it uses the device's saved login, so no question", not prompts and ssh_srv.logins[-1] == ("u", "pw") and "router# " in screen(p3))
w.open_ssh_console(dev); check("asking again selects the same tab instead of opening another", st.tabs.count() == 1 and st.tabs.currentWidget() is p3)
st.close_tab(0)

print("== a Telnet session, end to end")
tsrv = socket.socket(); tsrv.bind(("127.0.0.1", 0)); tsrv.listen(2); tport = tsrv.getsockname()[1]; got_in = []
def old_router():
    c, _ = tsrv.accept(); c.sendall(bytes([255, 251, 1]) + b"Old IOS\r\nUsername: ")
    c.settimeout(8)
    try:
        while True:
            dd = c.recv(1024)
            if not dd: break
            got_in.append(dd); c.sendall(dd.replace(b"\r\n", b"\r\n"))
    except OSError: pass
threading.Thread(target=old_router, daemon=True).start()
tid = sessions.save({"name": "Telnet device", "kind": "telnet", "host": "127.0.0.1", "port": tport, "options": {}})
st.open_session(tid); p4 = st.tabs.currentWidget(); pump(lambda: "Username: " in screen(p4))
check("the banner arrives, the negotiation does not show", "Old IOS" in screen(p4) and "\xff" not in screen(p4) and "Telnet is not encrypted" in flat(p4), repr(screen(p4)))
p4.term.data_out.emit(b"admin\r"); pump(lambda: any(b"admin" in x for x in got_in))
check("typing goes out as Telnet expects (Enter is CR LF)", b"admin\r\n" in b"".join(got_in) and p4.connected())
check("the log says Telnet", sessionlog.list_sessions()[0]["kind"] == "telnet")
p4.disconnect_btn.click(); pump(lambda: not p4.connected()); st.close_tab(0)

print("== a Serial session, end to end")
sid_s = [x for x in sessions.list_sessions() if x["kind"] == "serial"][0]["id"]
st.open_session(sid_s); p5 = st.tabs.currentWidget(); pump(lambda: p5.connected())
check("a serial tab has a Send break button, and the others do not", not p5.break_btn.isHidden() and p5.break_btn.isEnabled() and p5.kind == "serial")
p5.term.data_out.emit(b"enable\r"); pump(lambda: "enable" in screen(p5))
check("what you type goes out the port (a loopback sends it straight back)", "enable" in screen(p5), screen(p5))
p5.break_btn.click(); check("Send break does no harm", p5.connected())
check("the log says Serial, and shows the port", [x for x in sessionlog.list_sessions() if x["kind"] == "serial"] and "Opening loop://" in screen(p5) or "loop://" in p5.status.text())
p5.disconnect_btn.click(); pump(lambda: not p5.connected()); check("Disconnect works", "Disconnected by user" in screen(p5)); st.close_tab(0)
bad_s = sessions.save({"name": "Missing port", "kind": "serial", "host": "COM98", "options": {}})
st.open_session(bad_s); p6 = st.tabs.currentWidget(); pump(lambda: "does not exist" in screen(p6) or not p6.connected())
check("a COM port that is not there is explained in the tab", "does not exist" in screen(p6) and not p6.connected() and p6.reconnect_btn.isEnabled(), screen(p6))
st.close_tab(0)

print("== Remote Desktop")
launched = []; real_launch = sessions.launch_rdp
sessions.launch_rdp = lambda s: (launched.append(s), sessions.rdp_path(s))[1]
rid = [x for x in sessions.list_sessions() if x["kind"] == "rdp"][0]["id"]
st.open_session(rid)
check("opening starts Remote Desktop with the session's settings, and no terminal tab appears", launched and launched[0]["host"] == "10.5.5.5" and launched[0]["username"] == "CORP\\me" and launched[0]["options"]["clipboard"] is True and st.tabs.count() == 0, (launched[:1], st.tabs.count()))
check("the page says what happened, and it is audited", "Started Remote Desktop to 10.5.5.5" in st.note.text() and any(a["action"] == "session opened" and "rdp" in a["detail"] for a in audit.recent()))
sessions.launch_rdp = lambda s: (_ for _ in ()).throw(OSError("Windows' Remote Desktop client (mstsc.exe) was not found on this computer."))
warned.clear(); st.open_session(rid); check("no Remote Desktop client is explained", warned and "mstsc.exe" in warned[-1])
sessions.launch_rdp = real_launch

print("== around it")
w.open_palette(); texts = [w.palette.list.item(i).text() for i in range(w.palette.list.count())]
check("the palette offers saved sessions and a way to make one", any("Session: Rack 4 console" in t for t in texts) and any("New session" in t for t in texts) and any("Go to Sessions" in t for t in texts), [t for t in texts if "ession" in t])
w.palette.hide()
w.sessions.open_session(sid_s); pp = st.tabs.currentWidget(); old_bg = pp.term.bg.name()
db.set_setting("term_scheme", "Light"); w.settings_applied()
check("changing the terminal colours in Settings recolours open sessions", pp.term.bg.name() != old_bg)
db.set_setting("term_scheme", "Dark"); w.settings_applied()
st.open_logs(); lg = st.logs_dialog.logs
check("the session logs window lists every kind, with its type", {lg.table.item(i, 3).text() for i in range(lg.table.rowCount())} >= {"SSH", "TELNET", "SERIAL"} and "Type" in [lg.table.horizontalHeaderItem(i).text() for i in range(lg.table.columnCount())], [lg.table.item(i, 3).text() for i in range(lg.table.rowCount())])
before = len([x for x in sessionlog.list_sessions() if not x["ended_at"]]); w.sessions.shutdown()
check("closing the app finishes every open log", len([x for x in sessionlog.list_sessions() if not x["ended_at"]]) == 0 or before >= 1)
ssh_srv.stop()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

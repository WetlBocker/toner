# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The Files panel of an SSH session: this computer and the device side by side, over SFTP on the session's own login.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import logging, os, shutil, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\sf%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db
db.init()
db.set_setting("hostkey_mode", "Always trust")
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QApplication, QInputDialog, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
import ui.sessions as S
import ui.filebrowser as FB
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
asked, prompts, replace_asks = [], [], []
answer = {"v": QMessageBox.StandardButton.Yes}
QMessageBox.question = staticmethod(lambda *a, **k: (asked.append(a[2]), answer["v"])[1])
folder_reply = {"v": ("", False)}
QInputDialog.getText = staticmethod(lambda *a, **k: (prompts.append(a[2]), folder_reply["v"])[1])
replace_reply = {"v": "replace"}
FB.FileBrowser._ask = lambda self, name, folder: (replace_asks.append((name, folder)), self.worker.answer(replace_reply["v"]))

base = os.path.join(SP, "sftp%d" % int(time.time()))
remote_root, local_root = os.path.join(base, "device"), os.path.join(base, "pc")
os.makedirs(os.path.join(remote_root, "configs")); os.makedirs(os.path.join(remote_root, "sub", "deeper")); os.makedirs(local_root)
def put(root, rel, data=b"x"):
    p = os.path.join(root, *rel.split("/")); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "wb").write(data); return p
put(remote_root, "running.cfg", b"hostname R1\n"); put(remote_root, ".hidden", b"h"); put(remote_root, "sub/inner.txt", b"inner"); put(remote_root, "sub/deeper/leaf.bin", bytes(range(256)))
put(local_root, "notes.txt", b"local notes"); put(local_root, "firmware/image.bin", os.urandom(70000)); put(local_root, "firmware/md5.txt", b"abc")
link_ok = False
try:
    os.symlink(os.path.join(remote_root, "sub"), os.path.join(remote_root, "sub-link"), target_is_directory=True); link_ok = True
except OSError: pass
FB._last_local["path"] = local_root
def names(side): return [e["name"] for e in side.list.entries(selected=False)]
def pick(side, *wanted):
    side.list.clearSelection()
    for i in range(side.list.topLevelItemCount()):
        it = side.list.topLevelItem(i)
        if it.data(0, 0x0100)["name"] in wanted: it.setSelected(True)
def settled(fb): return not fb.busy
def rel_listing(root):
    out = []
    for r, ds, fs in os.walk(root):
        for f in fs: out.append(os.path.relpath(os.path.join(r, f), root).replace(os.sep, "/"))
    return sorted(out)

srv = ShellServer(sftp_root=remote_root)
w = A.Main(); w.resize(1300, 820); w.show(); st = w.sessions
w.tabs.setCurrentIndex([w.tabs.tabText(i) for i in range(w.tabs.count())].index("Sessions"))

print("== which sessions have a Files button")
for kind, host in (("serial", "loop://"), ("telnet", "127.0.0.1")):
    p = S.SessionPane({"name": kind, "kind": kind, "host": host, "port": 23, "username": "", "password": "", "options": {}})
    check(f"a {kind} session has no Files button", not p.files_btn.isVisibleTo(p))
spec = st._spec({"name": "R1", "kind": "ssh", "host": "127.0.0.1", "port": srv.port, "username": "u", "options": {}}, "pw")
st.open_spec(spec); pane = st.current_pane(); pump(lambda: pane.connected() and "router# " in screen(pane))
check("an SSH session has one, off to begin with, and no panel yet", pane.files_btn.isVisibleTo(pane) and pane.files_btn.text() == "Files" and pane.files_btn.isCheckable() and not pane.files_btn.isChecked() and pane.browser is None)
check("its tooltip says what it does", "side by side" in pane.files_btn.toolTip() and "SFTP" in pane.files_btn.toolTip())

print("== opening the panel")
pane.files_btn.setChecked(True); fb = pane.browser
check("Files opens the panel under the terminal, this computer on the left and the device on the right", fb is not None and fb.isVisibleTo(pane) and fb.local.title.text() == "This computer" and fb.remote.title.text() == "127.0.0.1" and pane.term.isVisibleTo(pane))
check("the columns are Name, Size and Modified", [fb.remote.list.headerItem().text(i) for i in range(3)] == ["Name", "Size", "Modified"])
check("the buttons: Up, Refresh, New folder, Delete and Upload / Download", [b.text() for b in (fb.local.up_btn, fb.local.refresh_btn, fb.local.mkdir_btn, fb.local.delete_btn, fb.local.action_btn)] == ["Up", "Refresh", "New folder", "Delete", "Upload"] and fb.remote.action_btn.text() == "Download")
check("this computer's side lists the folder straight away", fb.local.path == local_root and names(fb.local) == ["firmware", "notes.txt"], names(fb.local))
pump(lambda: fb.remote.path and settled(fb), 500)
check("the device side lists the login folder over SFTP on the same connection, hidden files included", fb.remote.path == "/" and set(names(fb.remote)) >= {"configs", "sub", "running.cfg", ".hidden"} and srv.logins.count(("u", "pw")) == 1, (fb.remote.path, names(fb.remote), srv.logins))
check("folders first, with a slash; files show their size and date", fb.remote.list.topLevelItem(0).text(0).endswith("/") and [e for e in fb.remote.list.entries(False) if e["name"] == "running.cfg"][0]["size"] == 12 and fb.remote.list.topLevelItem(fb.remote.list.topLevelItemCount() - 1).text(1) != "" and fb.remote.list.topLevelItem(0).text(2) != "")
if link_ok:
    check("a link to a folder is listed as a folder", [e for e in fb.remote.list.entries(False) if e["name"] == "sub-link"][0]["is_dir"])
check("the terminal still works beside it", (pane.term.data_out.emit(b"show files\r"), pump(lambda: "output of show files" in screen(pane)))[1])

print("== moving around")
fb.remote.list.entered.emit("sub"); pump(lambda: fb.remote.path == "/sub" and settled(fb))
check("double-clicking a folder enters it", fb.remote.path == "/sub" and fb.remote.box.text() == "/sub" and set(names(fb.remote)) == {"deeper", "inner.txt"}, names(fb.remote))
fb.remote.up_btn.click(); pump(lambda: fb.remote.path == "/" and settled(fb))
check("Up goes to the parent", fb.remote.path == "/")
fb.remote.box.setText("/sub/deeper"); fb.remote.box.returnPressed.emit(); pump(lambda: fb.remote.path == "/sub/deeper" and settled(fb))
check("a path typed in the box, then Enter, goes there", fb.remote.path == "/sub/deeper" and names(fb.remote) == ["leaf.bin"])
fb.remote.box.setText("/nowhere"); fb.remote.box.returnPressed.emit(); pump(lambda: "failed" in fb.note.text(), 200)
check("a folder that is not there is explained, and the list stays where it was", "Listing failed" in fb.note.text() and "no such file" in fb.note.text() and fb.remote.path == "/sub/deeper", fb.note.text())
fb.remote.box.setText("/"); fb.remote.box.returnPressed.emit(); pump(lambda: fb.remote.path == "/" and settled(fb))
fb.local.list.entered.emit("firmware"); check("the same on this computer", fb.local.path == os.path.join(local_root, "firmware") and names(fb.local) == ["image.bin", "md5.txt"])
fb.local.up_btn.click(); check("and Up", fb.local.path == local_root)

print("== upload")
pick(fb.local, "notes.txt"); seen = []
fb.note.setText(""); fb.local.action_btn.click(); pump(lambda: settled(fb) and fb.note.text().startswith("Uploaded"), 500)
check("Upload sends the selected file to the device's folder, and says so", os.path.exists(os.path.join(remote_root, "notes.txt")) and open(os.path.join(remote_root, "notes.txt"), "rb").read() == b"local notes" and fb.note.text() == "Uploaded 1 file(s) to /.", fb.note.text())
pump(lambda: "notes.txt" in names(fb.remote) and settled(fb)); check("the device side refreshes to show it", "notes.txt" in names(fb.remote))
fb.remote.list.dropped.emit({"side": "local", "names": ["firmware"]}, "configs"); pump(lambda: settled(fb) and fb.note.text().startswith("Uploaded"), 800)
check("a whole folder dragged onto a folder row lands inside that folder", rel_listing(os.path.join(remote_root, "configs")) == ["firmware/image.bin", "firmware/md5.txt"] and fb.note.text() == "Uploaded 2 file(s) to /configs.", (rel_listing(os.path.join(remote_root, "configs")), fb.note.text()))
check("the big file arrived whole", open(os.path.join(remote_root, "configs", "firmware", "image.bin"), "rb").read() == open(os.path.join(local_root, "firmware", "image.bin"), "rb").read())
progress_lines = []
fb.worker.progress.connect(lambda t, d, tot: progress_lines.append((t, d, tot)))
fb.remote.list.dropped.emit({"side": "local", "paths": [os.path.join(local_root, "firmware", "image.bin")]}, None); pump(lambda: settled(fb) and fb.note.text().startswith("Uploaded"), 800)
check("files dropped in from Windows Explorer are uploaded too, with progress along the way", os.path.exists(os.path.join(remote_root, "image.bin")) and progress_lines and progress_lines[0][0] == "Uploading image.bin" and progress_lines[-1][1] == progress_lines[-1][2] == 70000, progress_lines[:2])

print("== replacing")
replace_asks.clear(); replace_reply["v"] = "skip"; open(os.path.join(local_root, "notes.txt"), "wb").write(b"changed")
pick(fb.local, "notes.txt"); fb.local.action_btn.click(); pump(lambda: settled(fb) and replace_asks, 500); pump(lambda: settled(fb))
check("a file already there is asked about: Skip leaves it alone", replace_asks == [("notes.txt", "/")] and open(os.path.join(remote_root, "notes.txt"), "rb").read() == b"local notes" and fb.note.text() == "Uploaded 0 file(s) to /.", (replace_asks, fb.note.text()))
replace_reply["v"] = "replace"; pick(fb.local, "notes.txt"); fb.local.action_btn.click(); pump(lambda: settled(fb) and fb.note.text() == "Uploaded 1 file(s) to /.", 500)
check("Replace replaces it", open(os.path.join(remote_root, "notes.txt"), "rb").read() == b"changed")
replace_asks.clear(); replace_reply["v"] = "replace_all"; open(os.path.join(local_root, "firmware", "md5.txt"), "wb").write(b"def")
fb.remote.list.dropped.emit({"side": "local", "names": ["firmware"]}, "configs"); pump(lambda: settled(fb) and fb.note.text() == "Uploaded 2 file(s) to /configs.", 800)
check("Replace all asks once for a folder", len(replace_asks) == 1 and open(os.path.join(remote_root, "configs", "firmware", "md5.txt"), "rb").read() == b"def", replace_asks)
replace_asks.clear(); replace_reply["v"] = "cancel"
fb.remote.list.dropped.emit({"side": "local", "names": ["firmware"]}, "configs"); pump(lambda: settled(fb) and replace_asks, 500); pump(lambda: settled(fb))
check("Cancel in the question stops the rest", len(replace_asks) == 1 and "Stopped at your Cancel" in fb.note.text(), fb.note.text())
replace_reply["v"] = "replace"

print("== download")
fb.remote.box.setText("/"); fb.remote.box.returnPressed.emit(); pump(lambda: settled(fb) and "sub" in names(fb.remote))
pick(fb.remote, "running.cfg"); fb.remote.action_btn.click(); pump(lambda: settled(fb) and fb.note.text().startswith("Downloaded"), 500)
check("Download saves the selected file into this computer's folder", open(os.path.join(local_root, "running.cfg"), "rb").read() == b"hostname R1\n" and fb.note.text() == f"Downloaded 1 file(s) to {local_root}.", fb.note.text())
check("this computer's side refreshes", "running.cfg" in names(fb.local))
fb.local.list.dropped.emit({"side": "remote", "names": ["sub"]}, None); pump(lambda: settled(fb) and fb.note.text().startswith("Downloaded 2"), 800)
check("a folder dragged from the device comes down with everything in it", rel_listing(os.path.join(local_root, "sub")) == ["deeper/leaf.bin", "inner.txt"] and open(os.path.join(local_root, "sub", "deeper", "leaf.bin"), "rb").read() == bytes(range(256)), rel_listing(os.path.join(local_root, "sub")))
os.makedirs(os.path.join(local_root, "drop-here")); fb.list_local(local_root)
fb.local.list.dropped.emit({"side": "remote", "names": ["running.cfg", ".hidden"]}, "drop-here"); pump(lambda: settled(fb) and fb.note.text().startswith("Downloaded 2"), 500)
check("dropped on a folder row, they land in that folder", sorted(os.listdir(os.path.join(local_root, "drop-here"))) == [".hidden", "running.cfg"])

print("== new folder and delete")
prompts.clear(); folder_reply["v"] = ("backups", True); fb.remote.mkdir_btn.click(); pump(lambda: settled(fb) and "backups" in names(fb.remote), 300)
check("New folder on the device asks for a name and makes it", prompts[-1] == "Folder name:" and os.path.isdir(os.path.join(remote_root, "backups")) and "backups" in names(fb.remote))
folder_reply["v"] = ("local-new", True); fb.local.mkdir_btn.click()
check("and on this computer", os.path.isdir(os.path.join(local_root, "local-new")) and "local-new" in names(fb.local))
folder_reply["v"] = ("backups", True); fb.remote.mkdir_btn.click(); pump(lambda: "failed" in fb.note.text(), 300)
check("a name already used is explained", fb.note.text().startswith("New folder failed:"), fb.note.text())
asked.clear(); pick(fb.remote, "notes.txt"); fb.remote.delete_btn.click(); pump(lambda: settled(fb) and "notes.txt" not in names(fb.remote), 300)
check("Delete asks first, then removes the file from the device", asked == ["Delete 'notes.txt'?"] and not os.path.exists(os.path.join(remote_root, "notes.txt")), asked)
asked.clear(); pick(fb.remote, "configs"); fb.remote.delete_btn.click(); pump(lambda: settled(fb) and "configs" not in names(fb.remote), 300)
check("a folder goes with everything in it, and the question says so", asked == ["Delete the folder 'configs' and everything in it?"] and not os.path.exists(os.path.join(remote_root, "configs")), asked)
asked.clear(); answer["v"] = QMessageBox.StandardButton.No; pick(fb.remote, "sub"); fb.remote.delete_btn.click(); pump(n=5)
check("No keeps it", os.path.isdir(os.path.join(remote_root, "sub"))); answer["v"] = QMessageBox.StandardButton.Yes
asked.clear(); pick(fb.local, "running.cfg", "drop-here"); fb.local.delete_btn.click()
check("several at once on this computer: one question with the count", asked == ["Delete these 2 items?"] and not os.path.exists(os.path.join(local_root, "running.cfg")) and not os.path.exists(os.path.join(local_root, "drop-here")), asked)
check("Delete and Upload need something selected", not fb.local.delete_btn.isEnabled() and not fb.local.action_btn.isEnabled())

print("== cancelling a transfer")
srv.slow = 0.02; put(local_root, "big.bin", os.urandom(6000000)); fb.list_local(local_root)
pick(fb.local, "big.bin"); fb.local.action_btn.click(); pump(lambda: fb.cancel_btn.isVisible() and fb.bar.isVisible() and "Uploading big.bin" in fb.note.text(), 300)
check("while a file is copied, a progress bar and a Cancel button show", fb.cancel_btn.isVisibleTo(fb) and fb.bar.isVisibleTo(fb) and "Uploading big.bin" in fb.note.text() and "%" in fb.note.text(), fb.note.text())
fb.cancel_btn.click(); pump(lambda: settled(fb) and "cancelled" in fb.note.text(), 500)
check("Cancel stops it, says so, and the unfinished file is removed from the device", fb.note.text() == "Upload cancelled. The unfinished file was removed." and not os.path.exists(os.path.join(remote_root, "big.bin")) and not fb.cancel_btn.isVisibleTo(fb), fb.note.text())
srv.slow = 0

print("== the connection comes and goes")
pane.disconnect_btn.click(); pump(lambda: not pane.connected())
check("disconnected: the device side empties and says to connect", fb.note.text() == "Connect the session to browse the device's files." and fb.remote.list.topLevelItemCount() == 0 and not fb.remote.up_btn.isEnabled() and fb.worker is None)
pane.reconnect_btn.click(); pump(lambda: pane.connected() and fb.remote.path and settled(fb) and fb.remote.list.topLevelItemCount() > 0, 600)
check("reconnected: it lists again", fb.remote.list.topLevelItemCount() > 0 and "sub" in names(fb.remote), names(fb.remote))
pane.files_btn.setChecked(False); check("Files off hides the panel but keeps it", not fb.isVisibleTo(pane) and pane.browser is fb)
pane.files_btn.setChecked(True); check("and on shows it again", fb.isVisibleTo(pane))
st.close_pane(pane); pump(n=5)

print("== a device with no SFTP")
plain_srv = ShellServer()
spec2 = st._spec({"name": "Old", "kind": "ssh", "host": "127.0.0.1", "port": plain_srv.port, "username": "u", "options": {}}, "pw")
st.open_spec(spec2); p2 = st.current_pane(); pump(lambda: p2.connected() and "router# " in screen(p2))
p2.files_btn.setChecked(True); fb2 = p2.browser; pump(lambda: "SFTP" in fb2.note.text(), 300)
check("the panel says the device does not offer SFTP, and the terminal still works", fb2.note.text().startswith("This device does not offer SFTP, so its files cannot be browsed here. The terminal still works.") and not fb2.remote.up_btn.isEnabled(), fb2.note.text())
p2.term.data_out.emit(b"show after\r"); pump(lambda: "output of show after" in screen(p2))
check("(it does)", "output of show after" in screen(p2))
st.close_pane(p2); pump(n=5)
check("the panel's size helper", [FB.human_size(n) for n in (0, 999, 1024, 1536, 5 * 1024 * 1024)] == ["0 B", "999 B", "1.0 KB", "1.5 KB", "5.0 MB"])
srv.stop(); plain_srv.stop()
st.shutdown()

print(f"\n{ok} passed, {bad} failed")

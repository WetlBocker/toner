# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Ansible in the window: Settings > Ansible, Tools > Playbook Editor and the Automation section. No real Ansible is needed:
# the backend that would run it is replaced by one that prints what Ansible prints.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\ansui%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roamingansui%d" % int(time.time()))
from core import ansible as AN, db, scope
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
ANSWER = [QMessageBox.StandardButton.Yes]; ASKED = []
def question(parent, title, text, *a, **k):
    ASKED.append((title, text)); return ANSWER[0]
QMessageBox.question = staticmethod(question)
WARNED = []
QMessageBox.warning = staticmethod(lambda parent, title, text, *a, **k: WARNED.append((title, text)))
def wait(cond, ms=10000):
    t0 = time.time()
    while time.time() - t0 < ms / 1000:
        app.processEvents()
        if cond(): return True
        time.sleep(0.01)
    return False

OUT = """PLAY [NTP] ****

TASK [NTP server] ****
changed: [sw1]
fatal: [dc1]: UNREACHABLE! => {"msg": "timed out"}

PLAY RECAP ****
sw1                        : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
dc1                        : ok=0    changed=0    unreachable=1    failed=0    skipped=0    rescued=0    ignored=0
"""
class Fake(AN.Backend):
    name = "fake"
    hold = None
    def describe(self): return "fake backend"
    def check(self): return True, "ansible-playbook [core 2.17.1]"
    def run(self, spec, files_text, on_line, cancel=None):
        self.spec, self.files = spec, files_text
        for l in OUT.splitlines():
            on_line(l)
            if self.hold is not None:                              # a run that waits to be stopped
                while not self.hold.is_set() and not (cancel and cancel.is_set()): time.sleep(0.01)
                if cancel and cancel.is_set(): on_line("[Toner: the run was cancelled]"); return -1
        return 2
FB = Fake()
REAL_BACKEND = AN.backend
AN.backend = lambda: FB

def dev(name, vendor="cisco", host="10.0.0.1", folder=None, **kw):
    d = dict(name=name, vendor=vendor, host=host, port=0, platform="", username="admin", site="default", verify_ssl=0, ha_expected=0, enabled=kw.pop("enabled", 1), location="", details="", folder_id=folder, tags="", fields="")
    d.update(kw); db.save_device(d); return d

acme, zeta = db.create_folder("Acme"), db.create_folder("Zeta")
for n, v, h, f in (("sw1", "cisco", "10.0.0.1", acme), ("sw2", "cisco", "10.0.0.2", acme), ("dc1", "windows", "10.0.1.5", zeta), ("off1", "cisco", "10.0.0.9", acme)):
    dev(n, v, h, f, enabled=0 if n == "off1" else 1)

w = A.Main(); w.resize(1300, 820); w.show(); app.processEvents()

print("== in the sidebar")
names = [w.tabs.tabText(i) for i in range(w.tabs.count())]
check("Automation is below Sessions and above Settings", names.index("Automation") == names.index("Sessions") + 1 and names.index("Settings") == names.index("Automation") + 1, names)
w.go("Automation"); app.processEvents()
check("it opens, with a header saying what it is for", w.tabs.currentWidget() is w.automation and "playbooks" in w.headers["automation"].context.text())
check("its list has Ansible's Playbooks and Run history", [w.automation.pages.tabText(i) for i in range(w.automation.pages.count())] == ["Playbooks", "Run history"])
w.open_palette(); labels = [e[0] for e in w.palette.entries]
check("the search offers Go to Automation, the editor as a tool, the settings page and a new playbook", "Go to Automation" in labels and "Tool: Playbook Editor" in labels and "Settings: Ansible" in labels and "New playbook" in labels, [l for l in labels if "laybook" in l or "Ansible" in l])
w.palette.close()

print("== Tools > Playbook Editor")
tools = w.tools; ed = tools.playbooks
check("the editor is a tool, in its own group", "Playbook Editor" in [tools.tabs.tabText(i) for i in range(tools.tabs.count())])
check("with nothing in the library it says so, and cannot save or run", ed.list_hint.isVisible() or ed.listing.count() == 0)
check("nothing is open: the buttons that need a playbook are off", not ed.save_btn.isEnabled() and not ed.check_btn.isEnabled() and not ed.run_btn.isEnabled() and ed.editor.isReadOnly())
changed = []; ed.library_changed.connect(lambda: changed.append(1))
check("a playbook is made from a template and opened", ed.new_playbook(template="ping", name="site/ping") and ed.current == "site/ping.yml" and "ansible.builtin.ping" in ed.editor.toPlainText() and ed.listing.count() == 1 and changed)
check("it shows that the YAML is fine", ed.verdict.text() == "The YAML is valid.")
check("nothing is unsaved yet", not ed.dirty() and not ed.save_btn.isEnabled())
dlg_name = ed.new_playbook(template="ping", name="site/ping")
check("a name that is taken is refused and says why", dlg_name is False and WARNED and "already exists" in WARNED[-1][1], WARNED)
ed.editor.setPlainText("- hosts: all\n  tasks:\n    - name: x\n     bad: y\n"); app.processEvents()
check("typing marks it unsaved: Save and Revert come on, the title says so", ed.dirty() and ed.save_btn.isEnabled() and ed.revert_btn.isEnabled() and "not saved" in ed.title.text())
ed.check_now()
check("a mistake is reported with its line", ed.verdict.text().startswith("Line ") and "The YAML is valid" not in ed.verdict.text(), ed.verdict.text())
check("the check runs by itself a moment after typing stops", (ed.verdict.setText("-"), ed.live.start(10), wait(lambda: ed.verdict.text() != "-"))[2])
check("the library has not been touched", "bad: y" not in AN.read("site/ping.yml"))
ed.revert(); check("Revert puts the saved text back", not ed.dirty() and "ansible.builtin.ping" in ed.editor.toPlainText())
ed.editor.setPlainText("- hosts: all\n  gather_facts: false\n  tasks: []\n"); changed.clear()
check("Save writes the file and tells the rest of the window", ed.save() and AN.read("site/ping.yml").startswith("- hosts: all") and not ed.dirty() and changed)
print("-- keys")
ed.editor.setPlainText("a:"); c = ed.editor.textCursor(); c.movePosition(c.MoveOperation.End); ed.editor.setTextCursor(c)
QTest.keyClick(ed.editor, Qt.Key.Key_Return)
check("Enter after a colon indents one level", ed.editor.toPlainText() == "a:\n  ")
QTest.keyClick(ed.editor, Qt.Key.Key_Tab)
check("Tab is two spaces, not a jump", ed.editor.toPlainText() == "a:\n    ")
ed.editor.setPlainText("  - x: 1"); c = ed.editor.textCursor(); c.movePosition(c.MoveOperation.End); ed.editor.setTextCursor(c)
QTest.keyClick(ed.editor, Qt.Key.Key_Return)
check("Enter keeps the indent of the line above", ed.editor.toPlainText() == "  - x: 1\n  ")
ed.editor.setPlainText("a\nb\nc"); ed.editor.selectAll(); QTest.keyClick(ed.editor, Qt.Key.Key_Tab)
check("Tab with lines selected indents them all", ed.editor.toPlainText() == "  a\n  b\n  c", ed.editor.toPlainText())
QTest.keyClick(ed.editor, Qt.Key.Key_Backtab)
check("Shift+Tab takes it back", ed.editor.toPlainText() == "a\nb\nc", ed.editor.toPlainText())
ed.revert()
print("-- colours")
ed.editor.setPlainText("- hosts: all  # who\n  vars:\n    n: 5\n    s: \"x\"\n    t: '{{ y }}'\n"); app.processEvents(); ed.highlighter.rehighlight()
fm = lambda i: {(f.start, f.length): f.format.foreground().color().name() for f in ed.editor.document().findBlockByNumber(i).layout().formats()}
check("keys, strings, numbers and comments are coloured (and not all alike)", len(set(fm(0).values())) >= 2 and fm(2) and fm(3), (fm(0), fm(2)))
ed.revert()
print("-- the library")
AN.create("site/other", "blank"); ed.refresh()
check("a playbook added outside the editor shows after a refresh", ed.listing.count() == 2)
ed.editor.setPlainText("- hosts: x\n  tasks: []\n  # edited\n")
ANSWER[0] = QMessageBox.StandardButton.Cancel
ed._chosen(next(ed.listing.item(i) for i in range(ed.listing.count()) if ed.listing.item(i).data(Qt.ItemDataRole.UserRole) == "site/other.yml"))
check("choosing another with unsaved edits asks, and Cancel keeps the edits", ed.current == "site/ping.yml" and "# edited" in ed.editor.toPlainText() and ed.listing.currentItem().data(Qt.ItemDataRole.UserRole) == "site/ping.yml")
ANSWER[0] = QMessageBox.StandardButton.Discard
ed._chosen(next(ed.listing.item(i) for i in range(ed.listing.count()) if ed.listing.item(i).data(Qt.ItemDataRole.UserRole) == "site/other.yml"))
check("Discard moves on without saving", ed.current == "site/other.yml" and "# edited" not in AN.read("site/ping.yml"))
ed.editor.setPlainText("- hosts: y\n  tasks: []\n"); ANSWER[0] = QMessageBox.StandardButton.Save
check("Save writes it first, then moves on", ed.open_playbook("site/ping.yml") and "hosts: y" in AN.read("site/other.yml") and ed.current == "site/ping.yml")
ANSWER[0] = QMessageBox.StandardButton.Yes
check("renaming moves the file and keeps it open", ed.rename_playbook("site/renamed") and ed.current == "site/renamed.yml" and "site/ping.yml" not in ed.names() and "site/renamed.yml" in ed.names())
check("renaming to a name that is taken is refused", ed.rename_playbook("site/other") is False and ed.current == "site/renamed.yml")
check("deleting asks first, then removes it and empties the editor", ed.delete_playbook() and ed.current == "" and "site/renamed.yml" not in ed.names() and ed.editor.toPlainText() == "")
ANSWER[0] = QMessageBox.StandardButton.No
ed.open_playbook("site/other.yml"); n = ed.listing.count()
check("... and No keeps it", ed.delete_playbook() is False and ed.current == "site/other.yml" and ed.listing.count() == n)
ANSWER[0] = QMessageBox.StandardButton.Yes

print("== Ansible's own syntax check, from the editor")
class CheckFB(Fake):
    def run(self, spec, files_text, on_line, cancel=None):
        self.spec = spec; on_line("playbook: " + str(spec.playbook_path)); return 0
CFB = CheckFB(); AN.backend = lambda: CFB
ed.open_playbook("site/other.yml"); ed.check_with_ansible()
check("it runs, and the output shows", wait(lambda: not ed.checking() and ed.output.toPlainText() != "Checking..." and "passed" in ed.verdict.text(), 30000) and not ed.output.isHidden() and "playbook:" in ed.output.toPlainText() and CFB.spec.syntax_only and "passed" in ed.verdict.text(), ed.output.toPlainText())
check("it needs no devices and is not put in the history", AN.list_runs() == [])
class BadFB(Fake):
    def run(self, spec, files_text, on_line, cancel=None):
        on_line("ERROR! Syntax Error while loading YAML."); return 4
AN.backend = lambda: BadFB(); ed.check_with_ansible()
check("a failure is shown, with Ansible's words", wait(lambda: not ed.checking() and ed.output.toPlainText() != "Checking...") and "Syntax Error" in ed.output.toPlainText() and "found a problem" in ed.verdict.text())
def nobackend(): raise AN.BackendError("WSL is not installed on this PC.")
AN.backend = nobackend; ed.check_with_ansible()
check("with no way to run Ansible it says so", wait(lambda: not ed.checking() and ed.output.toPlainText() != "Checking...") and "WSL is not installed" in ed.output.toPlainText())
AN.backend = lambda: FB
ed.editor.setPlainText("- hosts: z\n  tasks: []\n"); ASKED.clear(); ANSWER[0] = QMessageBox.StandardButton.No; ed.check_with_ansible()
check("with unsaved edits it asks to save first (Ansible checks the saved file); No stops there", ASKED and "Save your changes first" in ASKED[-1][1] and not ed.checking())
ed.revert(); ANSWER[0] = QMessageBox.StandardButton.Yes

print("== hand over between the editor, Automation and Settings")
got = []; ed.run_requested.connect(got.append); ed.settings_requested.connect(lambda: got.append("settings"))
ed.editor.setPlainText("- hosts: q\n  tasks: []\n"); ed.run_btn.click()
check("Run... saves, then asks Automation to take it", got == ["site/other.yml"] and "hosts: q" in AN.read("site/other.yml"))
w.go("Tools"); ed.run_requested.emit("site/other.yml"); app.processEvents()
check("which opens Automation with that playbook chosen", w.tabs.currentWidget() is w.automation and w.automation.playbooks.selected() == "site/other.yml")
ed.settings_btn.click(); app.processEvents()
check("Settings opens Settings > Ansible", w.tabs.currentWidget() is w.settings and w.settings.current_title() == "Ansible")
w.go("Automation"); w.automation.playbooks.edit_btn.click(); app.processEvents()
check("Edit on the Automation page opens it in the editor", w.tabs.currentWidget() is w.tools and w.tools.tabs.currentWidget() is ed and ed.current == "site/other.yml")
w.go("Automation"); w.automation.playbooks.settings_btn.click(); app.processEvents()
check("and its Ansible settings button opens Settings > Ansible", w.tabs.currentWidget() is w.settings and w.settings.current_title() == "Ansible")

print("== Automation > Playbooks")
AN.backend = lambda: FB
pg = w.automation.playbooks; w.go("Automation"); w.automation.refresh(); app.processEvents()
check("the playbooks are listed", pg.listing.count() == 1 and pg.selected() in ("", "site/other.yml"))
pg.select("site/other.yml")
check("only enabled devices are offered, none ticked", [pg.devs.item(i).text() for i in range(pg.devs.count())] == ["dc1", "sw1", "sw2"] and not pg.checked_devices())
check("check mode is on, as Settings says by default, and the button says what it will do", pg.check.isChecked() and pg.go.text() == "Run check")
check("it says where it will run", "fake backend" in pg.where.text())
ASKED.clear(); pg.start()
check("with no device ticked it asks for one and does nothing", "Tick at least one device" in pg.status.text() and not pg.running())
pg._tick_all(True); pg.extra.setText("novalue")
check("variables that make no sense are explained and nothing runs", pg.start() is False and pg.status.text().startswith("Variables:") and not pg.running())
pg.extra.setText("ntp=10.9.9.9"); pg.tags.setText("ntp"); pg.verbosity.setCurrentIndex(1)
check("All ticks them all, None unticks them", len(pg.checked_devices()) == 3 and (pg._tick_all(False), not pg.checked_devices(), pg._tick_all(True))[1])
ASKED.clear(); pg.start()
check("a check runs without asking", pg.running() is True and not ASKED)
check("... and finishes", wait(lambda: pg.go.isEnabled()) and "finished with problems" in pg.status.text())
check("the output was streamed into the window", "TASK [NTP server]" in pg.output.toPlainText() and "PLAY RECAP" in pg.output.toPlainText())
check("the arguments were what was chosen", FB.spec.check and FB.spec.tags == "ntp" and FB.spec.extra_vars == {"ntp": "10.9.9.9"} and FB.spec.verbosity == 1 and [d["name"] for d in FB.spec.devices] == ["dc1", "sw1", "sw2"])
check("the recap is a table with Toner's device names", [(pg.recap.item(i, 0).text(), pg.recap.item(i, 2).text(), pg.recap.item(i, 3).text()) for i in range(pg.recap.rowCount())] == [("sw1", "1", "0"), ("dc1", "0", "1")] and not pg.recap_hint.isVisible())
check("the status line counts what changed and what failed", "1 changed, 1 failed or unreachable" in pg.status.text(), pg.status.text())
hp = w.automation.history
check("the run is in the history, newest first, with its output", hp.table.rowCount() == 1 and hp.table.item(0, 2).text() == "Check" and hp.table.item(0, 1).text() == "site/other.yml" and hp.table.item(0, 7).text() == "Problems" and "PLAY RECAP" in hp.output.toPlainText())
check("the history has the changed and failed counts", hp.table.item(0, 5).text() == "1" and hp.table.item(0, 6).text() == "1" and hp.table.item(0, 4).text() == "3")
print("-- a real run")
pg.check.setChecked(False)
check("untick check mode and the button says it will run for real", pg.go.text() == "Run playbook")
ASKED.clear(); ANSWER[0] = QMessageBox.StandardButton.No; pg.start()
check("it asks, naming the playbook and every device, and No stops it", ASKED and ASKED[0][0] == "Run playbook" and "site/other.yml" in ASKED[0][1] and all(n in ASKED[0][1] for n in ("dc1", "sw1", "sw2")) and "3 devices" in ASKED[0][1] and not pg.running() and pg.status.text() == "Not run.", ASKED)
check("nothing was recorded for a run that was not made", hp.table.rowCount() == 1)
ANSWER[0] = QMessageBox.StandardButton.Yes; ASKED.clear(); pg.start()
check("Yes runs it, with check mode off", ASKED and wait(lambda: pg.go.isEnabled()) and FB.spec.check is False and "--check" not in " ".join(AN.build_args(FB.spec, {"inventory": "i", "limit": "l", "playbook": "p"})))
check("and the history has it as a Run", hp.table.rowCount() == 2 and hp.table.item(0, 2).text() == "Run")
from ui.automation import confirm_text
long = confirm_text("x.yml", [{"name": f"d{i}"} for i in range(17)])
check("the question names only some of a long list", "and 5 more" in long and "d11" in long and "d12" not in long)
check("the question is in the singular for one device", "on 1 device and can change it" in confirm_text("x.yml", [{"name": "only"}]))
print("-- stopping, and failing to start")
pg.check.setChecked(True)
FB.hold = threading.Event(); pg.start()
check("Stop is on while it runs and Run is off", wait(lambda: "TASK" in pg.output.toPlainText() or "PLAY" in pg.output.toPlainText()) and pg.stop.isEnabled() and not pg.go.isEnabled())
pg.stop.click()
check("Stop ends it and says it was cancelled", wait(lambda: pg.go.isEnabled()) and "cancelled" in pg.output.toPlainText() and pg.go.isEnabled() and not pg.stop.isEnabled())
FB.hold = None
AN.backend = nobackend; pg.start()
check("with no way to run Ansible it says what is wrong and where to fix it", wait(lambda: pg.go.isEnabled()) and "WSL is not installed" in pg.status.text() and "Ansible settings" in pg.status.text(), pg.status.text())
AN.backend = lambda: FB
print("-- who and what is offered")
from core import orgs as ORGS
o = ORGS.create("Acme", "ACME")
with db.within(o):
    db.save_device(dict(name="acme-sw", vendor="cisco", host="10.9.0.1", port=0, platform="", username="", site="default", verify_ssl=0,
                        ha_expected=0, enabled=1, location="", details="", folder_id=None))
db.set_home(o); pg.refresh()
check("an organization offers only its own devices", [pg.devs.item(i).text() for i in range(pg.devs.count())] == ["acme-sw"])
db.set_home(0); ORGS.remove(o); pg.refresh()
pg._tick_all(False); pg.devs.item(0).setCheckState(Qt.CheckState.Checked); pg.refresh()
check("a refresh keeps what was ticked", [d["name"] for d in pg.checked_devices()] == ["dc1"])
print("-- history")
hp.table.selectRow(1)
check("choosing a run shows its output", "PLAY RECAP" in hp.output.toPlainText())
ANSWER[0] = QMessageBox.StandardButton.No; hp.clear()
check("Clear history asks, and No keeps it", hp.table.rowCount() >= 2)
ANSWER[0] = QMessageBox.StandardButton.Yes; hp.clear()
check("Yes empties it", hp.table.rowCount() == 0 and hp.hint.isVisible() is not None and hp.output.toPlainText() == "")

print("== Settings > Ansible")
w.go("Settings"); S = w.settings; S.select_page("Ansible"); page = next(p for p in S.pages if p.title == "Ansible"); app.processEvents()
check("it is in its own group, between Alerts and reports and Look and feel", S.page_titles().index("Ansible") == S.page_titles().index("Config backups") + 1)
check("it opens on WSL (Linux: this computer), with the server's boxes hidden", page.where.currentData() == "wsl" and not page.host.isVisible()
      and page.distro.isVisible() == (sys.platform == "win32"))
check("... showing what is saved: check mode on, 200 runs, the default playbook folder", page.check_default.isChecked() and page.keep.value() == 200 and page.folder.text() == "")
page.where.setCurrentIndex(1); app.processEvents()
check("choosing a server shows how to sign in: an Inventory device by default if one is set, else typed", page.login.currentData() == "typed" and page.host.isVisible() and not page.device.isVisible() and not page.distro.isVisible())
page.login.setCurrentIndex(0); app.processEvents()
check("an Inventory device shows its list and the explanation instead", page.device.isVisible() and not page.host.isVisible() and page.device_note.isVisible() and page.device.findData("sw1") >= 0)
page.login.setCurrentIndex(1)
S.check_dirty()
check("a change marks the page unsaved", S.dirty_pages() == [S.pages.index(page)] or S.pages.index(page) in S.dirty_pages())
check("a server with no address or user is a problem that stops the save", len(page.validate()) == 2 and all(m.startswith("Ansible:") for m in page.validate()))
page.host.setText("ansible.corp"); page.user.setText("svc"); page.port.setValue(2222); page.password.setText("s3cret!"); page.key_file.setText(r"C:\keys\id"); page.folder.setText(os.path.join(SP, "mine")); page.check_default.setChecked(False); page.keep.setValue(50)
page.command.setText("/opt/ansible/bin/ansible-playbook")
check("filled in, it is valid", page.validate() == [])
names_changed = [n for t, rows in S.pending_changes() if t == "Ansible" for n, _a, _b in rows]
check("the list of changes names them, and shows no password", any("Password" in n for n in names_changed) and not any("s3cret!" in str(x) for t, rows in S.pending_changes() for r in rows for x in r), names_changed)
S.save()
check("saving writes the choices", db.get_setting("ansible_backend") == "server" and db.get_setting("ansible_server") == {"host": "ansible.corp", "port": 2222, "user": "svc", "key_file": r"C:\keys\id"}
      and db.get_setting("ansible_command") == "/opt/ansible/bin/ansible-playbook" and db.get_setting("ansible_playbooks") == os.path.join(SP, "mine") and db.get_setting("ansible_check_default") is False and db.get_setting("ansible_keep_runs") == 50 and db.get_setting("ansible_server_device") == "")
check("the password went to Credential Manager, not the database", STORE.get((db.SERVICE, AN.SERVER_SECRET)) == "s3cret!" and "s3cret!" not in json.dumps(db.get_setting("ansible_server")) and page.password.text() == "")
check("the page says one is saved, and offers to remove it", "saved in the vault" in page.pw_note.text() and page.forget.parentWidget().isVisible())
page.forget.click(); S.save()
check("Remove saved password removes it", (db.SERVICE, AN.SERVER_SECRET) not in STORE and not page.forget.parentWidget().isVisible())
AN.backend = REAL_BACKEND; w.automation.playbooks.refresh(); AN.backend = lambda: FB
check("Automation follows the saved settings (a server over SSH now)", "server ansible.corp" in w.automation.playbooks.where.text(), w.automation.playbooks.where.text())
page.login.setCurrentIndex(0); page.device.setCurrentIndex(page.device.findData("sw2")); S.save()
check("an Inventory device is saved by name, and the typed login is not used", db.get_setting("ansible_server_device") == "sw2" and AN.server_login()["host"] == "10.0.0.2")
page.where.setCurrentIndex(0); page.distro.addItem("Ubuntu", "Ubuntu"); page.distro.setCurrentIndex(page.distro.findData("Ubuntu")); page.folder.setText(""); S.save()
check("WSL with a chosen distribution is saved too", db.get_setting("ansible_backend") == "wsl" and db.get_setting("ansible_distro") == "Ubuntu" and db.get_setting("ansible_playbooks") == "" and AN.playbook_dir() == AN.default_dir())
check("after saving, reloading shows it again", page.distro.currentData() == "Ubuntu" and page.where.currentData() == "wsl")
print("-- the test button")
class TB(AN.Backend):
    def __init__(self, res): self.res = res
    def check(self): return self.res
page.current_backend = lambda: TB((True, "ansible-playbook [core 2.17.1]")); page.test_btn.click()
check("Test shows the version when it works", wait(lambda: page.test_btn.isEnabled()) and page.test_out.text() == "OK: ansible-playbook [core 2.17.1]", page.test_out.text())
page.current_backend = lambda: TB((False, "Ansible is not installed in Ubuntu."))
page.test_btn.click()
check("and what to do when it does not", wait(lambda: page.test_btn.isEnabled()) and page.test_out.text() == "Failed: Ansible is not installed in Ubuntu.")
def boom(): raise AN.BackendError("The Ansible server device 'x' is not in the Inventory any more: choose another in Settings > Ansible.")
page.current_backend = boom; page.test_btn.click()
check("a device that has gone is explained", "not in the Inventory" in page.test_out.text() and page.test_btn.isEnabled())
del page.current_backend
page.where.setCurrentIndex(1); page.login.setCurrentIndex(1); page.host.setText("h.corp"); page.user.setText("u"); page.password.setText("typed-not-saved"); page.port.setValue(2200)
b = page.current_backend()
check("Test uses what is typed, before saving", isinstance(b, AN.ServerBackend) and b.login["host"] == "h.corp" and b.login["port"] == 2200 and b.login["password"] == "typed-not-saved" and db.get_setting("ansible_server")["host"] == "ansible.corp")
page.login.setCurrentIndex(0); page.device.setCurrentIndex(page.device.findData("dc1"))
check("or the chosen Inventory device", page.current_backend().login["host"] == "10.0.1.5")
S.reload(); app.processEvents()
page.where.setCurrentIndex(0); page.distro.clear(); page.distro.addItem("(the default one)", ""); AN.WslBackend.distros = staticmethod(lambda: ["Ubuntu", "Debian"]); page.find_distro.click()
check("Find installed lists the distributions", wait(lambda: page.distro.count() == 3) and page.test_out.text() == "Found: Ubuntu, Debian.", page.test_out.text())
AN.WslBackend.distros = staticmethod(lambda: []); page.find_distro.click()
check("with none it says how to install one", wait(lambda: "wsl --install" in page.test_out.text()))

print("== closing the window")
w.settings.cancel()                                  # the Settings edits above are dropped (leaving Settings would ask about them)
w.go("Tools"); ed.open_playbook("site/other.yml"); ed.editor.setPlainText("- hosts: z\n  tasks: []\n")
ANSWER[0] = QMessageBox.StandardButton.Cancel; w._quitting = True
ev = QCloseEvent(); w.closeEvent(ev)
check("an unsaved playbook is asked about on the way out; Cancel keeps the window open", not ev.isAccepted() and w._quitting is False and ed.dirty())
ed.revert()
FB.hold = threading.Event(); w.go("Automation"); pg.check.setChecked(True); pg._tick_all(True); pg.select("site/other.yml"); pg.start(); wait(lambda: "PLAY" in pg.output.toPlainText())
ANSWER[0] = QMessageBox.StandardButton.No; w._quitting = True; ev = QCloseEvent(); w.closeEvent(ev)
check("a playbook that is still running is asked about; No keeps it going", not ev.isAccepted() and pg.running())
FB.hold.set(); wait(lambda: pg.go.isEnabled())

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

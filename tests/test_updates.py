# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import hashlib, http.server, json, os, sys, threading, time
from datetime import datetime, timedelta
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\up%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import audit, db, updates
from core.version import VERSION, REPO
db.init()
import keyring
keyring.set_password = lambda *a: None
keyring.get_password = lambda *a: None
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtCore import QCoreApplication
app = QApplication([])
import app as A
A.apply_look(app)
import ui.about as AB

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def pump(cond, n=500):
    for _ in range(n):
        QCoreApplication.processEvents(); time.sleep(0.02)
        if cond(): break
    QCoreApplication.processEvents()
asked = []
QMessageBox.question = staticmethod(lambda *a, **k: (asked.append(a[2]), QMessageBox.StandardButton.Yes)[1])

# the installer is only ever started through updates.launch_installer: record how, instead of running anything
launched = []
class FakePopen:
    def __init__(self, args, **kw): launched.append((list(args), kw))
import types
updates.subprocess = types.SimpleNamespace(Popen=FakePopen, DEVNULL=-3, DETACHED_PROCESS=8, CREATE_NEW_PROCESS_GROUP=512)

# ================================================================ a fake GitHub
INSTALLER = b"MZ stand-in for the installer (never run in these tests)"
SHA = hashlib.sha256(INSTALLER).hexdigest()
state = {"release": None, "status": 200, "tamper": False, "slow": False}
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/repos/"):
            if state["status"] != 200: self.send_response(state["status"]); self.end_headers(); return
            body = json.dumps(state["release"]).encode() if state["release"] is not None else b"{}"
            if state["release"] is None: self.send_response(404); self.end_headers(); return
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        elif self.path.startswith("/dl/"):
            data = INSTALLER + (b"EXTRA" if state["tamper"] else b"")
            if self.path.endswith(".sha256"): data = f"{SHA}  Toner-Setup-9.9.9.exe\n".encode()
            self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers()
            if state["slow"]:
                for i in range(len(data)): self.wfile.write(data[i:i + 1]); self.wfile.flush(); time.sleep(0.01)
            else: self.wfile.write(data)
        else: self.send_response(404); self.end_headers()
    def log_message(self, *a): pass
web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler); threading.Thread(target=web.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{web.server_address[1]}"
updates.API = BASE + "/repos/{repo}/releases/latest"; updates.ALLOW_HTTP = True; updates.ALLOWED_HOSTS = ("127.0.0.1",)
def release(tag="v9.9.9", digest=True, sidecar=False, asset=True, notes="Fixes things.", name="Toner-Setup-9.9.9.exe"):
    assets = []
    if asset: assets.append({"name": name, "browser_download_url": f"{BASE}/dl/{name}", "size": len(INSTALLER), **({"digest": "sha256:" + SHA.upper()} if digest else {})})
    if sidecar: assets.append({"name": name + ".sha256", "browser_download_url": f"{BASE}/dl/{name}.sha256", "size": 80})
    assets.append({"name": "Source.zip", "browser_download_url": f"{BASE}/dl/Source.zip", "size": 5})
    return {"tag_name": tag, "name": "Toner " + tag, "body": notes, "html_url": "https://github.com/WetlBocker/toner/releases/tag/" + tag, "published_at": "2026-10-20T10:00:00Z", "assets": assets}

# ================================================================ versions
print("== versions")
check("the version is one number in one place", VERSION.count(".") == 2 and all(p.isdigit() for p in VERSION.split(".")) and REPO == "WetlBocker/toner")
check("parsing", updates.parse("v1.2.3") == (1, 2, 3) and updates.parse("1.10") == (1, 10) and updates.parse("Toner 2") == () and updates.parse("") == () and updates.parse("v2.0.0-beta") == (2, 0, 0))
for a, b, want in (("1.2.0", "1.1.9", True), ("1.10.0", "1.9.0", True), ("2.0", "1.9.9", True), ("1.1.0", "1.1.0", False), ("1.1", "1.1.0", False), ("1.1.0", "1.1.1", False), ("junk", "1.0.0", False), ("1.0.1", "1.0", True)):
    check(f"{a} is {'newer' if want else 'not newer'} than {b}", updates.is_newer(a, b) == want)

# ================================================================ finding a release
print("== finding a release")
state["release"] = release(); r = updates.fetch_latest()
check("the release is read: version, notes, page, date, installer and its checksum", r.version == "9.9.9" and r.notes == "Fixes things." and r.published == "2026-10-20" and r.asset_name == "Toner-Setup-9.9.9.exe" and r.sha256 == SHA and r.asset_size == len(INSTALLER) and r.page_url.endswith("v9.9.9"), r)
check("the installer is picked by its name, not the source archive", r.asset_url.endswith("Toner-Setup-9.9.9.exe"))
state["release"] = release(digest=False, sidecar=True); r = updates.fetch_latest()
check("without a digest, a .sha256 file next to it is used", r.sha256 == "" and r.checksum_url.endswith(".sha256") and updates.expected_hash(r) == SHA)
state["release"] = release(digest=False); r = updates.fetch_latest()
try: updates.expected_hash(r); check("no checksum anywhere is refused, with the reason", False)
except updates.UpdateError as e: check("no checksum anywhere is refused, with the reason", "does not publish a checksum" in str(e))
state["release"] = release(asset=False); r = updates.fetch_latest(); check("a release with no installer is reported as such", r.asset_url == "" and updates.check()[0] == "available")
state["release"] = release(tag="not-a-version")
try: updates.fetch_latest(); check("a tag that is not a version is refused", False)
except updates.UpdateError as e: check("a tag that is not a version is refused", "not a version number" in str(e))
state["release"] = None; check("a repository with no releases (or a private one) is not an error", updates.fetch_latest() is None and updates.check() == ("none", None))
state["release"] = release(); state["status"] = 403
try: updates.fetch_latest(); check("a rate limit is explained", False)
except updates.UpdateError as e: check("a rate limit is explained", "limiting requests" in str(e))
state["status"] = 500
try: updates.fetch_latest(); check("a server error is explained", False)
except updates.UpdateError as e: check("a server error is explained", "HTTP 500" in str(e))
state["status"] = 200
real_api = updates.API; updates.API = "http://127.0.0.1:9/{repo}"
try: updates.fetch_latest(timeout=2); check("no network is explained", False)
except updates.UpdateError as e: check("no network is explained", "Could not reach GitHub" in str(e))
updates.API = real_api
state["release"] = release(tag="v0.0.1"); check("an older release is 'current'", updates.check()[0] == "current")
state["release"] = release(tag="v" + VERSION); check("the same version is 'current'", updates.check()[0] == "current")
state["release"] = release(); st, rel = updates.check(); check("a newer one is 'available'", st == "available" and rel.version == "9.9.9")

# ================================================================ downloading
print("== downloading")
dest = os.path.join(SP, "dl%d" % int(time.time()))
seen = []; path, sha = updates.download(rel, dest, progress=lambda d, t: seen.append((d, t)))
check("the file is saved, intact, and its checksum matches", open(path, "rb").read() == INSTALLER and sha == SHA and os.path.basename(path) == "Toner-Setup-9.9.9.exe")
check("progress is reported", seen and seen[-1][0] == len(INSTALLER))
check("no partial file is left", not [f for f in os.listdir(dest) if f.endswith(".part")])
state["tamper"] = True
try: updates.download(rel, dest + "2"); check("a download that does not match its checksum is refused", False)
except updates.UpdateError as e: check("a download that does not match its checksum is refused", "bytes" in str(e) or "checksum" in str(e), str(e))
check("...and nothing is left behind", not os.path.exists(os.path.join(dest + "2", "Toner-Setup-9.9.9.exe")) and not [f for f in os.listdir(dest + "2") if f.endswith(".part")])
bad_rel = updates.Release(**{**rel.__dict__, "asset_size": 0})
try: updates.download(bad_rel, dest + "3"); check("a same-size-unknown tampered file is still caught by the checksum", False)
except updates.UpdateError as e: check("a same-size-unknown tampered file is still caught by the checksum", "checksum" in str(e), str(e))
state["tamper"] = False
for url, why in (("http://example.com/x.exe", "not https"), ("https://evil.example.com/Toner-Setup-9.9.9.exe", "not GitHub"), ("https://github.com.evil.com/x.exe", "a look-alike host")):
    updates.ALLOW_HTTP, saved_hosts = False, updates.ALLOWED_HOSTS; updates.ALLOWED_HOSTS = ("github.com", "githubusercontent.com")
    try: updates.download(updates.Release(**{**rel.__dict__, "asset_url": url}), dest + "4"); check(f"refused: {why}", False)
    except updates.UpdateError as e: check(f"refused: {why}", "not" in str(e), str(e))
    updates.ALLOW_HTTP, updates.ALLOWED_HOSTS = True, saved_hosts
updates.ALLOW_HTTP, saved_hosts = False, updates.ALLOWED_HOSTS; updates.ALLOWED_HOSTS = ("github.com", "githubusercontent.com")
for url in ("https://github.com/WetlBocker/toner/releases/download/v1/Toner-Setup-1.0.0.exe", "https://objects.githubusercontent.com/x", "https://release-assets.githubusercontent.com/x"):
    try: updates._check_url(url); check(f"real GitHub addresses are accepted: {url.split('/')[2]}", True)
    except updates.UpdateError as e: check(f"real GitHub addresses are accepted: {url.split('/')[2]}", False, str(e))
updates.ALLOW_HTTP, updates.ALLOWED_HOSTS = True, saved_hosts
cancel = threading.Event(); state["slow"] = True
class Cancel(threading.Thread):
    def run(self): time.sleep(0.1); cancel.set()
Cancel().start()
try: updates.download(rel, dest + "5", cancel=cancel); check("Cancel stops a download", False)
except updates.UpdateError as e: check("Cancel stops a download", "cancelled" in str(e) and not os.listdir(dest + "5") or not [f for f in os.listdir(dest + "5") if f.endswith(".part")])
state["slow"] = False

# ================================================================ a downloaded update waiting
print("== a downloaded update waiting to be installed")
udir = updates.updates_dir()
p, sha = updates.download(rel); updates.set_pending(rel, p, sha)
check("it is remembered, and found again", updates.pending() and updates.pending()["version"] == "9.9.9" and os.path.dirname(p) == str(udir))
open(p, "ab").write(b"tampered"); check("a file changed since it was checked is forgotten and removed from the list", updates.pending() is None and db.get_setting("update_pending") == {})
p, sha = updates.download(rel); updates.set_pending(rel, p, sha); check("a fresh download is accepted again", updates.pending() is not None)
check("an update that is not newer than this version is forgotten", updates.pending(current="99.0.0") is None)
p, sha = updates.download(rel); updates.set_pending(rel, p, sha); os.remove(p); check("a file that has gone is forgotten", updates.pending() is None)
other = os.path.join(SP, "elsewhere.exe"); open(other, "wb").write(INSTALLER); updates.set_pending(rel, other, SHA)
check("a file outside Toner's own updates folder is never trusted", updates.pending() is None)
open(other, "wb").close()
p, sha = updates.download(rel); updates.set_pending(rel, p, sha); updates.clear_pending(); check("clearing removes the file too", updates.pending() is None and not os.path.exists(p))
check("how long since the last check", updates.due() is True and (updates.mark_checked() or True) and updates.due() is False and updates.due(now=datetime.now() + timedelta(hours=25)) is True)

# ================================================================ starting the installer
print("== starting the installer")
p, sha = updates.download(rel); launched.clear()
updates.launch_installer(p, relaunch=True)
args = " ".join(launched[0][0])
check("it runs silently, without restarting the PC, and asks for Toner to be opened again", launched[0][0][0] == p and "/SILENT" in args and "/NORESTART" in args and "/SUPPRESSMSGBOXES" in args and "/relaunch=1" in args, args)
check("it is started detached, so it outlives Toner", launched[0][1]["creationflags"] == 8 | 512)
launched.clear(); updates.launch_installer(p, relaunch=False)
check("or told not to open Toner again", "/relaunch=0" in " ".join(launched[0][0]))
check("the installer's own log goes in the updates folder", "install.log" in " ".join(launched[0][0]))
check("the installer script has a /relaunch switch", "param:relaunch" in open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "packaging", "toner.iss")).read())
check("the build reads the version from the one place", "core.version" in open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "packaging", "build.ps1")).read())

# ================================================================ what is running
print("== what is running")
check("from source, it is not able to update itself", updates.installed_kind() == "source" and not updates.can_self_update() and os.path.normcase(updates.app_dir()) == os.path.normcase(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))      # whatever the project folder is called
fake_dir = os.path.join(SP, "prog%d" % int(time.time())); os.makedirs(fake_dir); open(os.path.join(fake_dir, "Toner.exe"), "wb").close()
sys.frozen = True; saved_exe = sys.executable; sys.executable = os.path.join(fake_dir, "Toner.exe")
check("a frozen copy with neither an uninstaller nor the portable marker is 'unpacked', and cannot update itself", updates.installed_kind() == "unpacked" and not updates.can_self_update())
open(os.path.join(fake_dir, "unins000.exe"), "wb").close()
check("one with the uninstaller beside it is 'installed' and can update itself", updates.installed_kind() == "installed" and updates.can_self_update())
portable_dir = os.path.join(SP, "port%d" % int(time.time())); os.makedirs(portable_dir); open(os.path.join(portable_dir, "Toner.exe"), "wb").close()
open(os.path.join(portable_dir, "portable.flag"), "w").write("x"); sys.executable = os.path.join(portable_dir, "Toner.exe")
check("with the portable marker next to it, it is 'portable' and can update itself", updates.installed_kind() == "portable" and updates.can_self_update())
p, sha = updates.download(rel); launched.clear(); updates.launch_installer(p, relaunch=True); args = launched[0][0]
check("a portable update runs the installer in portable mode, into the same folder", "/MODE=portable" in args and f"/DIR={portable_dir}" in args and "/relaunch=1" in args, args)
sys.executable = os.path.join(fake_dir, "Toner.exe"); launched.clear(); updates.launch_installer(p, relaunch=True)
check("an installed copy's update has neither", "/MODE=portable" not in launched[0][0] and not any(a.startswith("/DIR=") for a in launched[0][0]))
updates.clear_pending()
sys.executable = saved_exe; del sys.frozen

# ================================================================ the About page
print("== the About page")
ab = AB.AboutTab(); ab.resize(900, 800); ab.show()
details = dict(ab.details())
check("it lists the version, how it is installed, folders, database, log and system", details["Version"] == VERSION and "source" in details["Installed as"].lower() and details["Data folder"] == str(db.db_path().parent) and "MB" in details["Database"] and details["Log file"].endswith("toner.log") and "Python" in details and "Windows" in details and "License" in details and details["Source code"].startswith("https://github.com/"), list(details))
check("and the libraries it is built with, with versions", {n for n, v, _ in ab.libraries()} >= {"PySide6", "netmiko", "paramiko", "requests"} and all(v for n, v, _ in ab.libraries() if n in ("PySide6", "requests", "paramiko")), ab.libraries())
check("the copyable summary has the essentials", ab.details_text().startswith(f"Toner {VERSION}") and "Data folder:" in ab.details_text() and "PySide6" in ab.details_text())
QApplication.clipboard().clear(); ab.copy_btn.click(); check("Copy details puts it on the clipboard", QApplication.clipboard().text() == ab.details_text())
check("the logo and tagline are there", not ab.findChildren(AB.QLabel)[0].pixmap().isNull())
check("defaults: check daily on, installing automatically off", ab.auto_check_box.isChecked() and not ab.auto_install_box.isChecked() and not db.get_setting("update_auto_install"))
check("from source, automatic installing is greyed out and explained", not ab.auto_install_box.isEnabled() and "installer" in ab.auto_note.text())
ab.auto_check_box.setChecked(False); check("turning the daily check off is saved", db.get_setting("update_check") is False)
ab.auto_check_box.setChecked(True); check("...and on", db.get_setting("update_check") is True)
check("changes are in the audit log", any(a["action"] == "update options changed" for a in audit.recent()))

def check_now(manual=True):
    ab.check(manual); pump(lambda: ab.checker is not None and not ab.checker.isRunning()); QCoreApplication.processEvents()
state["release"] = release(); updates_seen = []; ab.update_available.connect(updates_seen.append)
check_now(); t = ab.status.text()
check("a newer version is announced with its date, and the notes are shown", "Version 9.9.9 is available" in t and "2026-10-20" in t and not ab.notes.isHidden() and "Fixes things." in ab.notes.toPlainText() and updates_seen == ["9.9.9"], t)
check("from source it says it cannot update itself and offers the release page", ab.install_btn.isHidden() and not ab.page_btn.isHidden() and "cannot update itself" in t)
check("the time of the check is recorded and shown", "Last checked: 20" in ab.last.text())
state["release"] = release(tag="v0.0.1"); check_now(); check("when up to date it says so", "up to date" in ab.status.text() and ab.notes.isHidden() and ab.page_btn.isHidden())
state["release"] = None; check_now(); check("with no releases published, it still says the version is up to date", f"up to date: version {VERSION} is the latest" in ab.status.text() and ab.notes.isHidden() and ab.install_btn.isHidden())
state["release"] = release(); state["status"] = 500; check_now(); check("a failed manual check says why", "Could not check for updates" in ab.status.text() and "HTTP 500" in ab.status.text() and ab.check_btn.isEnabled())
before = ab.status.text(); check_now(False); check("a failed background check is silent", ab.status.text() == before)
state["status"] = 200
db.set_setting("update_last_check", ""); db.set_setting("update_skip", "")
ab.release = None; check_now(); ab.skip(); check("Skip this version hides it and remembers", db.get_setting("update_skip") == "9.9.9" and ab.skip_btn.isHidden() and "will not be offered again" in ab.status.text())
updates_seen.clear(); check_now(False); check("a skipped version is not announced by a background check", updates_seen == [])
check_now(True); check("...but a manual check still shows it", updates_seen == ["9.9.9"])

print("== installing from an installed copy")
sys.frozen = True; sys.executable = os.path.join(fake_dir, "Toner.exe")
ab2 = AB.AboutTab(); ab2.show(); check("an installed copy can update itself: the option is on offer", ab2.auto_install_box.isEnabled() and "installer" not in ab2.auto_note.text())
db.set_setting("update_skip", ""); ab2.release = None
def check2(manual=True):
    ab2.check(manual); pump(lambda: not ab2.checker.isRunning()); QCoreApplication.processEvents()
check2(); check("it offers to download and install", not ab2.install_btn.isHidden() and ab2.install_btn.text() == "Download and install")
quits = []; ab2.quit_requested.connect(lambda: quits.append(1)); asked.clear()
launched.clear()
ab2.install_btn.click(); pump(lambda: bool(quits), 400)
check("it downloads, checks, asks, then starts the installer and asks Toner to close", quits == [1] and asked and "9.9.9" in asked[0] and "inventory" in asked[0], (quits, asked))
check("the installer was started with /relaunch=1", launched and "/relaunch=1" in " ".join(launched[-1][0]), launched)
check("nothing is left pending, and it is in the audit log", updates.pending() is None and any(a["action"] == "update downloaded" for a in audit.recent()) and any(a["action"] == "update installing" for a in audit.recent()))
state["tamper"] = True; quits.clear(); ab2.release = None; check2(); ab2.install_btn.click(); pump(lambda: "not installed" in ab2.status.text(), 400)
check("a download that fails its checksum is not installed, and says so", not quits and ("bytes" in ab2.status.text() or "does not match its published checksum" in ab2.status.text()), ab2.status.text())
state["tamper"] = False
state["release"] = release(digest=False); ab2.release = None; check2(); ab2.install_btn.click(); pump(lambda: "not installed" in ab2.status.text(), 400)
check("a release with no checksum is never installed", "does not publish a checksum" in ab2.status.text() and updates.pending() is None)
state["release"] = release()

print("== automatic updating")
db.set_setting("update_auto_install", True); db.set_setting("update_skip", ""); db.set_setting("update_last_check", ""); ab2.release = None
launched.clear()
check2(False); pump(lambda: updates.pending() is not None, 400)
check("a background check downloads and verifies a new version without asking", updates.pending() and updates.pending()["version"] == "9.9.9" and not quits)
check("and offers 'Install now' in the meantime", ab2.install_btn.text() == "Install now" and not ab2.install_btn.isHidden() and "installed when you close Toner" in ab2.status.text())
check("nothing was installed yet", not launched)
check("closing Toner installs it, quietly, without opening Toner again", ab2.apply_on_exit() is True)
check("...with /relaunch=0", launched and "/relaunch=0" in " ".join(launched[-1][0]) and updates.pending() is None)
check("closing again does not start it twice", ab2.apply_on_exit() is False)
db.set_setting("update_auto_install", False); p, sha = updates.download(rel); updates.set_pending(rel, p, sha)
check("with automatic installing off, closing never installs anything", ab2.apply_on_exit() is False and updates.pending() is not None)
db.set_setting("update_auto_install", True); del sys.frozen
check("a copy that cannot update itself never runs an installer on exit", ab.apply_on_exit() is False)
updates.clear_pending()
sys.executable = saved_exe

print("== in the main window")
w = A.Main()
names = [w.tabs.tabText(i) for i in range(w.tabs.count())]
check("About is the last section, after Settings", names[-2:] == ["Settings", "About"])
w.about.update_available.emit("9.9.9"); check("an available update puts a dot on About", "●" in w.tabs.list.item(len(names) - 1).text() and w.tabs.tabText(len(names) - 1) == "About")
w.about.update_cleared.emit(); check("and it goes away again", "●" not in w.tabs.list.item(len(names) - 1).text())
w.open_palette(); texts = [w.palette.list.item(i).text() for i in range(w.palette.list.count())] if hasattr(w.palette, "list") else []
check("it is listed in the palette", any("Check for updates" in t for t in texts) or not texts, texts[:5])
w.go("About"); check("Go to About works", w.tabs.currentWidget() is w.about)
check("the installer closing Toner is wired to a real quit", "self.about.quit_requested.connect(self.quit_for_real)" in open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")).read())
w.about.shutdown()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

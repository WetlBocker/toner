# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["APPDATA"] = os.path.join(SP, "roaming%d" % int(time.time()))
os.environ.pop("NETCHECK_DB", None)                                   # let the real rules choose the folder
from core import db, nettools, oui, paths, sessionlog, sessions, updates
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

appdata = os.path.join(os.environ["APPDATA"], "NetCheck")
print("== a normal copy")
check("from source, without the marker, data goes to %APPDATA%\\NetCheck", not paths.is_portable() and str(paths.data_dir()) == appdata and str(db.db_path()) == os.path.join(appdata, "netcheck.db"))

print("== a portable copy")
prog = os.path.join(SP, "usb%d" % int(time.time()), "Toner"); os.makedirs(prog); open(os.path.join(prog, "Toner.exe"), "wb").close()
sys.frozen = True; saved_exe = sys.executable; sys.executable = os.path.join(prog, "Toner.exe")
check("without the marker a frozen copy still uses %APPDATA%", not paths.is_portable() and str(paths.data_dir()) == appdata)
open(os.path.join(prog, "portable.flag"), "w").write("portable")
check("with portable.flag next to the program it is portable", paths.is_portable() and paths.app_dir() == prog)
data = os.path.join(prog, "data")
check("the data folder is 'data' beside the program, and is created", str(paths.data_dir()) == data and os.path.isdir(data))
check("the database is in it", str(db.db_path()) == os.path.join(data, "netcheck.db"))
db.init(); db.set_setting("report_org", "Portable Co"); db.save_device(dict(name="usb-sw", vendor="cisco", host="10.0.0.1", port=0, platform="", username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))
check("settings and devices are written there, not to %APPDATA%", os.path.exists(os.path.join(data, "netcheck.db")) and not os.path.exists(os.path.join(appdata, "netcheck.db")) and db.get_setting("report_org") == "Portable Co")
check("session logs, saved host keys, the MAC list, downloaded updates and Remote Desktop files follow it",
      str(sessionlog.log_dir()).startswith(data) and str(nettools.known_hosts_path()).startswith(data) and str(oui.cache_path()).startswith(data) and str(updates.updates_dir()).startswith(data)
      and str(sessions.rdp_path({"name": "x", "host": "h"})).startswith(data))
import app as A
check("the app's data_dir is the same folder", str(A.data_dir()) == data)
check("copying the whole folder takes everything: nothing was written to %APPDATA%", not os.listdir(appdata))
moved = os.path.join(SP, "usb_moved%d" % int(time.time())); import shutil; shutil.copytree(os.path.dirname(prog), moved)
sys.executable = os.path.join(moved, "Toner", "Toner.exe")
check("a copy of the folder, on another path, opens the same data", str(db.db_path()) == os.path.join(moved, "Toner", "data", "netcheck.db") and db.get_setting("report_org") == "Portable Co" and any(d["name"] == "usb-sw" for d in db.list_devices()))
db.set_setting("report_org", "Changed on the other drive"); sys.executable = os.path.join(prog, "Toner.exe")
check("and the two copies are independent", db.get_setting("report_org") == "Portable Co")

print("== checks running side by side (Run all checks), with the folder now and then held by OneDrive or a scanner")
import threading
real = paths._writable; flaky = [0]
def sometimes(folder):
    flaky[0] += 1
    return flaky[0] % 3 != 0 and real(folder)
paths._writable = sometimes
seen = []; errors = []
def worker():
    for _ in range(40):
        try:
            seen.append(str(db.db_path())); db.list_devices()
        except Exception as e:
            errors.append(e)
threads = [threading.Thread(target=worker) for _ in range(12)]
for t in threads: t.start()
for t in threads: t.join()
check("every connection opens the portable database: no 'no such table: devices'", set(seen) == {os.path.join(data, "netcheck.db")} and not errors, (set(seen), errors[:1]))
check("the folder is tested once, not on every connection", flaky[0] == 0, flaky[0])
check("and no test files are left behind", not [f for f in os.listdir(data) if f.startswith(".write-test")])
paths._writable = real
paths._confirmed.clear(); flaky[0] = 0; paths._writable = sometimes
check("a folder not yet known is tested once, then remembered", str(paths.data_dir()) == data and str(paths.data_dir()) == data and flaky[0] == 1)

print("== when the folder cannot be written to")
paths._confirmed.clear()                                              # as when Toner starts on a read-only drive
paths._writable = lambda folder: False
check("it falls back to %APPDATA% instead of failing to start", str(paths.data_dir()) == appdata and os.path.isdir(appdata))
paths._writable = real
check("and returns to the portable folder when it can be written", str(paths.data_dir()) == data)
os.remove(os.path.join(prog, "portable.flag"))
check("removing the marker makes it a normal copy again", not paths.is_portable() and str(paths.data_dir()) == appdata)
sys.executable = saved_exe; del sys.frozen

print("== the installer and the build")
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
iss = open(os.path.join(root, "packaging", "toner.iss"), encoding="utf-8").read()
check("the installer asks which kind to set up, and understands /MODE=portable for silent updates", "CreateCustomPage" in iss and "TNewRadioButton" in iss and "param:mode" in iss and "IsPortable" in iss)
check("a portable setup leaves out shortcuts, start-up entry and the uninstaller, and adds the marker", iss.count("Check: not IsPortable") >= 6 and "Uninstallable=not IsPortable" in iss and "CreateUninstallRegKey=not IsPortable" in iss and 'Source: "portable.flag"' in iss)
check("the marker file ships with the installer sources", os.path.exists(os.path.join(root, "packaging", "portable.flag")))
ignore = open(os.path.join(root, ".gitignore")).read().split()
check("a marker or data folder at the top of the project is ignored by git (so a development run is never portable by accident), but the installer's own copy is kept", "/portable.flag" in ignore and "/data/" in ignore and "portable.flag" not in ignore)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

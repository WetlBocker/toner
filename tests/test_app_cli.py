# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import io, os, subprocess, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\appcli%d.db" % int(time.time()); os.environ["APPDATA"] = SP
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

print("== Toner.exe cli ...")
r = subprocess.run([sys.executable, "app.py", "cli", "status"], cwd=root, capture_output=True, text=True, timeout=120, env=dict(os.environ, PYTHONUTF8="1"))
check("the same program runs the command line tool (no window)", r.returncode == 0 and "No results yet" in r.stdout, (r.stdout, r.stderr[-300:]))
r = subprocess.run([sys.executable, "app.py", "cli", "run", "--group", "Nope"], cwd=root, capture_output=True, text=True, timeout=120, env=dict(os.environ, PYTHONUTF8="1"))
check("and its exit codes and messages are passed through", r.returncode == 2 and "Unknown group" in r.stderr, (r.returncode, r.stderr))

print("== without a console (as when Task Scheduler starts it)")
import app as A
import ctypes
check("with a console already there nothing is changed", A.console_streams() is None)
real_out, real_err = sys.stdout, sys.stderr
real_attach, real_handle = ctypes.windll.kernel32.AttachConsole, ctypes.windll.kernel32.GetStdHandle
ctypes.windll.kernel32.AttachConsole = lambda pid: 0                 # there is no console to borrow
ctypes.windll.kernel32.GetStdHandle = lambda n: 0                    # and no redirected output either
sys.stdout = sys.stderr = None
try:
    how = A.console_streams()
    print("service started")
    sys.stdout.flush()
    path = A.data_dir() / "toner-service.log"
    out = sys.stdout
finally:
    sys.stdout, sys.stderr = real_out, real_err
    ctypes.windll.kernel32.AttachConsole, ctypes.windll.kernel32.GetStdHandle = real_attach, real_handle
out.close()
check("its output goes to toner-service.log in the data folder", how == "log" and "service started" in path.read_text(encoding="utf-8"), how)
check("the build includes the command line tool", "cli" in open(os.path.join(root, "packaging", "build.ps1")).read())

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

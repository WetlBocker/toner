"""Run every test file in its own process, several at a time, and print one line each. Exit code 1 if anything failed.

    python tests/run_all.py                    every file, as many at a time as the computer has room for
    python tests/run_all.py demarc snmp        only the files whose names contain one of the words
    python tests/run_all.py --jobs 2           this many at a time (--serial: one at a time, as before)
"""
import glob
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

here = os.path.dirname(os.path.abspath(__file__))
env = dict(os.environ, QT_QPA_PLATFORM="offscreen", PYTHONUTF8="1")
if sys.platform != "win32":                       # never the desktop's own keyring (a build machine has none); tests that store fake it
    env.setdefault("PYTHON_KEYRING_BACKEND", "keyring.backends.null.Keyring")
env.pop("SP", None)                               # each file makes its own throw-away folder

args = sys.argv[1:]
jobs = max(1, min(4, (os.cpu_count() or 2) // 2))     # each file starts a Qt app of its own: a few at a time is plenty
if "--serial" in args:
    jobs, args = 1, [a for a in args if a != "--serial"]
if "--jobs" in args:
    i = args.index("--jobs")
    jobs, args = max(1, int(args[i + 1])), args[:i] + args[i + 2:]
files = sorted(glob.glob(os.path.join(here, "test_*.py")))
if args:
    files = [f for f in files if any(a in os.path.basename(f) for a in args)]


def run(f):
    name = os.path.basename(f)
    started = time.time()
    try:
        r = subprocess.run([sys.executable, "-u", f], capture_output=True, text=True, timeout=420, env=env, encoding="utf-8", errors="replace")
        m = re.findall(r"(\d+) passed, (\d+) failed", r.stdout)
        p, b = (int(m[-1][0]), int(m[-1][1])) if m else (0, 1)
        note = "" if m and r.returncode == 0 and not b else "  <-- " + (r.stdout.strip().splitlines() or r.stderr.strip().splitlines() or ["no output"])[-1][:100]
        if note:                                              # say which checks failed (a CI log shows nothing else)
            for line in [l for l in r.stdout.splitlines() if l.lstrip().startswith("FAIL")][:6] + r.stderr.strip().splitlines()[-4:]:
                note += "\n        " + line.strip()[:200]
    except subprocess.TimeoutExpired:
        p, b, note = 0, 1, "  <-- timed out"
    return name, p, b, note, time.time() - started


failed = total_pass = 0
started = time.time()
with ThreadPoolExecutor(max_workers=jobs) as pool:
    for name, p, b, note, took in pool.map(run, files):
        total_pass += p
        failed += 1 if b else 0
        print(f"{'ok  ' if not b else 'FAIL'} {name:<28} {p:>4} passed, {b} failed  {took:5.0f} s{note}", flush=True)
print(f"\n{len(files) - failed}/{len(files)} test files clean, {total_pass} checks passed, {jobs} at a time, {(time.time() - started) / 60:.1f} min")
sys.exit(1 if failed else 0)

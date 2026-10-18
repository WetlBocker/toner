"""Run every test file in its own process and print one line each. Exit code 1 if anything failed."""
import glob
import os
import re
import subprocess
import sys

here = os.path.dirname(os.path.abspath(__file__))
env = dict(os.environ, QT_QPA_PLATFORM="offscreen", PYTHONUTF8="1")
if sys.platform != "win32":                       # never the desktop's own keyring (a build machine has none); tests that store fake it
    env.setdefault("PYTHON_KEYRING_BACKEND", "keyring.backends.null.Keyring")
files = sorted(glob.glob(os.path.join(here, "test_*.py")))
if len(sys.argv) > 1:
    files = [f for f in files if any(a in os.path.basename(f) for a in sys.argv[1:])]
failed = total_pass = 0
for f in files:
    name = os.path.basename(f)
    try:
        r = subprocess.run([sys.executable, "-u", f], capture_output=True, text=True, timeout=420, env=env, encoding="utf-8", errors="replace")
        m = re.findall(r"(\d+) passed, (\d+) failed", r.stdout)
        p, b = (int(m[-1][0]), int(m[-1][1])) if m else (0, 1)
        note = "" if m and r.returncode == 0 else "  <-- " + (r.stdout.strip().splitlines() or r.stderr.strip().splitlines() or ["no output"])[-1][:100]
        if note:                                              # say which checks failed (a CI log shows nothing else)
            for line in [l for l in r.stdout.splitlines() if l.lstrip().startswith("FAIL")][:6] + r.stderr.strip().splitlines()[-4:]:
                note += "\n        " + line.strip()[:200]
    except subprocess.TimeoutExpired:
        p, b, note = 0, 1, "  <-- timed out"
    total_pass += p
    failed += 1 if b else 0
    print(f"{'ok  ' if not b else 'FAIL'} {name:<28} {p:>4} passed, {b} failed{note}")
print(f"\n{len(files) - failed}/{len(files)} test files clean, {total_pass} checks passed")
sys.exit(1 if failed else 0)

# Run directly (python tests/test_x.py) or all together (python tests/run_all.py).
# The constellation backdrop: every dot drifts smoothly on a random path of its own across the whole page, never along its edges,
# and keeps still when motion is off. The update is driven by hand for 600 frames, so no real timer is needed.
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import sys
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
from PySide6.QtWidgets import QApplication
app = QApplication([])
from ui import backdrop, motion

W, H, FRAMES = 1200, 800, 600
def run(seed, level="Lively"):
    motion.force(level)
    bd = backdrop.Backdrop(seed=seed); bd.resize(W, H)
    paths = [[] for _ in bd.dot_positions()]
    for _ in range(FRAMES):
        bd.step_dots()
        for path, p in zip(paths, bd.dot_positions()):
            path.append(p)
    motion.force(None)
    return paths

print("== each dot drifts on its own path across the page")
paths = run(4)
xs = lambda p: [q[0] for q in p]; ys = lambda p: [q[1] for q in p]
spread = lambda v: (max(v) - min(v)) / 1.0
check("each dot's positions cover at least 40% of the width and of the height",
      all(spread(xs(p)) >= 0.4 and spread(ys(p)) >= 0.4 for p in paths), [(round(spread(xs(p)), 2), round(spread(ys(p)), 2)) for p in paths])
near = lambda q: q[0] < 0.05 or q[0] > 0.95 or q[1] < 0.05 or q[1] > 0.95
allq = [q for p in paths for q in p]
check("at most 20% of samples fall within 5% of an edge", sum(map(near, allq)) <= 0.2 * len(allq), sum(map(near, allq)) / len(allq))
check("every dot stays on the page", all(0 <= q[0] <= 1 and 0 <= q[1] <= 1 for q in allq))
check("different dots take different paths", len({tuple(p[-1]) for p in paths}) == len(paths) and len({tuple(p[100]) for p in paths}) == len(paths))
steps = [abs(b[0] - a[0]) * W for p in paths for a, b in zip(p, p[1:])]
check("no single step jumps more than 2% of the width", max(steps) <= 0.02 * W, max(steps))
check("the same seed gives the same path, another seed another", run(4) == paths and run(5) != paths)

print("== motion off")
still = run(7, "Off")
check("with motion off nothing moves", all(len(set(p)) == 1 for p in still))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

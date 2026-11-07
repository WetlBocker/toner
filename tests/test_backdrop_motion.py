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

W, H, FRAMES = 1200, 800, 6000          # ten minutes at 15 frames a second: the dots drift slowly, about a minute to cross the page
def run(seed, level="Lively", links=None):
    motion.force(level)
    bd = backdrop.Backdrop(seed=seed); bd.resize(W, H)
    paths = [[] for _ in bd.dot_positions()]
    for _ in range(FRAMES):
        bd.step_dots()
        if links is not None: links.extend((((bd._dots[a][0] - bd._dots[b][0]) * W) ** 2 + ((bd._dots[a][1] - bd._dots[b][1]) * H) ** 2) ** 0.5 for a, b, k in bd.links())
        for path, p in zip(paths, bd.dot_positions()):
            path.append(p)
    motion.force(None)
    return paths

print("== each dot drifts on its own path across the page")
SEEDS = (1, 2, 3, 4, 5)
runs = [run(s) for s in SEEDS]
paths = runs[0]
spread = lambda v: max(v) - min(v)
cover = [(spread([q[0] for q in p]), spread([q[1] for q in p])) for r in runs for p in r]
check("on each of 5 seeds every dot's positions cover at least 40% of the width and of the height", all(a >= 0.4 and b >= 0.4 for a, b in cover), min(min(c) for c in cover))
near = lambda q: q[0] < 0.05 or q[0] > 0.95 or q[1] < 0.05 or q[1] > 0.95
allq = [q for r in runs for p in r for q in p]
check("at most 20% of samples fall within 5% of an edge", sum(map(near, allq)) <= 0.2 * len(allq), sum(map(near, allq)) / len(allq))
check("every dot stays on the page", all(0 <= q[0] <= 1 and 0 <= q[1] <= 1 for q in allq))
check("different dots take different paths", len({tuple(p[-1]) for p in paths}) == len(paths) and len({tuple(p[100]) for p in paths}) == len(paths))
steps = [abs(b[0] - a[0]) * W for p in paths for a, b in zip(p, p[1:])]
check("no single step jumps more than 2% of the width (and it is slow: under 0.2%)", max(steps) <= 0.002 * W, max(steps))
check("the same seed gives the same path, another seed another", run(1) == paths and runs[1] != paths)
crossing = sum(abs(b[0] - a[0]) for p in paths for a, b in zip(p, p[1:])) / len(paths) / FRAMES
check("a dot takes about a minute or more to cross the page", 1 / crossing / 15 >= 50, 1 / crossing / 15)

print("== links join only dots that are near")
seen = []
run(1, links=seen)
reach = backdrop.LINK_NEAR * min(W, H)
check("at least one link appears over the run", len(seen) > 0)
check("no link drawn over the run is longer than the threshold", all(d < reach for d in seen), max(seen))
bd0 = backdrop.Backdrop(seed=1); bd0.resize(W, H)
check("the cap holds", len(bd0.links()) <= backdrop.MAX_LINKS)

print("== motion off")
still = run(7, "Off")
check("with motion off nothing moves", all(len(set(p)) == 1 for p in still))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

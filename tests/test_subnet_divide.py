# Run directly (python tests/test_subnet_divide.py). The Subnet Calculator's divide view: Broadcast, Subnet mask and Wildcard mask
# columns, and Join merging the subnets you select into the one network they form.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import ipaddress
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
from PySide6.QtWidgets import QApplication, QAbstractItemView
app = QApplication([])
from core import subnets
import ui.toast
from ui.tools import SubnetTab
SAID = []
ui.toast.toast = lambda w, text, problem=False: SAID.append(text)   # SubnetTab imports toast when it speaks
REFUSAL = "These subnets can't be joined into one network."
N = ipaddress.ip_network

print("== the columns")
S = SubnetTab()
check("the tree has Broadcast, Subnet mask and Wildcard mask", all(c in S.COLS for c in ("Broadcast", "Subnet mask", "Wildcard mask")), S.COLS)
def cells(text):
    S.inp.setText(text); app.processEvents()
    it = S.tree.topLevelItem(0)
    return {c: it.text(i) for i, c in enumerate(S.COLS)}
r = cells("10.0.0.0/24")
check("/24", (r["Broadcast"], r["Subnet mask"], r["Wildcard mask"]) == ("10.0.0.255", "255.255.255.0", "0.0.0.255"), r)
r = cells("10.0.0.32/27")
check("/27", (r["Broadcast"], r["Subnet mask"], r["Wildcard mask"]) == ("10.0.0.63", "255.255.255.224", "0.0.0.31"), r)
r = cells("10.0.0.4/31")
check("/31 shows what the main view shows", (r["Broadcast"], r["Subnet mask"], r["Wildcard mask"]) == ("10.0.0.5", "255.255.255.254", "0.0.0.1"), r)
r = cells("10.0.0.4/32")
check("/32 shows what the main view shows", (r["Broadcast"], r["Subnet mask"], r["Wildcard mask"]) == ("10.0.0.4", "255.255.255.255", "0.0.0.0"), r)
r = cells("2001:db8::/48")
check("IPv6 leaves the three blank", (r["Broadcast"], r["Subnet mask"], r["Wildcard mask"]) == ("", "", ""), r)

print("== core join")
check("two neighbours make their /26", subnets.join([N("10.0.0.32/27"), N("10.0.0.0/27")]) == N("10.0.0.0/26"))
check("a gap is refused", subnets.join([N("10.0.0.0/27"), N("10.0.0.64/27")]) is None)
check("unaligned neighbours are refused", subnets.join([N("10.0.0.32/27"), N("10.0.0.64/27")]) is None)
check("one network is no join", subnets.join([N("10.0.0.0/27")]) is None)
check("a repeat is refused", subnets.join([N("10.0.0.0/27"), N("10.0.0.0/27")]) is None)

print("== Join in the tree")
def fresh():
    S.inp.setText(""); S.inp.setText("10.0.0.0/25"); app.processEvents(); SAID.clear()
    root = S.tree.topLevelItem(0)
    S.split_to(root, 27); app.processEvents()
    return root
def pick(root, *idx):
    S.tree.clearSelection()
    for i in idx: root.child(i).setSelected(True)
    app.processEvents()
def names(root): return [root.child(i).text(0) for i in range(root.childCount())]
check("the tree allows several rows", S.tree.selectionMode() == QAbstractItemView.SelectionMode.ExtendedSelection)
root = fresh(); pick(root, 0, 1); S.join_up(); app.processEvents()
check("two neighbours join into the /26", names(root) == ["10.0.0.0/26", "10.0.0.64/27", "10.0.0.96/27"], names(root))
check("the joined row has its columns", root.child(0).text(1) == "10.0.0.1" and root.child(0).text(4) == "10.0.0.63", root.child(0).text(4))
root = fresh(); pick(root, 0, 1, 2, 3); S.join_up(); app.processEvents()
check("all four /27s give the /25", root.childCount() == 0 and S.tree.currentItem() is root and not SAID, names(root))
root = fresh(); pick(root, 0, 2); S.join_up(); app.processEvents()
check("a gap is refused and the tree is unchanged", SAID == [REFUSAL] and len(names(root)) == 4, SAID)
root = fresh(); pick(root, 1, 2); S.join_up(); app.processEvents()
check("unaligned neighbours are refused and the tree is unchanged", SAID == [REFUSAL] and len(names(root)) == 4, SAID)
root = fresh(); pick(root, 1); S.join_up(); app.processEvents()
check("one subnet does nothing", len(names(root)) == 4 and not SAID)
check("Join is off for one subnet, on for two", (not S.join.isEnabled()) and (pick(root, 0, 1) or S.join.isEnabled()))

check("Join's tooltip says what it does now", S.join.toolTip() == "Join the selected subnets into one network", S.join.toolTip())
check("the note above the tree says how to join", S.split_note.text() == "Choose a network in the tree, then split it into smaller subnets; select subnets and Join to merge them.", S.split_note.text())
readme = open(_os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "README.md"), encoding="utf-8").read()
check("README: Join merges the subnets you select", "Join to merge the subnets you select" in readme and "Join to put them back" not in readme)
check("README: the Look up uses your IP lookup provider", "a **Look up** with your IP lookup provider (the API URL and key go under Settings > Connections)" in readme
      and "at ipstack.com (location" not in readme)
check("README: WHOIS shows where it is with an IP lookup key", "and, with an IP lookup key, where it is" in readme and "with an ipstack key" not in readme)

print(f"{ok} passed, {bad} failed")
raise SystemExit(1 if bad else 0)

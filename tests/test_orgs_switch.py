# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Switching organization in the sidebar: every section shows the organization just picked, through the real set_org path.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "orgsw%d.db" % int(time.time())); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import db, orgs, sessions
from drivers.base import Result
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

from PySide6.QtWidgets import QApplication
app = QApplication.instance() or QApplication([])
import app as A
A.apply_look(app)


def dev(name, host):
    return dict(name=name, vendor="cisco", host=host, port=0, platform="", username="u", site="default", verify_ssl=0, ha_expected=0,
                enabled=1, location="", details="", folder_id=None)


ster, sg = orgs.create("Stericycle", "STER"), orgs.create("SG360", "SG")
NAMES = {ster: ("ster-fw", "ster-sw1"), sg: ("sg-core", "sg-sw1")}
for org, names in NAMES.items():
    with db.within(org):
        for i, n in enumerate(names):
            db.save_device(dev(n, f"10.{org}.0.{i + 1}"))
        db.save_run([Result(n, "ping", "OK", "1 ms", "", 1.0) for n in names])
        sessions.save({"name": f"{names[0]}-ssh", "kind": "ssh", "host": f"10.{org}.0.1", "port": 22, "username": "u", "folder_id": None, "options": {}})
        from core import backup
        backup.store(names[0], f"hostname {names[0]}\n", mask=False)
orgs.set_current(ster)
w = A.Main(); w.resize(1400, 860); w.show(); app.processEvents()


def tree_names(tree):
    out = []
    def walk(it):
        for i in range(it.childCount()):
            ch = it.child(i); out.append(ch.text(0)); walk(ch)
    for i in range(tree.topLevelItemCount()):
        t = tree.topLevelItem(i); out.append(t.text(0)); walk(t)
    return out


def shown():
    """What each section lists right now: {section: set of device or session names}."""
    return {"inventory": {n for n in tree_names(w.inventory.table) if "-" in n},
            "results": {w.results.table.topLevelItem(i).text(0) for i in range(w.results.table.topLevelItemCount())},
            "history runs": {w.history.runs.item(i, 5).text() for i in range(w.history.runs.rowCount())},
            "history devices": {w.history.dev.itemText(i).split(" (")[0] for i in range(w.history.dev.count())},
            "configs": {w.configs.devs.item(i, 0).text() for i in range(w.configs.devs.rowCount())},
            "sessions": {n for n in tree_names(w.sessions.tree) if n.endswith("-ssh")}}


def expect(org):
    names = set(NAMES[org]) if org else {n for ns in NAMES.values() for n in ns}
    return {"inventory": names, "results": names, "history devices": names, "configs": names,
            "history runs": {orgs.name(org)} if org else {orgs.name(o) for o in NAMES},
            "sessions": {f"{NAMES[org][0]}-ssh"} if org else {f"{ns[0]}-ssh" for ns in NAMES.values()}}


def every_section(tag, org):
    got, want = shown(), expect(org)
    for section in want:
        check(f"{tag}: {section} shows {orgs.name(org)}'s rows", got[section] == want[section], (sorted(got[section]), sorted(want[section])))
    check(f"{tag}: the headers name {orgs.name(org)}", w.headers["inventory"].title.text() == f"{orgs.name(org)} - Inventory"
          and w.headers["inventory"].context.text().startswith(f"{len(want['inventory'])} device"), w.headers["inventory"].context.text())


print("== the window opens on the organization picked last time")
every_section("at start", ster)

print("== the sidebar switcher")
w.tabs.org.setCurrentIndex(w.tabs.org.findData(sg)); app.processEvents()
check("picking SG360 in the switcher makes it the home organization", db.home() == sg)
every_section("after switching to SG360", sg)

print("== set_org to Global and back")
w.set_org(0); app.processEvents()
every_section("in Global", 0)
w.set_org(ster); app.processEvents()
every_section("back in Stericycle", ster)

print("== the inventory's search box and folders start clean in the new organization")
w.inventory.search.setText("sg"); app.processEvents()
w.set_org(sg); app.processEvents()
check("the search box is cleared on a switch", w.inventory.search.text() == "")
every_section("SG360 after a search in Stericycle", sg)

print("== removing or archiving an organization from Global redraws the lists (1.6.10 left its rows on screen)")
w.set_org(0); app.processEvents()
orgs.set_archived(ster, True); w.settings.orgs_changed.emit(); app.processEvents()
got = shown()
check("an archived organization's devices and sessions leave the Global lists",
      not any(n.startswith("ster-") for n in got["inventory"] | got["sessions"]), (sorted(got["inventory"]), sorted(got["sessions"])))
orgs.set_archived(ster, False); w.settings.orgs_changed.emit(); app.processEvents()
check("restoring it brings them back", shown()["inventory"] == expect(0)["inventory"])
orgs.remove(sg); w.settings.orgs_changed.emit(); app.processEvents()
NAMES.pop(sg)
every_section("after removing SG360 from Global", 0)

w.close()
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

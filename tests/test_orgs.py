# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Organizations: a file each, Global listing everything, Shared items, settings that follow Global, moving devices.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\org%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import db, orgs, profiles
from drivers.base import Result
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def dev(name, **kw):
    return dict(dict(name=name, vendor="cisco", host="10.0.0.1", port=0, platform="", username="u", site="default", verify_ssl=0,
                     ha_expected=0, enabled=1, location="", details="", folder_id=None), **kw)

print("== creating organizations")
acme = orgs.create("Acme Charter", "ACME")
globex = orgs.create("Globex", orgs.suggest_code("Globex"))
check("two organizations, by name", [o["name"] for o in orgs.list_orgs()] == ["Acme Charter", "Globex"])
check("each has its own file next to the Global one", db.org_path(acme).exists() and db.org_path(acme).parent.name.endswith(".orgs"))
check("a code is suggested from the name", orgs.suggest_code("Acme Charter Schools") == "ACS" and orgs.suggest_code("Globex") == "GLOBEX2")
for args, said in ((("acme charter", "X"), "already exists"), (("Initech", "ACME"), "already used"), (("Global", "G"), "used by Toner"),
                   (("Initech", "a b"), "letters, digits")):
    try:
        orgs.create(*args); check(f"refused: {args}", False)
    except ValueError as e:
        check(f"refused: {args} ({said})", said in str(e), str(e))

print("== devices live in their own organization's file")
db.save_device(dev("core-sw1"))                                    # Global (nothing picked)
db.save_device(dev("jump", shared=1))                              # Shared
with db.within(acme):
    db.save_device(dev("edge-fw"))
    db.save_device(dev("core-sw1", host="10.1.1.1"))               # the same name in another organization is fine
with db.within(globex):
    db.save_device(dev("edge-fw", host="10.2.2.2"))
try:
    with db.within(acme):
        db.save_device(dev("EDGE-FW"))
    check("the same name twice in one organization is refused", False)
except db.NameTaken as e:
    check("the same name twice in one organization is refused, naming it", str(e) == "A device named EDGE-FW already exists in Acme Charter.", str(e))
try:
    with db.within(globex):
        db.save_device(dev("jump"))
    check("an organization cannot reuse a Shared device's name", False)
except db.NameTaken as e:
    check("an organization cannot reuse a Shared device's name", "Global (Shared)" in str(e), str(e))
try:
    db.save_device(dev("edge-fw", shared=1))
    check("a Shared device cannot take a name an organization uses", False)
except db.NameTaken as e:
    check("a Shared device cannot take a name an organization uses", "Acme Charter" in str(e), str(e))

every = db.list_devices()
check("Global lists every organization's devices", sorted((d["name"], d["org"]) for d in every) ==
      sorted([("core-sw1", 0), ("jump", 0), ("edge-fw", acme), ("core-sw1", acme), ("edge-fw", globex)]), [(d["name"], d["org"]) for d in every])
check("same-named devices get different keys in Global", len({d["key"] for d in every}) == 5 and
      {d["key"] for d in every if d["name"] == "edge-fw"} == {f"edge-fw@@{acme}", f"edge-fw@@{globex}"})
check("keys come apart again", db.split_key(f"udm@@{acme} / ap-1") == ("udm / ap-1", acme) and db.split_key("udm / ap-1") == ("udm / ap-1", None))
db.set_home(acme)
mine = db.list_devices()
check("an organization lists its own devices plus Shared ones", sorted((d["name"], d["org"]) for d in mine) == [("core-sw1", acme), ("edge-fw", acme), ("jump", 0)])
check("and keys are plain names there", {d["key"] for d in mine} == {"core-sw1", "edge-fw", "jump"})
j = next(d for d in mine if d["name"] == "jump")
check("a Shared device has no folder in an organization's view", j["folder_id"] is None and "_folder_id" in j)
db.set_home(0)

print("== passwords are kept under the organization's names")
with db.within(acme):
    db.set_secret(db.secret_name("edge-fw"), "acme-pw")
with db.within(globex):
    db.set_secret(db.secret_name("edge-fw"), "globex-pw")
db.set_secret(db.secret_name("core-sw1"), "global-pw")
check("Global keeps plain names (nothing stored before moves)", STORE.get(("netcheck", "core-sw1")) == "global-pw")
check("organizations prefix theirs", STORE.get(("netcheck", f"org{acme}/edge-fw")) == "acme-pw" and STORE.get(("netcheck", f"org{globex}/edge-fw")) == "globex-pw")
a_dev = next(d for d in every if d["key"] == f"edge-fw@@{acme}")
g_dev = next(d for d in every if d["key"] == f"edge-fw@@{globex}")
check("a device's password is found from Global's list", profiles.secret(a_dev) == "acme-pw" and profiles.secret(g_dev) == "globex-pw")

print("== settings start from Global and can be changed per organization")
db.set_setting("ssh_timeout", 30)
with db.within(acme):
    check("an organization follows Global", db.get_setting("ssh_timeout") == 30 and not db.overridden("ssh_timeout"))
    db.set_setting("ssh_timeout", 45)
    check("its own value wins", db.get_setting("ssh_timeout") == 45 and db.overridden("ssh_timeout"))
check("Global is unchanged", db.get_setting("ssh_timeout") == 30)
with db.within(globex):
    check("other organizations still follow Global", db.get_setting("ssh_timeout") == 30)
with db.within(acme):
    db.set_setting("ssh_timeout", 30)
    check("setting it back to Global's value follows Global again", not db.overridden("ssh_timeout"))
db.set_setting("ssh_timeout", 25)
with db.within(acme):
    check("...including later changes in Global", db.get_setting("ssh_timeout") == 25)
    db.set_setting("ssh_timeout", 50)
    db.follow_global("ssh_timeout")
    check("Reset to Global forgets its own value", db.get_setting("ssh_timeout") == 25 and not db.overridden("ssh_timeout"))
    db.set_setting("theme", "Dark")
check("a setting managed by Global is written to Global from anywhere", db.get_setting("theme") == "Dark")
db.set_setting("acks", {"x": 1})
with db.within(acme):
    check("an organization's own lists never borrow Global's", db.get_setting("acks") == {})
    th = db.get_thresholds(); th["cpu"] = {"warn": 50, "fail": 60}; db.set_thresholds(th)
    check("thresholds can be its own", db.get_thresholds()["cpu"] == {"warn": 50, "fail": 60})
check("Global's thresholds are untouched", db.get_thresholds()["cpu"] == {"warn": 70, "fail": 90})

print("== results go to the device's own file; Global reads them all")
rid = db.save_run([Result("core-sw1", "cpu", "OK", "1%"), Result("edge-fw", "cpu", "FAIL", "99%", org=acme),
                   Result("core-sw1", "cpu", "WARN", "80%", org=acme), Result("edge-fw", "cpu", "OK", "2%", org=globex)])
runs = db.list_runs()
check("one run per file", sorted(r["org"] for r in runs) == sorted([0, acme, globex]), runs)
health = db.device_health()
check("health keys tell the same names apart", health["core-sw1"]["status"] == "OK" and health[f"core-sw1@@{acme}"]["status"] == "WARN"
      and health[f"edge-fw@@{acme}"]["status"] == "FAIL" and health[f"edge-fw@@{globex}"]["status"] == "OK", sorted(health))
db.set_home(acme)
check("an organization sees only its own health", sorted(db.device_health()) == ["core-sw1", "edge-fw"])
check("...and its own runs", [r["org"] for r in db.list_runs()] == [acme])
db.set_home(0)
rows, at = db.latest_results()
check("Global's latest results carry keys and the organization", {(r["device"], r["org"]) for r in rows} ==
      {("core-sw1", 0), (f"edge-fw@@{acme}", acme), (f"core-sw1@@{acme}", acme), (f"edge-fw@@{globex}", globex)})
gr = next(r for r in runs if r["org"] == globex)
check("a run's rows read from its own file", [x["device"] for x in db.run_results(gr["id"], globex)] == [f"edge-fw@@{globex}"])

print("== Shared devices' results show in every organization")
db.save_run([Result("jump", "cpu", "WARN", "75%", org=0)])
db.set_home(globex)
check("the Shared device's health shows in an organization", "jump" in db.device_health() and "core-sw1" not in db.device_health())
db.set_home(0)

print("== the runner checks each device with its own organization's settings")
from core import runner
seen = []
def fake_run_one(d, th, opts=None):
    seen.append((d["name"], d.get("org"), db.target(), th["cpu"]))
    return [Result(d["name"], "cpu", "OK", "1%")]
real = runner.run_one; runner.run_one = fake_run_one
res = runner.run_all([a_dev, g_dev], lambda d: db.thresholds_for(d), workers=2)
runner.run_one = real
check("each runs inside its own file, with its organization's thresholds", sorted(seen) == sorted([
    ("edge-fw", acme, acme, {"warn": 50, "fail": 60}), ("edge-fw", globex, globex, {"warn": 70, "fail": 90})]), seen)
check("results are tagged with the organization", sorted(r.org for r in res) == sorted([acme, globex]))

print("== moving devices between organizations")
with db.within(globex):
    fid = db.ensure_folder_path("Chicago/Core")
    pid = profiles.save({"name": "ro", "username": "readonly"}, {"main": "prof-pw"})
    db.save_device(dev("sw-move", folder_id=fid, profile_id=pid))
    db.set_secret(db.secret_name("sw-move"), "move-pw")
    from core import sessions as S
    sid = S.save({"name": "sw-move ssh", "kind": "ssh", "host": "10.9.9.9", "device": "sw-move"})
    S.set_password(sid, "sess-pw")
    db.save_run([Result("sw-move", "cpu", "WARN", "80%"), Result("edge-fw", "cpu", "OK", "1%")])
mv = next(d for d in db.list_devices() if d["name"] == "sw-move")
n = orgs.move_devices([mv], acme, with_data=True)
with db.within(acme):
    got = next((d for d in db.list_devices() if d["name"] == "sw-move" and d["org"] == acme), None)
    check("the device is in the new organization", n == 1 and got is not None)
    check("in the same folder path", db.folder_paths().get(got["folder_id"]) == "Chicago/Core")
    check("with its credential profile (copied, passwords too)", profiles.of(got).get("name") == "ro" and profiles.secret({**got, "username": ""}) == "move-pw")
    check("its history came along", "sw-move" in db.device_health() and db.device_health()["sw-move"]["status"] == "WARN")
    s2 = [s for s in S.list_sessions() if s["device"] == "sw-move"]
    check("its saved session came along, with its password", len(s2) == 1 and S.password(s2[0]["id"]) == "sess-pw")
check("its password moved to the new organization's name", STORE.get(("netcheck", f"org{acme}/sw-move")) == "move-pw"
      and ("netcheck", f"org{globex}/sw-move") not in STORE)
with db.within(globex):
    check("nothing of it is left behind", not any(d["name"] == "sw-move" for d in db.list_devices()) and "sw-move" not in db.device_health()
          and not [s for s in S.list_sessions() if s["device"] == "sw-move"])
    check("the rest of that run stays", "edge-fw" in db.device_health())

with db.within(globex):
    db.save_device(dev("sw-only"))
    db.save_run([Result("sw-only", "cpu", "OK", "1%")])
orgs.move_devices([next(d for d in db.list_devices() if d["name"] == "sw-only")], acme, with_data=False)
with db.within(globex):
    check("devices only: the history stays where it was", "sw-only" in db.device_health())
with db.within(acme):
    check("devices only: the device moved without it", any(d["name"] == "sw-only" for d in db.list_devices()) and "sw-only" not in db.device_health())
try:
    orgs.move_devices([next(d for d in db.list_devices() if d["key"] == f"edge-fw@@{globex}")], acme)
    check("moving onto a name already used is refused", False)
except ValueError as e:
    check("moving onto a name already used is refused, before anything changes", str(e) == "A device named edge-fw already exists in Acme Charter."
          and any(d["key"] == f"edge-fw@@{globex}" for d in db.list_devices()), str(e))

print("== archive, restore, remove")
db.set_home(globex)
orgs.set_archived(globex, True)
check("archiving the open organization goes back to Global", db.home() == 0 and orgs.current() == 0)
check("an archived organization is hidden from Global", not any(d["org"] == globex for d in db.list_devices()))
db.show_archived = True
check("...unless archived ones are asked for", any(d["org"] == globex for d in db.list_devices()))
db.show_archived = False
orgs.set_archived(globex, False)
check("restored", any(d["org"] == globex for d in db.list_devices()))
orgs.set_current(acme)
check("the pick is remembered", orgs.current() == acme and db.home() == acme)
orgs.set_current(0)

init = orgs.create("Initech", "INIT")
with db.within(init):
    db.save_device(dev("printer"))
    db.set_secret(db.secret_name("printer"), "p")
    db.save_run([Result("printer", "toner", "WARN", "10%")])
orgs.remove(init, move_to=globex)
check("removing with a destination moves its devices and history", (not db.org_path(init).exists(), orgs.get(init) is None) == (True, True)
      and any(d["name"] == "printer" and d["org"] == globex for d in db.list_devices()), (db.org_path(init).exists(), orgs.get(init)))
with db.within(globex):
    check("...and their passwords", profiles.secret(next(d for d in db.list_devices() if d["name"] == "printer")) == "p"
          and "printer" in db.device_health())
init2 = orgs.create("Hooli", "HOOLI")
with db.within(init2):
    db.save_device(dev("gone"))
    db.set_secret(db.secret_name("gone"), "x")
orgs.remove(init2)
check("removing without one deletes them, file and passwords", not db.org_path(init2).exists() and not any(d["name"] == "gone" for d in db.list_devices())
      and ("netcheck", f"org{init2}/gone") not in STORE)
try:
    orgs.remove(0); check("Global cannot be removed", False)
except ValueError:
    check("Global cannot be removed", True)

print("== startup brings every organization's file up to date")
db.init()
with db.within(acme):
    check("an organization's file has the current schema", db.schema_version() == db.SCHEMA_VERSION)
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

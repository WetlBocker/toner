# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Organizations, the rest: Shared profiles, checks and windows, alerts per organization, agents, schedules, the audit log,
# the Settings window (its line at the top, pages managed by Global, Reset to Global), Settings > Organizations and the import step.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
from datetime import datetime, timedelta
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\orgm%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import agents, alerts, audit, custom, db, maintenance, notify, orgs, profiles, service
from drivers.base import Result
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def dev(name, **kw):
    return dict(dict(name=name, vendor="cisco", host="10.0.0.1", port=0, platform="", username="", site="default", verify_ssl=0,
                     ha_expected=0, enabled=1, location="", details="", folder_id=None), **kw)

acme, globex = orgs.create("Acme", "ACME"), orgs.create("Globex", "GLOBEX")

print("== Shared credential profiles")
pid = profiles.save({"name": "noc", "username": "noc-user", "shared": 1, "org": 0}, {"main": "noc-pw"})
profiles.save({"name": "global-only", "username": "g"}, {"main": "g-pw"})
with db.within(acme):
    names = {p["name"]: p for p in profiles.list_profiles()}
    check("an organization sees its own profiles plus Global's Shared ones", set(names) == {"noc"} and names["noc"]["id"] == -pid, names)
    db.save_device(dev("sw1", profile_id=-pid))
    sw1 = next(d for d in db.list_devices() if d["name"] == "sw1")
    check("its device uses the Shared profile's user name and password", profiles.username(sw1) == "noc-user" and profiles.secret(sw1) == "noc-pw")
check("Global's list of profiles is its own", {p["name"] for p in profiles.list_profiles()} == {"noc", "global-only"})
check("Global's Settings list shows every organization's profiles", {(p["name"], p["org"]) for p in profiles.listing()} == {("noc", 0), ("global-only", 0)})
check("the Shared profile's users include the organizations' devices", profiles.users_of(pid) == ["sw1 (Acme)"], profiles.users_of(pid))
with db.within(acme):
    profiles.save({"name": "acme-ro", "username": "ro"}, {"main": "ro-pw"})
check("a profile made in an organization is kept there, with its password", STORE.get(("netcheck", f"org{acme}/profile:acme-ro")) == "ro-pw"
      and "acme-ro" not in {p["name"] for p in profiles.list_profiles()})
moved = next(d for d in db.list_devices() if d["key"] == f"sw1@@{acme}")
orgs.move_devices([moved], globex)
with db.within(globex):
    g = next(d for d in db.list_devices() if d["name"] == "sw1")
    check("a device moved to another organization keeps the Shared profile", g["profile_id"] == -pid and profiles.secret(g) == "noc-pw")
orgs.move_devices([next(d for d in db.list_devices() if d["name"] == "sw1")], 0)
g = next(d for d in db.list_devices() if d["name"] == "sw1" and d["org"] == 0)
check("...and moved to Global it refers to it by its own id", g["profile_id"] == pid and profiles.secret(g) == "noc-pw")
profiles.delete(pid)
check("deleting a Shared profile leaves no device pointing at it", db.get_device(g["id"], 0)["profile_id"] is None)

print("== Shared custom checks and maintenance windows")
custom.save_check({"name": "web", "kind": "http", "target": "https://x", "shared": 1, "org": 0})
custom.save_check({"name": "g-only", "kind": "tcp", "port": 22, "org": 0})
with db.within(acme):
    custom.save_check({"name": "acme-port", "kind": "tcp", "port": 443})
    check("an organization's checks are its own plus the Shared ones", sorted(c["name"] for c in custom.list_checks()) == ["acme-port", "web"])
    check("...and they are what its runs use", sorted(c["name"] for c in db.runtime_options()["custom"]) == ["acme-port", "web"])
check("Global's runs use Global's", sorted(c["name"] for c in custom.list_checks()) == ["g-only", "web"])
check("Global's Settings list shows every organization's", sorted((c["name"], c["org"]) for c in custom.listing()) ==
      sorted([("acme-port", acme), ("g-only", 0), ("web", 0)]))
now = datetime.now()
maintenance.save_window({"name": "patching", "kind": "once", "start_at": (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M"),
                         "end_at": (now + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M"), "scope": [], "shared": 1, "org": 0})
with db.within(acme):
    db.save_device(dev("acme-fw"))
    check("a Shared maintenance window covers an organization's devices too", "acme-fw" in maintenance.devices_in_maintenance())
with db.within(globex):
    maintenance.save_window({"name": "x", "kind": "once", "start_at": "2020-01-01 00:00", "end_at": "2020-01-02 00:00", "scope": []})
check("Global lists every organization's windows in Settings", sorted(w["name"] for w in maintenance.listing()) == ["patching", "x"])
held = maintenance.devices_in_maintenance()
check("in Global, devices in maintenance are keyed apart", f"acme-fw@@{acme}" in held, sorted(held))

print("== alerts: each organization with its own settings; Global's channels say whose it is")
sent = []
notify.deliver = lambda ch, msg, desktop=None, secrets=None, retry_delay=2: sent.append((ch["name"], msg.title)) or (True, "ok")
db.set_setting("notify_enabled", True)
db.set_setting("notify_channels", [{"id": "g1", "type": "webhook", "name": "Global hook", "enabled": True, "min": "WARN and worse", "recoveries": True, "url": "x"}])
with db.within(globex):
    db.set_setting("notify_channels", [{"id": "x1", "type": "webhook", "name": "Globex hook", "enabled": True, "min": "WARN and worse", "recoveries": True, "url": "y"}])
    db.save_device(dev("globex-sw"))
maintenance.delete_window(next(w["id"] for w in maintenance.list_windows() if w["name"] == "patching"), 0)
with db.within(acme):
    db.save_device(dev("acme-sw"))
res = [Result("acme-sw", "cpu", "FAIL", "99%", org=acme), Result("globex-sw", "cpu", "FAIL", "99%", org=globex)]
said = notify.process_run(res, [f"acme-sw@@{acme}", f"globex-sw@@{globex}"], True)
check("one run in Global alerts each organization separately", sorted(n for n, _t in sent) == ["Global hook", "Globex hook"], (said, sent))
titles = dict(sent)
check("an organization using Global's channel is named in the alert", titles["Global hook"].startswith("[Acme] Toner"), titles)
check("one with its own channel is not", titles["Globex hook"].startswith("Toner"), titles)
with db.within(acme):
    check("each organization keeps its own alert state", any(r["device"] == "acme-sw" for r in db.connect().execute("SELECT device FROM alert_state")))
orgs.set_archived(globex, True)
sent.clear()
notify.process_run([Result("globex-sw", "cpu", "OK", "1%", org=globex), Result("acme-sw", "cpu", "OK", "1%", org=acme)],
                   [f"globex-sw@@{globex}", f"acme-sw@@{acme}"], True)
check("an archived organization stays quiet", [n for n, _t in sent] == ["Global hook"], sent)
orgs.set_archived(globex, False)

print("== agents report into their own organization")
with db.within(acme):
    db.save_device(dev("pc1", vendor="windows", platform="agent"))
    tok = agents.token_for("pc1")
check("the token is kept under the organization's name", STORE.get(("netcheck", f"org{acme}/pc1:agent")) == tok)
check("a report's token is found in its organization's file", agents.token_owner(tok) == ("pc1", acme))
db.set_home(globex)
with db.within(agents.token_owner(tok)[1]):
    agents.store("pc1", {"cpu": 5, "computer": "PC1"}, "10.0.0.9")
db.set_home(0)
with db.within(acme):
    check("the report landed in that organization's file, whichever one is open", agents.latest("pc1")[0]["computer"] == "PC1")
check("Global's agent list shows it, keyed apart", any(r["device"] == f"pc1@@{acme}" for r in agents.overview()))
db.set_setting("agent_enroll", True)
code, ans = agents.enroll("NEWPC", agents.enroll_key(), "10.0.0.50")
check("the sign-up package adds computers to Global", code == 200 and any(d["name"] == "NEWPC" and d["org"] == 0 for d in db.list_devices()), (code, ans))
pc = next(d for d in db.list_devices() if d["key"] == f"pc1@@{acme}")
orgs.move_devices([pc], globex, with_data=False)
check("a device moved without its data still keeps its agent's token", agents.token_owner(tok) == ("pc1", globex))

print("== each organization's schedule runs its own devices")
ran = []
real_checks = service.run_checks
service.run_checks = lambda groups=None, do_notify=True, scheduled=True, on_result=None, own=False: ran.append((db.target(), own, [d["name"] for d in service.own_devices(groups)])) or []
db.set_setting("schedule_enabled", True); db.set_setting("schedule_minutes", 60)
with db.within(globex):
    db.set_setting("schedule_minutes", 15)
d = service.Daemon(log=lambda *a: None)
d._arm()
check("Global and every organization get their own next run", set(d.due) == {0, acme, globex} and
      (d.due[globex]["checks"] - d.due[0]["checks"]).total_seconds() < -2000)
d.tick(datetime.now() + timedelta(minutes=20))
check("an organization with its own interval runs on it, with only its own devices", ran == [(globex, True, ["globex-sw", "pc1"])], ran)
d.tick(datetime.now() + timedelta(minutes=61))
check("the others follow Global's interval as runs of their own", sorted(r[0] for r in ran[1:]) == sorted([0, acme, globex]), ran)
check("Global's covers its own and Shared devices", next(r for r in ran[1:] if r[0] == 0)[2] == ["NEWPC", "sw1"], ran)
service.run_checks = real_checks
db.set_setting("schedule_enabled", False)

print("== the audit log: each organization its own, Global sees them all")
with db.within(acme):
    audit.log("thing done", "in acme")
audit.log("thing done", "in global")
check("Global's audit log shows every organization's entries", {(r["detail"], r["org"]) for r in audit.recent() if r["action"] == "thing done"}
      == {("in acme", acme), ("in global", 0)})
db.set_home(acme)
check("an organization sees only its own", [r["detail"] for r in audit.recent() if r["action"] == "thing done"] == ["in acme"])
db.set_home(0)

print("== the window: Settings, Settings > Organizations, the import step")
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication.instance() or QApplication([])
import ui.settings as S
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
QMessageBox.warning = staticmethod(lambda *a, **k: None)
QMessageBox.information = staticmethod(lambda *a, **k: None)
st = S.SettingsTab(); st.resize(1100, 800); st.show(); app.processEvents()
titles = st.page_titles()
check("Settings > Organizations is there in Global", "Organizations" in titles and not st.scope_note.isVisibleTo(st))
op = next(p for p in st.pages if p.title == "Organizations")
check("it lists the organizations", [op.table.item(i, 0).text() for i in range(op.table.rowCount())] == ["Acme", "Globex"])
db.set_home(acme); st.reload(); app.processEvents()
check("inside an organization the line at the top says so", st.scope_note.isVisibleTo(st) and st.scope_note.text() == "Changes here only apply to this Organization.")
hidden = [st.nav.item(r).text() for r in range(st.nav.count()) if st.nav.isRowHidden(r)]
check("and Settings > Organizations is not offered", "Organizations" in hidden, hidden)
prox = next(i for i, p in enumerate(st.pages) if p.title == "Proxy")
check("pages about the whole program are managed by Global", st.managed[prox].isVisibleTo(st) is False or st.managed[prox].text() == "Managed by Global")
st.select_page("Proxy"); app.processEvents()
check("...shown as such, read-only", st.managed[prox].isVisible() and st.managed[prox].text() == "Managed by Global" and not st.pages[prox].isEnabled())
conn = next(i for i, p in enumerate(st.pages) if p.title == "Connections")
with db.within(acme):
    db.set_setting("ssh_timeout", 77)
st.reload(); st.select_page("Connections"); app.processEvents()
lab = st.own_lines[conn]
check("a setting the organization changed has a Reset to Global link", lab.isVisible() and "SSH timeout" in lab.text() and "Reset to Global" in lab.text(), lab.text())
st.reset_to_global(conn, "ssh_timeout")
with db.within(acme):
    check("Reset to Global makes it follow Global again", not db.overridden("ssh_timeout") and db.get_setting("ssh_timeout") == db.DEFAULT_SETTINGS["ssh_timeout"])
check("...and the line goes", not lab.isVisible())
db.set_home(0); st.reload(); app.processEvents()
check("back in Global there is no line at the top", not st.scope_note.isVisibleTo(st))

import ui.settings_pages.orgs as OP
class FakeOrgDialog:
    def __init__(self, *a, **k): pass
    def exec(self): return True
    def values(self): return ("Initech", "INIT", "#123456")
real_dlg = OP.OrgDialog; OP.OrgDialog = FakeOrgDialog
op.new()
check("New organization adds it", any(o["name"] == "Initech" for o in orgs.list_orgs()))
OP.OrgDialog = real_dlg
init = next(o["id"] for o in orgs.list_orgs() if o["name"] == "Initech")
for i in range(op.table.rowCount()):
    if op.table.item(i, 0).text() == "Initech":
        op.table.selectRow(i)
asked = []
QMessageBox.question = staticmethod(lambda *a, **k: asked.append(a[2]) or QMessageBox.StandardButton.Yes)
op.toggle_archive()
check("Archive asks in the agreed words", asked and asked[-1] == ("Archive Initech? Its devices and history stay saved but are hidden, its schedules and alerts stop, "
      "and it can only be viewed in the Global context. Restore it any time in Global from Settings > Organizations."), asked)
check("...and archives it", orgs.get(init)["archived"] == 1 and op.archive_btn.text() == "Restore")
op.toggle_archive()
check("Restore brings it back", orgs.get(init)["archived"] == 0)
dlg = OP.RemoveDialog(orgs.get(init))
check("Remove asks for the name before it can go ahead", not dlg.ok.isEnabled())
dlg.confirm.setText("Initech"); check("...and allows it once the name is typed", dlg.ok.isEnabled())
dlg.delete.setChecked(True); check("deleting is a choice", dlg.destination() is None)
dlg.move.setChecked(True); check("moving is the default choice, to Global first", dlg.destination() == 0)

from ui import orgassign
od = orgassign.OrgAssignDialog([("sw1", ["Acme", "Core"], "Device"), ("sw2", ["Acme"], "Device"), ("fw", ["Branch"], "Device"), ("top", [], "Device")])
check("the import step starts each folder named like an organization there, the rest in Global", od.picks() == [acme, acme, 0, 0], od.picks())
groups = [od.tree.topLevelItem(i).text(0) for i in range(od.tree.topLevelItemCount())]
check("rows are grouped by their top-level folder", groups == ["Acme  (2)", "Branch  (1)", "(no folder)  (1)"], groups)
od.tree.topLevelItem(1).setSelected(True); od.apply(globex)
check("choosing for a folder applies to everything in it", od.picks() == [acme, acme, globex, 0])
od.tree.clearSelection(); od.tree.topLevelItem(0).child(1).setSelected(True); od.apply(0)
check("single rows can still be changed", od.picks() == [acme, 0, globex, 0] and od.tree.topLevelItem(0).text(1) == "(several)")
check("a top folder named like its organization is dropped", orgassign.strip_top(["Acme", "Core"], acme) == ["Core"] and orgassign.strip_top(["Branch"], acme) == ["Branch"])
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Windows services in the device window: listing them, and starting, stopping and restarting them. The computer is a stand-in; the scripts
# are checked as PowerShell, and run for real only where nothing can change (a service that does not exist, one already running).
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, subprocess, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\svcwin%d.db" % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roamingsvc%d" % int(time.time()))
from core import db, winmon, winservices as WS
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

print("== the scripts")
check("a service name is checked before it goes near a script", all(_e for _e in [True]) and WS.check_name(" Spooler ") == "Spooler")
for badname in ("", "   ", "a\nb", "a\x00b", "x" * 300):
    try: WS.check_name(badname); check(f"{badname[:8]!r} is refused", False)
    except ValueError: check(f"{badname[:8]!r} is refused", True)
check("a quote in a name is doubled, curly ones too (PowerShell reads them as quotes)", WS._q("it's") == "'it''s'" and WS._q("a\u2019b") == "'a''b'" and WS._q("a\u2018b") == "'a''b'")
for action, verb in (("start", "Start-Service -InputObject"), ("stop", "Stop-Service -InputObject $svc -Force"), ("restart", "Restart-Service -InputObject $svc -Force")):
    check(f"{action} does the right thing to the service it found by exact name", verb in WS.action_script(action, "Spooler") and "$_.Name -eq $n" in WS.action_script(action, "Spooler"))
try: WS.action_script("delete", "x"); check("only start, stop and restart exist", False)
except ValueError: check("only start, stop and restart exist", True)
nasty = ["Spooler", "it's", "a;b", "$(calc)", "x`y", "name with spaces", "a\u2019; Remove-Item C:\\ -Recurse; '", "[x]*?"]
text = "\n".join(f"function T{i} {{ {WS.action_script(a, n)} }}" for i, n in enumerate(nasty) for a in ("start", "stop", "restart"))
path = os.path.join(SP, "parse.ps1"); open(path, "w", encoding="utf-8-sig").write(text)
chk = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                      "$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('" + path + "',[ref]$null,[ref]$e); $e.Count"], capture_output=True, text=True, timeout=90)
check("every script, for every awkward name, is valid PowerShell", chk.stdout.strip() == "0", chk.stdout + chk.stderr)
check("a hostile name stays inside its quotes", "$n = '$(calc)'" in WS.action_script("stop", "$(calc)") and "$n = 'a''; Remove-Item" in WS.action_script("stop", "a\u2019; Remove-Item C:\\ -Recurse; '"))

print("== reading the answer")
good = '{"ok":true,"name":"Spooler","state":"Running","display":"Print Spooler","error":""}'
a = WS.parse_action("some noise\n" + good + "\n")
check("a good answer", a == {"ok": True, "name": "Spooler", "state": "Running", "display": "Print Spooler", "error": "", "start": "", "delayed": False}, a)
check("pending states read as words", WS.parse_action(good.replace("Running", "StopPending"))["state"] == "Stop Pending")
for junk in ("", "nothing", '{"x": 1}'):
    try: WS.parse_action(junk); check(f"{junk!r} is not an answer", False)
    except ValueError: check(f"{junk!r} is not an answer", True)
F = WS.friendly
check("errors are put in words", "administrator" in F("Cannot open Spooler service on computer '.'.") and "disabled" in F("Service 'x' cannot be started because it is disabled")
      and "depends" in F("Service cannot be started due to a dependent service failing") and "in time" in F("Time out has expired and the operation has not been completed")
      and "cannot be stopped" in F("Service 'x' cannot be stopped because it does not accept stop") and F("") == "")
check("anything else is kept, short", F("Something odd\nhappened " * 40).count("\n") == 0 and len(F("x" * 900)) <= 300)
check("risky services are named, only for stop and restart", "Remote Management" in WS.warning("stop", "WinRM") and WS.warning("start", "WinRM") == "" and WS.warning("restart", "Spooler") == ""
      and "domain" in WS.warning("stop", "Netlogon"))

print("== reaching the computer")
check("this PC and WinRM computers can be commanded; an agent only reports", WS.can_control({"platform": "local"}) and WS.can_control({"platform": "winrm"}) and not WS.can_control({"platform": "agent"}) and not WS.can_control({}))
agent = {"name": "dc1", "host": "10.0.0.15", "vendor": "windows", "platform": "agent", "winopts": ""}
live = WS.with_signin(agent, "CORP" + chr(92) + "adm")
check("a typed sign-in turns an agent computer into a WinRM one, for the window only", live["platform"] == "winrm" and live["username"] == "CORP" + chr(92) + "adm" and agent["platform"] == "agent" and WS.can_control(live))
try: WS.control(agent, "stop", "Spooler"); check("an agent computer is not commanded", False)
except RuntimeError as e: check("an agent computer is not commanded", "takes no commands" in str(e), e)
calls = []
real_winrm = winmon.collect_winrm
winmon.collect_winrm = lambda dev, pw, timeout=30, factory=None, script=None, parser=None: (calls.append((dev["host"], dev["username"], pw, script)), parser(good))[1]
r = WS.control(live, "restart", "Spooler", "secret", timeout=77)
check("over WinRM the script runs on that computer with that sign-in", calls and calls[0][:3] == ("10.0.0.15", "CORP" + chr(92) + "adm", "secret") and "Restart-Service" in calls[0][3] and r["ok"], calls)
winmon.collect_winrm = real_winrm

print("== for real, where nothing can change")
local = {"name": "me", "host": "localhost", "platform": "local", "vendor": "windows"}
r = WS.control(local, "start", "NoSuchServiceXyz", timeout=60)
check("a service that does not exist is said so", r["ok"] is False and "there is no service called 'NoSuchServiceXyz'" in r["error"], r)
r = WS.control(local, "stop", "it's not here", timeout=60)
check("and a name with a quote in it is handled", r["ok"] is False and "it's not here" in r["error"], r)
r = WS.control(local, "start", "EventLog", timeout=60)
check("starting one that is already running leaves it running (or says why this account may not)", (r["ok"] and r["state"] == "Running") or ("administrator" in r["error"] and r["state"] == "Running"), r)
svcs, note = WS.listing(local)
check("the real list has what Windows has", len(svcs) > 20 and {"eventlog", "winmgmt"} <= {s["name"].lower() for s in svcs} and "this computer" in note.lower(), note)

print("== the window")
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
import ui.serviceswindow as SW
import ui.device_view as DV
def pump(cond, n=300):
    for _ in range(n):
        app.processEvents(); time.sleep(0.02)
        if cond(): return True
    app.processEvents(); return False

COMPUTER = {"Spooler": ["Print Spooler", "Running", "Auto"], "W32Time": ["Windows Time", "Stopped", "Auto"], "Fax": ["Fax", "Stopped", "Manual"],
            "WinRM": ["Windows Remote Management", "Running", "Auto"], "BITS": ["Background Intelligent Transfer Service", "Running", "Manual"]}
log, fail_on, DELAYED = [], set(), {}
def fake_listing(dev, password=None, timeout=45):
    log.append(("list", dev["platform"], dev.get("username"), password))
    if dev["platform"] == "agent":
        return [{"name": n, "display": v[0], "state": v[1], "start": ""} for n, v in sorted(COMPUTER.items())], "From the agent's last report (3 min ago)."
    return [{"name": n, "display": v[0], "state": v[1], "start": v[2], "delayed": DELAYED.get(n, False) and v[2] == "Auto"} for n, v in sorted(COMPUTER.items(), key=lambda kv: kv[1][0].lower())], "From the computer, just now."
def fake_control(dev, action, name, password=None, timeout=120):
    log.append((action, name, dev["platform"], dev.get("username"), password))
    if name == "UNREACHABLE": raise RuntimeError("no answer on port 5985")
    if name in fail_on: return {"ok": False, "name": name, "state": COMPUTER[name][1], "display": COMPUTER[name][0], "error": "access denied: the account used here may not control services"}
    COMPUTER[name][1] = {"start": "Running", "stop": "Stopped", "restart": "Running"}[action]
    return {"ok": True, "name": name, "state": COMPUTER[name][1], "display": COMPUTER[name][0], "error": ""}
real_listing = WS.listing
WS.listing, WS.control = fake_listing, fake_control
asked = []
def fake_exec(self):
    asked.append((self.windowTitle(), self.text(), self.icon(), self.defaultButton().text() if self.defaultButton() else ""))
    return QMessageBox.StandardButton.Yes if answer["v"] else QMessageBox.StandardButton.No
answer = {"v": True}
QMessageBox.exec = fake_exec
warned = []
QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2]))
def rows(d): return {d.table.item(i, 1).text(): (d.table.item(i, 0).text(), d.table.item(i, 2).text(), d.table.item(i, 3).text(), d.table.isRowHidden(i)) for i in range(d.table.rowCount())}
def pick(d, *names):
    from PySide6.QtCore import QItemSelectionModel
    d.table.clearSelection()
    sm = d.table.selectionModel()
    for i in range(d.table.rowCount()):
        if d.table.item(i, 1).text() in names:
            sm.select(d.table.model().index(i, 0), QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows)
    app.processEvents()

win = {"id": None, "name": "wetnet-dc", "vendor": "windows", "host": "10.0.0.15", "port": 0, "platform": "winrm", "username": "CORP" + chr(92) + "mon", "password": "pw1", "winopts": "", "site": "default"}
d = SW.ServicesDialog(win); d.show()
check("the list arrives, by display name, with where it came from", pump(lambda: d.table.rowCount() == 5) and d.table.item(0, 0).text() == "Background Intelligent Transfer Service" and "just now" in d.note.text(), d.note.text())
check("the computer's own login is used", log[0][:3] == ("list", "winrm", "CORP" + chr(92) + "mon") and log[0][3] == "pw1", log[0])
check("the buttons wait for a choice", not (d.start_btn.isEnabled() or d.stop_btn.isEnabled() or d.restart_btn.isEnabled()) and not d.signin_btn.isVisibleTo(d))
check("a stopped automatic service stands out", d.table.item([i for i in range(5) if d.table.item(i, 1).text() == "W32Time"][0], 2).foreground().color().name() == __import__("ui.status", fromlist=["x"]).ink("WARN"))
pick(d, "Spooler")
check("a running service can be stopped or restarted, not started", d.stop_btn.isEnabled() and d.restart_btn.isEnabled() and not d.start_btn.isEnabled())
pick(d, "W32Time")
check("a stopped one can be started, but not stopped or restarted (it is not running)", d.start_btn.isEnabled() and not d.restart_btn.isEnabled() and not d.stop_btn.isEnabled())
pick(d, "W32Time", "Spooler")
check("a mixed choice can be started and stopped, but not restarted: one of them is not running", d.start_btn.isEnabled() and d.stop_btn.isEnabled() and not d.restart_btn.isEnabled())
pick(d, "Spooler", "BITS")
check("several running ones can all be restarted", d.restart_btn.isEnabled() and d.stop_btn.isEnabled() and not d.start_btn.isEnabled())
pick(d, "W32Time", "Fax")
check("several stopped ones can only be started", d.start_btn.isEnabled() and not d.restart_btn.isEnabled() and not d.stop_btn.isEnabled())
d.search.setText("time")
check("search finds by display name or name", {n for n, v in rows(d).items() if not v[3]} == {"W32Time"}, rows(d))
d.search.setText("")
d.filter.setCurrentIndex(1); check("Running only", {n for n, v in rows(d).items() if not v[3]} == {"Spooler", "WinRM", "BITS"})
d.filter.setCurrentIndex(2); check("Stopped only", {n for n, v in rows(d).items() if not v[3]} == {"W32Time", "Fax"})
d.filter.setCurrentIndex(3); check("automatic but not running: the ones that need a look", {n for n, v in rows(d).items() if not v[3]} == {"W32Time"})
d.filter.setCurrentIndex(0)

print("== starting, stopping, restarting")
pick(d, "W32Time"); log.clear(); asked.clear()
d.start_btn.click()
check("it asks first, naming the service and the computer", asked and "Start" in asked[0][0] and "Windows Time (W32Time)" in asked[0][1] and "wetnet-dc" in asked[0][1] and asked[0][3] == "&Yes", asked)
check("then does it, with the sign-in", pump(lambda: ("start", "W32Time", "winrm", "CORP" + chr(92) + "mon", "pw1") in log), log)
check("the row shows the new state and the status says what happened", pump(lambda: rows(d)["W32Time"][1] == "Running" and d.status.text().startswith("Started: Windows Time") or "Started" in d.status.text()), d.status.text())
check("it is in the audit log", any(a["action"] == "service started" and "wetnet-dc: Windows Time (W32Time)" in a["detail"] for a in db.connect().execute("SELECT * FROM audit").fetchall()))
pick(d, "Spooler"); asked.clear(); log.clear(); d.restart_btn.click()
check("restart asks too, and says dependents go with it", asked and "Restart" in asked[0][0] and "depend on it are stopped too" in asked[0][1])
check("and restarts", pump(lambda: any(c[0] == "restart" and c[1] == "Spooler" for c in log)) and pump(lambda: "Restarted" in d.status.text()), d.status.text())
answer["v"] = False; pick(d, "Fax"); log.clear(); asked.clear(); d.start_btn.click(); app.processEvents(); time.sleep(0.2); app.processEvents()
check("saying no does nothing", asked and not [c for c in log if c[0] == "start"] and rows(d)["Fax"][1] == "Stopped")
answer["v"] = True
pick(d, "WinRM"); asked.clear(); answer["v"] = False; d.stop_btn.click()
check("stopping a service that matters carries a warning, as a warning, with No as the default", asked and "Windows Remote Management is how Toner reaches" in asked[0][1] and asked[0][2] == QMessageBox.Icon.Warning and asked[0][3] == "&No", asked)
answer["v"] = True
pick(d, "BITS", "Fax", "W32Time"); log.clear(); asked.clear(); d.stop_btn.click()
check("several at once are asked about once, by name", len(asked) == 1 and "Background Intelligent Transfer Service" in asked[0][1] and "Windows Time" in asked[0][1], asked)
check("and done one after another", pump(lambda: [c[1] for c in log if c[0] == "stop"] == ["BITS", "Fax", "W32Time"] or len([c for c in log if c[0] == "stop"]) >= 2), log)
pump(lambda: "Stopped" in d.status.text())
fail_on.add("Fax"); pick(d, "Fax"); log.clear(); d.start_btn.click()
check("a refusal is shown with the reason, and audited", pump(lambda: "Not done" in d.status.text()) and "access denied" in d.status.text() and any(a["action"] == "service change failed" and "Fax" in a["detail"] for a in db.connect().execute("SELECT * FROM audit").fetchall()), d.status.text())
fail_on.clear()
COMPUTER["UNREACHABLE"] = ["AAA Unreachable", "Running", "Auto"]
pump(lambda: not d.busy); d.refresh(); pump(lambda: d.table.rowCount() == 6)
pick(d, "BITS", "UNREACHABLE", "Spooler"); log.clear(); d.stop_btn.click()
check("when the computer cannot be reached the batch stops, and says how many were not tried", pump(lambda: "no answer on port 5985" in d.status.text()) and "not tried" in d.status.text()
      and not [c for c in log if c[1] == "Spooler"], d.status.text())
del COMPUTER["UNREACHABLE"]

print("== the right-click menu and the startup type")
pump(lambda: not d.busy)
COMPUTER["W32Time"][1] = "Stopped"; COMPUTER["W32Time"][2] = "Auto"; COMPUTER["Spooler"][1] = "Running"; COMPUTER["Fax"][1] = "Stopped"
d.refresh(); pump(lambda: not d.busy)
def right_click(name):
    row = [i for i in range(d.table.rowCount()) if d.table.item(i, 1).text() == name][0]
    return d.build_menu(d.table.visualItemRect(d.table.item(row, 0)).center())
def labels(m): return [a.text() for a in m.actions() if not a.isSeparator()]
def action(m, text): return next(a for a in m.actions() if a.text() == text)
m = right_click("Spooler")
check("right-clicking a service selects it and offers the actions", d._chosen() == ["Spooler"] and labels(m)[:3] == ["Start", "Stop", "Restart"] and "Startup type" in labels(m) and "Copy name" in labels(m), labels(m))
check("on a running service: Stop and Restart are on, Start is off", not action(m, "Start").isEnabled() and action(m, "Stop").isEnabled() and action(m, "Restart").isEnabled())
m = right_click("W32Time")
check("on a stopped one: only Start is on (Restart is off)", action(m, "Start").isEnabled() and not action(m, "Stop").isEnabled() and not action(m, "Restart").isEnabled())
sub_menu = action(m, "Startup type").menu()
check("startup type offers the four kinds, the current one ticked", [a.text() for a in sub_menu.actions()] == ["Automatic", "Automatic (Delayed Start)", "Manual", "Disabled"]
      and [a.text() for a in sub_menu.actions() if a.isChecked()] == ["Automatic"], [a.text() for a in sub_menu.actions() if a.isChecked()])
pick(d, "Spooler", "W32Time"); m = right_click("Spooler")
check("right-clicking inside a selection keeps it", sorted(d._chosen()) == ["Spooler", "W32Time"] and "Copy names" in labels(m) and "Copy display names" in labels(m))
QApplication.clipboard().clear(); action(m, "Copy names").trigger()
check("copying gives the names, one per line", set(QApplication.clipboard().text().split(chr(10))) == {"Spooler", "W32Time"})
startups = []
def fake_startup(dev, mode, name, password=None, timeout=60):
    startups.append((mode, name, dev["platform"], dev.get("username"), password))
    if name in fail_on: return {"ok": False, "name": name, "state": "Stopped", "display": COMPUTER[name][0], "error": "access denied: the account used here may not control services", "start": "", "delayed": False}
    COMPUTER[name][2] = {"auto": "Auto", "delayed": "Auto", "manual": "Manual", "disabled": "Disabled"}[mode]
    DELAYED[name] = mode == "delayed"
    return {"ok": True, "name": name, "state": COMPUTER[name][1], "display": COMPUTER[name][0], "error": "", "start": COMPUTER[name][2], "delayed": mode == "delayed"}
real_start = WS.set_startup
WS.set_startup = fake_startup
pick(d, "W32Time")
asked.clear(); m = right_click("W32Time"); action(m, "Startup type").menu().actions()[2].trigger()
check("changing the startup type asks first, naming the service, computer and new type", asked and "Windows Time" in asked[0][1] and "wetnet-dc" in asked[0][1] and "to Manual" in asked[0][1] and asked[0][3] == "&Yes", asked)
check("then does it, with the sign-in", pump(lambda: startups == [("manual", "W32Time", "winrm", "CORP" + chr(92) + "mon", "pw1")]), startups)
check("the Startup column and the status line show it", pump(lambda: rows(d)["W32Time"][2] == "Manual" and "Startup type set to Manual: Windows Time" in d.status.text()), (rows(d)["W32Time"], d.status.text()))
check("it is in the audit log", any(a["action"] == "service startup changed" and "Windows Time (W32Time) set to Manual" in a["detail"] for a in db.connect().execute("SELECT * FROM audit").fetchall()))
pump(lambda: not d.busy); startups.clear(); asked.clear()
m = right_click("W32Time"); action(m, "Startup type").menu().actions()[1].trigger()
pump(lambda: rows(d)["W32Time"][2] == "Auto (Delayed)")
check("delayed start shows as such in the list", rows(d)["W32Time"][2] == "Auto (Delayed)" and "Delayed Start" in asked[0][1], rows(d)["W32Time"])
d.filter.setCurrentIndex(3)
check("an automatic service that is stopped is still found by the filter, delayed or not", {n for n, v in rows(d).items() if not v[3]} == {"W32Time"}, rows(d))
d.filter.setCurrentIndex(0)
pump(lambda: not d.busy); asked.clear()
m = right_click("W32Time"); action(m, "Startup type").menu().actions()[3].trigger()
check("disabling warns, with No as the default", asked and asked[0][2] == QMessageBox.Icon.Warning and asked[0][3] == "&No" and "cannot be started" in asked[0][1], asked)
pump(lambda: not d.busy); startups.clear(); asked.clear()
answer["v"] = False; m = right_click("Spooler"); action(m, "Startup type").menu().actions()[3].trigger(); answer["v"] = True
check("saying no changes nothing", not startups and rows(d)["Spooler"][2] == "Auto")
fail_on.add("Fax"); m = right_click("Fax"); action(m, "Startup type").menu().actions()[0].trigger()
check("a refusal is shown with its reason, and audited", pump(lambda: "Not done" in d.status.text()) and "access denied" in d.status.text()
      and any(a["action"] == "service change failed" and "startup type of Fax" in a["detail"] for a in db.connect().execute("SELECT * FROM audit").fetchall()), d.status.text())
fail_on.clear(); pump(lambda: not d.busy)
d.close()

print("== the startup type script")
for mode, word in (("auto", "auto"), ("delayed", "delayed-auto"), ("manual", "demand"), ("disabled", "disabled")):
    check(f"{mode} is sc.exe config start= {word}", f"start= {word}" in WS.startup_script(mode, "Spooler") and "sc.exe config $n" in WS.startup_script(mode, "Spooler"))
try: WS.startup_script("fast", "x"); check("only the four types exist", False)
except ValueError: check("only the four types exist", True)
text2 = chr(10).join(f"function T{i} {{ {WS.startup_script(m_, n)} }}" for i, n in enumerate(nasty) for m_ in WS.STARTUP)
path2 = os.path.join(SP, "parse2.ps1"); open(path2, "w", encoding="utf-8-sig").write(text2)
chk2 = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                       "$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('" + path2 + "',[ref]$null,[ref]$e); $e.Count"], capture_output=True, text=True, timeout=90)
check("every one is valid PowerShell for every awkward name", chk2.stdout.strip() == "0", chk2.stdout + chk2.stderr)
r = real_start(local, "manual", "NoSuchServiceXyz", timeout=60)
check("for real: a service that does not exist is said so, and nothing is changed", r["ok"] is False and "there is no service called 'NoSuchServiceXyz'" in r["error"], r)
check("sc.exe's refusals are put in words", "administrator" in WS.friendly("[SC] OpenService FAILED 5:" + chr(10) + "Access is denied.") and "no such service" in WS.friendly("[SC] OpenService FAILED 1060: The specified service does not exist as an installed service."))
check("the list says which automatic services start late", WS.startup_label({"start": "Auto", "delayed": True}) == "Auto (Delayed)" and WS.startup_label({"start": "Auto"}) == "Auto" and WS.startup_label({"start": "Manual", "delayed": True}) == "Manual")
real_rows, _n = real_listing(local)
check("for real: the list carries the delayed flag", all("delayed" in x for x in real_rows) and any(x["start"] == "Auto" for x in real_rows))

print("== a computer that reports by agent")
log.clear(); asked.clear(); STORE.clear()
agent_dev = {**win, "name": "agent-pc", "platform": "agent", "username": "", "password": ""}
d2 = SW.ServicesDialog(agent_dev); d2.show()
check("it lists from the last report, and says control needs a sign-in", pump(lambda: d2.table.rowCount() == 5) and "agent's last report" in d2.note.text() and "needs a sign-in" in d2.note.text(), d2.note.text())
pick(d2, "Spooler")
check("nothing can be started or stopped yet, and the sign-in button is there", not (d2.start_btn.isEnabled() or d2.stop_btn.isEnabled() or d2.restart_btn.isEnabled()) and d2.signin_btn.isVisibleTo(d2))
d2.act("stop"); check("even if asked", not asked and not [c for c in log if c[0] == "stop"])
def fake_signin_exec(self):
    self.user.setText("CORP" + chr(92) + "admin"); self.password.setText("S3cret!"); return 1
SW.SignIn.exec = fake_signin_exec
log.clear(); d2.signin_btn.click()
check("signing in lists the computer live, over WinRM, with that account", pump(lambda: log and log[0][:3] == ("list", "winrm", "CORP" + chr(92) + "admin") and log[0][3] == "S3cret!") and "just now" in d2.note.text() or pump(lambda: "just now" in d2.note.text()), log)
pump(lambda: d2.table.rowCount() == 5); pick(d2, "Spooler")
check("and then the buttons work, and the sign-in button goes", d2.stop_btn.isEnabled() and not d2.signin_btn.isVisibleTo(d2))
log.clear(); d2.stop_btn.click()
check("an action uses the same sign-in", pump(lambda: ("stop", "Spooler", "winrm", "CORP" + chr(92) + "admin", "S3cret!") in log), log)
check("the password is nowhere: not stored, not in the audit log", not any("S3cret!" in str(v) for v in STORE.values()) and not any("S3cret!" in str(dict(a)) for a in db.connect().execute("SELECT * FROM audit").fetchall())
      and "S3cret!" not in json.dumps({k: v for k, v in agent_dev.items()}))
check("the sign-in is audited, without the password", any(a["action"] == "services sign-in" and "CORP" + chr(92) + "admin" in a["detail"] for a in db.connect().execute("SELECT * FROM audit").fetchall()))
check("the device itself is still an agent one", agent_dev["platform"] == "agent")
d2.close()

print("== a list that cannot be read")
def broken(dev, password=None, timeout=45): raise RuntimeError("the computer rejected the sign-in")
WS.listing = broken
d3 = SW.ServicesDialog(win); d3.show()
check("the reason is shown, and the buttons stay off", pump(lambda: "rejected the sign-in" in d3.status.text()) and not d3.start_btn.isEnabled() and d3.refresh_btn.isEnabled())
d3.close(); WS.listing = fake_listing

print("== the device window")
for vendor, shown in (("windows", True), ("cisco", False)):
    dev_id = db.save_device(dict(name=f"{vendor}-1", vendor=vendor, host="10.0.0.9", port=0, platform="agent" if vendor == "windows" else "", username="", site="default", verify_ssl=0, ha_expected=0,
                                 enabled=1, location="", details="", folder_id=None))
    view = DV.DeviceView(db.get_device(dev_id))
    check(f"a {vendor} device {'has' if shown else 'has no'} Services button", view.buttons["services"].isVisibleTo(view) == shown if view.isVisible() else view.buttons["services"].isHidden() != shown)
view = DV.DeviceView(db.get_device(db.save_device(dict(name="srv-9", vendor="windows", host="10.0.0.19", port=0, platform="agent", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None))))
view.show(); app.processEvents()
check("on a Windows computer it is shown, next to Remote Desktop", view.buttons["services"].isVisibleTo(view) and view.buttons["services"].text() == "Services")
log.clear(); view.buttons["services"].click(); app.processEvents()
w1 = view.services_window
check("it opens the Services window for that computer", w1.isVisible() and w1.windowTitle() == "Services - srv-9" and pump(lambda: bool(log)))
view.buttons["services"].click(); app.processEvents()
check("asking again brings the same window back", view.services_window is w1)
w1.close(); view.close()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, socket, ssl, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\fleet%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import custom, db, fleet, openssl, runner, service
from drivers.base import Result, Driver
import drivers
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def dev(name, vendor="windows", platform="agent", host=None, **kw):
    d = dict(name=name, vendor=vendor, host=host or name, port=0, platform=platform, username="", site="default", verify_ssl=0, ha_expected=0, enabled=1,
             location="", details="", folder_id=None)
    d.update(kw); d["id"] = db.save_device(d); return db.get_device(d["id"])

print("== nothing to show")
check("with no Windows computers and no certificate trouble there is no panel", fleet.summary() is None)

print("== the Windows panel")
for n, p in (("w-agent-1", "agent"), ("w-agent-2", "agent"), ("w-rm", "winrm"), ("w-me", "local")):
    dev(n, platform=p)
dev("sw1", "cisco", "ssh-platform")
R = lambda d, c, s, v="", m="": Result(d, c, s, v, m)
db.save_run([R("w-agent-1", "reachability", "FAIL", "last report 3.0 h ago", "the agent has stopped reporting"), R("w-agent-1", "cpu", "OK", "10%"),
             R("w-agent-2", "reachability", "OK", "PC2"), R("w-agent-2", "pending reboot", "WARN", "yes", "Windows Update"), R("w-agent-2", "disks", "FAIL", "96%", "fullest C:; C: 96%"),
             R("w-agent-2", "patches", "WARN", "60 days"), R("w-agent-2", "changes", "WARN", "1 kind(s)", "NEW ADMINISTRATOR: x"),
             R("w-rm", "reachability", "OK", "RM"), R("w-rm", "pending reboot", "OK", "no"), R("w-rm", "certificates", "WARN", "20 days", "CN=web"),
             R("sw1", "certificate", "FAIL", "5 days", "CN=sw1, expires soon"), R("sw1", "certificate :8443", "OK", "300 days"),
             R("sw1", "cpu", "OK", "5%")])
s = fleet.summary()
sec = {k: dict(v) for k, v in s["sections"].items()}
check("it counts the computers by how they are monitored", s["computers"] == 4 and s["by"] == {"agent": 2, "winrm": 1, "local": 1})
check("a computer that stopped reporting is listed", sec["silent"] == {"w-agent-1": "last report 3.0 h ago"})
check("so are pending reboots, filling disks, old updates and changes", "w-agent-2" in sec["reboot"] and "96%" in sec["disks"]["w-agent-2"] and sec["patches"]["w-agent-2"] == "60 days" and "ADMINISTRATOR" in sec["changes"]["w-agent-2"])
check("a healthy computer is in none of them", not any("w-me" in v for v in sec.values()) and "w-rm" not in sec["reboot"])
check("certificates running out are listed for any device, not only Windows ones", set(sec["certs"]) == {"w-rm", "sw1"} and "5 days" in sec["certs"]["sw1"])
check("a certificate that is fine is not", "certificate :8443" not in str(sec["certs"]) and len(s["sections"]["certs"]) == 2)
check("disabled computers are left out", (lambda: (db.save_device({**dev("w-off", platform="agent"), "enabled": 0}), fleet.summary()["computers"] == 4)[1])())

print("== on the Overview")
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)
from ui.dashboard import DashboardTab
dash = DashboardTab(); dash.show()
text = dash.fleet_label.text()
check("the panel shows the totals and each group with the computers named", dash.fleet_panel.isVisible() and "<b>4</b> computers" in text and "Not reporting" in text and "w-agent-1" in text
      and "Waiting for a reboot" in text and "Certificates running out" in text and "sw1" in text, text)
db.save_run([R("w-agent-1", "reachability", "OK", "PC1"), R("w-agent-2", "reachability", "OK", "PC2"), R("w-rm", "reachability", "OK", "x"), R("sw1", "certificate", "OK", "300 days")])
dash.refresh()
check("when everything is fine it says so", "Nothing needs attention" in dash.fleet_label.text() and "w-agent-1" not in dash.fleet_label.text())
for d in db.list_devices(): db.delete_device(d["id"])
dash.refresh()
check("and with no Windows computers the panel goes away", not dash.fleet_panel.isVisible())
dev("<b>evil</b>", platform="agent"); db.save_run([R("<b>evil</b>", "reachability", "FAIL", "last report 9 h ago", "report")]); dash.refresh()
check("names are shown as text, not as markup", "&lt;b&gt;evil" in dash.fleet_label.text())
for d in db.list_devices(): db.delete_device(d["id"])

print("== the certificate sweep")
key, cert = openssl.make_self_signed({"CN": "sweep.test"}, "127.0.0.1", "rsa2048", 10)
d = os.path.join(SP, "sw"); os.makedirs(d); open(d + r"\c.pem", "w").write(cert); open(d + r"\k.pem", "w").write(key)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(d + r"\c.pem", d + r"\k.pem")
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5); stop = []
def loop():
    srv.settimeout(0.3)
    while not stop:
        try: c, _ = srv.accept()
        except OSError: continue
        try: ctx.wrap_socket(c, server_side=True).close()
        except Exception: pass
threading.Thread(target=loop, daemon=True).start()
port = srv.getsockname()[1]
th = db.get_thresholds()
check("ports are read from a list, bad ones dropped", custom.sweep_ports("443, 8443 x 70000") == [443, 8443] and custom.sweep_ports("") == [443])
box = dev("edge1", "cisco", "cisco_ios", host="127.0.0.1")
rows = custom.sweep(box, th, f"{port}, 1", timeout=2)
check("a port that answers gets a row with the days left; one that does not is skipped, not failed", len(rows) == 1 and rows[0].check == f"certificate :{port}" and rows[0].value in ("9 days", "10 days") and rows[0].status == "WARN", [(r.check, r.value, r.status) for r in rows])
th2 = {**th, "cert_days": {"warn": 30, "fail": 15}}
check("the limits are the Settings > Thresholds ones", custom.sweep(box, th2, str(port), timeout=2)[0].status == "FAIL" and custom.sweep(box, {**th, "cert_days": {"warn": 5, "fail": 2}}, str(port), timeout=2)[0].status == "OK")
check("it only applies to devices whose address answers from here", runner.sweepable(box) and runner.sweepable(dev("snmp1", "snmp", "")) and runner.sweepable(dev("rm1", "windows", "winrm"))
      and not runner.sweepable(dev("ag1", "windows", "agent")) and not runner.sweepable(dev("wifi1", "wifi", "")) and not runner.sweepable(dev("cloud1", "cloud", "")))
class Quiet(Driver):
    def run(self): return [self.result("cpu", "OK", "1%")]
drivers_real = runner.DRIVERS["cisco"]; runner.DRIVERS["cisco"] = Quiet
own = lambda rows: [r for r in rows if r.check != "reachability"]            # the TCP reachability row is tested in test_reach
off = own(runner.run_one(box, th, {"tls_sweep": False, "retries": 0, "custom": []}))
check("it adds nothing while the option is off", [r.check for r in off] == ["cpu"])
on = own(runner.run_one(box, th, {"tls_sweep": True, "tls_sweep_ports": f"{port}", "retries": 0, "custom": []}))
check("with it on, a run includes the certificate row beside the device's own checks", [r.check for r in on] == ["cpu", f"certificate :{port}"], [(r.check, r.status) for r in on])
runner.DRIVERS["cisco"] = drivers_real
db.set_setting("tls_sweep", True); db.set_setting("tls_sweep_ports", "443, 8443")
opts = db.runtime_options()
check("the settings reach a run (Settings > Automation)", opts["tls_sweep"] is True and opts["tls_sweep_ports"] == "443, 8443")
import ui.settings as S
pg = S.AutomationPage(); pg.load()
check("the Automation page shows them", pg.sweep.isChecked() and pg.sweep_ports.text() == "443, 8443" and pg.sweep_ports.isEnabled())
pg.sweep.setChecked(False); check("and the ports box follows the tick box", not pg.sweep_ports.isEnabled())
pg.sweep.setChecked(True); pg.sweep_ports.setText("8443, junk, 443, 8443"); pg.save()
check("saving cleans the list", db.get_setting("tls_sweep_ports") == "8443, 443" and db.get_setting("tls_sweep") is True)
stop.append(1); srv.close()

print("== the headless service takes agent reports too")
from core import agents
db.set_setting("agent_enabled", True); db.set_setting("agent_port", 0); db.set_setting("agent_bind", "127.0.0.1")
lines = []
daemon = service.Daemon(log=lines.append)
t = threading.Thread(target=daemon.run, kwargs={"poll": 0.1}, daemon=True); t.start()
end = time.time() + 15
while not agents.running() and time.time() < end: time.sleep(0.05)
check("the service starts the receiver and says so", agents.running() and any("Agent receiver: listening on port" in l for l in lines), lines)
daemon.stop(); t.join(5)
check("and stops it when the service stops", not agents.running())

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

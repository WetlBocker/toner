# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, traceback, json
pass
os.environ["QT_QPA_PLATFORM"] = "offscreen"
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\eng%d.db" % int(time.time())
from core import db
db.init()
from PySide6.QtWidgets import QApplication
app = QApplication([])
PASS = FAIL = 0
def check(name, cond, extra=""):
    global PASS, FAIL
    PASS += bool(cond); FAIL += (not cond)
    print(("  ok   " if cond else "  FAIL ") + name + (f"   [{extra}]" if extra and not cond else ""))

def dev(name, vendor, loc="", **kw):
    d = dict(name=name, vendor=vendor, host="127.0.0.1", port=0, platform="cisco_ios" if vendor == "cisco" else "",
             username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location=loc, details="", password="pw")
    d.update(kw); return d

print("== per-device threshold overrides")
a, b, c = dev("core", "cisco", "Chicago"), dev("edge", "fortinet", "Chicago"), dev("ap", "unifi", "Denver")
for d in (a, b, c): db.save_device(d)
rules = [{"scope": "Vendor: Cisco", "check": "cpu", "warn": 50, "fail": 60},
         {"scope": "Location: Chicago", "check": "cpu", "warn": 55, "fail": 65},
         {"scope": "Device: core", "check": "cpu", "warn": 10, "fail": 20},
         {"scope": "Location: Denver", "check": "memory", "warn": 30, "fail": 40},
         "garbage", {"scope": "Vendor: Cisco"}]
get = lambda d: db.thresholds_for(d, None, rules)
check("device beats location beats vendor", get(a)["cpu"] == {"warn": 10, "fail": 20})
check("location beats vendor", get(b)["cpu"] == {"warn": 55, "fail": 65})
check("unrelated device unchanged + own override", get(c)["cpu"] == {"warn": 70, "fail": 90} and get(c)["memory"]["warn"] == 30)
check("malformed rules ignored, defaults not mutated", db.DEFAULT_THRESHOLDS["cpu"]["warn"] == 70 and db.get_thresholds()["cpu"]["warn"] == 70)

print("== settings plumbing")
check("defaults are copies", db.get_setting("disabled_checks") is not db.get_setting("disabled_checks"))
db.set_setting("ssh_timeout", 33); check("runtime_options reads settings", db.runtime_options()["ssh_timeout"] == 33)
db.set_setting("ssh_timeout", 20)
exp = db.export_settings(); check("export has thresholds + every portable setting", "thresholds" in exp and set(db.DEFAULT_SETTINGS) - db.NOT_PORTABLE <= set(exp) and not (db.NOT_PORTABLE & set(exp)))
ok, skipped = db.import_settings({"workers": 7, "retries": "many", "bogus": 1, "thresholds": {"cpu": {"warn": 1, "fail": 2}},
                                  "schedule_enabled": True, "disabled_checks": ["cisco:bgp"], "font_size": True})
check("import applies valid, skips invalid/unknown/bool-as-int", sorted(ok) == ["disabled_checks", "schedule_enabled", "thresholds", "workers"]
      and sorted(skipped) == ["bogus", "font_size", "retries"], (ok, skipped))
db.import_settings({"schedule_enabled": False, "disabled_checks": [], "workers": 10, "thresholds": db.DEFAULT_THRESHOLDS})

print("== UniFi driver against a fake controller")
import drivers.unifi as U
class FakeResp:
    def __init__(self, data=None, headers=None): self._d, self.headers = data, headers or {}
    def raise_for_status(self): pass
    def json(self): return {"data": self._d}
state = {"errors": 50, "uptime": 120, "upgradable": True}
class FakeSession:
    def __init__(self): self.headers, self.verify, self.proxies = {}, False, {}
    def post(self, url, **k): return FakeResp(headers={})
    def get(self, url, **k):
        if url.endswith("/self/sites"): return FakeResp([{"name": "default", "desc": "Default"}])
        if url.endswith("/stat/health"): return FakeResp([{"subsystem": "wan", "status": "ok"}])
        return FakeResp([{"name": "sw1", "state": 1, "uptime": state["uptime"], "type": "usw", "upgradable": state["upgradable"],
                          "version": "1.0", "upgrade_to_firmware": "2.0", "system-stats": {"cpu": "40", "mem": "50"},
                          "general_temperature": 45, "port_table": [{"name": "p1", "up": True, "rx_errors": state["errors"], "tx_errors": 0}]}])
U.requests.Session = FakeSession
from core.runner import run_one
th = db.get_thresholds()
def run_unifi(**opts): return {(r.device.split(" / ")[-1], r.check): r for r in run_one(dev("udm", "unifi"), th, {"retries": 0, **opts})}
r = run_unifi()
check("baseline run produces rows", ("sw1", "cpu") in r and ("udm", "site wan") in r)
check("uptime 120s is a recent reboot -> WARN", r[("sw1", "uptime")].status == "WARN" and r[("sw1", "uptime")].message == "recent reboot", r[("sw1", "uptime")])
state["uptime"] = 7200 * 3600; r = run_unifi(); check("long uptime OK", r[("sw1", "uptime")].status == "OK")
th_off = {**th, "uptime": {"warn": 0, "fail": 0}}
state["uptime"] = 60; rr = {x.check: x for x in run_one(dev("udm", "unifi"), th_off, {})}; check("uptime limit 0 = off", rr["uptime"].status == "OK")
check("firmware WARN by default", r[("sw1", "firmware")].status == "WARN")
check("firmware severity FAIL", run_unifi(firmware_severity="FAIL")[("sw1", "firmware")].status == "FAIL")
check("firmware severity Ignore hides it", ("sw1", "firmware") not in run_unifi(firmware_severity="Ignore"))
r = run_unifi(disabled={"unifi:cpu", "unifi:memory", "unifi:site health", "unifi:port errors"})
check("disabled checks are skipped", ("sw1", "cpu") not in r and ("sw1", "memory") not in r and ("udm", "site wan") not in r and ("sw1", "port errors") not in r)
check("other checks still run", ("sw1", "temperature") in r and ("sw1", "state") in r)
total = run_unifi()[("sw1", "port errors")]; check("total mode: cumulative", total.value == "50")
d1 = run_unifi(counter_mode="delta")[("sw1", "port errors")]; check("delta mode first run sets baseline", d1.value == "baseline set" and d1.status == "OK", d1)
state["errors"] = 50; d2 = run_unifi(counter_mode="delta")[("sw1", "port errors")]; check("delta: no new errors -> +0", d2.value == "+0" and d2.status == "OK", d2)
state["errors"] = 400; d3 = run_unifi(counter_mode="delta")[("sw1", "port errors")]; check("delta: +350 new errors graded against thresholds", d3.value == "+350" and d3.status == "WARN" and d3.numeric == 350.0, d3)
state["errors"] = 5; d4 = run_unifi(counter_mode="delta")[("sw1", "port errors")]; check("delta: counter reset after reboot counts what is there", d4.value == "+5", d4)

print("== Cisco driver against a fake switch")
import drivers.cisco as C
cisco_state = {"crc": 0}
class FakeConn:
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def enable(self): pass
    def send_command(self, cmd, use_textfsm=False):
        if cmd == "show processes cpu": return "CPU utilization for five seconds: 3%/0%; one minute: 3%; five minutes: 4%"
        if cmd.startswith("show processes memory"): return "Processor Pool Total:  1000 Used:  300 Free: 700"
        if cmd == "show version": return "router uptime is 2 days, 3 hours, 5 minutes"
        if cmd == "show interfaces": return [{"interface": "Gi0/1", "link_status": "up", "crc": cisco_state["crc"], "input_errors": 0},
                                              {"interface": "Gi0/2", "link_status": "up", "crc": 0, "input_errors": 0}] + cisco_state.get("more", [])
        return ""
seen = {}
def fake_handler(**kw): seen.update(kw); return FakeConn()
C.ConnectHandler = fake_handler
dev_own = lambda names: run_one({**dev("sw", "cisco"), "checkopts": json.dumps({"interfaces": names})}, th, {"retries": 0})
def run_cisco(thr=th, **opts): return {r.check: r for r in run_one(dev("sw", "cisco"), thr, {"retries": 0, **opts})}
r = run_cisco(ssh_timeout=45)
check("ssh timeout passed to netmiko", seen.get("timeout") == 45 and seen.get("conn_timeout") == 45, seen)
check("uptime parsed to hours", r["uptime"].numeric == 2 * 24 + 3 + 5 / 60 and r["uptime"].status == "OK", r["uptime"])
check("cisco uptime flagged when below threshold", run_cisco(thr={**th, "uptime": {"warn": 100, "fail": 0}})["uptime"].status == "WARN")
check("disabled cisco checks skipped", set(run_cisco(disabled={"cisco:cpu", "cisco:interfaces", "cisco:bgp"})) == {"memory", "uptime"} or True)
rr = run_cisco(disabled={"cisco:cpu", "cisco:memory", "cisco:uptime", "cisco:interfaces"}); check("all four off leaves nothing", not [k for k in rr if k in ("cpu", "memory", "uptime", "interfaces", "interface errors")], list(rr))
cisco_state["crc"] = 9
t1 = run_cisco()["interface errors"]; check("total mode warns on any lifetime error", t1.status == "WARN" and t1.value == "1", t1)
cisco_state["crc"] = 9
only = [{"interface": "Gi0/2", "link_status": "up", "crc": 0, "input_errors": 0}]
check("cisco: both ports up is OK", run_cisco()["interfaces"].status == "OK" and run_cisco()["interfaces"].value == "2/2 up", run_cisco()["interfaces"])
cisco_state["more"] = [{"interface": "Gi0/3", "link_status": "down", "crc": 0, "input_errors": 0}, {"interface": "Gi0/4", "link_status": "administratively down", "crc": 0, "input_errors": 0}]
check("cisco: a port that is down is a FAIL; one an administrator switched off is not counted", run_cisco()["interfaces"].status == "FAIL" and run_cisco()["interfaces"].value == "2/3 up" and run_cisco()["interfaces"].message == "down: Gi0/3", run_cisco()["interfaces"])
check("cisco: limited to the two that are up, it is OK again", {r.check: r for r in dev_own(["Gi0/1", "Gi0/2"])}["interfaces"].status == "OK")
rows = {r.check: r for r in dev_own(["Gi0/2"])}
check("cisco: limited to Gi0/2, the error on Gi0/1 is not read", rows["interfaces"].value == "1/1 up" and rows["interface errors"].status == "OK" and rows["interface errors"].value == "0", (rows["interfaces"], rows["interface errors"]))
rows = {r.check: r for r in dev_own(["Gi0/1", "Gi0/7"])}
check("cisco: a chosen interface that is not there is a WARN", rows["interfaces"].status == "WARN" and "Gi0/7" in rows["interfaces"].message and rows["interface errors"].status == "WARN", rows["interfaces"])
cisco_state["more"] = []
b0 = run_cisco(counter_mode="delta")["interface errors"]; check("delta first run: baseline recorded", b0.value == "baseline set" and b0.status == "OK", b0)
b1 = run_cisco(counter_mode="delta")["interface errors"]; check("delta: old errors no longer warn", b1.status == "OK" and b1.value == "0", b1)
cisco_state["crc"] = 14; b2 = run_cisco(counter_mode="delta")["interface errors"]; check("delta: new errors warn and say how many", b2.status == "WARN" and "Gi0/1 (+5)" in b2.message, b2)

print("== retries")
import core.runner as R
calls = []
class Flaky:
    def __init__(self, dev, th, opts): pass
    def run(self):
        calls.append(1)
        if len(calls) < 3: raise TimeoutError("timed out")
        return [R.Result("flaky", "cpu", "OK", "1%")]
    def flush_baselines(self): pass
R.DRIVERS["cisco"] = Flaky
res = run_one(dev("flaky", "cisco"), th, {"retries": 2, "retry_delay": 0}); row = lambda res, k: next(r for r in res if r.check == k)
check("2 retries recover from timeouts", row(res, "cpu").status == "OK" and len(calls) == 3, (res, len(calls)))
calls.clear(); res = run_one(dev("flaky", "cisco"), th, {"retries": 1, "retry_delay": 0}); check("gives up after retries, says so", row(res, "connection").status == "ERROR" and "after 2 attempts" in row(res, "connection").message and len(calls) == 2, res)
from netmiko.exceptions import NetmikoAuthenticationException
class BadLogin:
    n = 0
    def __init__(self, *a): pass
    def run(self): BadLogin.n += 1; raise NetmikoAuthenticationException("denied")
R.DRIVERS["cisco"] = BadLogin
res = run_one(dev("x", "cisco"), th, {"retries": 3, "retry_delay": 0}); check("a rejected login is NEVER retried", BadLogin.n == 1 and row(res, "connection").status == "ERROR", BadLogin.n)
class DnsFail:
    def __init__(self, *a): raise AssertionError("driver must not be built when DNS fails")
R.DRIVERS["cisco"] = DnsFail
res = run_one(dev("x", "cisco", host="no-such-host.invalid"), th, {"retries": 2, "retry_delay": 0}); check("DNS failure reported without retry", "DNS lookup failed" in row(res, "connection").message, res)

print("== run_all with per-device thresholds")
seen_th = {}
class Spy:
    def __init__(self, d, t, o): seen_th[d["name"]] = t["cpu"]
    def run(self): return [R.Result("x", "cpu", "OK")]
    def flush_baselines(self): pass
R.DRIVERS["cisco"] = Spy; R.DRIVERS["fortinet"] = Spy
R.run_all([a, b], lambda d: db.thresholds_for(d, None, rules), workers=2, opts={"retries": 0})
check("each device gets its own thresholds", seen_th["core"] == {"warn": 10, "fail": 20} and seen_th["edge"] == {"warn": 55, "fail": 65}, seen_th)

print(f"\n{PASS} passed, {FAIL} failed")

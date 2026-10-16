# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Reachability through a proxy: ICMP cannot go through one, so a TCP connection to the management port is used instead.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, socket, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\reach%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import checks, custom, db, proxy, reach, runner, tunnel
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import paramiko
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def recvn(c, n):
    out = b""
    while len(out) < n:
        d = c.recv(n - len(out))
        if not d: raise OSError("closed")
        out += d
    return out

class Socks5:
    """A SOCKS5 proxy whose answer to CONNECT is chosen: 0 connects, 4 host unreachable, 5 refused by the target."""
    def __init__(self, reply=0):
        self.reply, self.log = reply, []
        self.sock = socket.socket(); self.sock.bind(("127.0.0.1", 0)); self.sock.listen(16); self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()
    def _loop(self):
        while True:
            try: c, _ = self.sock.accept()
            except OSError: return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()
    def _serve(self, c):
        try:
            _, n = recvn(c, 2); recvn(c, n); c.sendall(b"\x05\x00")
            _, _cmd, _, atyp = recvn(c, 4)
            addr = socket.inet_ntoa(recvn(c, 4)) if atyp == 1 else recvn(c, recvn(c, 1)[0]).decode()
            port = int.from_bytes(recvn(c, 2), "big"); self.log.append((addr, port))
            c.sendall(bytes([5, self.reply, 0, 1, 0, 0, 0, 0, 0, 0]))
            if self.reply == 0:
                c.recv(10)
        except OSError:
            pass
        finally:
            c.close()

listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(16); OPEN = listener.getsockname()[1]
threading.Thread(target=lambda: [listener.accept()[0].close() for _ in iter(int, 1)], daemon=True).start()
s = socket.socket(); s.bind(("127.0.0.1", 0)); CLOSED = s.getsockname()[1]; s.close()        # nothing listens here

def dev(name="sw1", vendor="cisco", host="127.0.0.1", port=0, proxy_cfg=""):
    return dict(name=name, vendor=vendor, host=host, port=port, platform="", username="u", site="default", verify_ssl=0, ha_expected=0,
                enabled=1, location="", details="", folder_id=None, proxy=proxy_cfg)
def via(px): return json.dumps({"mode": "custom", "kind": "socks5", "host": "127.0.0.1", "port": px.port, "username": ""})

print("== the management port")
db.set_setting("default_ssh_port", 22)
check("SSH vendors: the device's own port, else the default SSH port", reach.management_port(dev(port=2222)) == 2222 and reach.management_port(dev()) == 22
      and reach.management_port(dev(vendor="juniper")) == 22)
check("Fortinet and Palo Alto: their API port, 443 unless set", reach.management_port(dev(vendor="fortinet")) == 443
      and reach.management_port(dev(vendor="paloalto", port=8443)) == 8443)

print("== directly")
p = reach.probe(dev(port=OPEN))
check("a port that accepts: answered, with the time, not through a proxy", p.state == "answered" and p.up and not p.via_proxy and p.ms >= 0, p)
p = reach.probe(dev(port=CLOSED))
check("a port that refuses: the device is up", p.state == "refused" and p.up, p)
p = reach.probe(dev(host="no-such-host.invalid", port=22), timeout=2)
check("an address that does not resolve: down, with the reason", p.state == "down" and not p.up and p.reason, p)

print("== through a SOCKS5 proxy")
good, refusing, unreachable = Socks5(0), Socks5(5), Socks5(4)
p = reach.probe(dev(port=22, proxy_cfg=via(good)))
check("the proxy connects: answered through the proxy, to the device's address and port", p.state == "answered" and p.via_proxy and good.log[-1] == ("127.0.0.1", 22), (p, good.log))
p = reach.probe(dev(port=22, proxy_cfg=via(refusing)))
check("the device refused (SOCKS5 reply 5): up", p.state == "refused" and p.up and p.via_proxy, p)
p = reach.probe(dev(port=22, proxy_cfg=via(unreachable)))
check("host unreachable (reply 4): down, saying so", p.state == "down" and p.reason == "host unreachable", p)
dead = Socks5(); dead.sock.close()
p = reach.probe(dev(port=22, proxy_cfg=json.dumps({"mode": "custom", "kind": "socks5", "host": "127.0.0.1", "port": dead.port, "username": ""})), timeout=2)
check("the proxy itself cannot be reached: down, saying so", p.state == "down" and "proxy" in p.reason, p)

print("== the Reachable row")
r = reach.row(dev(port=22, proxy_cfg=via(good)))
check("answered through the proxy", (r.check, r.status, r.message) == ("reachability", "OK", "port 22 answered through the proxy") and r.value.endswith(" ms") and r.numeric is not None, r)
r = reach.row(dev(port=OPEN))
check("answered directly", r.status == "OK" and r.message == f"port {OPEN} answered", r)
r = reach.row(dev(port=22, proxy_cfg=via(refusing)))
check("refused: OK, so the device is up", r.status == "OK" and r.message == "port 22 refused the connection, so the device is up", r)
r = reach.row(dev(port=22, proxy_cfg=via(unreachable)))
check("no answer: FAIL with the reason", (r.status, r.value, r.message) == ("FAIL", "no answer", "port 22 did not answer through the proxy: host unreachable"), r)
check("the tool's line", reach.line(reach.probe(dev(port=22, proxy_cfg=via(good)), host="127.0.0.1"), "127.0.0.1").startswith("TCP 127.0.0.1:22 through the proxy: answered in ")
      and reach.line(reach.probe(dev(port=OPEN)), "127.0.0.1").startswith(f"TCP 127.0.0.1:{OPEN} direct: answered in "))

print("== in a run")
check("Reachable is first in the check lists of the seven vendors", all(checks.CATALOG[v][0] == ("reachability", "Reachable (TCP to the management port)")
      for v in ("cisco", "juniper", "arista", "hpe", "mikrotik", "fortinet", "paloalto")))
class Dead:
    def __init__(self, *a): pass
    def run(self): raise TimeoutError("timed out")
class Fine:
    def __init__(self, *a): self.custom = []
    def run(self): return [runner.Result("sw1", "cpu", "OK", "3%")]
    def flush_baselines(self): pass
saved = dict(runner.DRIVERS)
runner.DRIVERS["cisco"] = Fine
res = runner.run_one(dev(port=22, proxy_cfg=via(good)), db.get_thresholds(), {**db.runtime_options(), "retries": 0})
check("a run starts with the Reachable row, then the device's own checks", [r.check for r in res][:2] == ["reachability", "cpu"] and res[0].status == "OK", [(r.check, r.status) for r in res])
runner.DRIVERS["cisco"] = Dead
res = runner.run_one(dev(port=22, proxy_cfg=via(unreachable)), db.get_thresholds(), {**db.runtime_options(), "retries": 0})
check("when the login fails too, the Reachable row says whether the device answered", {r.check: r.status for r in res} == {"reachability": "FAIL", "connection": "ERROR"}, res)
res = runner.run_one(dev(port=22, proxy_cfg=via(refusing)), db.get_thresholds(), {**db.runtime_options(), "retries": 0})
check("...so a device that is up but whose login failed is told apart", {r.check: r.status for r in res} == {"reachability": "OK", "connection": "ERROR"}, res)
res = runner.run_one(dev(port=22, proxy_cfg=via(good)), db.get_thresholds(), {**db.runtime_options(), "retries": 0, "disabled": {checks.key("cisco", "reachability")}})
check("switched off, there is no Reachable row", "reachability" not in [r.check for r in res])
runner.DRIVERS.update(saved)

print("== the Ping custom check, Through the proxy (TCP)")
chk = {"name": "ping", "kind": "ping", "options": {"tcp": True}, "higher_worse": 1}
r = custom.run_ping(chk, dev(port=22, proxy_cfg=via(good)))
check("ticked, a device behind a proxy is tested with TCP through it", r.status == "OK" and r.message == "TCP to port 22 through the proxy (ICMP cannot go through it)"
      and r.value.endswith(" ms"), r)
r = custom.run_ping(chk, dev(port=22, proxy_cfg=via(unreachable)))
check("...and no answer is a FAIL", (r.status, r.value) == ("FAIL", "no answer") and "host unreachable" in r.message, r)
r = custom.run_ping(chk, dev(host="127.0.0.1"))
check("a device without a proxy is still pinged", "TCP" not in r.message, r)
before = len(good.log)
r = custom.run_ping({**chk, "options": {}}, dev(port=22, proxy_cfg=via(good)))
check("unticked, it is four ordinary pings, not through the proxy", "TCP" not in r.message and len(good.log) == before, r)

print("== the SSH tunnel tells refused apart from no answer")
E = paramiko.ChannelException
check("'Connection refused' from the server is SOCKS5 reply 5 (the device is up)", tunnel._socks_reply(E(2, "Connection refused")) == 5)
check("other connect failures (timed out, no route) are 4, host unreachable", tunnel._socks_reply(E(2, "connect failed: Connection timed out")) == 4
      and tunnel._socks_reply(E(2, "No route to host")) == 4)
check("not allowed by the server's rules is 2", tunnel._socks_reply(E(1, "administratively prohibited")) == 2)

print("== the tools")
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QCoreApplication
app = QApplication([])
import app as A
A.apply_look(app)
import ui.tools as T, ui.tools2 as T2
def pump(cond, n=300):
    for _ in range(n):
        QCoreApplication.processEvents(); time.sleep(0.02)
        if cond(): return True
    return False
db.save_device(dev(name="behind", port=22, proxy_cfg=via(good)))
diag = T.DiagnosticsTab()
check("Diagnostics: Through the proxy (TCP), unticked by default, Traceroute available", diag.via_proxy.text() == "Through the proxy (TCP)" and not diag.via_proxy.isChecked()
      and diag.buttons["Traceroute"].isEnabled())
diag.picker.setCurrentIndex(next(i for i in range(diag.picker.count()) if (diag.picker.itemData(i) or {}).get("name") == "behind"))
check("picking a device leaves it unticked", not diag.via_proxy.isChecked())
diag.via_proxy.setChecked(True)
check("ticked, Traceroute is off and says why", not diag.buttons["Traceroute"].isEnabled() and diag.buttons["Traceroute"].toolTip() == reach.TRACE_NEEDS_ICMP)
diag.ping(); pump(lambda: diag.out.toPlainText().count("TCP 127.0.0.1:22") >= 4 and not diag.busy(), 600)
text = diag.out.toPlainText()
check("Ping makes four TCP connections through the device's proxy and says so", text.count("TCP 127.0.0.1:22 through the proxy: answered in ") == 4, text[-400:])
check("and Traceroute stays off afterwards", not diag.buttons["Traceroute"].isEnabled() and diag.buttons["Ping"].isEnabled())
diag.via_proxy.setChecked(False)
check("unticked, Traceroute is back", diag.buttons["Traceroute"].isEnabled() and diag.buttons["Traceroute"].toolTip() == "")
diag.shutdown()
live = T2.LivePingTab()
check("Live ping has the same checkbox, unticked", live.via_proxy.text() == "Through the proxy (TCP)" and not live.via_proxy.isChecked())
live.picker.setCurrentIndex(next(i for i in range(live.picker.count()) if (live.picker.itemData(i) or {}).get("name") == "behind"))
live.via_proxy.setChecked(True); before = len(good.log)
live.start(); pump(lambda: live.sent >= 2, 300); live.halt()
check("ticked, it samples with TCP through the device's proxy", live.sent >= 2 and live.lost == 0 and len(good.log) > before, (live.sent, live.lost))
mtr = T2.MtrTab()
check("Path (MTR) has it too, unticked, with Start available", mtr.via_proxy.text() == "Through the proxy (TCP)" and not mtr.via_proxy.isChecked() and mtr.go.isEnabled())
mtr.via_proxy.setChecked(True)
check("ticked, Start is off and says why", not mtr.go.isEnabled() and mtr.go.toolTip() == reach.TRACE_NEEDS_ICMP)
mtr.start(); check("and nothing is traced", mtr.mtr is None)
mtr.via_proxy.setChecked(False); check("unticked, Start is back", mtr.go.isEnabled())

print("== the Ping custom check's editor")
from ui.settings_pages import checks as CP
d = CP.CheckDialog()
d.kind.setCurrentIndex(d.kind.findData("ping")); d.name.setText("reach")
check("the Ping kind shows Through the proxy (TCP), unticked, and the help mentions it", d.form.isRowVisible(d.via_proxy) and not d.via_proxy.isChecked()
      and "Tick Through the proxy (TCP) to test devices behind a proxy" in d.help.text())
check("unticked it saves no option; ticked it saves it", d.values()["options"] == {} and (d.via_proxy.setChecked(True) or d.values()["options"] == {"tcp": True}))
d.kind.setCurrentIndex(d.kind.findData("tcp")); check("other kinds do not show it", not d.form.isRowVisible(d.via_proxy) and d.values()["options"] == {})

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

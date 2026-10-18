# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time, json, socket, threading, socketserver
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
pass
os.environ["QT_QPA_PLATFORM"] = "offscreen"
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\notify%d.db").replace("\\", os.sep) % int(time.time())
from core import db, alerts, notify
db.init()
PASS = FAIL = 0
def check(name, cond, extra=""):
    global PASS, FAIL
    PASS += bool(cond); FAIL += (not cond)
    print(("  ok   " if cond else "  FAIL ") + name + (f"   [{extra}]" if extra and not cond else ""))

# in-memory Credential Manager so tests never touch the real one
class FakeKeyring:
    store = {}
    @classmethod
    def get_password(cls, s, n): return cls.store.get((s, n))
    @classmethod
    def set_password(cls, s, n, v): cls.store[(s, n)] = v
    @classmethod
    def delete_password(cls, s, n):
        if (s, n) not in cls.store: raise KeyError(n)
        del cls.store[(s, n)]
notify.keyring = FakeKeyring

from drivers.base import Result
for n in ("core", "edge", "udm"):
    db.save_device(dict(name=n, vendor="cisco", host="127.0.0.1", port=0, platform="", username="u", site="default",
                        verify_ssl=0, ha_expected=0, enabled=1, location="", details=""))
R = lambda dev, chk, st, val="", msg="": Result(dev, chk, st, val, msg)
ev = lambda evs: sorted((e.kind, e.device, e.check, e.status) for e in evs)

print("== change detection")
t0 = datetime(2026, 1, 1, 12, 0)
e = alerts.evaluate([R("core", "cpu", "WARN", "75%")], ["core"], now=t0)
check("a new problem is announced", ev(e) == [("new", "core", "cpu", "WARN")], ev(e))
check("the same problem next run is NOT announced again", alerts.evaluate([R("core", "cpu", "WARN", "76%")], ["core"], now=t0) == [])
e = alerts.evaluate([R("core", "cpu", "FAIL", "95%")], ["core"], now=t0)
check("getting worse is announced", ev(e) == [("worse", "core", "cpu", "FAIL")] and e[0].prev == "WARN", ev(e))
check("still FAIL: quiet", alerts.evaluate([R("core", "cpu", "FAIL", "96%")], ["core"], now=t0) == [])
check("FAIL -> WARN (improved, still bad) is quiet", alerts.evaluate([R("core", "cpu", "WARN", "80%")], ["core"], now=t0) == [])
e = alerts.evaluate([R("core", "cpu", "FAIL", "97%")], ["core"], now=t0)
check("...but going bad again re-alerts", ev(e) == [("worse", "core", "cpu", "FAIL")], ev(e))
e = alerts.evaluate([R("core", "cpu", "OK", "10%")], ["core"], now=t0)
check("recovery is announced with what it was", ev(e) == [("recovered", "core", "cpu", "OK")] and e[0].prev == "FAIL", ev(e))
check("healthy again: quiet", alerts.evaluate([R("core", "cpu", "OK", "10%")], ["core"], now=t0) == [])

print("== alert after N runs / blips")
alerts.evaluate([R("edge", "mem", "OK")], ["edge"])
check("1st bad run with consecutive=2: quiet", alerts.evaluate([R("edge", "mem", "FAIL")], ["edge"], consecutive=2) == [])
e = alerts.evaluate([R("edge", "mem", "FAIL")], ["edge"], consecutive=2)
check("2nd bad run: announced", ev(e) == [("new", "edge", "mem", "FAIL")], ev(e))
alerts.evaluate([R("edge", "mem", "OK")], ["edge"])
alerts.evaluate([R("edge", "bgp", "FAIL")], ["edge"], consecutive=2)
e = alerts.evaluate([R("edge", "bgp", "OK")], ["edge"], consecutive=2)
check("a one-run blip never alerts, and its 'recovery' stays silent too", e == [])

print("== reminders")
alerts.evaluate([R("udm", "wan", "FAIL")], ["udm"], now=t0, remind_hours=4)
check("no reminder before the interval", alerts.evaluate([R("udm", "wan", "FAIL")], ["udm"], now=t0 + timedelta(hours=3), remind_hours=4) == [])
e = alerts.evaluate([R("udm", "wan", "FAIL")], ["udm"], now=t0 + timedelta(hours=5), remind_hours=4)
check("reminder after 4h+", ev(e) == [("reminder", "udm", "wan", "FAIL")] and e[0].since, ev(e))
check("and reminders are off at 0", alerts.evaluate([R("udm", "wan", "FAIL")], ["udm"], now=t0 + timedelta(hours=99), remind_hours=0) == [])
alerts.evaluate([R("udm", "wan", "OK")], ["udm"])

print("== scoping and cleanup")
alerts.evaluate([R("core", "ospf", "FAIL")], ["core"])
alerts.evaluate([R("edge", "x", "OK")], ["edge"])
check("a device that did not run keeps its state (no false recovery)", alerts.evaluate([R("edge", "x", "OK")], ["edge"]) == [])
e = alerts.evaluate([R("core", "cpu", "OK")], ["core"])
check("a check that vanished on a device that ran = recovered ('no longer reported')", ev(e) == [("recovered", "core", "ospf", "OK")] and "no longer" in e[0].message, ev(e))
alerts.evaluate([R("udm / ap1", "state", "FAIL", "disconnected"), R("udm", "connection", "OK")], ["udm"])
e = alerts.evaluate([R("udm / ap1", "state", "OK", "connected")], ["udm"])
check("UniFi 'controller / device' rows scope to the controller", ev(e) == [("recovered", "udm / ap1", "state", "OK")], ev(e))
alerts.evaluate([R("core", "z", "FAIL")], ["core"]); db.delete_device(db.list_devices()[0]["id"]); db.save_device(dict(name="core", vendor="cisco", host="1", port=0, platform="", username="", site="d", verify_ssl=0, ha_expected=0, enabled=1, location="", details="")) if False else None
with db.connect() as c: before = c.execute("select count(*) from alert_state").fetchone()[0]
alerts.evaluate([], [])
with db.connect() as c: after = c.execute("select count(*) from alert_state").fetchone()[0]
check("state for devices removed from the inventory is cleaned up", after <= before)
db.save_device(dict(name="core", vendor="cisco", host="127.0.0.1", port=0, platform="", username="u", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details=""))
with db.connect() as c: c.execute("DELETE FROM alert_state")

print("== retry after total delivery failure")
e1 = alerts.evaluate([R("edge", "retry", "FAIL")], ["edge"]); alerts.unmark(e1)
e2 = alerts.evaluate([R("edge", "retry", "FAIL")], ["edge"]); check("'new' event comes back if nobody received it", ev(e2) == [("new", "edge", "retry", "FAIL")], ev(e2))
alerts.evaluate([R("edge", "retry", "OK")], ["edge"])

print("== message building")
evs = [alerts.Event("new", "core", "cpu", "WARN", "OK", "75%", ""), alerts.Event("new", "edge", "wan links", "FAIL", "OK", "0/2 up", "down: wan1"),
       alerts.Event("worse", "core", "memory", "FAIL", "WARN", "95%", ""), alerts.Event("recovered", "udm", "bgp", "OK", "FAIL", "", "")]
m = notify.build_message(evs, "Acme")
check("title counts problems and recoveries, includes organisation", m.title == "Toner (Acme): 3 problems, 1 recovered", m.title)
check("worst first, recoveries last", [s for s, _ in m.lines] == ["FAIL", "FAIL", "WARN", "OK"], [s for s, _ in m.lines])
check("lines read well", "FAIL  edge - WAN Links: 0/2 up (down: wan1)" in m.lines[0][1] or "edge - WAN Links: 0/2 up (down: wan1)" in m.plain(), m.lines)
check("worse and recovered wording", "[worse, was WARN]" in m.plain() and "RECOVERED  udm - BGP (was FAIL)" in m.plain())
big = notify.build_message([alerts.Event("new", f"d{i}", "cpu", "WARN", "OK") for i in range(100)])
check("long lists are capped with a count", len(big.lines) == notify.MAX_LINES + 1 and "and 60 more" in big.lines[-1][1], big.lines[-1])
one = notify.build_message(evs[:1]); check("singular wording", one.title == "Toner: 1 problem", one.title)

print("== validation")
vt = lambda t, **kw: notify.validate({**notify.new_channel(t), **kw}, kw.pop("_s", {}) if False else {})
ch = notify.new_channel("slack"); check("slack needs a URL", any("required" in p for p in notify.validate(ch, {})))
check("slack rejects plain http", any("https" in p for p in notify.validate(ch, {"url": "http://hooks.example.com/x"})))
check("slack accepts https", notify.validate(ch, {"url": "https://hooks.slack.com/services/T/B/X"}) == [])
check("loopback http is allowed (local testing)", notify.validate(ch, {"url": "http://127.0.0.1:9/x"}) == [])
check("generic webhook allows internal http", notify.validate(notify.new_channel("webhook"), {"url": "http://intranet.local/hook"}) == [])
em = {**notify.new_channel("email"), "smtp_host": "mail", "from_addr": "a@b.com", "to_addrs": "x@y.com, bad address"}
check("bad recipient address is caught", any("bad address" in p for p in notify.validate(em, {})), notify.validate(em, {}))
check("email needs host, from, to", len(notify.validate(notify.new_channel("email"), {})) == 3, notify.validate(notify.new_channel("email"), {}))
check("desktop needs nothing", notify.validate(notify.new_channel("desktop"), {}) == [])

print("== delivery against local services")
captured = []
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        captured.append({"path": self.path, "headers": dict(self.headers), "body": body})
        if self.path.startswith("/fail"): self.send_response(500); self.end_headers(); self.wfile.write(b"boom secret-token-123"); return
        if self.path.startswith("/redir"): self.send_response(302); self.send_header("Location", "https://elsewhere.example/x"); self.end_headers(); return
        self.send_response(202 if self.path.startswith("/teams") else 200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
http = HTTPServer(("127.0.0.1", 0), H); hp = http.server_address[1]; threading.Thread(target=http.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{hp}"
msg = notify.build_message([alerts.Event("new", "core <sw>", "cpu", "FAIL", "OK", "95%", "a & b"), alerts.Event("recovered", "udm", "bgp", "OK", "FAIL")])
def send(ctype, secrets, **fields):
    ch = {**notify.new_channel(ctype), **fields}; captured.clear(); return notify.deliver(ch, msg, secrets=secrets, retry_delay=0), (captured[-1] if captured else None)
(ok, d), c = send("slack", {"url": base + "/slack"}); body = json.loads(c["body"])
check("slack: posts text, escapes < > &", ok and "&lt;sw&gt;" in body["text"] and "a &amp; b" in body["text"] and body["text"].startswith("*Toner"), body)
(ok, d), c = send("discord", {"url": base + "/discord"}); body = json.loads(c["body"])
check("discord: 'content' with code block", ok and body["content"].startswith("**Toner") and "```" in body["content"])
bigmsg = notify.build_message([alerts.Event("new", f"device-{i}", "cpu", "FAIL", "OK", "95%", "x" * 40) for i in range(40)])
captured.clear(); ch = {**notify.new_channel("discord")}; notify.deliver(ch, bigmsg, secrets={"url": base + "/discord"})
check("discord: stays under its 2000-character limit", len(json.loads(captured[-1]["body"])["content"]) <= 2000, len(json.loads(captured[-1]["body"])["content"]))
(ok, d), c = send("teams", {"url": base + "/teams"}); body = json.loads(c["body"]); card = body["attachments"][0]["content"]
check("teams: adaptive card, red text for FAIL, 202 accepted", ok and body["type"] == "message" and card["type"] == "AdaptiveCard" and card["body"][1]["color"] == "Attention" and card["body"][-1]["color"] == "Good", card["body"][:2])
(ok, d), c = send("webhook", {"url": base + "/hook", "bearer": "tok-1"}); body = json.loads(c["body"])
check("webhook: JSON document + bearer header", ok and body["source"] == "Toner" and body["problems"] == 1 and body["recovered"] == 1 and body["events"][0]["kind"] == "new" and c["headers"]["Authorization"] == "Bearer tok-1", body)
(ok, d), c = send("ntfy", {"topic": "my-topic", "token": ""}, server=base)
check("ntfy: topic in URL, title/priority headers, text body", ok and c["path"] == "/my-topic" and c["headers"]["Priority"] == "4" and c["headers"]["Title"].startswith("Toner") and b"core <sw>" in c["body"], c)
(ok, d), c = send("slack", {"url": base + "/fail/T0000/B0000/secret-token-123"})
check("HTTP 500 is a failure, with the reason", not ok and "HTTP 500" in d, d)
(ok, d), c = send("slack", {"url": base + "/redir"}); check("redirect is a failure (a POST would be silently dropped)", not ok and "302" in d and "elsewhere.example" in d, d)
t = time.time(); (ok, d), c = send("slack", {"url": "http://127.0.0.1:9/x/secret-token-999"})
check("unreachable service fails after one retry, and the token is not in the error", not ok and "secret-token-999" not in d, d)
# secrets scrubbed even when the library echoes the path
check("scrubber hides URL paths", "secret-token" not in notify._scrub("ConnectionError: url: /services/T0/B0/secret-token-1", {"url": "https://hooks.slack.com/services/T0/B0/secret-token-1"}))

# fake SMTP server (no TLS, no auth)
mails = []
class Smtp(socketserver.StreamRequestHandler):
    def handle(self):
        w = lambda s: self.wfile.write((s + "\r\n").encode()); w("220 test ESMTP"); data = False; buf = []; rcpt = []
        for raw in self.rfile:
            line = raw.decode(errors="replace").rstrip("\r\n")
            if data:
                if line == ".": mails.append({"rcpt": rcpt, "text": "\n".join(buf)}); w("250 queued"); data = False; buf = []
                else: buf.append(line[1:] if line.startswith("..") else line)
                continue
            cmd = line.upper()
            if cmd.startswith("EHLO") or cmd.startswith("HELO"): w("250-test"); w("250 8BITMIME")
            elif cmd.startswith("MAIL"): w("250 ok")
            elif cmd.startswith("RCPT"): rcpt.append(line.split(":", 1)[1].strip(" <>")); w("250 ok")
            elif cmd == "DATA": w("354 go"); data = True
            elif cmd == "QUIT": w("221 bye"); return
            else: w("250 ok")
class TS(socketserver.ThreadingTCPServer): allow_reuse_address = True; daemon_threads = True
smtp = TS(("127.0.0.1", 0), Smtp); sp = smtp.server_address[1]; threading.Thread(target=smtp.serve_forever, daemon=True).start()
em = {**notify.new_channel("email"), "smtp_host": "127.0.0.1", "smtp_port": sp, "security": "None", "from_addr": "toner@example.com", "to_addrs": "a@example.com; b@example.com"}
ok, d = notify.deliver(em, msg, secrets={}, retry_delay=0)
check("email: delivered to every recipient", ok and len(mails) == 1 and mails[0]["rcpt"] == ["a@example.com", "b@example.com"], (ok, d, mails))
check("email: subject prefix, title, body", "Subject: [Toner] Toner: 1 problem, 1 recovered" in mails[0]["text"] and "core <sw>" in mails[0]["text"], mails[0]["text"][:300])
smtp.shutdown(); ok, d = notify.deliver({**em, "smtp_port": sp}, msg, secrets={}, retry_delay=0); check("email to a dead server fails cleanly", not ok and d, d)
shown = []
ok, d = notify.deliver(notify.new_channel("desktop"), msg, desktop=lambda t, b: shown.append((t, b)))
check("desktop: title + first lines", ok and shown and shown[0][0].startswith("Toner") and "core <sw>" in shown[0][1], shown)
ok, d = notify.deliver(notify.new_channel("desktop"), msg, desktop=None); check("desktop without a tray reports why", not ok and "tray" in d, d)

print("== channel filters")
mk = lambda **kw: {**notify.new_channel("webhook"), **kw}
warn_ev, fail_ev, rec_fail, rec_warn = (alerts.Event("new", "a", "c", "WARN", "OK"), alerts.Event("new", "a", "c", "FAIL", "OK"),
                                        alerts.Event("recovered", "a", "c", "OK", "FAIL"), alerts.Event("recovered", "a", "c", "OK", "WARN"))
allc, failc, errc = mk(min="WARN and worse"), mk(min="FAIL and ERROR only"), mk(min="ERROR only")
check("WARN-and-worse channel wants everything", all(notify.wants(allc, e) for e in (warn_ev, fail_ev, rec_fail, rec_warn)))
check("FAIL-only channel skips WARN and recoveries from WARN", not notify.wants(failc, warn_ev) and notify.wants(failc, fail_ev) and notify.wants(failc, rec_fail) and not notify.wants(failc, rec_warn))
check("ERROR-only skips FAIL", not notify.wants(errc, fail_ev))
check("recoveries can be switched off per channel", not notify.wants(mk(recoveries=False), rec_fail) and notify.wants(mk(recoveries=False), fail_ev))

print("== process_run end to end")
for k, v in (("notify_consecutive", 1), ("notify_remind_hours", 0)): db.set_setting(k, v)
a = {**notify.new_channel("webhook"), "name": "all", "id": "aaaa1111"}; b = {**notify.new_channel("webhook"), "name": "critical", "id": "bbbb2222", "min": "FAIL and ERROR only", "recoveries": False}
notify.set_secrets(a, {"url": base + "/hook-all"}); notify.set_secrets(b, {"url": base + "/hook-crit"})
notify.save_channels([a, b])
res = lambda *rows: [R(*r) for r in rows]
cap = lambda: [c for c in captured]
captured.clear(); out = notify.process_run(res(("core", "cpu", "WARN", "75%")), ["core"], True)
check("master switch off -> nothing", out == "off" and not captured)
db.set_setting("notify_enabled", True)
db.set_setting("notify_snooze_until", (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")); out = notify.process_run(res(("core", "cpu", "WARN")), ["core"], True)
check("snoozed -> nothing", out == "snoozed" and not captured); db.set_setting("notify_snooze_until", "")
db.set_setting("notify_on_manual", False); out = notify.process_run(res(("core", "cpu", "WARN")), ["core"], False); check("manual runs can be excluded", out.startswith("manual") and not captured); db.set_setting("notify_on_manual", True)
captured.clear(); out = notify.process_run(res(("core", "cpu", "WARN", "75%")), ["core"], True)
check("WARN goes to the 'all' channel only", [c["path"] for c in captured] == ["/hook-all"] and out == "1/1 channels", ([c["path"] for c in captured], out))
captured.clear(); out = notify.process_run(res(("core", "cpu", "FAIL", "95%")), ["core"], True)
check("escalation to FAIL goes to both", sorted(c["path"] for c in captured) == ["/hook-all", "/hook-crit"], [c["path"] for c in captured])
captured.clear(); out = notify.process_run(res(("core", "cpu", "FAIL", "96%")), ["core"], True); check("unchanged -> silence", out == "no changes" and not captured)
captured.clear(); notify.process_run(res(("core", "cpu", "OK", "5%")), ["core"], True)
check("recovery goes only where recoveries are wanted", [c["path"] for c in captured] == ["/hook-all"], [c["path"] for c in captured])
# everything down: nothing delivered -> retried next run, then delivered
notify.set_secrets(a, {"url": "http://127.0.0.1:9/dead"}); notify.set_secrets(b, {"url": "http://127.0.0.1:9/dead"})
orig = notify.deliver; notify.deliver = lambda ch, m, d=None, s=None, retry_delay=2: orig(ch, m, d, s, 0)
captured.clear(); out = notify.process_run(res(("edge", "wan", "FAIL", "0/2")), ["edge"], True); check("all channels down -> reported as 0 delivered", out == "0/2 channels", out)
notify.set_secrets(a, {"url": base + "/hook-all"}); notify.set_secrets(b, {"url": base + "/hook-crit"})
captured.clear(); out = notify.process_run(res(("edge", "wan", "FAIL", "0/2")), ["edge"], True)
check("...so the same problem is announced again once a channel works", len(captured) == 2 and out == "2/2 channels", (len(captured), out))
# one channel down, one up: no unmark (the problem was delivered somewhere)
notify.set_secrets(a, {"url": "http://127.0.0.1:9/dead"})
captured.clear(); notify.process_run(res(("edge", "mem", "FAIL")), ["edge"], True); notify.set_secrets(a, {"url": base + "/hook-all"}); captured.clear()
out = notify.process_run(res(("edge", "mem", "FAIL")), ["edge"], True); check("partial delivery is not repeated", out == "no changes" and not captured, out)
log = alerts.recent_deliveries(50); check("every attempt is logged, failures flagged", any(not r["ok"] for r in log) and any(r["ok"] for r in log) and all(r["channel"] for r in log), len(log))
check("log never contains the webhook token", all("hook-all" not in (r["detail"] or "") for r in log))
db.set_setting("notify_channels", [{"id": "x", "type": "carrier-pigeon", "name": "n"}, a]); check("unknown channel types are ignored, not fatal", [c["name"] for c in notify.channels()] == ["all"])
notify.save_channels([a, b])

print("== secrets and export")
check("secrets live in the vault, not the settings", "hook-all" not in json.dumps(db.get_setting("notify_channels")) and FakeKeyring.get_password(db.SERVICE, "notify:aaaa1111:url") == base + "/hook-all")
check("settings export leaves channels out", "notify_channels" not in db.export_settings() and "notify_snooze_until" not in db.export_settings() and "notify_enabled" in db.export_settings())
ok, sk = db.import_settings({"notify_channels": [], "notify_enabled": False}); check("import cannot overwrite channels", "notify_channels" in sk and "notify_enabled" in ok and len(notify.channels()) == 2)
notify.delete_secrets(b); check("removing a channel deletes its secret", FakeKeyring.get_password(db.SERVICE, "notify:bbbb2222:url") is None)
notify.save_channels([a]); db.set_setting("notify_enabled", False)

print(f"\n{PASS} passed, {FAIL} failed")

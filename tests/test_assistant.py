# Run directly (python tests/test_assistant.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The Assistant without any provider SDK: settings and the key in the vault, prices, conversations and monthly totals, the spend
# stop, every tool against the test database with masking checked (no vault password or backup secret ever comes back), the
# turn loop with a scripted provider, Settings > AI and Test, the status strip, the side button and the panel pushing the page,
# and "what is on screen" from each covered page. The three SDKs against fake servers are in test_assistant_providers.py.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "ai%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import audit, backup, db, orgs, sessionlog, vault
db.init()
from core import assistant as AI
from core.assistant import agent, prices, providers, store, tools as T
from drivers.base import Result
from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
import ui.settings as S
from ui import assistant as UA

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def settle(n=6):
    for _ in range(n): QCoreApplication.processEvents()
def wait(cond, secs=10):
    end = time.time() + secs
    while not cond() and time.time() < end: app.processEvents(); time.sleep(0.01)
    return cond()
def dev(name, **kw):
    d = dict(name=name, vendor="cisco", host="10.0.0.1", port=0, platform="cisco_ios", username="admin", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="Chicago", details="", folder_id=None, tags="core")
    d.update(kw); db.save_device(d); return [x for x in db.list_devices() if x["name"] == name][0]

PW, PROFILE_PW, COMMUNITY, AI_KEY = "Sup3rS3cret!pw", "Pr0filePass!", "c0mmun1tyRO", "sk-ant-api03-FAKEKEY-abcdefghijklmnop"
acme = orgs.create("Acme Charter Schools", "acme")
globex = orgs.create("Globex", "glbx")

print("== settings and the key")
check("defaults: Claude, Claude Opus 5.5, Normal, USD 20", AI.provider_id() == "claude" and AI.model_for() == "claude-opus-5-5" and AI.depth() == "normal" and AI.spend_limit() == 20)
check("the settings are the installation's (Global only)", all(k in db.GLOBAL_ONLY for k in ("ai_provider", "ai_model", "ai_depth", "ai_spend_limit")))
with db.within(acme):
    db.set_setting("ai_depth", "thorough")
check("set from an organization, the setting lands in Global and is read everywhere", db.get_setting("ai_depth") == "thorough" and AI.depth() == "thorough")
db.set_setting("ai_depth", "normal")
check("no key to begin with", not AI.has_key() and AI.get_key() == "")
AI.set_key("claude", AI_KEY)
check("the key lives in the vault under service:ai-claude, never in the settings", STORE.get(("netcheck", "service:ai-claude")) == AI_KEY and AI.has_key("claude")
      and AI_KEY not in json.dumps(db.export_settings(), default=str))
check("the three key names are exported with the other service passwords", all(n in vault.SERVICE_NAMES for n in ("service:ai-claude", "service:ai-openai", "service:ai-gemini")) and set(AI.key_names()) <= set(vault.known_names()))
AI.set_model("openai", "gpt-6-luna")
check("a model is remembered per provider", AI.model_for("openai") == "gpt-6-luna" and AI.model_for("claude") == "claude-opus-5-5")
check("the limit sentence names the limit as shown", AI.limit_text() == "This organization's monthly spend limit (USD 20) is reached. Raise it under Settings > AI.")
check("money: whole dollars plain, cents when there are any", AI.money(20) == "20" and AI.money(14.9) == "14.90" and AI.money(0.5) == "0.50")

print("== prices")
check("exact ids, a family prefix, and nothing for the unknown", prices.rate("claude-opus-5-5") == (4.0, 20.0) and prices.rate("gpt-6.1-sol") == (2.0, 10.0) and prices.rate("models/gemini-3.8-flash") == (0.75, 3.75)
      and prices.rate("gemini-2.5-flash-preview-09-2025") == (0.30, 2.50) and prices.rate("gpt-6.1-sol-2026-11-01") == (2.0, 10.0) and prices.rate("mystery-9") is None)
check("the longest prefix wins (flash-lite is not priced as flash)", prices.rate("gemini-2.5-flash-lite-latest") == (0.10, 0.40) and prices.rate("gpt-5.4-mini-2026") == (0.75, 4.50))
check("cost: 1M in at 4 USD and 500k out at 20 USD is 14 USD; unknown models cost 0", abs(prices.cost("claude-opus-5-5", 1_000_000, 500_000) - 14.0) < 1e-9 and prices.cost("mystery-9", 10, 10) == 0 and prices.known("gpt-5") and not prices.known("x"))

print("== conversations and totals")
with db.within(acme):
    c1 = store.create("claude", "claude-opus-5-5", "What is wrong with core-sw1 today, and why did it reboot last night at three in the morning?")
    conv = store.get(c1)
    check("a conversation starts with the first question as its title, cut short", conv["provider"] == "claude" and conv["title"].endswith("…") and len(conv["title"]) <= store.TITLE_LENGTH and conv["history"] == [])
    store.add_turn(c1, "user", "hello")
    store.add_turn(c1, "tool", "Reading core-sw1's history…")
    store.add_turn(c1, "assistant", "It rebooted.", "claude-opus-5-5", 2000, 1000, prices.cost("claude-opus-5-5", 2000, 1000))
    store.add_turn(c1, "assistant", "More.", "claude-opus-5-5", 1000, 500, prices.cost("claude-opus-5-5", 1000, 500))
    store.set_history(c1, [{"role": "user", "content": "hello"}, {"role": "assistant", "content": [{"type": "thinking", "thinking": "", "signature": "SIG"}]}])
    conv = store.get(c1)
    check("turns, tokens and cost are summed on the conversation; the history round-trips", conv["turns"] == 2 and conv["tokens_in"] == 3000 and conv["tokens_out"] == 1500 and abs(conv["cost"] - 0.042) < 1e-9
          and conv["history"][1]["content"][0]["signature"] == "SIG")
    kinds = [t["kind"] for t in store.turns(c1)]
    check("the transcript keeps every line in order", kinds == ["user", "tool", "assistant", "assistant"])
    here = store.month_totals()
    check("this organization this month", here == {"conversations": 1, "turns": 2, "tokens_in": 3000, "tokens_out": 1500, "tokens": 4500, "cost": here["cost"]} and abs(here["cost"] - 0.042) < 1e-9)
    with db.connect() as c:                                            # an answer from another month does not count
        c.execute("INSERT INTO ai_turns(conversation_id, at, kind, text, tokens_in, tokens_out, cost) VALUES(?,?,?,?,?,?,?)", (c1, "2020-01-05 10:00:00", "assistant", "old", 900, 900, 9.0))
    check("only this month counts", store.month_totals()["turns"] == 2 and abs(store.month_totals()["cost"] - 0.042) < 1e-9)
with db.within(globex):
    c2 = store.create("openai", "gpt-6.1-sol", "Short")
    store.add_turn(c2, "assistant", "x", "gpt-6.1-sol", 1_000_000, 0, prices.cost("gpt-6.1-sol", 1_000_000, 0))
every = store.every_org_totals()
check("every organization's month side by side, Global first", [n for _o, n, _t in every] == ["Global", "Acme Charter Schools", "Globex"] and every[1][2]["conversations"] == 1 and abs(every[2][2]["cost"] - 2.0) < 1e-9)
check("the installation's total adds them up", store.all_totals()["conversations"] == 2 and abs(store.all_totals()["cost"] - 2.042) < 1e-9 and store.all_totals()["tokens"] == 4500 + 1_000_000)
with db.within(acme):
    check("an organization lists only its own", [r["id"] for r in store.list_conversations()] == [c1])
check("Global lists every organization's, each with its organization", {r["org"] for r in store.list_conversations()} == {globex, acme} and len(store.list_conversations()) == 2)

print("== the spend stop")
check("under the limit nothing stops", not AI.spend_reached())
db.set_setting("ai_spend_limit", 2)
check("at the limit (USD 2.04 of 2) it is reached, for every organization alike", AI.spend_reached() and (lambda: (db.set_home(acme), AI.spend_reached())[1])())
db.set_home(db.GLOBAL)
db.set_setting("ai_spend_limit", 0)
check("a limit of 0 means no limit", not AI.spend_reached())
db.set_setting("ai_spend_limit", 20)

print("== the tools against the test database")
db.set_home(acme)
with db.within(acme):
    sw = dev("core-sw1")
    fw1 = dev("edge-fw", vendor="fortinet", host="10.0.0.9", platform="", tags="edge", location="Boston")
    db.set_secret(db.secret_name("core-sw1"), PW)
    db.set_secret(db.secret_name("core-sw1", "snmp"), COMMUNITY)
    from core import profiles
    profiles.save({"name": "Net team", "username": "ro", "snmp": {}, "notes": ""}, {"main": PROFILE_PW})
    backup.store("core-sw1", f"hostname core-sw1\nenable secret 5 abcdef\nusername admin password 7 {PW}\nsnmp-server community {COMMUNITY} RO\ninterface Gi0/1\n description uplink\n", mask=False)
    time.sleep(1.1)
    backup.store("core-sw1", f"hostname core-sw1\nenable secret 5 abcdef\nusername admin password 7 {PW}\nsnmp-server community {COMMUNITY} RO\ninterface Gi0/1\n description uplink to core\n shutdown\n", mask=False)
    db.save_run([Result("core-sw1", "cpu", "WARN", "75", "CPU at 75%", 75.0), Result("core-sw1", "uptime", "OK", "3 days", "", 72.0), Result("edge-fw", "cpu", "OK", "10", "", 10.0)])
    db.save_run([Result("core-sw1", "cpu", "FAIL", "95", f"CPU at 95% (password {PW} leaked into a message)", 95.0), Result("core-sw1", "uptime", "OK", "3 days", "", 73.0)])
    log = sessionlog.SessionLog("core-sw1", "10.0.0.1", 22, "admin")
    log.write(b"\x1b[32mcore-sw1#\x1b[0m show version\r\nCisco IOS Software, Version 15.2\r\n" + f"password {PW}\r\n".encode())
    log.close("Closed by user.")
    secrets_in_vault = {PW, COMMUNITY, PROFILE_PW, AI_KEY}
    check("every vault value is known to the masker, the Assistant's own key too", secrets_in_vault <= set(T.secrets()))
    def tool(name, **args):
        text = T.run(name, args)
        leaked = sum(1 for s in secrets_in_vault if s in text)          # a count: the values themselves are never printed
        check(f"{name}: no vault secret in the result", not leaked, f"{leaked} leaked")
        return json.loads(text)
    r = tool("list_devices")
    check("list_devices: the organization's devices with status and folder", r["count"] == 2 and {d["name"] for d in r["devices"]} == {"core-sw1", "edge-fw"} and r["devices"][0]["status"] in ("FAIL", "OK") and "organization" not in r["devices"][0])
    r = tool("device_details", device="core-sw1")
    check("device_details: settings, latest results and problems, never a password", r["name"] == "core-sw1" and r["username"] == "admin" and r["status"] == "FAIL" and any(p["status"] == "FAIL" for p in r["problems"]) and len(r["latest_results"]) == 2 and "****" in json.dumps(r))
    r = tool("latest_results", device="core-sw1")
    check("latest_results: the newest run's rows, the leaked password masked", r["count"] == 2 and {x["check"] for x in r["results"]} == {"CPU", "Uptime"} and any("****" in x["message"] for x in r["results"]))
    r = tool("device_history", device="core-sw1")
    check("device_history: newest run first, every check, with the checks seen", len(r["runs"]) == 2 and r["runs"][0]["results"][0]["status"] in ("FAIL", "OK") and set(r["checks_seen"]) == {"CPU", "Uptime"})
    r = tool("device_history", device="core-sw1", check="cpu", runs=1)
    check("device_history: narrowed to one check and one run", len(r["runs"]) == 1 and [x["check"] for x in r["runs"][0]["results"]] == ["CPU"] and r["runs"][0]["results"][0]["status"] == "FAIL")
    r = tool("list_backups", device="core-sw1")
    ids = [v["id"] for v in r["versions"]]
    check("list_backups: both versions, newest first", r["count"] == 2 and ids == sorted(ids, reverse=True) and r["versions"][0]["added"] == 2)
    r = tool("read_backup", device="core-sw1")
    check("read_backup: the newest, and the masked copy only (the stored one held the password)", r["backup_id"] == ids[0] and "shutdown" in r["configuration"] and "<masked>" in r["configuration"] and PW not in r["configuration"] and COMMUNITY not in r["configuration"])
    r = tool("read_backup", device="core-sw1", backup_id=ids[1])
    check("read_backup: an older version by id", r["backup_id"] == ids[1] and "shutdown" not in r["configuration"])
    r = tool("diff_backups", device="core-sw1", older_id=ids[1], newer_id=ids[0])
    check("diff_backups: a unified diff of the masked copies", r["added"] == 2 and r["removed"] == 1 and "+ shutdown" in r["diff"] and PW not in r["diff"])
    r = tool("diff_backups", device="core-sw1", older_id=ids[0], newer_id=ids[1])
    check("diff_backups: the ids may be given in either order", r["older"] <= r["newer"] and r["added"] == 2)
    r = tool("list_backups", device="edge-fw")
    check("list_backups: a device with none says so", r["count"] == 0 and "No backup" in r["note"])
    r = tool("read_backup", device="core-sw1", backup_id=999)
    check("a wrong id is an error the model can read, not a failure", "error" in r and "no backup with id 999" in r["error"])
    r = tool("latest_results", device="nope")
    check("an unknown device is an error naming it", "error" in r and "nope" in r["error"] and "list_devices" in r["error"])
    r = tool("firmware_check")
    check("firmware_check: nothing yet says where the results come from", r["results"] == [] and "Firmware Transfer" in r["note"])
    T.firmware_snapshot([{"key": "core-sw1", "name": "core-sw1", "host": "10.0.0.1", "platform": "cisco_ios", "version": "15.2(4)E7", "mode": "", "image": "c2960x.bin", "boot": ["flash:/c2960x.bin"],
                          "flashes": [{"member": 1, "role": "Master", "state": "Ready", "fs": "flash:", "total": 120_000_000, "free": 40_000_000, "files": {}},
                                      {"member": 2, "role": "Member", "state": "Ready", "fs": "flash2:", "total": 120_000_000, "free": 38_000_000, "files": {}}],
                          "ping": True, "port": True, "note": "", "held": "", "dev": sw}], "tftp://10.0.0.5")
    r = tool("firmware_check")
    check("firmware_check: the page's rows after Check devices, stack members included", r["server"] == "tftp://10.0.0.5" and r["results"][0]["version"] == "15.2(4)E7" and r["results"][0]["status"] == "Ready" and r["results"][0]["stack"][0]["member"] == 2 and "MB" in r["results"][0]["free_space"])
    r = tool("list_session_logs")
    check("list_session_logs: the logged session", r["count"] == 1 and r["sessions"][0]["device"] == "core-sw1" and r["sessions"][0]["result"] == "Closed by user." and r["sessions"][0]["type"] == "SSH")
    sid = r["sessions"][0]["id"]
    r = tool("read_session_log", session_id=sid)
    check("read_session_log: the device's output, cleaned, the password masked", "show version" in r["log"] and "\x1b" not in r["log"] and "Version 15.2" in r["log"] and PW not in r["log"] and "****" in r["log"])
    r = tool("read_session_log", session_id=4242)
    check("read_session_log: a wrong id is an error", "error" in r)
    audit.log("device added", "core-sw1 by hand")
    r = tool("audit_log", text="assistant")
    check("audit_log: the entries, filtered by a word; every tool call has written one", r["count"] >= 10 and all(e["action"] == "assistant" for e in r["entries"]))
    details = [e["detail"] for e in r["entries"]]
    check("audit lines read as 'read core-sw1's history', 'compared ... backups', 'read what is on screen'", "read core-sw1's history" in details and f"compared core-sw1's backups {ids[1]} and {ids[0]}" in details and "read the device list" in details and "read session log %d" % sid in details)
    screen = {"section": "Inventory", "organization": "Acme Charter Schools", "selected_device": {"name": "core-sw1"}, "note": f"typed {PW}"}
    text = T.run("whats_on_screen", {}, screen)
    check("whats_on_screen: the snapshot handed in, masked", json.loads(text)["selected_device"]["name"] == "core-sw1" and PW not in text and "****" in text)
    check("whats_on_screen with nothing captured says so", "Nothing was captured" in T.run("whats_on_screen", {}, None))
    check("read what is on screen is audited", "read what is on screen" in [e["detail"] for e in audit.recent(5)])
    check("an unknown tool is answered, not raised", "no tool called" in T.run("bogus", {}))
    check("steps read as the panel shows them", T.BY_NAME["device_history"].step({"device": "core-sw1"}) == "Reading core-sw1's history…" and T.BY_NAME["whats_on_screen"].step({}) == "Reading what is on screen…")
    check("every tool has a name, a description, an object schema and a step", all(t.schema["type"] == "object" and t.description and t.step({}) for t in T.TOOLS) and len(T.TOOLS) == 12)
    with db.within(globex):
        r = json.loads(T.run("list_devices", {}))
        check("another organization sees none of these devices", r["count"] == 0)

print("== the turn loop with a scripted provider")
class Scripted(providers.Provider):
    """Answers from a script: each item is ('tool', [(name, args)]) or ('text', words) or ('refusal',) or ('error',)."""
    name, label, host, default_model = "claude", "Claude", "api.anthropic.com", "claude-opus-5-5"
    def __init__(self, script, hold=None):
        super().__init__("k", "claude-opus-5-5", "normal"); self.script = list(script); self.seen = []; self.hold = hold
    def list_models(self): return [("claude-opus-5-5", "Claude Opus 5.5")]
    def complete(self, system, history, tools, on_text, cancel=None):
        self.seen.append((system, [dict(m) for m in history], [t.name for t in tools]))
        step = self.script.pop(0)
        r = providers.Reply(); r.model = "claude-opus-5-5"; r.tokens_in, r.tokens_out = 1000, 100
        if step[0] == "tool":
            r.calls = [(f"toolu_{i}", n, a) for i, (n, a) in enumerate(step[1])]; r.stop = "tool"
            r.native = [{"role": "assistant", "content": [{"type": "thinking", "thinking": "", "signature": "SIG1"}] + [{"type": "tool_use", "id": c[0], "name": c[1], "input": c[2]} for c in r.calls]}]
        elif step[0] == "text":
            for piece in step[1].split(" "):
                if self.hold is not None: self.hold.wait(2)
                if cancel is not None and cancel.is_set(): raise providers.Cancelled()
                r.text += piece + " "; on_text(piece + " ")
            r.native = [{"role": "assistant", "content": [{"type": "text", "text": r.text}]}]
        elif step[0] == "refusal":
            r.stop, r.refusal = "refusal", "bio"
        elif step[0] == "error":
            raise providers.NoAnswer("no answer from api.anthropic.com")
        return r
    def user_message(self, text): return [{"role": "user", "content": text}]
    def tool_results(self, reply, results): return [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": c[0], "content": t} for c, t in results]}]

events = []
with db.within(acme):
    cid = store.create("claude", "claude-opus-5-5")
prov = Scripted([("tool", [("latest_results", {"device": "core-sw1"}), ("whats_on_screen", {})]), ("text", "core-sw1 is failing on CPU.")])
done = agent.run_turn(cid, acme, "What is wrong with core-sw1?", {"section": "Results", "selected_devices": ["core-sw1"]}, lambda k, p: events.append((k, p)), provider=prov)
kinds = [k for k, _ in events]
check("the loop: tools first (each announced), then the streamed answer, then done", kinds[:2] == ["tool", "tool"] and kinds.count("text") == 5 and kinds[-1] == "done",
      kinds)
check("the steps read as approved", [p for k, p in events if k == "tool"] == ["Reading core-sw1's latest results…", "Reading what is on screen…"])
check("done carries the text, model, tokens summed over both rounds and the cost", done["text"].strip() == "core-sw1 is failing on CPU." and done["tokens_in"] == 2000 and done["tokens_out"] == 200 and abs(done["cost"] - prices.cost("claude-opus-5-5", 2000, 200)) < 1e-9 and done["priced"] and done["note"] == "")
sys_prompt, hist1, toolnames = prov.seen[0]
check("the system prompt names the organization and the date; every tool is offered", "Acme Charter Schools" in sys_prompt and time.strftime("%Y") in sys_prompt and set(toolnames) == set(T.BY_NAME))
hist2 = prov.seen[1][1]
check("the second round got the thinking block back unchanged and a tool_result per call", hist2[1]["content"][0] == {"type": "thinking", "thinking": "", "signature": "SIG1"} and [b["tool_use_id"] for b in hist2[2]["content"]] == ["toolu_0", "toolu_1"]
      and "FAIL" in hist2[2]["content"][0]["content"] and "Results" in hist2[2]["content"][1]["content"])
with db.within(acme):
    conv = store.get(cid); turns = store.turns(cid)
check("stored: the history for the next question, and the transcript with its usage", len(conv["history"]) == 4 and conv["title"] == "What is wrong with core-sw1?" and [t["kind"] for t in turns] == ["user", "tool", "tool", "assistant"]
      and turns[-1]["tokens_in"] == 2000 and conv["turns"] == 1)
check("the tool results were masked and audited on the way", PW not in json.dumps(conv["history"]) and "read core-sw1's latest results" in [e["detail"] for e in (lambda: (db.set_home(acme), audit.recent(20))[1])()])
events.clear()
prov = Scripted([("refusal",)])
done = agent.run_turn(cid, acme, "Something it declines", {}, lambda k, p: events.append((k, p)), provider=prov)
check("a refusal is a normal end: the panel is told in words", events[-1][0] == "done" and done["note"] == AI.REFUSED and store.turns(cid, acme)[-1]["text"] == AI.REFUSED)
events.clear()
prov = Scripted([("error",)])
check("a provider that does not answer: an error event with the reason, nothing raised", agent.run_turn(cid, acme, "q", {}, lambda k, p: events.append((k, p)), provider=prov) is None and events == [("error", "no answer from api.anthropic.com")])
events.clear()
hold = threading.Event(); cancel = threading.Event()
prov = Scripted([("text", "one two three four")], hold=hold)
t = threading.Thread(target=lambda: agent.run_turn(cid, acme, "q", {}, lambda k, p: events.append((k, p)), cancel=cancel, provider=prov)); t.start()
time.sleep(0.2); cancel.set(); hold.set(); t.join(5)
check("Stop ends the turn: a stopped event, and 'Stopped.' in the transcript", events and events[-1] == ("stopped", None) and store.turns(cid, acme)[-1]["text"] == "Stopped.")
events.clear()
db.set_setting("ai_spend_limit", 1)
prov = Scripted([("text", "never")])
agent.run_turn(cid, acme, "q", {}, lambda k, p: events.append((k, p)), provider=prov)
check("at the limit nothing is sent and the limit sentence is the answer", events == [("error", "This organization's monthly spend limit (USD 1) is reached. Raise it under Settings > AI.")] and prov.seen == [])
db.set_setting("ai_spend_limit", 20)
db.set_home(db.GLOBAL)

print("== Settings > AI")
check("the page is listed under Automation and managed by Global", "AI" in dict(S.GROUPS)["Automation"] and "AI" in S.GLOBAL_PAGES)
tab = S.SettingsTab(); tab.resize(1100, 700); tab.show(); settle()
P = {p.title: p for p in tab.pages}; pg = P["AI"]
check("the fields: Provider, API key (dots), Model, Depth, Monthly spend limit (USD), Test", pg.provider.currentText() == "Claude" and pg.key.echoMode() == pg.key.EchoMode.Password and pg.model.currentText() == "claude-opus-5-5"
      and pg.depth.currentText() == "Normal" and pg.limit.value() == 20 and pg.test_btn.text() == "Test" and pg.key.placeholderText() == "saved; leave blank to keep")
labels = [pg.form.labelForField(f).text() for f in (pg.provider, pg.key, pg.model, pg.depth, pg.limit)]
check("the labels read as approved", labels == ["Provider", "API key", "Model", "Depth", "Monthly spend limit (USD)"], labels)
canned = {"ok": True, "text": "Connected: Claude Opus 5.5.", "models": [("claude-opus-5-5", "Claude Opus 5.5"), ("claude-sonnet-5-5", "Claude Sonnet 5.5")], "model": "Claude Opus 5.5"}
asked = []
REAL_TEST = AI.test_connection
AI.test_connection = lambda p, k, m=None: (asked.append((p, k, m)), canned if p == "claude" else {"ok": False, "text": "Not connected: the API key was refused.", "models": [], "model": ""})[1]
pg.test()
check("Test runs in the background and reports the approved line; the model list fills from the provider", wait(lambda: pg.result.text() != "Testing…") and pg.result.text() == "Connected: Claude Opus 5.5." and asked[-1] == ("claude", AI_KEY, "claude-opus-5-5")
      and [pg.model.itemData(i) for i in range(pg.model.count())] == ["claude-opus-5-5", "claude-sonnet-5-5"] and pg.model.currentData() == "claude-opus-5-5")
pg.provider.setCurrentIndex(pg.provider.findData("openai")); settle()
check("another provider: its remembered model, an empty key box and no stale result", pg.model.currentText() == "gpt-6-luna" and pg.key.placeholderText() == "" and pg.result.text() == "")
pg.key.setText("sk-test-openai-key-1234567890"); pg.test()
check("Test with a refused key says so", wait(lambda: pg.result.text() != "Testing…") and pg.result.text() == "Not connected: the API key was refused." and asked[-1][1] == "sk-test-openai-key-1234567890")
pg.limit.setValue(35); pg.depth.setCurrentIndex(pg.depth.findData("quick"))
checks = []
AI.check_in_background = lambda done=None: checks.append(1)
tab.save()
check("Save stores provider, model, depth and limit, puts the key in the vault, clears the box and re-tests", AI.provider_id() == "openai" and AI.model_for() == "gpt-6-luna" and AI.depth() == "quick" and AI.spend_limit() == 35
      and STORE.get(("netcheck", "service:ai-openai")) == "sk-test-openai-key-1234567890" and pg.key.text() == "" and pg.key.placeholderText() == "saved; leave blank to keep" and checks == [1])
check("a second Save with the box left blank keeps the key", (tab.save(), STORE.get(("netcheck", "service:ai-openai")))[1] == "sk-test-openai-key-1234567890")
pg.provider.setCurrentIndex(pg.provider.findData("claude")); settle(); pg.depth.setCurrentIndex(pg.depth.findData("normal")); pg.limit.setValue(20); tab.save()
check("the provider can be switched back without typing the key again (it is still in the vault)", AI.provider_id() == "claude" and AI.has_key("claude") and AI.model_for() == "claude-opus-5-5")
tab.close()

print("== the provider marks")
import hashlib
from ui import brandicons
check("OpenAI's Blossom is the published file, unmodified (light and dark versions)", hashlib.sha256(brandicons.BRAND_SVG["openai"]["light"].encode()).hexdigest() == "75c1e9fffa5e8c437bec1d67197a73992bca45d166c6ff23215185dea8fae92a"
      and hashlib.sha256(brandicons.BRAND_SVG["openai"]["dark"].encode()).hexdigest() == "01d158767c4eec0e47bd617e67759c33da0accd1438be1a8d29dfdb99ce87285")
def drawn(provider):
    img = brandicons.provider_icon(provider).pixmap(64, 64).toImage()
    return sum(1 for x in range(0, 64, 2) for y in range(0, 64, 2) if img.pixelColor(x, y).alpha() > 100)
check("each provider's mark draws something; the placeholders stand in for Claude and Gemini", drawn("openai") > 40 and drawn("claude") > 200 and drawn("gemini") > 200 and not brandicons.has_brand_mark("claude") and not brandicons.has_brand_mark("gemini"))
brandicons._cache.clear()
db.set_setting("theme", "Dark"); A.apply_look(app)
dark_img = brandicons.provider_icon("openai").pixmap(64, 64).toImage()
db.set_setting("theme", "Light"); A.apply_look(app)
light_img = brandicons.provider_icon("openai").pixmap(64, 64).toImage()
mid = lambda img: next((img.pixelColor(x, y).lightness() for x in range(0, 64) for y in range(0, 64) if img.pixelColor(x, y).alpha() > 200), None)
check("the white Blossom on the dark theme, the black one on the light theme", mid(dark_img) is not None and mid(dark_img) > 200 and mid(light_img) is not None and mid(light_img) < 60, (mid(dark_img), mid(light_img)))
db.set_setting("theme", "System"); A.apply_look(app)

print("== the status strip, the side button and the panel")
db.set_home(db.GLOBAL)
AI._state.update(connected=None, text="", checked=False, model="")
w = A.Main(); w.resize(1300, 820); w.show(); settle()
time.sleep(0.3); settle()                                              # the startup check (no key: not connected) has reported
names = [w.tabs.tabText(i) for i in range(w.tabs.count())]
check("the top tab is Automation/AI, between Sessions and Settings", "Automation/AI" in names and names.index("Automation/AI") == names.index("Sessions") + 1 and "Automation" not in names)
w.go("Automation"); settle()
check("go('Automation') still opens it, and its list has the AI section with Assistant", w.tabs.currentWidget() is w.automation and [w.automation.pages.tabText(i) for i in range(w.automation.pages.count())] == ["Playbooks", "Run history", "Assistant"]
      and w.headers["automation"].title.text().endswith("Automation/AI"))
check("before the check: no strip part, no button, the panel closed", not w.strip.ai.isVisible() and not w.ai_button.isVisible() and not w.assistant.isVisible())
AI.set_state(True, "Connected: Claude Opus 5.5.", "Claude Opus 5.5"); settle()
check("connected: the strip says so and the round button appears at the right edge, centred", w.strip.ai.isVisible() and w.strip.ai.text() == "Assistant: connected" and w.ai_button.isVisible()
      and w.ai_button.width() == w.ai_button.height() == UA.BUTTON and w.ai_button.x() + w.ai_button.width() <= w.width() and w.ai_button.x() > w.width() - 80
      and abs(w.ai_button.y() + w.ai_button.height() // 2 - (w.body.y() + w.body.height() // 2)) <= 2, (w.ai_button.pos().toTuple(), w.body.height()))
for sec in ("Inventory", "Results", "Configs", "Settings"):
    w.go(sec); settle()
check("the button stays on every section", w.ai_button.isVisible() and w.ai_button.parent() is w)
w.go("Inventory"); settle()
tabs_before = w.tabs.width()
w.ai_button.click(); settle()
check("click: the panel opens beside the page and pushes it narrower (never covers it)", w.assistant.isVisible() and w.tabs.width() < tabs_before and w.tabs.x() + w.tabs.width() <= w.assistant.x()
      and w.assistant.x() + w.assistant.width() == w.body.width() and w.assistant.width() == UA.PANEL_WIDTH and w.body.count() == 2, (tabs_before, w.tabs.width(), w.body.sizes()))
check("the panel's furniture: title, placeholder, Send, Stop, New conversation", w.assistant.title.text() == "Assistant" and w.assistant.input.placeholderText() == "Ask about what is on screen, or anything in this organization"
      and (w.assistant.send_btn.text(), w.assistant.stop_btn.text(), w.assistant.new_btn.text()) == ("Send", "Stop", "New conversation") and not w.assistant.stop_btn.isEnabled())
check("the button moves to the panel's edge and reads as pressed", abs(w.ai_button.x() + w.ai_button.width() // 2 - w.body.mapTo(w, w.assistant.pos()).x()) <= 1 and w.ai_button.isChecked())
w.body.setSizes([w.body.width() - 480, 480]); w.body.splitterMoved.emit(w.body.width() - 480, 1); settle()
wait(lambda: (db.get_setting("splitters") or {}).get("assistant_panel") is not None, 3)
check("the width is remembered like other splitters", (db.get_setting("splitters") or {}).get("assistant_panel") == w.body.sizes())
w.ai_button.click(); settle()
check("click again: closed, the page has its width back", not w.assistant.isVisible() and w.tabs.width() == tabs_before and not w.ai_button.isChecked())
AI.set_state(False, "Not connected: the API key was refused.", ""); settle()
check("not connected: the strip says so and the button is gone", w.strip.ai.text() == "Assistant: not connected" and not w.ai_button.isVisible() and "refused" in w.strip.ai.toolTip())
gone = []
w.strip.navigate.connect(lambda s, p: gone.append((s, p)))
w.strip.ai.clicked.emit()
check("clicking the strip's part opens Settings > AI", gone == [("Settings", "AI")])
AI.set_state(True, "Connected: Claude Opus 5.5.", "Claude Opus 5.5"); settle()

print("== the panel asks, with the scripted provider")
REAL_MAKE = AI.make
script = [("tool", [("whats_on_screen", {})]), ("text", "You are looking at core-sw1, which is failing.")]
made = []
AI.make = lambda *a, **k: made.append(Scripted(list(script))) or made[-1]
w.set_org(acme); settle()
w.go("Inventory"); settle()
items = [w.inventory.table.topLevelItem(i) for i in range(w.inventory.table.topLevelItemCount())]
def find_item(name):
    out = []
    def walk(it):
        if it.text(0) == name: out.append(it)
        for k in range(it.childCount()): walk(it.child(k))
    for it in items: walk(it)
    return out[0] if out else None
it = find_item("core-sw1")
if it is not None: w.inventory.table.setCurrentItem(it); it.setSelected(True)
settle()
w.show_assistant(True); settle()
panel = w.assistant
check("switching to an organization gives the panel that organization's newest conversation", panel.org == acme and panel.conv_id() == cid and panel.entries and panel.entries[0] == ("user", "What is wrong with core-sw1?"))
panel.new_conversation(); settle()
check("New conversation empties the transcript", panel.conv_id() is None and panel.entries == [])
panel.input.setPlainText("What am I looking at?")
check("Send starts a turn: the question is in the transcript and Stop is live", panel.send() and panel.entries[0] == ("user", "What am I looking at?") and panel.stop_btn.isEnabled() and not panel.send_btn.isEnabled())
check("the turn finished", wait(lambda: not panel.running(), 15))
settle()
kinds = [k for k, _ in panel.entries]
check("the transcript: the question, the step as it happened, the answer and a line with tokens and cost", kinds == ["user", "muted", "assistant", "muted"] and panel.entries[1][1] == "Reading what is on screen…"
      and panel.entries[2][1].strip() == "You are looking at core-sw1, which is failing." and panel.entries[3][1] == "2,000 tokens in, 200 out  ·  USD 0.01", panel.entries)
screen_seen = made[0].seen[1][1][2]["content"][0]["content"]
check("the tool got what was on screen when Send was pressed: Inventory in Acme with core-sw1 selected", '"section": "Inventory"' in screen_seen and '"organization": "Acme Charter Schools"' in screen_seen and "core-sw1" in screen_seen, screen_seen[:200])
check("the conversation was created in Acme's file and the Automation/AI page lists it", panel.conv_id() is not None and panel.conv_id() in [r["id"] for r in store.list_conversations()] and panel.conv_id() in [r["id"] for r in w.automation.assistant_page.rows])
check("Send and the input are back", panel.send_btn.isEnabled() and not panel.stop_btn.isEnabled() and panel.input.toPlainText() == "")
w.set_org(globex); settle()
check("switching organization switches the conversation (Globex has its own, older one)", panel.org == globex and panel.conv_id() == c2 and panel.entries and panel.entries[0][0] == "assistant")
w.set_org(acme); settle()
check("back in Acme: the same conversation, redrawn from what is stored", panel.conv_id() is not None and [k for k, _ in panel.entries] == ["user", "muted", "assistant", "muted"])
db.set_setting("ai_spend_limit", 1)
panel.input.setPlainText("Another question")
check("at the limit nothing is sent and the panel says the approved sentence", not panel.send() and panel.status.text() == "This organization's monthly spend limit (USD 1) is reached. Raise it under Settings > AI." and panel.input.toPlainText() == "Another question")
db.set_setting("ai_spend_limit", 20)
panel.new_conversation(); settle()
check("New conversation: an empty transcript; the next question starts a new one", panel.conv_id() is None and panel.entries == [] and panel.hint.isVisible())
AI.make = REAL_MAKE

print("== Automation/AI > Assistant")
w.go("Automation"); w.automation.pages.setCurrentWidget(w.automation.assistant_page); settle()
pg = w.automation.assistant_page; pg.refresh()
check("provider and model, connection, this organization's month, the installation's month against the limit", "Claude" in pg.provider.text() and "Claude Opus 5.5" in pg.provider.text() and pg.connection.text() == "<b>Connection:</b> connected"
      and pg.here.isVisible() and pg.here.text().startswith("<b>This organization this month:</b> ") and "USD" in pg.here.text()
      and "across all organizations" in pg.everywhere.text() and " of 20 across all organizations" in pg.everywhere.text(), (pg.here.text(), pg.everywhere.text()))
check("what it can see: the organization, its device count and what the tools read", "Acme Charter Schools, 2 devices" in pg.sees.text() and "configuration backups (passwords masked)" in pg.sees.text() and "what is on screen" in pg.sees.text())
titles = [pg.table.item(i, 0).text() for i in range(pg.table.rowCount())]
check("the conversation list: title from the first question, started, turns, cost", pg.table.rowCount() == len(store.list_conversations()) and "What am I looking at?" in titles and pg.table.item(titles.index("What am I looking at?"), 2).text() == "1"
      and pg.table.item(titles.index("What am I looking at?"), 1).text()[:4] == time.strftime("%Y") and pg.table.horizontalHeaderItem(4).text() == "Cost (USD)")
pg.table.selectRow(0); settle()
opened = []
w.open_assistant_conversation = lambda cid_, org_: opened.append((cid_, org_))
pg.open_requested.disconnect(); pg.open_requested.connect(w.open_assistant_conversation)
pg.open_btn.click()
check("Open hands the conversation to the panel", opened == [(pg.rows[0]["id"], acme)])
pg.ask = lambda n: True
n_before = len(store.list_conversations())
pg.table.selectRow(0); settle(); pg.delete_btn.click(); settle()
check("Delete removes it and its lines", len(store.list_conversations()) == n_before - 1 and pg.table.rowCount() == n_before - 1)
w.set_org(db.GLOBAL); settle(); w.go("Automation"); pg.refresh()
check("in Global: every organization's month side by side with a total, and every conversation with its organization", pg.orgs_table.isVisible() and not pg.here.isVisible() and pg.orgs_table.rowCount() == 4 and pg.orgs_table.item(3, 0).text() == "Total"
      and pg.orgs_table.item(0, 0).text() == "Global" and any("(Globex)" in pg.table.item(i, 0).text() for i in range(pg.table.rowCount())))

print("== what is on screen, from each page")
w.set_org(acme); settle()
w.go("Inventory"); settle()
it = find_item("core-sw1") if False else None
items = [w.inventory.table.topLevelItem(i) for i in range(w.inventory.table.topLevelItemCount())]
it = find_item("core-sw1")
if it is not None: w.inventory.table.setCurrentItem(it); it.setSelected(True)
settle()
sc = w.screen_context()
check("Inventory: the selected device", sc["section"] == "Inventory" and sc["organization"] == "Acme Charter Schools" and sc["selected_devices"] == ["core-sw1"] and sc["selected_device"]["host"] == "10.0.0.1" and sc["selected_device"]["status"] == "FAIL", sc)
w.go("Results"); settle(); w.results.load_stored(); settle()
top = next((w.results.table.topLevelItem(i) for i in range(w.results.table.topLevelItemCount()) if "core-sw1" in w.results.table.topLevelItem(i).text(0)), None)
if top is not None: w.results.table.setCurrentItem(top); top.setSelected(True)
sc = w.screen_context()
check("Results: the selected device and its rows", sc["section"] == "Results" and sc["selected_devices"] == ["core-sw1"] and any(r["check"].lower() == "cpu" and r["status"] == "FAIL" for r in sc["rows"]), sc)
check("what the screen holds is masked once it goes through the tool", PW in json.dumps(sc) and PW not in T.run("whats_on_screen", {}, sc))
w.go("History"); settle(); w.history.refresh(); settle()
sc = w.screen_context()
check("History: the chosen run and its rows", sc["section"] == "History" and "selected_run" in sc and sc["selected_run"]["fail"] == "1" and any(r["device"] == "core-sw1" for r in sc["rows"]), sc)
w.go("Configs"); settle(); w.configs.refresh(); w.configs.select_device("core-sw1"); settle(); w.configs.view.setCurrentIndex(w.configs.view.findData("full")); w.configs.show_text(); settle()
sc = w.screen_context()
check("Configs: the device, the version and the masked text", sc["section"] == "Configs" and sc["selected_device"] == "core-sw1" and sc["selected_versions"] and sc["view"] == "full configuration" and "hostname core-sw1" in sc["text"] and PW not in sc["text"] and "<masked>" in sc["text"], {k: v for k, v in sc.items() if k != "text"})
w.go("Tools"); w.tools.tabs.setCurrentWidget(w.tools.runner); settle()
run_tab = w.tools.runner
run_tab.commands.setPlainText("show version"); run_tab.results = {"core-sw1": {"device": "core-sw1", "ok": True, "seconds": 1.2, "error": "", "outputs": [("show version", "Cisco IOS 15.2")]}}
run_tab.output.setPlainText("$ show version\nCisco IOS 15.2")
sc = w.screen_context()
check("Tools > Command Runner: the commands and the last output", sc["section"] == "Tools" and sc["page"] == "Command Runner" and sc["commands"] == "show version" and sc["results"][0]["output"].endswith("Cisco IOS 15.2") and sc["read_only_mode"], sc)
w.tools.tabs.setCurrentWidget(w.tools.firmware); settle()
sc = w.screen_context()
check("Tools > Firmware Transfer: the step and its table", sc["page"] == "Firmware Transfer" and sc["step"] == "Step 1 of 6: Devices" and "devices" in sc, sc)
w.tools.firmware.stack.setCurrentIndex(2); settle()
sc = w.screen_context()
check("Firmware Transfer on Check devices: the results rows", sc["step"] == "Step 3 of 6: Check devices" and "results" in sc and "progress" in sc, sc)
w.tools.firmware.stack.setCurrentIndex(0)
w.go("Sessions"); settle()
from core import sessions as SESS
with db.within(acme):
    sid_saved = SESS.save({"name": "sw1 console", "kind": "ssh", "host": "10.0.0.1", "port": 22, "username": "admin", "device": "core-sw1", "options": {}, "folder_id": None})
w.sessions.refresh(); settle()
for item in w.sessions._all_items():
    if item.text(0) == "sw1 console": w.sessions.tree.setCurrentItem(item); item.setSelected(True)
settle()
sc = w.screen_context()
check("Sessions: the selected saved session", sc["section"] == "Sessions" and sc["selected_sessions"] and sc["selected_sessions"][0]["host"] == "10.0.0.1" and sc["selected_sessions"][0]["type"] == "ssh", sc)
w.go("Automation"); w.automation.pages.setCurrentWidget(w.automation.playbooks); settle()
sc = w.screen_context()
check("Automation/AI > Playbooks: the playbook chosen and the devices ticked", sc["section"] == "Automation/AI" and sc["page"] == "Playbooks" and "devices_ticked" in sc and "check_mode" in sc, sc)
w.automation.pages.setCurrentWidget(w.automation.history); settle()
sc = w.screen_context()
check("Automation/AI > Run history: the run chosen", sc["page"] == "Run history", sc)
w.go("Overview"); settle()
sc = w.screen_context()
check("a page with nothing to add still names the section and organization", sc == {"section": "Overview", "organization": "Acme Charter Schools"}, sc)
w.close()

print("== the startup check")
AI._state.update(connected=None, text="", checked=False, model="")
asked.clear()
AI.test_connection = lambda p, k, m=None: (asked.append((p, k, m)), canned)[1]
import core.assistant as _ai_mod
_ai_mod.check_in_background = (lambda f: f)(_ai_mod.check_in_background) if False else _ai_mod.check_in_background
# the real check_in_background (the page's Save replaced the name on the module earlier in this file)
def real_check(done=None):
    def work():
        AI.check_now()
        if done: done()
    t = threading.Thread(target=work, daemon=True); t.start(); return t
AI.check_in_background = real_check
w2 = A.Main(); w2.show(); settle()
check("with a key stored, the window runs the test in the background and ends up connected", wait(lambda: AI.state()["connected"] is True and w2.ai_button.isVisible(), 10) and asked and asked[-1][0] == "claude" and w2.strip.ai.text() == "Assistant: connected"
      and w2.assistant.model_line.text() == "Claude  ·  Claude Opus 5.5")
w2.close()
AI.set_key("claude", ""); AI._state.update(connected=None, text="", checked=False, model="")
w3 = A.Main(); w3.show(); settle(); time.sleep(0.3); settle()
check("with no key stored nothing is asked and nothing is shown", AI.state()["connected"] is None and not w3.strip.ai.isVisible() and not w3.ai_button.isVisible() and len(asked) == 1)
w3.close()
AI.test_connection = REAL_TEST

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

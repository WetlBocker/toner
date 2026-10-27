# Run directly (python tests/test_assistant_search.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The Assistant's internet search, apart from the SDKs (those are in test_assistant_providers.py): the Settings > AI switch (on by
# default), the instructions each way, the check for a query that names something from the network, the per-search prices, the
# usage line and the Sources line, what the turn loop does with searches reported as they happen and with the answer (audit lines,
# the stored turn, the done payload), the panel drawing it live and again from the store, and the Settings page.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "aisearch%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import audit, db, orgs
db.init()
from core import assistant as AI
from core.assistant import agent, prices, providers, store, tools as T
from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QApplication
app = QApplication([])
import app as A
A.apply_look(app)
import ui.settings as S
from ui import assistant as UA
from ui.settings_pages import ai as AIPAGE

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
    d = dict(name=name, vendor="cisco", host="10.0.0.1", port=0, platform="cisco_ios", username="admin", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None, tags="")
    d.update(kw); db.save_device(d); return [x for x in db.list_devices() if x["name"] == name][0]
def audited(n=10):
    return [e["detail"] for e in audit.recent(n)]

ADVISORY = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-2026-0235"
NVD = "https://nvd.nist.gov/vuln/detail/CVE-2026-0235"
acme = orgs.create("Acme Charter Schools", "acme")
db.set_home(acme)
with db.within(acme):
    dev("core-sw1", host="10.20.30.40")
AI.set_key("claude", "sk-ant-test-key-0123456789")

print("== the switch")
check("on by default, the installation's (Global only), with two columns on the turns", AI.search_allowed() is True and "ai_search" in db.GLOBAL_ONLY and db.DEFAULT_SETTINGS["ai_search"] is True
      and {"searches", "sources"} <= {r[1] for r in db.connect().execute("PRAGMA table_info(ai_turns)")})
p = agent.system_prompt(acme)
check("the instructions, when on", "search the internet through your own web search" in p and "Never put anything from this network in a search" in p and "Searching costs money" in p and "cannot reach the internet" not in p)
check("what it can see names the internet", T.what_it_sees()[-1] == "the internet, through the provider's own search (allowed under Settings > AI)")
db.set_setting("ai_search", False)
p = agent.system_prompt(acme)
check("the instructions, when off", "You cannot reach the internet." in p and "searching can be allowed under\nSettings > AI" in p and "your own web search" not in p and "the internet" not in T.what_it_sees())
db.set_setting("ai_search", True)

print("== a query that names something from the network")
with db.within(acme):
    check("a device's name, its address or the organization, capitals ignored", T.names_network("CORE-SW1 CVE-2026-0235") and T.names_network("ping 10.20.30.40 fails") and T.names_network("acme charter schools switches")
          and not T.names_network("Catalyst 9300 17.09.04a CVE-2026-0235") and not T.names_network(""))
check("the step and audit lines, marked or not", agent.search_step("search", "CVE-2026-0235") == ("Searching the web for CVE-2026-0235…", "searched the web: CVE-2026-0235")
      and agent.search_step("search", "core-sw1 CVE", True) == ("Searching the web for core-sw1 CVE… (named a device)", "searched the web: core-sw1 CVE (named a device)")
      and agent.search_step("fetch", ADVISORY) == (f"Reading the page {ADVISORY}…", f"read the page: {ADVISORY}"))

print("== prices and lines")
check("per search: Claude and OpenAI 1 cent, Gemini 3 and newer 1.4 cents, Gemini 2.5 3.5 cents, unknown nothing",
      prices.search_rate("claude-opus-5-5") == 0.01 and prices.search_rate("gpt-6.1-sol") == 0.01 and prices.search_rate("o3") == 0.01 and prices.search_rate("gemini-3.8-flash") == 0.014
      and prices.search_rate("models/gemini-2.5-flash") == 0.035 and prices.search_rate("mystery") == 0.0)
check("cost adds the searches; a model with no price still costs nothing", abs(prices.cost("claude-opus-5-5", 1_000_000, 0, 3) - 4.03) < 1e-9 and prices.cost("mystery", 10, 10, 5) == 0)
check("the usage line counts searches, singular and plural, and stays as it was without any", UA.usage_line(1234, 456, 0.07, True, 2) == "1,234 tokens in, 456 out, 2 searches  ·  USD 0.07"
      and UA.usage_line(10, 5, 0.01, True, 1) == "10 tokens in, 5 out, 1 search  ·  USD 0.01" and UA.usage_line(10, 5, 0.01) == "10 tokens in, 5 out  ·  USD 0.01")
check("the Sources line: title and host, the host alone when there is no title", UA.sources_text([("Cisco Security Advisory", ADVISORY), ("", NVD)]) == "Sources: Cisco Security Advisory (sec.cloudapps.cisco.com), nvd.nist.gov (nvd.nist.gov)")

print("== the turn loop")
class Scripted(providers.Provider):
    """Each step: ('live', query, text) announces the search as it happens; ('late', [queries], text) reports them with the answer
    (Gemini's way); ('text', words). Every search carries the advisory as its source."""
    name, label, host, default_model = "claude", "Claude", "api.anthropic.com", "claude-opus-5-5"
    def __init__(self, script):
        super().__init__("k", "claude-opus-5-5", "normal"); self.script = list(script); self.seen = []
    def list_models(self): return [("claude-opus-5-5", "Claude Opus 5.5")]
    def complete(self, system, history, tools, on_text, cancel=None, search=False, on_search=None):
        self.seen.append((system, [dict(m) for m in history], [t.name for t in tools], search))
        step = self.script.pop(0)
        r = providers.Reply(); r.model = "claude-opus-5-5"; r.tokens_in, r.tokens_out = 1000, 100
        if step[0] == "live":
            on_search("search", step[1]); r.queries, r.searches, r.sources = [step[1]], 1, [("Cisco Security Advisory", ADVISORY)]
        elif step[0] == "late":
            r.queries, r.searches, r.sources = list(step[1]), len(step[1]), [("Cisco Security Advisory", ADVISORY), ("CVE-2026-0235", NVD)]
        r.text = step[2] if len(step) > 2 else step[1]; on_text(r.text)
        r.native = [{"role": "assistant", "content": [{"type": "text", "text": r.text}]}]
        return r
    def user_message(self, text): return [{"role": "user", "content": text}]
    def tool_results(self, reply, results): return [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": c[0], "content": t} for c, t in results]}]

events = []
with db.within(acme):
    cid = store.create("claude", "claude-opus-5-5")
prov = Scripted([("live", "CVE-2026-0235 Catalyst 9300", "Affected below 17.09.04a.")])
done = agent.run_turn(cid, acme, "Are these switches affected by CVE-2026-0235?", {}, lambda k, p: events.append((k, p)), provider=prov)
check("search is asked for; the step comes as it happens; done carries the count, the sources and no after-steps", prov.seen[0][3] is True and events[0] == ("tool", "Searching the web for CVE-2026-0235 Catalyst 9300…")
      and done["searches"] == 1 and done["sources"] == [("Cisco Security Advisory", ADVISORY)] and done["after"] == [] and abs(done["cost"] - prices.cost("claude-opus-5-5", 1000, 100, 1)) < 1e-9, (events, done))
with db.within(acme):
    turns = store.turns(cid)
check("the audit line, and the stored turn with its searches and sources", "searched the web: CVE-2026-0235 Catalyst 9300" in audited(5)
      and [t["kind"] for t in turns] == ["user", "tool", "assistant"] and turns[-1]["searches"] == 1 and turns[-1]["sources"] == [["Cisco Security Advisory", ADVISORY]], turns)
events.clear()
prov = Scripted([("late", ["CVE-2026-0235", "core-sw1 firmware"], "Two searches say yes.")])
done = agent.run_turn(cid, acme, "And the other switch?", {}, lambda k, p: events.append((k, p)), provider=prov)
with db.within(acme):
    turns = store.turns(cid)
check("queries known only with the answer come after it, marked where they name a device; both audited", [k for k, _ in events] == ["text", "done"]
      and done["after"] == ["Searched the web for CVE-2026-0235…", "Searched the web for core-sw1 firmware… (named a device)"] and done["searches"] == 2 and len(done["sources"]) == 2
      and audited(3)[:2] == ["searched the web: core-sw1 firmware (named a device)", "searched the web: CVE-2026-0235"]
      and [t["kind"] for t in turns][-3:] == ["assistant", "tool", "tool"] and turns[-1]["text"].startswith("Searched the web for core-sw1"), (events, done, audited(3)))
db.set_setting("ai_search", False)
prov = Scripted([("text", "I cannot reach the internet.")])
agent.run_turn(cid, acme, "CVE?", {}, lambda k, p: None, provider=prov)
check("switched off between questions: no search asked for, the instructions say so", prov.seen[0][3] is False and "You cannot reach the internet." in prov.seen[0][0])
db.set_setting("ai_search", True)

print("== the panel")
panel = UA.AssistantPanel(lambda: {}); panel.resize(520, 700); panel.show(); settle()
panel.set_org(acme); settle()
kinds = [k for k, _ in panel.entries]
texts = [t for _, t in panel.entries]
check("from the store: the answer, its Sources line, the usage line with the searches, then the late steps", kinds == ["user", "muted", "assistant", "sources", "muted", "user", "assistant", "sources", "muted", "muted", "muted", "user", "assistant", "muted"]
      and texts[3] == "Sources: Cisco Security Advisory (sec.cloudapps.cisco.com)" and texts[4] == "1,000 tokens in, 100 out, 1 search  ·  USD 0.02"
      and texts[8] == "1,000 tokens in, 100 out, 2 searches  ·  USD 0.03" and texts[9] == "Searched the web for CVE-2026-0235…", (kinds, texts))
check("the Sources are links that open outside Toner", panel.view.openExternalLinks() and 'href="https://sec.cloudapps.cisco.com' in panel.view.toHtml())
panel.new_conversation(); AI.set_state(True, "Connected: Claude Opus 5.5.", "Claude Opus 5.5"); settle()
UA.Worker.run = lambda self: agent.run_turn(self.conv_id, self.org, self.question, self.screen, lambda k, p: self.event.emit(k, p), self.cancel,
                                            provider=Scripted([("live", "CVE-2026-0235", "Yes.")]))
panel.input.setPlainText("Affected?"); panel.send()
check("live: the step, the answer, its sources and the usage line in that order", wait(lambda: len(panel.entries) >= 5 and not panel.running()) and [k for k, _ in panel.entries] == ["user", "muted", "assistant", "sources", "muted"]
      and panel.entries[1][1] == "Searching the web for CVE-2026-0235…" and panel.entries[3][1].startswith("Sources: Cisco") and "1 search" in panel.entries[4][1], panel.entries)
panel.shutdown()

print("== Settings > AI")
tab = S.SettingsTab(); tab.resize(1100, 760); tab.show(); settle()
pg = {p.title: p for p in tab.pages}["AI"]
check("the box, ticked, with its note, under the show-commands box", pg.search.text() == "Let the Assistant search the internet" and pg.search.isChecked()
      and pg.search.toolTip().startswith("When on, the Assistant may search the web through the provider's own search") and "USD 0.01 to 0.035" in pg.search.toolTip()
      and pg.form.getWidgetPosition(pg.search)[0] > pg.form.getWidgetPosition(pg.run_cmds)[0] and "unless you switch that off below" in AIPAGE.INTRO)
pg.search.setChecked(False)
AI.check_in_background = lambda done=None: None
tab.save()
check("Save keeps it off; load shows it", AI.search_allowed() is False and (pg.load(), not pg.search.isChecked())[1])
tab.close()
db.set_setting("ai_search", True)

print("== the README")
readme = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "README.md"), encoding="utf-8").read()
check("the README has the paragraph, the switch and the prices", "**Searching the internet.**" in readme and "Let the Assistant search the internet" in readme and "(named a device)" in readme
      and "Search was not available with this model." in readme and "0.035" in readme)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

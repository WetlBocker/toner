# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The window follows the signed-in role: Tools and the AI the role switched off are hidden, Settings pages it may not change are
# read-only under one banner, and Accounts and sign-in is for Admins. With sign-in off nothing is hidden.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if _sys.platform == "win32":          # the offscreen platform finds no fonts on Windows by itself
    _os.environ.setdefault("QT_QPA_FONTDIR", _os.path.join(_os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\roleui%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

from core import datakey, orgs, perms, roles, session
import app as A
A.plain_look(app)
for n in ("question", "warning", "information"):
    setattr(QMessageBox, n, staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes))
PW, PW2, PW3 = "correct horse battery 42", "another long password 9", "a third quite long password 5"
BANNER = "Your role can view this page but not change it."


def build():
    w = A.Main(); w.resize(1100, 800); w.show(); app.processEvents()
    return w


def tool_names(w):
    return [w.tools.tabs.tabText(i) for i in range(w.tools.tabs.count()) if i not in w.tools.tabs._off]


def section_names(w):
    return [w.tabs.tabText(i) for i in range(w.tabs.count()) if w.tabs.shown(i)]


def page_row(st, title):
    return next(r for r in range(st.nav.count()) if st.nav.item(r).text() == title)


# ---------------------------------------------------------------- sign-in off: nothing is hidden
db.init()
check("no keys file: sign-in off", not datakey.exists())
w = build(); st = w.settings
check("off: every tool is listed", len(tool_names(w)) == 25, tool_names(w))
check("off: every section is shown", section_names(w) == [w.tabs.tabText(i) for i in range(w.tabs.count())])
check("off: no Settings page is locked", not st.locked and all(p.isEnabled() for p in st.pages))
check("off: Accounts and sign-in is listed", "Accounts and sign-in" in st.page_titles())
check("off: no role banner shows", not any(lab.isVisibleTo(st) for lab in st.role_lines.values()))
check("off: every Settings page title is a permission key (but Accounts)",
      {p.title for p in st.pages} - {"Accounts and sign-in"} == set(perms.SETTINGS_PAGES), {p.title for p in st.pages} ^ set(perms.SETTINGS_PAGES))
w._ai_state(True, "connected")
w.show_assistant(True)
check("off: the Assistant opens", w.ai_button.isVisibleTo(w) and w.assistant.isVisible())
w.close()
os.environ["NETCHECK_DB"] = SP + os.sep + "roleui_keyed.db"                    # the off phase used a plain database; the keyed one starts fresh

# ---------------------------------------------------------------- an Admin, then a Tech and an Engineer
datakey.create("Admin1", PW)
db.init()
session.sign_out(); session.sign_in("Admin1", PW)
datakey.add_local("Tech1", PW2, role="Tech")
datakey.add_local("Eng1", PW3, role="Engineer")
acme = orgs.create("Acme", "ACME")
roles.set_permissions("Tech", {"tool:snmp": False, "ai": False, "tool:sessions": False, "tool:rdp": False})
roles.sync_grants()

session.sign_out(); session.sign_in("Admin1", PW)
w = build(); st = w.settings
check("Admin: everything is shown", len(tool_names(w)) == 25 and "Sessions" in section_names(w) and "Accounts and sign-in" in st.page_titles())
check("Admin: no page is locked", not st.locked and all(p.isEnabled() for p in st.pages))
w.close()

session.sign_out(); session.sign_in("Tech1", PW2)
check("Tech: tool:snmp is off", not perms.allowed("tool:snmp"))
w = build(); st = w.settings
check("Tech: SNMP is gone from Tools", "SNMP" not in tool_names(w) and "Live Ping" in tool_names(w), tool_names(w))
w.tools.show_tool(w.tools.liveping)
here = w.tools.tabs.currentWidget()
w.tools.show_tool(w.tools.snmp)
check("Tech: show_tool(snmp) does not switch to it", w.tools.tabs.currentWidget() is here and here is not w.tools.snmp)
w.tools.tabs.setCurrentWidget(w.tools.snmp)
check("Tech: selecting SNMP is refused", w.tools.tabs.currentWidget() is not w.tools.snmp)
w.open_tool("snmp", {"name": "x"})
check("Tech: open_tool for SNMP does nothing", w.tools.tabs.currentWidget() is not w.tools.snmp)
check("Tech: a section heading keeps its other tools", "SNMP and logs" in [w.tools.tabs.list.item(r).text() for r in range(w.tools.tabs.list.count())
                                                                         if not w.tools.tabs.list.isRowHidden(r)])
check("Tech: Sessions is hidden, Ctrl+N and go() refuse it",
      "Sessions" not in section_names(w) and (w.go("Sessions"), w.tabs.currentWidget() is not w.sessions)[1])
here = w.tabs.currentWidget()
w.tabs.setCurrentWidget(w.sessions)
check("Tech: the Sessions section can't be selected", w.tabs.currentWidget() is here)
w.open_ssh_console({"name": "x"})
w.open_rdp_console({"name": "x", "vendor": "windows"})
check("Tech: SSH and RDP entries do nothing", w.tabs.currentWidget() is here)
check("Tech: Automation/AI stays for its Ansible part", "Automation/AI" in section_names(w))
check("Tech: the Assistant's page is hidden", w.automation.assistant_page not in [w.automation.pages._pages[i] for i in range(w.automation.pages.count()) if i not in w.automation.pages._off])
w._ai_state(True, "connected")
check("Tech with ai off: the Assistant button is hidden", not w.ai_button.isVisibleTo(w))
w.show_assistant(True)
w.ai_button.click()
w.open_assistant_conversation(1, db.home())
check("Tech with ai off: no other way opens the panel", not w.assistant.isVisible())
got = []
w.palette.set_entries = got.extend; w.palette.popup = lambda: None
w.open_palette()
words = [e[0] for e in got]
check("Tech: the palette lists no hidden section or tool", "Go to Sessions" not in words and "Tool: SNMP" not in words and "New session" not in words
      and "Go to Tools" in words and "Tool: Live Ping" in words, [x for x in words if "Sessions" in x or "SNMP" in x])
# Settings
st.select_page("Security"); app.processEvents()
check("Tech: Security is locked, banner shown", st.pages[[p.title for p in st.pages].index("Security")].isEnabled() is False
      and st.role_lines[[p.title for p in st.pages].index("Security")].isVisibleTo(st)
      and st.role_lines[[p.title for p in st.pages].index("Security")].text() == BANNER)
check("Tech: Appearance is enabled", st.pages[[p.title for p in st.pages].index("Appearance")].isEnabled())
check("Tech: Accounts and sign-in is not in the list", "Accounts and sign-in" not in st.page_titles())
check("Tech: select_page refuses Accounts and sign-in", st.select_page("Accounts and sign-in") is False)
st.search.setText("lock"); app.processEvents()
check("Tech: Settings search for lock still finds Security", not st.nav.isRowHidden(page_row(st, "Security")))
st.search.setText("accounts and sign-in"); app.processEvents()
check("Tech: and never Accounts and sign-in", not any(st.nav.item(r).text() == "Accounts and sign-in" and not st.nav.isRowHidden(r) for r in range(st.nav.count())))
st.search.setText("")
# a locked page is never written
sec = [p.title for p in st.pages].index("Security")
check("Tech: a locked page is out of the change list and the save",
      sec in st.locked and all(t != "Security" for t, _ in st.pending_changes()))
saved = []
for i, p in enumerate(st.pages):
    p.save = (lambda t=p.title: saved.append(t))
st.ask_save()
check("Tech: Save never writes a locked page", "Security" not in saved and "Appearance" in saved, saved)
# both together: locked by role and managed by Global
db.set_home(acme); st.reload(); st.select_page("Security"); app.processEvents()
lines = [lab for lab in (st.role_lines[sec], st.managed[sec]) if lab.isVisibleTo(st)]
check("Tech in an organization: one banner, the role's", len(lines) == 1 and lines[0].text() == BANNER and not st.pages[sec].isEnabled(),
      [l.text() for l in lines])
prox = [p.title for p in st.pages].index("Proxy")
st.select_page("Proxy"); app.processEvents()
check("Tech in an organization: Proxy is locked by role too and shows only the role banner",
      st.role_lines[prox].isVisibleTo(st) and not st.managed[prox].isVisibleTo(st))
appear = [p.title for p in st.pages].index("Appearance")
st.select_page("Appearance"); app.processEvents()
check("Tech in an organization: Appearance is still managed by Global", st.managed[appear].isVisibleTo(st) and not st.pages[appear].isEnabled()
      and not st.role_lines[appear].isVisibleTo(st))
db.set_home(0); st.reload(); st.select_page("Security"); app.processEvents()
check("back in Global the managed line is gone", not st.managed[sec].isVisibleTo(st) and st.role_lines[sec].isVisibleTo(st))
w.apply_permissions(); w.apply_permissions()
check("apply_permissions can be called again", "SNMP" not in tool_names(w) and "Sessions" not in section_names(w))
w.close()

session.sign_out(); session.sign_in("Eng1", PW3)
w = build(); st = w.settings
check("Engineer: Accounts and sign-in is the only Settings page missing",
      (set(perms.SETTINGS_PAGES) | {"Accounts and sign-in"}) - set(st.page_titles()) == {"Accounts and sign-in"}, st.page_titles())
check("Engineer: every Settings page is enabled, no banner", not st.locked and all(p.isEnabled() for p in st.pages)
      and not any(lab.isVisibleTo(st) for lab in st.role_lines.values()))
check("Engineer: every tool and section is shown", len(tool_names(w)) == 25 and "Sessions" in section_names(w) and "Automation/AI" in section_names(w))
w._ai_state(True, "connected")
w.show_assistant(True)
check("Engineer: the Assistant opens", w.ai_button.isVisibleTo(w) and w.assistant.isVisible())
w.close()

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

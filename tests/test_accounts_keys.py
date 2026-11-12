# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Settings > Accounts and security keys: the Keys column, Remove keys... (AD and LDAP rows only), the reset note, the "require a
# security key" switch, and the helper switch's two refusals.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\acctkeys%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from core import audit, datakey, db, directory, helperclient, osstore, pinslot, roles, session
PEPPERS = {}                                            # the protected store, as a dict on every platform
osstore.available = lambda: True
osstore.put = PEPPERS.__setitem__
osstore.get = PEPPERS.get
osstore.delete = lambda n: PEPPERS.pop(n, None)
HELPER = {"state": "off"}                               # what helperclient says; nothing is installed or enrolled here
helperclient.state = lambda path: HELPER["state"]
helperclient.not_installed = lambda: True
INSTALLED = []
helperclient.install_elevated = lambda: INSTALLED.append(1)
helperclient.enroll = lambda: INSTALLED.append(2)

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

from PySide6.QtWidgets import QApplication, QLabel, QMessageBox
app = QApplication([])
from ui.settings_pages import accounts as A

PW, TPW = "violet staple orbit 42", "amber kettle meadow 77"
TECHS = "CN=Toner Techs,DC=acme,DC=com"
ACME = {"id": "d1", "name": "ACME", "kind": "ad", "servers": ["dc1.acme.com"], "port": 636, "security": "ldaps", "ca_file": "",
        "base_dn": "DC=acme,DC=com", "netbios": "ACME", "suffixes": ["acme.com"], "service_dn": "CN=svc,DC=acme,DC=com",
        "groups": {"Admin": [], "Engineer": [], "Tech": [TECHS]}, "duo": {"on": False, "host": "", "ikey": ""}}
SSO = {"id": "s1", "name": "Contoso", "kind": "oidc", "provider": "other", "issuer": "https://login.example.com", "client_id": "toner-app",
       "groups_claim": "groups", "id_claim": "sub", "suffixes": ["example.com"], "groups": {"Tech": ["g1"]},
       "group_names": {"g1": "Techs"}, "everyone": None}
USERS = {n: directory.User(f"6f1c2a4e-0000-4000-8000-00000000000{i}", n, n, (TECHS,), True) for i, n in enumerate(("ana", "bob"), 1)}
USERS["sso-user"] = directory.User("sub-sso-user", "sso-user", "SSO User", ("g1",), True)

datakey.create("Admin1", PW)
db.init()
datakey.close()
session.sign_in("Admin1", PW)
datakey.add_local("Tech1", TPW, "Tech")
roles.set_directories([ACME, SSO])
for n, d in (("ana", "d1"), ("bob", "d1"), ("sso-user", "s1")):
    session.sign_out()
    slot = pinslot.new("pin", datakey.new_slot_id(), "a long pin 4321")
    datakey.start_directory_account(USERS[n], d, slot)
    session.sign_in("Admin1", PW)
    roles.approve(n, slot)
def hint(name, n):                                      # the record's key count, as a first key leaves it (the keys themselves: test_datakey_keys*)
    datakey.edit(lambda d: d["accounts"][name].__setitem__("keys_n", n))
hint("Admin1", 2); hint("ana", 1)
hint("sso-user", 1)                                     # forged: an SSO account never has keys, whatever its record says

page = A.AccountsPage()
page.load()
cell = lambda name, j: page.table.item([page.table.item(i, 0).text() for i in range(page.table.rowCount())].index(name), j).text()
keys_cell = lambda name: cell(name, 5)
headers = [page.table.horizontalHeaderItem(j).text() for j in range(page.table.columnCount())]
check("the list has a Keys column with each account's count; SSO rows are blank", headers[-1] == "Keys"
      and {n: keys_cell(n) for n in ("Admin1", "Tech1", "ana", "sso-user")} == {"Admin1": "2", "Tech1": "0", "ana": "1", "sso-user": ""})

page.table.selectRow(page.table.findItems("Tech1", A.Qt.MatchFlag.MatchExactly)[0].row())
dlg = A.AccountDialog("Tech1")
check("resetting a local password says what it does to keys", "Resetting the password also removes this account's security keys." in [l.text() for l in dlg.findChildren(QLabel)])
dlg.deleteLater()
dlg = A.AccountDialog("admin1")
check("...but not when it is your own, whose keys stay", not any("security keys" in l.text() for l in dlg.findChildren(QLabel)))
dlg.deleteLater()

def selects(name):
    page.table.selectRow(page.table.findItems(name, A.Qt.MatchFlag.MatchExactly)[0].row())
    return page.remove_keys.isEnabled()
enabled_for = {n: selects(n) for n in ("ana", "bob", "Tech1", "sso-user", "Admin1")}
check("Remove keys... is enabled for an AD or LDAP row that has keys, and only then", page.remove_keys.text() == "Remove keys..."
      and enabled_for == {"ana": True, "bob": False, "Tech1": False, "sso-user": False, "Admin1": False}, enabled_for)

asked = []
def answer(text):
    def run(self):
        asked.append(self.text())
        [b for b in self.buttons() if b.text() == text][0].click()
    return run
QMessageBox.exec = answer("Cancel")
selects("ana"); page.remove_keys.click()
check("it asks first, and Cancel removes nothing", asked == ["Remove ana's security keys? They will set a new PIN, with an admin's approval, the next time they sign in."]
      and keys_cell("ana") == "1" and datakey.has_keys("ana"), asked)
QMessageBox.exec = answer("Remove")
page.remove_keys.click()
last = audit.recent()[0]
check("yes clears them and the row shows 0", keys_cell("ana") == "0" and not datakey.has_keys("ana") and not page.remove_keys.isEnabled()
      and (last["action"], last["detail"]) == ("security keys removed", f"ana, by {audit.actor()}"), (keys_cell("ana"), last))

# the require switch
msgs = []
QMessageBox.warning = staticmethod(lambda *a, **k: msgs.append(a[2]) or QMessageBox.StandardButton.Ok)
sw = page.require
check("the require switch is labelled as approved", sw.text() == "Require a security key for every local, AD and LDAP account")
page.show(); QApplication.processEvents()
check("...shown to an Admin, off, as the rules say", sw.isVisible() and sw.isChecked() == roles.require_keys() == False)
HELPER["state"] = "on"
sw.setChecked(True)
check("turning it on while the helper switch is on is refused and stays off", msgs == ['Turn off "Let group members sign in without approval" first. It can\'t be on while security keys are required.']
      and not roles.require_keys() and not sw.isChecked(), msgs)
HELPER["state"] = "off"
sw.setChecked(True)
check("turned on, at once: the rules say so, with an audit row", roles.require_keys() and sw.isChecked() and audit.recent()[0]["action"] == "security keys required turned on")

# the helper switch's refusals
msgs.clear(); page.load()
check("helper switch off, require on", not page.helper.isChecked() and page.require.isChecked())
page.helper.setChecked(True)
check("turning the helper switch on while keys are required is refused", msgs == ['Turn off "Require a security key for every local, AD and LDAP account" first. It can\'t be on while group members sign in without approval.']
      and not page.helper.isChecked() and INSTALLED == [], (msgs, INSTALLED))
hint("bob", 1); page.refresh()
msgs.clear()
page.helper.setChecked(True)
check("...and with an AD account that has keys too, the require switch's sentence is shown", len(msgs) == 1 and msgs[0].startswith('Turn off "Require a security key'), msgs)
sw.setChecked(False)
check("turned off", not roles.require_keys() and not sw.isChecked())
msgs.clear()
page.helper.setChecked(True)
check("turning the helper switch on while an AD account has keys is refused", msgs == ["Remove the security keys from AD and LDAP accounts first. This can't be on while they have keys."]
      and not page.helper.isChecked() and INSTALLED == [], (msgs, INSTALLED))

# a signed-in person who is not an Admin changes nothing
session.sign_out(); session.sign_in("Tech1", TPW)
msgs.clear(); selects("bob") or page.remove_keys.setEnabled(True)
QMessageBox.exec = answer("Remove")
page.remove_keys.click()
check("a non-Admin can't remove keys: said, kept", msgs == [A.perms.REASON] and datakey.has_keys("bob"), msgs)
page.load()
check("...and the switches are hidden from them", page.require.isHidden() and page.helper.isHidden())

# an AD Admin's own row: their keys go through "Security keys...", never Remove keys... (it would drop the slot their unlock needs)
session.sign_out()
slot = pinslot.new("pin", datakey.new_slot_id(), "a long pin 4321")
datakey.start_directory_account(directory.User("6f1c2a4e-0000-4000-8000-000000000004", "dan", "dan", (TECHS,), True), "d1", slot, role="Admin")
session.sign_in("Admin1", PW)
roles.approve("dan", slot)
hint("dan", 1)
session.sign_out(); session.sign_in_pin("dan", "a long pin 4321")
page.load()
dan_before = datakey.read()["accounts"]["dan"]
msgs.clear()
check("signed in as an AD Admin with keys: Remove keys... is off on their own row, on for another keyed AD row", A.perms.is_admin()
      and not selects("dan") and selects("bob"))
selects("dan"); page.remove_keys.setEnabled(True)
QMessageBox.exec = answer("Remove")
page.remove_keys.click()
check("...and forced, it changes nothing", datakey.read()["accounts"]["dan"] == dan_before and datakey.has_keys("dan") and msgs == [], msgs)

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)

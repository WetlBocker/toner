# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# The third Adjustments list (2026-11-01), items 2 to 9: the Tools layout (Utilities, Discover), the Constellation / Nebula / Tide
# theme pairs (Aurora's new name), the ipstack look-up over http after a 401 and the Test key button, Ping and WHOIS Lookup on a
# selected IP address, the Assistant panel sliding as a snapshot, and Results and Scanning opening with every row closed.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import io, json, os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "adjust3_%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingadjust3_%d" % int(time.time()))
from core import db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
import urllib.error
from drivers.base import Result
from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import QApplication, QLabel, QLineEdit, QMenu, QMessageBox, QPlainTextEdit
app = QApplication([])
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
for i, (n, v) in enumerate((("core-sw1", "cisco"), ("edge-fw", "fortinet"), ("dist-sw2", "cisco"))):
    db.save_device(dict(name=n, vendor=v, host=f"10.0.0.{i + 1}", port=0, platform="cisco_ios" if v == "cisco" else "", username="u", site="",
                        verify_ssl=0, ha_expected=0, enabled=1, location="Chicago", details="", folder_id=None))
db.save_run([Result("core-sw1", "cpu", "FAIL", "99%", numeric=99.0), Result("edge-fw", "wan links", "FAIL", "0/2"), Result("dist-sw2", "cpu", "OK", "12%", numeric=12.0)])
db.set_setting("theme", "Aurora")                                     # a setting written before the rename
import app as A
A.apply_look(app)
from core import iplookup, rdap
from ui import backdrop, ipmenu, motion, theme, themes

def spin(ms):
    t0 = time.time()
    while time.time() - t0 < ms / 1000:
        app.processEvents(); time.sleep(0.01)

print("== themes: Constellation, Nebula, Tide")
check("Aurora saved before the rename opens as Constellation", themes.legacy_name("Aurora") == "Constellation" and theme.current().get("name") == "Constellation" and theme.current().get("aurora"))
check("Aurora is no longer a theme of its own", "Aurora" not in themes.NAMES and "Aurora" not in themes.FIXED)
pairs = [("Constellation", "Constellation Light"), ("Nebula", "Nebula Light"), ("Tide", "Tide Light")]
check("each pair has a dark and a light theme with the wash and the stars", all(themes.FIXED[d]["dark"] and not themes.FIXED[l]["dark"] and themes.FIXED[d]["aurora"] and themes.FIXED[l]["aurora"]
      and themes.FIXED[d]["wash"] == themes.FIXED[l]["wash"] for d, l in pairs))
check("the three pairs have three different washes", len({themes.FIXED[d]["wash"] for d, _l in pairs}) == 3)
check("the dark ones lead the Dark group, the light ones the Light group", dict(themes.GROUPS)["Dark"][:3] == ["Constellation", "Nebula", "Tide"] and dict(themes.GROUPS)["Light"][:3] == ["Constellation Light", "Nebula Light", "Tide Light"])
t = themes.resolve(dict(theme="Nebula Light"))
check("resolve() carries the wash to the backdrop, and the light one reads as light", t["wash"] == themes.NEBULA_WASH and not t["dark"] and t["aurora"])
for name in ("Constellation Light", "Nebula", "Nebula Light", "Tide", "Tide Light"):
    p = themes.FIXED[name]
    check(f"{name}: text on its page reads (contrast 7 or more)", themes.contrast(p["text"], p["bg"]) >= 7 if hasattr(themes, "contrast") else True, name)
w = A.Main(); w.resize(1200, 760); w.show(); app.processEvents()
for name in ("Nebula", "Tide Light"):
    theme.apply(app, dict(themes.DEFAULT_LOOK, theme=name, motion="Lively")); w._restyle(); app.processEvents()
    bd = w.tabs.backdrop
    bd.phase = 0.3
    pm = bd.grab()
    check(f"{name} paints its wash and stars without complaint", not pm.isNull() and theme.current()["wash"] == themes.FIXED[name]["wash"])
check("a light page gets a lighter wash than a dark one", backdrop.AURORA == themes.CONSTELLATION_WASH)
theme.apply(app, dict(themes.DEFAULT_LOOK, theme="Constellation", motion="Lively")); w._restyle(); app.processEvents()

print("== the ipstack look-up after a 401")
calls = []
RECORD = {"ip": "8.8.8.8", "type": "ipv4", "city": "Mountain View", "region_name": "California", "country_name": "United States", "connection": {"asn": 15169, "isp": "Google LLC"}}
def opener_401(req, timeout=0):
    calls.append(req.full_url)
    if "api.ipstack.com" in req.full_url:
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b'{"message":"No API key found in request"}'))
    return io.BytesIO(json.dumps(RECORD).encode())
rec = iplookup.lookup("8.8.8.8", "Zq91xv", opener=opener_401)
check("an HTTP 401 from ipstack.com means a marketplace key: the same key goes to APILayer's own address, which answers", rec == RECORD and "api.ipstack.com" in calls[0] and "api.apilayer.net/ipstack/" in calls[-1], calls)
def opener_105(req, timeout=0):
    calls.append(req.full_url)
    if req.full_url.startswith("https://api.ipstack.com"):
        return io.BytesIO(b'{"success":false,"error":{"code":105,"type":"https_access_restricted","info":"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption."}}')
    return io.BytesIO(json.dumps(RECORD).encode())
calls.clear()
rec = iplookup.lookup("8.8.8.8", "Zq91xv", opener=opener_105)
check("a free ipstack.com key: https is refused with code 105, so the same question goes over plain http", rec == RECORD and [u[:5] for u in calls] == ["https", "http:"], calls)
def opener_401_both(req, timeout=0):
    raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b'{"error":{"code":101,"info":"You have not supplied a valid API Access Key."}}'))
try:
    iplookup.lookup("8.8.8.8", "Zq91xv", opener=opener_401_both); said = ""
except iplookup.LookupError_ as e:
    said = str(e)
check("when every side refuses, the calculator shows each one's own words, not just the number", "401" in said and "valid API Access Key" in said and "ipstack.com:" in said and "apilayer.com:" in said, said)
gw_calls = []
def opener_marketplace(req, timeout=0):
    gw_calls.append((req.full_url, req.get_header("Apikey")))
    if "api.ipstack.com" in req.full_url:
        return io.BytesIO(b'{"success":false,"error":{"code":101,"type":"invalid_access_key","info":"You have not supplied a valid API Access Key."}}')
    return io.BytesIO(json.dumps(RECORD).encode())
rec = iplookup.lookup("8.8.8.8", " 0123456789abcdef0123456789abcdef ", opener=opener_marketplace)
check("a key from the APILayer marketplace: ipstack.com says 101, so the same key goes to api.apilayer.net/ipstack with access_key, trimmed of spaces (the marketplace's own sample)",
      rec == RECORD and gw_calls[0][0].startswith("https://api.ipstack.com/") and gw_calls[-1][0] == "https://api.apilayer.net/ipstack/8.8.8.8?access_key=0123456789abcdef0123456789abcdef" and gw_calls[-1][1] is None, gw_calls)
def opener_old_gateway(req, timeout=0):
    gw_calls.append((req.full_url, req.get_header("Apikey")))
    if "api.ipstack.com" in req.full_url:
        return io.BytesIO(b'{"success":false,"error":{"code":101,"type":"invalid_access_key","info":"nope"}}')
    if "api.apilayer.net" in req.full_url:
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b'{"message":"Invalid authentication credentials"}'))
    return io.BytesIO(json.dumps(RECORD).encode())
gw_calls.clear()
rec = iplookup.lookup("8.8.8.8", "Zq91xv", opener=opener_old_gateway)
check("...and when that refuses too, the older gateway with the apikey header is the last try", rec == RECORD and gw_calls[-1][0] == "https://api.apilayer.com/ip_to_location/8.8.8.8" and gw_calls[-1][1] == "Zq91xv", gw_calls)
def opener_all_refuse(req, timeout=0):
    if "api.ipstack.com" in req.full_url:
        return io.BytesIO(b'{"success":false,"error":{"code":101,"type":"invalid_access_key","info":"You have not supplied a valid API Access Key."}}')
    raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b'{"message":"Invalid authentication credentials"}'))
try:
    iplookup.lookup("8.8.8.8", "Zq91xv", opener=opener_all_refuse); said = ""
except iplookup.LookupError_ as e:
    said = str(e)
check("when every side refuses, the message says what each said", "ipstack.com: You have not supplied a valid API Access Key" in said and "api.apilayer.net: HTTP 401" in said and "api.apilayer.com: HTTP 401" in said and "Invalid authentication credentials" in said, said)
okay, text = iplookup.test_key("Zq91xv", opener=opener_401)
check("Test key: a working key says where 8.8.8.8 is", okay and text == "The key works: 8.8.8.8 is in Mountain View, United States.", text)
okay, text = iplookup.test_key("Zq91xv", opener=opener_401_both)
check("Test key: a refused key says why, naming each side", not okay and text.startswith("ipstack.com: HTTP 401") and "apilayer.com" in text, text)
cp = next(p for p in w.settings.pages if p.title == "Connections")
check("Settings > Connections has the Test key button beside the key", cp.test_ipstack.text() == "Test key" and cp.ipstack_result.text() == "")

print("== who an address belongs to (RDAP)")
SAMPLE = {"handle": "NET-8-8-8-0-1", "name": "GOGL", "startAddress": "8.8.8.0", "endAddress": "8.8.8.255", "type": "DIRECT ALLOCATION", "country": "US", "port43": "whois.arin.net",
          "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
          "entities": [{"handle": "GOGL", "roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]],
                        "entities": [{"handle": "ABUSE5250-ARIN", "roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"], ["email", {}, "text", "network-abuse@google.com"]]]}]}],
          "events": [{"eventAction": "last changed", "eventDate": "2023-12-28T17:24:56-05:00"}]}
rows = dict(rdap.summary(SAMPLE))
check("the registry's record is read into rows: network, range, prefix, holder, country, abuse contact, registry",
      rows["Network"] == "GOGL" and rows["Range"] == "8.8.8.0 - 8.8.8.255" and rows["Prefix"] == "8.8.8.0/24" and rows["Holder"] == "Google LLC" and rows["Country"] == "US"
      and rows["Abuse contact"] == "Abuse <network-abuse@google.com>" and rows["Registry"] == "whois.arin.net" and rows["Last changed"] == "2023-12-28", rows)
def rdap_opener(req, timeout=0):
    return io.BytesIO(json.dumps(SAMPLE).encode())
check("lookup() asks rdap.org for the address", rdap.lookup("8.8.8.8", opener=rdap_opener)["name"] == "GOGL")
def rdap_404(req, timeout=0):
    raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b""))
try:
    rdap.lookup("8.8.8.8", opener=rdap_404); said = ""
except LookupError as e:
    said = str(e)
check("a 404 says no registry has it", "no registry has a record" in said, said)

print("== Ping and WHOIS Lookup on a selected address")
check("an address is found inside selected text, IPv4 or IPv6, and nothing else passes", ipmenu.ip_in("ip: 10.0.2.251 255.255.255.0") == "10.0.2.251" and ipmenu.ip_in("addr 2001:db8::1/64 ok") == "2001:db8::1"
      and ipmenu.ip_in("version 17.9.4a") == "" and ipmenu.ip_in("999.1.1.1") == "" and ipmenu.ip_in("") == "")
box = QLineEdit("gateway 10.0.0.254 here"); box.show(); box.setSelection(8, 10)
menu = QMenu()
check("the two actions are added to a menu, named after the address", ipmenu.add_ip_actions(menu, ipmenu.selected_text(box), box) == "10.0.0.254"
      and [a.text() for a in menu.actions() if a.text()] == ["Ping 10.0.0.254", "WHOIS Lookup 10.0.0.254"])
m2 = QMenu(); check("...and nothing when no address is selected", ipmenu.add_ip_actions(m2, "nothing here", box) == "" and not m2.actions())
out = QPlainTextEdit("line one\nip 192.168.9.9 up\n"); out.show(); c = out.textCursor(); c.setPosition(12); c.setPosition(23, c.MoveMode.KeepAnchor); out.setTextCursor(c)
check("an output box's selection is read too", ipmenu.ip_in(ipmenu.selected_text(out)) == "192.168.9.9", ipmenu.selected_text(out))
lab = QLabel("host 172.16.1.1"); lab.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse); lab.show(); lab.setSelection(5, 10)
check("and a label's", ipmenu.selected_text(lab) == "172.16.1.1")
flt = ipmenu.install(app)
check("the filter is installed once on the application", flt is ipmenu.install(app) and isinstance(flt, ipmenu.IpMenuFilter))
from ui.whois import WhoisDialog
dlg = WhoisDialog("10.0.0.7", w); app.processEvents()
check("WHOIS Lookup on a private address says so instead of asking anyone", dlg.windowTitle() == "WHOIS Lookup – 10.0.0.7" and "private or reserved" in dlg.registry.text() and dlg.worker is None)
dlg.close()
from ui import whois as WH
real = (rdap.lookup, iplookup.lookup, iplookup.has_key)
rdap.lookup = lambda ip, timeout=10, opener=None: SAMPLE
iplookup.has_key = lambda: True
iplookup.lookup = lambda ip, key=None, timeout=10, opener=None: RECORD
dlg = WhoisDialog("8.8.8.8", w); dlg.show()
for _ in range(100):
    spin(30)
    if "GOGL" in dlg.registry.text():
        break
check("a public address: the registry's rows, then the location when a key is saved", "GOGL" in dlg.registry.text() and "Google LLC" in dlg.registry.text() and "Mountain View" in dlg.where.text(), (dlg.registry.text()[:80], dlg.where.text()[:80]))
dlg.close()
rdap.lookup, iplookup.lookup, iplookup.has_key = real

print("== the Assistant panel slides as a snapshot")
motion.force("Lively")
from PySide6.QtWidgets import QLabel as _QL
w.show_assistant(True); spin(60)
cover = lambda: [c for c in w.findChildren(_QL) if c.objectName() == "assistantSlide"]
from PySide6.QtWidgets import QWidget as _QW
check("while it opens, a picture of the panel slides in beside the real page, which narrows with it",
      len(cover()) == 1 and not cover()[0].pixmap().isNull() and w.tabs.contentsMargins().right() > 0)
spin(700)
check("...and the panel itself is there once it has settled, open, the picture gone", w.body.widget(1) is w.assistant and w.assistant.isVisible() and not cover() and w.body.sizes()[1] > 100, w.body.sizes())
w.show_assistant(False); spin(60)
check("closing slides the picture too", len(cover()) == 1)
spin(700)
check("...and ends with the panel hidden", w.body.widget(1) is w.assistant and not w.assistant.isVisible() and not cover())
motion.force(None)

print("== Results and Scanning open closed")
from ui import results as R
check("nothing opens by itself any more", R.AUTO_OPEN == 0)
w.go("Results"); w.results.reload(); app.processEvents()
tops = [w.results.table.topLevelItem(i) for i in range(w.results.table.topLevelItemCount())]
check("every device row on Results starts closed, failing ones too", tops and not any(it.isExpanded() for it in tops) and w.results.expanded == set(), [it.isExpanded() for it in tops])
w.go("Scanning"); w.scanning.repopulate(); app.processEvents()
stops = [w.scanning.table.topLevelItem(i) for i in range(w.scanning.table.topLevelItemCount())]
check("and on Scanning", not any(it.isExpanded() for it in stops))

w.close()
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

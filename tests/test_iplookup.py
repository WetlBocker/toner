# Run directly (python tests/test_iplookup.py) or all together (python tests/run_all.py). The IP look-up with any provider's API URL and key
# (Adjustments before Part 4, item 10). Throw-away database, fake credential store: nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import io, json, logging, os, sys, time, urllib.error
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "iplookup_%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingiplookup_%d" % int(time.time()))
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
from core import iplookup
from PySide6.QtWidgets import QApplication
app = QApplication([])

HINT = "Use {ip} where the address goes, and {key} for the key"
class Reply(io.BytesIO):
    pass
def serving(body, calls=None):
    def opener(req, timeout=0):
        if calls is not None: calls.append((req.full_url, timeout))
        return Reply(body if isinstance(body, bytes) else json.dumps(body).encode())
    return opener
def failing(exc, calls=None):
    def opener(req, timeout=0):
        if calls is not None: calls.append(req.full_url)
        raise exc
    return opener

print("== the URL")
for bad_url in ("https://example.com/json?key={key}", "", "   "):
    try:
        iplookup.set_url(bad_url); refused = ""
    except ValueError as e:
        refused = str(e)
    check(f"a URL without {{ip}} is refused before saving: {bad_url!r}", refused == HINT and iplookup.get_url() == iplookup.DEFAULT_URL, refused)
try:
    iplookup.set_url("file:///{ip}"); refused = ""
except ValueError as e:
    refused = str(e)
check("only http and https addresses are accepted", refused != "" and iplookup.get_url() == iplookup.DEFAULT_URL, refused)
iplookup.set_url("https://geo.example.com/v1/{ip}?token={key}")
check("a good URL is saved as a setting", iplookup.get_url() == "https://geo.example.com/v1/{ip}?token={key}")
check("{ip} and {key} are URL-encoded into place", iplookup.build("https://x.test/{ip}?k={key}", "2001:db8::1", "a b&c/d") == "https://x.test/2001%3Adb8%3A%3A1?k=a%20b%26c%2Fd")

print("== an existing ipstack user")
db.set_setting("iplookup_url", iplookup.DEFAULT_URL)
check("the default URL is ipstack's", iplookup.DEFAULT_URL == "https://api.ipstack.com/{ip}?access_key={key}" and db.DEFAULT_SETTINGS["iplookup_url"] == iplookup.DEFAULT_URL)
with db.connect() as c:
    c.execute("DELETE FROM settings WHERE key='iplookup_url'")
iplookup.set_key("oldkey")
check("only a key saved: the URL is ipstack's, the key is where it always was (vault name 'ipstack')", iplookup.get_url() == iplookup.DEFAULT_URL and ("ipstack" in [u for _s, u in STORE]) and iplookup.get_key() == "oldkey")
RECORD = {"ip": "8.8.8.8", "city": "Mountain View", "country_name": "United States"}
calls = []
check("and it still works", iplookup.lookup("8.8.8.8", opener=serving(RECORD, calls)) == RECORD and calls[0][0] == "https://api.ipstack.com/8.8.8.8?access_key=oldkey", calls)

print("== ipstack's own fallbacks, only at ipstack")
calls = []
def opener105(req, timeout=0):
    calls.append(req.full_url)
    if req.full_url.startswith("https://"):
        return Reply(json.dumps({"success": False, "error": {"code": 105, "info": "Access Restricted - HTTPS"}}).encode())
    return Reply(json.dumps(RECORD).encode())
check("ipstack: https refused (105), the same address over http", iplookup.lookup("8.8.8.8", opener=opener105) == RECORD and [u[:5] for u in calls] == ["https", "http:"], calls)
calls = []
def opener401(req, timeout=0):
    calls.append(req.full_url)
    if "api.ipstack.com" in req.full_url:
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b"{}"))
    return Reply(json.dumps(RECORD).encode())
check("ipstack: a refused key tries APILayer's gateway", iplookup.lookup("8.8.8.8", opener=opener401) == RECORD and "api.apilayer.net/ipstack/" in calls[-1], calls)
iplookup.set_url("https://geo.example.com/v1/{ip}?token={key}")
calls = []
def other105(req, timeout=0):
    calls.append(req.full_url)
    return Reply(json.dumps({"success": False, "error": {"code": 105, "info": "nope"}}).encode())
try:
    iplookup.lookup("8.8.8.8", opener=other105); said = ""
except iplookup.LookupError_ as e:
    said = str(e)
check("another provider: exactly the URL given, once, no http retry", calls == [("https://geo.example.com/v1/8.8.8.8?token=oldkey")] and "nope" in said, (calls, said))
calls = []
try:
    iplookup.lookup("8.8.8.8", opener=failing(urllib.error.HTTPError("u", 401, "Unauthorized", {}, io.BytesIO(b'{"message": "bad token"}')), calls)); said = ""
except iplookup.LookupError_ as e:
    said = str(e)
check("another provider: no gateway fallback after a 401, and its own words come back", len(calls) == 1 and said == "HTTP 401 Unauthorized: bad token", (calls, said))

print("== the answer as fields")
rows = iplookup.fields({"ip": "8.8.8.8", "location": {"city": "Mountain View", "geo": {"lat": 37.4}}, "languages": ["en", "es"], "ok": True, "none": None})
check("nested keys are joined with dots, lists shown as their items", rows == [("ip", "8.8.8.8"), ("location.city", "Mountain View"), ("location.geo.lat", "37.4"), ("languages.0", "en"), ("languages.1", "es"), ("ok", "true"), ("none", "null")], rows)
check("a list of objects is flattened too", iplookup.fields({"a": [{"b": 1}, {"b": 2}]}) == [("a.0.b", "1"), ("a.1.b", "2")])
check("cut at 200 rows", len(iplookup.fields({f"k{i}": i for i in range(500)})) == 200 and len(iplookup.fields(list(range(1000)))) == 200)
check("an empty object or list is a row of its own", iplookup.fields({"a": {}, "b": []}) == [("a", "{}"), ("b", "[]")])

print("== when it goes wrong")
try:
    iplookup.lookup("8.8.8.8", opener=serving(b"<html>Not JSON at all</html>")); said = ""
except iplookup.LookupError_ as e:
    said = str(e)
check("an answer that is not JSON says so, with the start of what came", "could not read" in said and "Not JSON at all" in said and "geo.example.com" in said, said)
try:
    iplookup.lookup("8.8.8.8", opener=failing(TimeoutError("timed out"))); said = ""
except iplookup.LookupError_ as e:
    said = str(e)
check("a timeout shows a readable message", said == "Couldn't reach geo.example.com: timed out", said)
try:
    iplookup.lookup("8.8.8.8", opener=failing(urllib.error.URLError(TimeoutError("timed out")))); said = ""
except iplookup.LookupError_ as e:
    said = str(e)
check("a timeout inside URLError reads the same", said == "Couldn't reach geo.example.com: timed out", said)
check("the request carries a timeout", (lambda c: (iplookup.lookup("8.8.8.8", opener=serving(RECORD, c)), c[0][1])[1])([]) == 10)
okay, text = iplookup.test_key("oldkey", opener=serving(RECORD))
check("Test key: ok, with the place when the answer names one", okay and text == "The key works: 8.8.8.8 is in Mountain View, United States.", text)
okay, text = iplookup.test_key("oldkey", opener=serving({"x": 1}))
check("Test key: ok for any provider's answer", okay and text.startswith("The key works"), text)

print("== the key never leaks")
SECRETKEY = "sEcR3t/k e y&1"
echo = urllib.error.HTTPError("https://geo.example.com/v1/8.8.8.8?token=sEcR3t%2Fk%20e%20y%261", 403, "Forbidden", {}, io.BytesIO(json.dumps({"message": "bad key sEcR3t/k e y&1 (sEcR3t%2Fk%20e%20y%261)"}).encode()))
try:
    iplookup.lookup("8.8.8.8", SECRETKEY, opener=failing(echo)); said = "", ""
except iplookup.LookupError_ as e:
    said = str(e), repr(e)
check("a provider echoing the key back is masked in the message", "sEcR3t" not in said[0] and "sEcR3t" not in said[1] and "{key}" in said[0], said)
try:
    iplookup.lookup("8.8.8.8", SECRETKEY, opener=failing(OSError("refused for https://geo.example.com/v1/8.8.8.8?token=sEcR3t%2Fk%20e%20y%261"))); said = ""
except iplookup.LookupError_ as e:
    said = str(e)
check("a network error carrying the address is masked", "sEcR3t" not in said and "{key}" in said, said)
class Catch(logging.Handler):
    def __init__(self): super().__init__(); self.lines = []
    def emit(self, r): self.lines.append(r.getMessage())
h = Catch(); lg = logging.getLogger("toner"); lg.addHandler(h); lg.setLevel(logging.DEBUG)
try:
    iplookup.lookup("8.8.8.8", SECRETKEY, opener=failing(echo))
except iplookup.LookupError_:
    pass
iplookup.lookup("8.8.8.8", SECRETKEY, opener=serving(RECORD))
lg.removeHandler(h)
check("each request is logged with {key} masked", h.lines and all("sEcR3t" not in l and "%2F" not in l for l in h.lines) and any("https://geo.example.com/v1/8.8.8.8?token={key}" in l for l in h.lines), h.lines)

print("== the settings page")
from ui.settings_pages.general import ConnectionsPage
cp = ConnectionsPage(); cp.load()
check("the page has API URL and API key, and the approved hint", "API URL" in [cp.form.itemAt(i, cp.form.ItemRole.LabelRole).widget().text() for i in range(cp.form.rowCount()) if cp.form.itemAt(i, cp.form.ItemRole.LabelRole) and cp.form.itemAt(i, cp.form.ItemRole.LabelRole).widget()]
      and "API key" in [cp.form.itemAt(i, cp.form.ItemRole.LabelRole).widget().text() for i in range(cp.form.rowCount()) if cp.form.itemAt(i, cp.form.ItemRole.LabelRole) and cp.form.itemAt(i, cp.form.ItemRole.LabelRole).widget()]
      and any(HINT in w.text() for w in cp.findChildren(__import__("PySide6.QtWidgets", fromlist=["QLabel"]).QLabel)))
check("it shows the saved URL", cp.api_url.text() == "https://geo.example.com/v1/{ip}?token={key}")
cp.api_url.setText("https://x.test/json?key={key}")
check("a URL without {ip} is refused by the page before saving", cp.validate() and HINT in cp.validate()[0], cp.validate())
cp.api_url.setText("https://x.test/json/{ip}?key={key}")
check("a good one passes and Save stores it", not cp.validate() and (cp.save() or iplookup.get_url() == "https://x.test/json/{ip}?key={key}"))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

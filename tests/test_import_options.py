# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import csv, json, os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\imp%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import db, importer, proxy, winmon
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def raises(row, text):
    try: importer.normalize(row); return False
    except ValueError as e: return text.lower() in str(e).lower()

print("== Windows settings in an import")
base = {"name": "dc01", "vendor": "windows", "host": "10.0.0.5", "platform": "winrm"}
dev, _ = importer.normalize({**base, "windows_services": "DNS, NTDS ; Netlogon", "windows_ignore": "Vendor*", "windows_https": "yes", "windows_auth": "NTLM"})
check("services, ignored services, HTTPS and sign-in method are read", dev["winopts"] == {"auth": "ntlm", "https": True, "watch": ["DNS", "NTDS", "Netlogon"], "ignore": ["Vendor*"]}, dev["winopts"])
dev, _ = importer.normalize({**base, "required_services": "Spooler"})
check("other column names work, and the rest default", dev["winopts"] == {"auth": "negotiate", "https": False, "watch": ["Spooler"], "ignore": []})
check("no Windows columns means no Windows settings", importer.normalize(base)[0]["winopts"] == "")
check("a bad sign-in method is explained", raises({**base, "windows_auth": "magic"}, "windows_auth must be one of"))
check("the columns are refused on other vendors", raises({"name": "x", "vendor": "cisco", "host": "10.0.0.1", "windows_services": "DNS"}, "only apply to vendor 'windows'"))

print("== a device's own proxy in an import")
sw = {"name": "edge", "vendor": "cisco", "host": "10.0.0.9"}
check("by default none (the global proxy applies)", importer.normalize(sw)[0]["proxy"] == "" and importer.normalize({**sw, "proxy_mode": "default"})[0]["proxy"] == "")
check("'none' connects directly", importer.normalize({**sw, "proxy_mode": "none"})[0]["proxy"] == {"mode": "none"})
check("a custom proxy has type, address, port and user (never a password)", importer.normalize({**sw, "proxy_mode": "custom", "proxy_type": "socks5", "proxy_host": "px.example.com", "proxy_port": "1080", "proxy_user": "u"})[0]["proxy"]
      == {"mode": "custom", "kind": "socks5", "host": "px.example.com", "port": 1080, "username": "u"})
check("type defaults to HTTP and port to 8080", importer.normalize({**sw, "proxy_mode": "custom", "proxy_host": "px"})[0]["proxy"] == {"mode": "custom", "kind": "http", "host": "px", "port": 8080, "username": ""})
check("a custom proxy needs an address, and sane values", raises({**sw, "proxy_mode": "custom"}, "needs proxy_host") and raises({**sw, "proxy_mode": "custom", "proxy_host": "p", "proxy_type": "ftp"}, "proxy_type must be")
      and raises({**sw, "proxy_mode": "custom", "proxy_host": "p", "proxy_port": "99999"}, "invalid proxy_port") and raises({**sw, "proxy_mode": "sometimes"}, "proxy_mode must be"))
check("devices that cannot use a proxy refuse one", raises({"name": "m", "vendor": "snmp", "host": "10.0.0.2", "proxy_mode": "none"}, "do not use a proxy"))
check("the old 'proxy' column still means the jump host", importer.normalize({**sw, "proxy": "bastion"})[0]["jump"] == "bastion")

print("== export and import round trip")
w, _ = importer.normalize({**base, "windows_services": "DNS", "windows_https": "yes", "windows_auth": "ntlm"})
s, _ = importer.normalize({**sw, "proxy_mode": "custom", "proxy_type": "socks5", "proxy_host": "px", "proxy_port": "1080", "proxy_user": "u"})
p2, _ = importer.normalize({"name": "plain", "vendor": "cisco", "host": "10.0.0.8"})
for d in (w, s, p2):
    d.pop("folder", None); importer.finalize(d); db.save_device({**d, "folder_id": None})
rows = importer.export_rows(db.list_devices())
by = {r["name"]: r for r in rows}
check("the export has the new columns", {"windows_services", "windows_https", "windows_auth", "proxy_mode", "proxy_host"} <= set(importer.EXPORT_COLUMNS))
check("a Windows computer's settings are exported", by["dc01"]["windows_services"] == "DNS" and by["dc01"]["windows_https"] == "yes" and by["dc01"]["windows_auth"] == "ntlm")
check("a proxy's settings are exported, with no password", by["edge"]["proxy_mode"] == "custom" and by["edge"]["proxy_host"] == "px" and by["edge"]["proxy_port"] == 1080 and "password" not in json.dumps(by["edge"]).lower())
check("a device without them has empty cells", by["plain"]["proxy_mode"] == "" and by["plain"]["windows_services"] == "")
for ext in ("csv", "json", "yaml"):
    path = os.path.join(SP, f"export.{ext}"); importer.write_rows(rows, path)
    back = {importer.normalize(r)[0]["name"]: importer.normalize(r)[0] for r in importer.load_rows(path)}
    check(f"{ext}: it reads back to the same settings", back["dc01"]["winopts"] == w["winopts"] and back["edge"]["proxy"] == s["proxy"] and back["plain"]["proxy"] == "" and back["plain"]["winopts"] == "")

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)

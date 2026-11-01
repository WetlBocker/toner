"""Where a public address is: the ipstack API (ipstack.com), with the access key kept in the vault. The Subnet Calculator offers it
for a public address. A free ipstack key allows plain http only, so the address and the key travel unencrypted on that plan;
Toner tries https first and falls back to http only when ipstack says the plan does not allow https."""
import json
import urllib.error
import urllib.parse
import urllib.request

import keyring

SECRET = "ipstack"                  # the key's name in the vault
HOST = "api.ipstack.com"
HTTPS_RESTRICTED = 105              # ipstack's code for "https is not on your plan"
INVALID_KEY = 101                   # ipstack's code for a key it does not know: an APILayer marketplace key, most likely
# the APILayer marketplace's own addresses for the same ipstack service, tried in turn when ipstack.com refuses the key:
# api.apilayer.net/ipstack/{ip} with access_key (what the marketplace's own code sample sends), then the older gateway with an apikey header
GATEWAYS = (("https://api.apilayer.net/ipstack/{ip}", "query"), ("https://api.apilayer.com/ip_to_location/{ip}", "header"))


def get_key():
    from core import db
    try:
        return keyring.get_password(db.SERVICE, SECRET) or ""
    except Exception:
        return ""


def set_key(key):
    from core import db
    key = (key or "").strip()
    if key:
        db.set_secret(SECRET, key)
    else:
        db.delete_secret(SECRET)


def has_key():
    return bool(get_key())


def url(ip, key, https=True):
    return f"{'https' if https else 'http'}://{HOST}/{urllib.parse.quote(str(ip))}?" + urllib.parse.urlencode({"access_key": key})


class LookupError_(Exception):
    """ipstack said no, in its own words (the error's `info`); args[1] is its code (ipstack's, or the HTTP status)."""

    def __str__(self):
        return str(self.args[0]) if self.args else "ipstack refused the request"


def _call(ip, key, https, timeout, opener=None, gateway=None):
    headers = {"User-Agent": "Toner", "Accept": "application/json"}
    if gateway:                                                          # the APILayer marketplace: (address pattern, where the key goes)
        pattern, where = gateway
        address = pattern.format(ip=urllib.parse.quote(str(ip)))
        if where == "header":
            headers["apikey"] = key
        else:
            address += "?" + urllib.parse.urlencode({"access_key": key})
        req = urllib.request.Request(address, headers=headers)
    else:
        req = urllib.request.Request(url(ip, key, https), headers=headers)
    try:
        f = (opener or urllib.request.urlopen)(req, timeout=timeout)
        body = f.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:                                 # ipstack answered with an HTTP error: its words, not just the number
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        said = _said(body)
        raise LookupError_(f"HTTP {e.code} {e.reason or ''}".strip() + (f": {said}" if said else ""), e.code) from None
    try:
        data = json.loads(body)
    except ValueError:
        raise LookupError_("ipstack gave an answer Toner could not read: " + " ".join(body.split())[:160], None) from None
    if isinstance(data, dict) and data.get("success") is False:
        err = data.get("error") or {}
        raise LookupError_(f"{err.get('info') or err.get('type') or 'the request was refused'} (code {err.get('code', '?')})", err.get("code"))
    return data


def _said(body):
    """What an error body says, in one line: the JSON error's info or message when it has one, else the text."""
    try:
        data = json.loads(body)
        err = data.get("error") if isinstance(data, dict) else None
        if isinstance(err, dict):
            return str(err.get("info") or err.get("message") or err.get("type") or "")
        if isinstance(data, dict):
            return str(data.get("message") or data.get("detail") or "")
    except ValueError:
        pass
    return " ".join(str(body).split())[:160]


def lookup(ip, key=None, timeout=10, opener=None):
    """The ipstack record for an address, as the dict it returns. LookupError_ when ipstack refuses, ValueError without a key,
    and the usual network errors when it cannot be reached. `opener` stands in for urlopen in tests. https is tried first; the free
    plan (code 105, or an HTTP 401/403 for the same reason) is tried again over plain http."""
    key = (key if key is not None else get_key()).strip()
    if not key:
        raise ValueError("Add your ipstack access key under Settings > Connections first.")
    try:
        return _call(ip, key, True, timeout, opener)
    except LookupError_ as e:
        code = e.args[1] if len(e.args) > 1 else None
        if code in (HTTPS_RESTRICTED, 403):
            try:
                return _call(ip, key, False, timeout, opener)        # the free plan on ipstack.com: plain http
            except LookupError_ as e2:
                raise LookupError_(f"{e2.args[0]} (over http; over https: {e.args[0]})", e2.args[1] if len(e2.args) > 1 else None) from None
        if code in (INVALID_KEY, 401):                                # a key from the APILayer marketplace: the same service at its gateway
            return _gateway(ip, key, timeout, opener, e)
        raise
    except urllib.error.URLError as e:
        if "ssl" in str(e).lower() or "certificate" in str(e).lower():
            return _call(ip, key, False, timeout, opener)
        raise


def _gateway(ip, key, timeout, opener, first):
    """The APILayer marketplace paths, in turn; when every one refuses, the message names what each side said."""
    said = [f"ipstack.com: {first.args[0]}"]
    for gateway in GATEWAYS:
        host = gateway[0].split("/")[2]
        try:
            return _call(ip, key, True, timeout, opener, gateway=gateway)
        except LookupError_ as e:
            code = e.args[1] if len(e.args) > 1 else None
            if code == 404:
                continue
            said.append(f"{host}: {e.args[0]}")
            if code in (401, INVALID_KEY):
                continue
            raise LookupError_("; ".join(said), code) from None
    raise LookupError_("; ".join(said) + " (the key was sent exactly as typed, trimmed of spaces)", 401) from None


def test_key(key, timeout=10, opener=None):
    """Settings' Test key: (ok, text) from one look-up of 8.8.8.8 with this key."""
    try:
        rec = lookup("8.8.8.8", key, timeout, opener)
    except (LookupError_, ValueError) as e:
        return False, f"ipstack refused: {e}"
    except Exception as e:
        return False, f"Couldn't reach ipstack: {e}"
    place = ", ".join(x for x in (rec.get("city"), rec.get("country_name")) if x) if isinstance(rec, dict) else ""
    return True, f"The key works: 8.8.8.8 is in {place or 'the record ipstack sent'}."


def summary(data):
    """[(label, value)] of what matters from a record: where, who provides it, the network, the time zone."""
    if not isinstance(data, dict):
        return []
    place = ", ".join(x for x in (data.get("city"), data.get("region_name"), data.get("country_name")) if x)
    conn = data.get("connection") or {}
    tz = data.get("time_zone") or {}
    rows = [("Address", f"{data.get('ip', '')}  ({data.get('type', '') or 'IP'})".strip()), ("Location", place or "unknown")]
    if data.get("latitude") is not None and data.get("longitude") is not None:
        rows.append(("Coordinates", f"{data['latitude']}, {data['longitude']}"))
    if conn.get("isp"):
        rows.append(("Provider", str(conn["isp"])))
    if conn.get("asn"):
        rows.append(("Network", f"AS{conn['asn']}"))
    if tz.get("id"):
        off = tz.get("gmt_offset")
        rows.append(("Time zone", f"{tz['id']}" + (f"  (UTC{'+' if off >= 0 else '-'}{abs(off) // 3600:02d}:{abs(off) % 3600 // 60:02d})" if isinstance(off, (int, float)) else "")))
    sec = data.get("security") or {}
    if sec:
        flags = [k.replace("is_", "") for k in ("is_proxy", "is_tor", "is_crawler") if sec.get(k)]
        rows.append(("Security", ", ".join(flags) if flags else "nothing flagged"))
    return rows

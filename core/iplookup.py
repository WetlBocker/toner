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
    """ipstack said no, in its own words (the error's `info`)."""


def _call(ip, key, https, timeout, opener=None):
    req = urllib.request.Request(url(ip, key, https), headers={"User-Agent": "Toner"})
    f = (opener or urllib.request.urlopen)(req, timeout=timeout)
    data = json.loads(f.read().decode("utf-8", "replace"))
    if isinstance(data, dict) and data.get("success") is False:
        err = data.get("error") or {}
        raise LookupError_(f"{err.get('info') or err.get('type') or 'the request was refused'} (code {err.get('code', '?')})", err.get("code"))
    return data


def lookup(ip, key=None, timeout=10, opener=None):
    """The ipstack record for an address, as the dict it returns. LookupError_ when ipstack refuses, ValueError without a key,
    and the usual network errors when it cannot be reached. `opener` stands in for urlopen in tests."""
    key = key if key is not None else get_key()
    if not key:
        raise ValueError("Add your ipstack access key under Settings > Connections first.")
    try:
        return _call(ip, key, True, timeout, opener)
    except LookupError_ as e:
        if len(e.args) > 1 and e.args[1] == HTTPS_RESTRICTED:
            return _call(ip, key, False, timeout, opener)            # the free plan: plain http
        raise
    except urllib.error.URLError as e:
        if "ssl" in str(e).lower() or "certificate" in str(e).lower():
            return _call(ip, key, False, timeout, opener)
        raise


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

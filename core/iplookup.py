"""Where a public address is: any provider's JSON API, given as an API URL with {ip} and {key} in it and an API key kept in the vault.
The Subnet Calculator and WHOIS Lookup show the answer as a list of fields. ipstack (api.ipstack.com) is the default and the only
provider with extras: a free ipstack key allows plain http only, so Toner tries https first and falls back to http only when ipstack
says the plan does not allow https, and tries the APILayer gateways when ipstack.com refuses the key. Any other URL is called exactly as given."""
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request

import keyring

log = logging.getLogger("toner")
SECRET = "ipstack"                  # the key's name in the vault (kept from when ipstack was the only provider)
DEFAULT_URL = "https://api.ipstack.com/{ip}?access_key={key}"
HINT = "Use {ip} where the address goes, and {key} for the key"
MAX_ROWS = 200
MAX_BODY = 2 * 1024 * 1024         # an answer or error body is read up to this many bytes
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
        return
    try:
        keyring.delete_password(db.SERVICE, SECRET)
    except Exception:
        if get_key():                       # the vault kept it: say so, so a new URL is never saved beside the old key
            raise


def has_key():
    return bool(get_key())


def get_url():
    from core import db
    return str(db.get_setting("iplookup_url") or "").strip() or DEFAULT_URL


def check_url(url):
    """The address as it may be saved: it needs {ip}, and only http or https is called. ValueError otherwise."""
    url = (url or "").strip()
    if "{ip}" not in url:
        raise ValueError(HINT)
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"unknown url type: {scheme}")                   # urllib's own words
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValueError(f"API URL: {HINT}")
    authority = url.split("//", 1)[1].split("/", 1)[0] if "//" in url else ""
    if "{ip}" in authority or "{key}" in authority or not urllib.parse.urlsplit(url.replace("{ip}", "x").replace("{key}", "x")).hostname:
        raise ValueError(f"API URL: {HINT}")
    return url


def same_url(a, b):
    """The same address, ignoring what does not change where it goes: capitals in the scheme and host, and a trailing '/'."""
    def norm(u):
        p = urllib.parse.urlsplit((u or "").strip())
        return p.scheme.lower(), p.netloc.lower(), p.path.rstrip("/"), p.query, p.fragment
    return norm(a) == norm(b)


def set_url(url):
    from core import db
    db.set_setting("iplookup_url", check_url(url))


def build(template, ip, key):
    return template.replace("{ip}", urllib.parse.quote(str(ip), safe="")).replace("{key}", urllib.parse.quote(str(key), safe=""))


def host(template=None):
    return urllib.parse.urlsplit(template or get_url()).hostname or ""


def _hide(text, key):
    """The text with the key (as typed and as URL-encoded) replaced by {key}: it must never reach a message or a log."""
    text = str(text)
    for k in {key, urllib.parse.quote(key, safe=""), urllib.parse.quote_plus(key)}:
        if k:
            text = text.replace(k, "{key}")
    return text


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):                                 # a 3xx is an HTTP error: the key is never forwarded to another address
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)                       # still honours the proxy settings, as urlopen did


class LookupError_(Exception):
    """The provider said no, in its own words (the error's `info`); args[1] is its code (the provider's, or the HTTP status)."""

    def __str__(self):
        return str(self.args[0]) if self.args else "the request was refused"


def _call(ip, key, template, timeout, opener=None, gateway=None):
    headers = {"User-Agent": "Toner", "Accept": "application/json"}
    if gateway:                                                          # the APILayer marketplace: (address pattern, where the key goes)
        pattern, where = gateway
        address = pattern.format(ip=urllib.parse.quote(str(ip)))
        who = pattern.split("/")[2]
        if where == "header":
            headers["apikey"] = key
        else:
            address += "?" + urllib.parse.urlencode({"access_key": key})
    else:
        address, who = build(template, ip, key), host(template)
    part = urllib.parse.urlsplit(address)                                # scheme and host only: a key may have been pasted anywhere after them
    log.info("IP look-up: GET %s://%s", part.scheme, part.hostname or "")
    req = urllib.request.Request(address, headers=headers)
    try:
        f = (opener or _OPENER.open)(req, timeout=timeout)
        try:
            raw = f.read(MAX_BODY + 1)
        finally:
            f.close()
        body = raw[:MAX_BODY].decode("utf-8", "replace")
    except urllib.error.HTTPError as e:                                 # the provider answered with an HTTP error: its words, not just the number
        try:
            body = e.read(MAX_BODY).decode("utf-8", "replace")
        except Exception:
            body = ""
        finally:
            e.close()
        said = _said(body)
        raise LookupError_(f"HTTP {e.code} {e.reason or ''}".strip() + (f": {said}" if said else ""), e.code) from None
    try:
        if len(raw) > MAX_BODY:
            raise ValueError("too large")
        data = json.loads(body)
    except (ValueError, RecursionError):
        raise LookupError_(f"{who} gave an answer Toner could not read: " + " ".join(body[:400].split())[:160], None) from None
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


def lookup(ip, key=None, timeout=10, opener=None, template=None):
    """The provider's answer for an address, as the JSON it sent. LookupError_ when it refuses or cannot be reached, ValueError without a key.
    `opener` stands in for urlopen in tests. Every message has the key replaced by {key}."""
    key = (key if key is not None else get_key()).strip()
    if not key:
        raise ValueError("Add your API key under Settings > Connections first.")
    template = check_url(template or get_url())
    try:
        return _lookup(ip, key, template, timeout, opener)
    except LookupError_ as e:
        raise LookupError_(_hide(e.args[0], key), *e.args[1:]) from None
    except OSError as e:                                                 # a timeout, a refused connection, a name that does not resolve
        raise LookupError_(f"Couldn't reach {host(template)}: " + _hide(getattr(e, "reason", None) or e, key), None) from None
    except Exception as e:                                               # anything else (a malformed address, say) may quote the address
        raise LookupError_(_hide(e, key), None) from None


def _lookup(ip, key, template, timeout, opener):
    if host(template) != HOST:                                           # another provider: exactly the URL given
        return _call(ip, key, template, timeout, opener)
    https, http = re.sub(r"^https?", "https", template, flags=re.I), re.sub(r"^https?", "http", template, flags=re.I)
    try:
        return _call(ip, key, https, timeout, opener)
    except LookupError_ as e:
        code = e.args[1] if len(e.args) > 1 else None
        if code in (HTTPS_RESTRICTED, 403):
            try:
                return _call(ip, key, http, timeout, opener)             # the free plan on ipstack.com: plain http
            except LookupError_ as e2:
                raise LookupError_(f"{e2.args[0]} (over http; over https: {e.args[0]})", e2.args[1] if len(e2.args) > 1 else None) from None
        if code in (INVALID_KEY, 401):                                    # a key from the APILayer marketplace: the same service at its gateway
            return _gateway(ip, key, timeout, opener, e)
        raise
    except urllib.error.URLError as e:
        if "ssl" in str(e).lower() or "certificate" in str(e).lower():
            return _call(ip, key, http, timeout, opener)
        raise


def _gateway(ip, key, timeout, opener, first):
    """The APILayer marketplace paths, in turn; when every one refuses, the message names what each side said."""
    said = [f"ipstack.com: {first.args[0]}"]
    for gateway in GATEWAYS:
        who = gateway[0].split("/")[2]
        try:
            return _call(ip, key, None, timeout, opener, gateway=gateway)
        except LookupError_ as e:
            code = e.args[1] if len(e.args) > 1 else None
            if code == 404:
                continue
            said.append(f"{who}: {e.args[0]}")
            if code in (401, INVALID_KEY):
                continue
            raise LookupError_("; ".join(said), code) from None
    raise LookupError_("; ".join(said) + " (the key was sent exactly as typed, trimmed of spaces)", 401) from None


def test_key(key, timeout=10, opener=None, template=None):
    """Settings' Test key: (ok, text) from one look-up of 8.8.8.8 with this key (and this URL, else the saved one)."""
    try:
        rec = lookup("8.8.8.8", key, timeout, opener, template)
    except (LookupError_, ValueError) as e:
        return False, str(e)
    place = ", ".join(x for x in (rec.get("city"), rec.get("country_name")) if x) if isinstance(rec, dict) else ""
    return True, "The key works" + (f": 8.8.8.8 is in {place}." if place else ".")


def fields(data):
    """[(label, value)] for every field of a JSON answer: nested keys joined with dots, list items numbered, at most MAX_ROWS."""
    rows, stack = [], [("", data)]
    while stack and len(rows) < MAX_ROWS:                                # a stack, not recursion: any depth is safe
        prefix, v = stack.pop()
        if isinstance(v, dict) and v:
            items = [(f"{prefix}.{k}" if prefix else str(k), x) for k, x in v.items()]
        elif isinstance(v, list) and v:
            items = [(f"{prefix}.{i}" if prefix else str(i), x) for i, x in enumerate(v)]
        else:
            rows.append((prefix, v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)))
            continue
        stack.extend(reversed(items))
    return rows

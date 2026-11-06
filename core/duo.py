"""Duo Auth API v2 client: push first, a passcode as the backup. Requests are signed with signature version 5
(HMAC-SHA512, JSON body). The secret key comes from the OS store and is never logged or put in an exception."""
import base64
import hashlib
import hmac
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from email.utils import formatdate

from core import osstore

_TEST_ALLOW_HTTP = False        # only tests set this
PUSH_SECONDS = 60
REQUEST_TIMEOUT = 10


class Unavailable(Exception):
    pass


class Denied(Exception):
    pass


def _h(s):
    return hashlib.sha512(s.encode()).hexdigest()


def sign(skey, date, method, host, path, query, body):
    """Duo signature v5 with no X-Duo-* headers (the last line is the SHA-512 of the empty header text). `query` is the encoded, sorted query string; `body` the JSON text."""
    canon = "\n".join([date, method.upper(), host.lower(), path, query, _h(body), _h("")])
    return hmac.new(skey.encode(), canon.encode(), hashlib.sha512).hexdigest()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)
_HOST = re.compile(r"[A-Za-z0-9.-]+")
_HOST_PORT = re.compile(r"[A-Za-z0-9.-]+(:[0-9]{1,5})?")


class _ReadTimeout(Exception):
    pass


def _call(cfg, method, path, params):
    try:
        return _call_(cfg, method, path, params)
    except _ReadTimeout:
        if path.endswith("auth_status"):
            raise
        raise Unavailable("Duo timed out") from None
    except Unavailable:
        raise
    except Exception:
        raise Unavailable("Duo request failed") from None


def _call_(cfg, method, path, params):
    duo = cfg["duo"]
    host, ikey = duo["host"], duo["ikey"]
    if not isinstance(host, str) or not (_HOST_PORT if _TEST_ALLOW_HTTP else _HOST).fullmatch(host):
        raise Unavailable("bad Duo host")
    skey = osstore.get("duo:" + cfg["id"])
    if not skey:
        raise Unavailable("no Duo secret key")
    date = formatdate(usegmt=False)
    if method == "GET":
        query, body = "&".join(f"{urllib.parse.quote(k, safe='~')}={urllib.parse.quote(v, safe='~')}"
                               for k, v in sorted(params.items())), ""
    else:
        query, body = "", json.dumps(params, separators=(",", ":"), sort_keys=True)
    sig = sign(skey.decode(), date, method, host, path, query, body)
    url = ("http://" if _TEST_ALLOW_HTTP else "https://") + host + path + ("?" + query if query else "")
    req = urllib.request.Request(url, data=body.encode() if method != "GET" else None, method=method, headers={
        "Date": date, "Content-Type": "application/json",
        "Authorization": "Basic " + base64.b64encode(f"{ikey}:{sig}".encode()).decode()})
    try:
        with _OPENER.open(req, timeout=REQUEST_TIMEOUT) as r:
            if not 200 <= r.status < 300:
                raise Unavailable("Duo answered oddly")
            out = json.loads(r.read())
    except (urllib.error.URLError, OSError, ValueError) as e:
        # urllib wraps a timeout waiting for the reply in URLError; a connect timeout looks the same (then the poll just runs to its deadline)
        if isinstance(e, TimeoutError) or isinstance(getattr(e, "reason", None), TimeoutError):
            raise _ReadTimeout() from None
        # (HTTPError is a URLError, so a 3xx or 4xx lands here)
        raise Unavailable("Duo could not be reached") from None
    if not isinstance(out, dict) or out.get("stat") != "OK" or not isinstance(out.get("response"), dict):
        raise Unavailable("Duo refused the request")
    return out["response"]


def preauth(cfg, user):
    r = _call(cfg, "POST", "/auth/v2/preauth", {"username": user}).get("result")
    return r if r in ("auth", "allow", "deny", "enroll") else "deny"


def push(cfg, user, cancel):
    txid = _call(cfg, "POST", "/auth/v2/auth", {"username": user, "factor": "push", "device": "auto", "async": "1"}).get("txid")
    if not isinstance(txid, str):
        raise Unavailable("Duo gave no transaction")
    end = time.monotonic() + PUSH_SECONDS
    while time.monotonic() < end:
        if cancel.is_set():
            break
        box = []

        def go():
            try:
                box.append(_call(cfg, "GET", "/auth/v2/auth_status", {"txid": txid}))
            except _ReadTimeout:
                box.append({"result": "waiting"})       # the long poll ran out; ask again until the deadline
            except Exception as e:
                box.append(e)
        t = threading.Thread(target=go, daemon=True)
        t.start()
        while t.is_alive() and not cancel.is_set() and time.monotonic() < end:
            t.join(0.1)
        if not box:
            break
        if isinstance(box[0], Exception):
            raise box[0]
        res = box[0].get("result")
        if res == "allow":
            return
        if res == "deny":
            break
        time.sleep(0.05)
    raise Denied("push not approved")


def passcode(cfg, user, code):
    r = _call(cfg, "POST", "/auth/v2/auth", {"username": user, "factor": "passcode", "passcode": code})
    if r.get("result") != "allow":
        raise Denied("passcode refused")

"""Duo Auth API v2 client: push first, a passcode as the backup. Requests are signed with signature version 5
(HMAC-SHA512, JSON body). The secret key comes from the OS store and is never logged or put in an exception."""
import base64
import hashlib
import hmac
import json
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
    """Duo signature v5, no X-Duo-* headers (so the last line is empty; matches the docs example). `query` is the encoded, sorted query string; `body` the JSON text."""
    canon = "\n".join([date, method.upper(), host.lower(), path, query, _h(body), ""])
    return hmac.new(skey.encode(), canon.encode(), hashlib.sha512).hexdigest()


def _call(cfg, method, path, params):
    duo = cfg["duo"]
    skey = osstore.get("duo:" + cfg["id"])
    if not skey:
        raise Unavailable("no Duo secret key")
    host, ikey = duo["host"], duo["ikey"]
    date = formatdate(usegmt=False)
    if method == "GET":
        query, body = urllib.parse.urlencode(sorted(params.items()), quote_via=urllib.parse.quote), ""
    else:
        query, body = "", json.dumps(params, separators=(",", ":"), sort_keys=True)
    sig = sign(skey.decode(), date, method, host, path, query, body)
    url = ("http://" if _TEST_ALLOW_HTTP else "https://") + host + path + ("?" + query if query else "")
    req = urllib.request.Request(url, data=body.encode() if method != "GET" else None, method=method, headers={
        "Date": date, "Content-Type": "application/json",
        "Authorization": "Basic " + base64.b64encode(f"{ikey}:{sig}".encode()).decode()})
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as r:
            out = json.loads(r.read())
    except (urllib.error.URLError, OSError, ValueError):
        raise Unavailable("Duo could not be reached") from None
    if out.get("stat") != "OK":
        raise Unavailable("Duo refused the request")
    return out["response"]


def preauth(cfg, user):
    r = _call(cfg, "POST", "/auth/v2/preauth", {"username": user}).get("result")
    return r if r in ("auth", "allow", "deny", "enroll") else "deny"


def push(cfg, user, cancel):
    txid = _call(cfg, "POST", "/auth/v2/auth", {"username": user, "factor": "push", "device": "auto", "async": "1"})["txid"]
    end = time.monotonic() + PUSH_SECONDS
    while time.monotonic() < end:
        if cancel.is_set():
            break
        box = []

        def go():
            try:
                box.append(_call(cfg, "GET", "/auth/v2/auth_status", {"txid": txid}))
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

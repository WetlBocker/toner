"""What the UniFi API-key drivers share: the HTTP call (X-API-KEY header, certificate and proxy handling, the rate limit, readable
errors) and the two kinds of paging. The login-based driver for UniFi OS consoles is drivers/unifi.py; these three use the
Integration APIs that UniFi publishes at developer.ui.com:

    Network       https://<console>/proxy/network/integration/v1/...   (offset / limit paging)
    Protect       https://<console>/proxy/protect/integration/v1/...   (plain lists)
    Site Manager  https://api.ui.com/v1/...                            (pageSize / nextToken paging, the cloud)
"""
import time
from datetime import datetime, timezone

import requests
import urllib3

from core import proxy
from .base import Driver, OK, WARN, FAIL

CLOUD_HOST = "api.ui.com"
MAX_PAGES = 50


class UnifiApi(Driver):
    PREFIX = ""                      # the part of the path after the host: /proxy/network/integration
    LOCAL = True                     # a console on the network (its certificate may be self-signed); False for api.ui.com

    # ---------------------------------------------------------------- the call
    def base(self):
        d = self.dev
        host = (d.get("host") or "").strip() or (CLOUD_HOST if not self.LOCAL else "")
        port = f":{d['port']}" if d.get("port") else ""
        return f"https://{host}{port}{self.PREFIX}/v1"

    def verify(self):
        return bool(self.dev.get("verify_ssl")) if self.LOCAL else True

    def get(self, path, params=None, optional=False):
        """GET one path and return its JSON. `optional`: a 404 (this version does not have it) gives None."""
        if not self.verify():
            urllib3.disable_warnings()
        r = None
        for attempt in range(2):                                      # one polite retry when the rate limit is hit
            r = requests.get(self.base() + path, params=params or None,
                             headers={"X-API-KEY": self.password or "", "Accept": "application/json"},
                             timeout=self.opts["http_timeout"], verify=self.verify(), **proxy.requests_kwargs(self.dev))
            if r.status_code == 429 and attempt == 0:
                try:
                    wait = float(r.headers.get("Retry-After", 1))
                except ValueError:
                    wait = 1.0
                time.sleep(min(10.0, max(0.0, wait)))
                continue
            break
        code = getattr(r, "status_code", 200)
        if code == 404 and optional:
            return None
        if code == 401:
            raise ValueError("the API key was rejected (HTTP 401). Create a key for this application at unifi.ui.com and paste it again")
        if code == 403:
            raise ValueError(f"this API key may not read {path} (HTTP 403)")
        if code == 429:
            raise ValueError("UniFi's rate limit is in effect (HTTP 429): try again in a minute, or run the checks less often")
        r.raise_for_status()
        return r.json()

    def offset_pages(self, path, params=None, limit=200, optional=False):
        """Network API lists: {'offset', 'limit', 'count', 'totalCount', 'data'} until everything has been read."""
        rows, offset = [], 0
        for _ in range(MAX_PAGES):
            data = self.get(path, {**(params or {}), "offset": offset, "limit": limit}, optional=optional)
            if data is None:
                return rows
            if isinstance(data, list):
                return rows + data
            page = data.get("data") or []
            rows += page
            offset += len(page)
            if not page or offset >= int(data.get("totalCount") or 0):
                break
        return rows

    def token_pages(self, path, params=None, size=100, optional=False):
        """Site Manager lists: {'data': [...], 'nextToken': '...'} until there is no next token."""
        rows, token = [], None
        for _ in range(MAX_PAGES):
            q = {**(params or {}), "pageSize": str(size)}
            if token:
                q["nextToken"] = token
            data = self.get(path, q, optional=optional)
            if data is None:
                return rows
            if isinstance(data, list):
                return rows + data
            rows += data.get("data") or []
            token = data.get("nextToken")
            if not token:
                break
        return rows

    # ---------------------------------------------------------------- rows
    def row(self, label, check, status, value="", message="", numeric=None):
        """A result that belongs to something the console manages: shown as 'this device / that thing'."""
        r = self.result(check, status, value, message, numeric)
        if label:
            r.device = f"{self.name} / {label}"
        return r

    def wanted(self, *names):
        """The Site field as a filter on names and ids: blank, '*' and 'all' mean everything, and so does 'default' in the cloud
        driver (the device dialog fills that in); the Network driver treats 'default' as the console's default site."""
        want = (self.dev.get("site") or "").strip().lower()
        if want in ("", "*", "all") or (want == "default" and not self.LOCAL):
            return True
        return any(want in str(n).lower() for n in names if n)


def hours_ago(stamp):
    """How long ago a Unix time was, in hours. Protect sends seconds or milliseconds depending on the field."""
    try:
        t = float(stamp)
    except (TypeError, ValueError):
        return None
    if t > 1e11:
        t /= 1000.0
    return max(0.0, (datetime.now(timezone.utc).timestamp() - t) / 3600.0)


def stamp_text(stamp):
    try:
        t = float(stamp)
    except (TypeError, ValueError):
        return str(stamp or "")
    if t > 1e11:
        t /= 1000.0
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")


def state_status(state):
    """A device state to OK / WARN / FAIL and a word for it. Online is fine; coming up or going through a change is a warning."""
    word = str(state or "unknown").lower().replace("_", " ")
    up = str(state or "").upper()
    if up in ("ONLINE", "CONNECTED"):
        return OK, word
    if up in ("UPDATING", "GETTING_READY", "ADOPTING", "PENDING_ADOPTION", "CONNECTING", "PROVISIONING", "UPGRADING", "ADOPTING"):
        return WARN, word
    return FAIL, word

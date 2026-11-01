"""What the drivers for controllers and managers reached over HTTPS share (Cisco ISE, SD-WAN Manager, FMC, vCenter, SonicWall, Mist):
one session for the run, the self-signed certificate accepted unless 'Verify SSL certificate' is ticked, the proxy, JSON in and out,
and readable errors for the usual failures. Each driver adds its own way of signing in (a token, a cookie, a header)."""
import urllib3
import requests

from core import proxy
from .base import AuthRejected, Driver


class WebApi(Driver):
    PREFIX = ""                    # the part of the path before the API's own paths
    DEFAULT_PORT = 443
    NAME = "the API"
    SCHEME = "https"

    def base(self):
        d = self.dev
        port = d.get("port") or self.DEFAULT_PORT
        host = d["host"]
        if port in (443, 0) and self.SCHEME == "https":
            return f"https://{host}{self.PREFIX}"
        return f"{self.SCHEME}://{host}:{port}{self.PREFIX}"

    def session(self):
        """The requests session for this run (made once)."""
        if getattr(self, "_session", None) is None:
            s = requests.Session()
            s.verify = bool(self.dev.get("verify_ssl"))
            if not s.verify:
                urllib3.disable_warnings()
            s.headers.update({"Accept": "application/json"})
            self._session = s
        return self._session

    def call(self, method, path, optional=False, raw=False, **kw):
        """One request. JSON back (None for an empty body); `optional`: a 400, 404 or 501 (this version has no such path) gives None;
        `raw`: the response itself. A 401 ends the run (AuthRejected): every check would fail the same way."""
        kw.setdefault("timeout", self.opts["http_timeout"])
        r = self.session().request(method, (self.base() + path) if path.startswith("/") else path, **{**proxy.requests_kwargs(self.dev), **kw})
        code = getattr(r, "status_code", 200)
        if code in (400, 404, 501) and optional:
            return None
        if code == 401:
            raise AuthRejected(f"{self.NAME} rejected the login (HTTP 401): check the user name and password or key")
        if code == 403:
            raise ValueError(f"the login may not read {path} (HTTP 403): give it read access to that part of {self.NAME}")
        r.raise_for_status()
        if raw:
            return r
        if not getattr(r, "content", b""):
            return None
        return r.json()

    def get(self, path, optional=False, **kw):
        return self.call("GET", path, optional=optional, **kw)

    def post(self, path, optional=False, **kw):
        return self.call("POST", path, optional=optional, **kw)

    @staticmethod
    def pct(used, total):
        try:
            used, total = float(used), float(total)
        except (TypeError, ValueError):
            return None
        return used / total * 100 if total > 0 else None

    def close(self):
        s = getattr(self, "_session", None)
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
            self._session = None

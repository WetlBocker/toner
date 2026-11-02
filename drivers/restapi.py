"""What the REST drivers for servers and appliances share (Proxmox VE, TrueNAS, OPNsense): the HTTPS call with the vendor's own way of
sending the key, a self-signed certificate accepted unless 'Verify SSL certificate' is ticked, the proxy, and readable errors for the common
failures. It is WebApi with each request sent on its own (no session) and the key sent the way `auth()` says; a 401 ends the run as there."""
import requests

from core import tlsverify
from .webapi import WebApi


class RestApi(WebApi):
    PREFIX = ""                    # the part of the path before the API's own paths, e.g. /api2/json
    DEFAULT_PORT = 443
    NAME = "the API"
    CREDENTIAL = "the key"
    REJECTED_HINT = "check the key, and that it has not expired"

    def auth(self):
        """(headers, requests auth) for the key the person stored."""
        return {}, None

    def base(self):
        d = self.dev
        return f"https://{d['host']}:{d.get('port') or self.DEFAULT_PORT}{self.PREFIX}"

    def transport(self, method, url, **kw):
        kw.setdefault("verify", tlsverify.verify(self.dev))
        return requests.request(method, url, **kw) if method != "GET" else requests.get(url, **kw)

    def get(self, path, params=None, optional=False):
        """GET one path and return its JSON. `optional`: a 404 or 400 (this version or feature is not there) gives None."""
        headers, auth = self.auth()
        return self.call("GET", path, optional=optional, params=params or None, headers={"Accept": "application/json", **headers}, auth=auth)

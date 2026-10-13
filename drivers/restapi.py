"""What the REST drivers for servers and appliances share (Proxmox VE, TrueNAS, OPNsense): the HTTPS call with the vendor's own way of sending the key,
a self-signed certificate accepted unless 'Verify SSL certificate' is ticked, the proxy, and readable errors for the common failures."""
import urllib3
import requests

from core import proxy
from .base import Driver


class RestApi(Driver):
    PREFIX = ""                    # the part of the path before the API's own paths, e.g. /api2/json
    DEFAULT_PORT = 443
    NAME = "the API"

    def auth(self):
        """(headers, requests auth) for the key the person stored."""
        return {}, None

    def base(self):
        d = self.dev
        return f"https://{d['host']}:{d.get('port') or self.DEFAULT_PORT}{self.PREFIX}"

    def get(self, path, params=None, optional=False):
        """GET one path and return its JSON. `optional`: a 404 or 400 (this version or feature is not there) gives None."""
        verify = bool(self.dev.get("verify_ssl"))
        if not verify:
            urllib3.disable_warnings()
        headers, auth = self.auth()
        headers = {"Accept": "application/json", **headers}
        r = requests.get(self.base() + path, params=params or None, headers=headers, auth=auth, timeout=self.opts["http_timeout"], verify=verify,
                         **proxy.requests_kwargs(self.dev))
        code = getattr(r, "status_code", 200)
        if code in (400, 404, 501) and optional:
            return None
        if code == 401:
            raise ValueError(f"{self.NAME} rejected the key (HTTP 401): check the key, and that it has not expired")
        if code == 403:
            raise ValueError(f"the key may not read {path} (HTTP 403): give it read access to that part of {self.NAME}")
        r.raise_for_status()
        return r.json()

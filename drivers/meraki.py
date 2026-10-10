from core import proxy
import time
from datetime import datetime, timezone

import requests

from .base import Driver, OK, WARN, FAIL


class MerakiDriver(Driver):
    """Meraki Dashboard API. Host is the API server (api.meraki.com), the secret is the API key and
    the Organization field says which organization to check."""

    def _get(self, path, params=None):
        d = self.dev
        url = f"https://{d['host']}{':' + str(d['port']) if d.get('port') else ''}/api/v1{path}"
        rows = []
        for _ in range(20):                                      # follow pagination, bounded
            for attempt in range(2):                             # one polite retry on the rate limit
                r = requests.get(url, params=params, headers={"Authorization": f"Bearer {self.password}"},
                                 timeout=self.opts["http_timeout"], verify=True,
                                 **proxy.requests_kwargs(self.dev))
                if r.status_code == 429 and attempt == 0:
                    time.sleep(min(10, float(r.headers.get("Retry-After", 1))))
                    continue
                break
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, list):
                return data
            rows += data
            nxt = r.links.get("next", {}).get("url")
            if not nxt:
                return rows
            url, params = nxt, None
        return rows

    def _org(self):
        orgs = self._get("/organizations")
        want = (self.dev.get("site") or "default").strip()
        if want.lower() == "default" and len(orgs) == 1:
            return orgs[0]
        match = next((o for o in orgs if want.lower() in (str(o.get("id", "")).lower(), o.get("name", "").lower())),
                     None)
        if not match:
            avail = ", ".join(f"{o.get('name')} ({o.get('id')})" for o in orgs) or "none visible"
            raise ValueError(f"organization '{want}' not found; this key can see: {avail}")
        return match

    def run(self):
        org = self._org()
        self._org_id = org["id"]
        out = []
        for name, fn in (("devices", self.devices), ("uplinks", self.uplinks), ("licenses", self.licenses)):
            if self.enabled(name):
                self.safe(out, name, fn)
        return out

    def _optional(self, path):
        """Some endpoints do not exist for every organization; treat that as 'nothing to report'."""
        try:
            return self._get(path)
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code in (400, 404):
                return None
            raise

    def _statuses(self):
        if not hasattr(self, "_st"):
            self._st = self._get(f"/organizations/{self._org_id}/devices/statuses", {"perPage": 1000})
        return self._st

    def devices(self):
        devs = [x for x in self._statuses() if x.get("status") != "dormant"]
        name = lambda x: x.get("name") or x.get("serial") or "?"
        off = [name(x) for x in devs if x.get("status") == "offline"]
        alert = [name(x) for x in devs if x.get("status") == "alerting"]
        online = len(devs) - len(off) - len(alert)
        status = FAIL if off else WARN if alert else OK
        msg = "; ".join(p for p in ((f"offline: {', '.join(off[:5])}" if off else ""),
                                    (f"alerting: {', '.join(alert[:5])}" if alert else "")) if p)
        return self.result("devices", status, f"{online}/{len(devs)} online", msg, numeric=float(online))

    def uplinks(self):
        rows = self._optional(f"/organizations/{self._org_id}/appliance/uplink/statuses")
        if not rows:
            return []
        names = {x.get("serial"): x.get("name") for x in self._statuses()}
        down, dead = [], []
        for ap in rows:
            ups = ap.get("uplinks") or []
            bad = [u for u in ups if u.get("status") == "failed"]
            label = names.get(ap.get("serial")) or ap.get("serial") or "?"
            down += [f"{label} {u.get('interface', '?')}" for u in bad]
            if ups and len(bad) == len(ups):
                dead.append(label)
        status = FAIL if dead else WARN if down else OK
        total = sum(len(ap.get("uplinks") or []) for ap in rows)
        return self.result("uplinks", status, f"{total - len(down)}/{total} up",
                           ("down: " + ", ".join(down[:5])) if down else "", numeric=float(total - len(down)))

    def licenses(self):
        ov = self._optional(f"/organizations/{self._org_id}/licenses/overview")
        if not ov:
            return []
        state = ov.get("status", "?")
        days, when = None, ov.get("expirationDate", "")
        try:
            exp = datetime.strptime(when.replace(" UTC", ""), "%b %d, %Y").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
        except ValueError:
            pass
        status = OK if state == "OK" else WARN
        msg = [] if state == "OK" else [f"license state: {state}"]
        if days is not None:
            if days < 7:
                status = FAIL
            elif days < 30 and status == OK:
                status = WARN
            if days < 30:
                msg.append(f"expires in {days} day(s)" if days >= 0 else "expired")
        return self.result("licenses", status, state if days is None else f"{state}, {days} days left",
                           "; ".join(msg), numeric=float(days) if days is not None else None)

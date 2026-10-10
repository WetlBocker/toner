"""A cloud service's public status page (any page built on Atlassian Statuspage: GitHub, Cloudflare, Zoom, Meraki, Duo,
Discord and many more). The host is the status page's address, for example www.githubstatus.com."""
from core import proxy
import requests

from .base import Driver, OK, WARN, FAIL

INDICATOR = {"none": (OK, 0), "minor": (WARN, 1), "major": (FAIL, 2), "critical": (FAIL, 3)}
COMPONENT = {"operational": OK, "under_maintenance": OK, "degraded_performance": WARN, "partial_outage": WARN,
             "major_outage": FAIL}
RANK = {OK: 0, WARN: 1, FAIL: 2}
PRESETS = [("GitHub", "www.githubstatus.com"), ("Cloudflare", "www.cloudflarestatus.com"), ("Zoom", "status.zoom.us"),
           ("Cisco Meraki", "status.meraki.com"), ("Cisco Duo", "status.duo.com"), ("Discord", "discordstatus.com")]


class CloudDriver(Driver):
    def fetch(self):
        url = f"https://{self.dev['host']}/api/v2/summary.json"
        r = requests.get(url, timeout=self.opts["http_timeout"], headers={"User-Agent": "Toner"},
                         **proxy.requests_kwargs(self.dev))
        r.raise_for_status()
        try:
            return r.json()
        except ValueError:
            raise ValueError(f"{self.dev['host']} did not return a Statuspage summary (expected {url})") from None

    def run(self):
        data = self.fetch()
        out = []
        for key, fn in (("status", self.status), ("components", self.components), ("incidents", self.incidents)):
            if self.enabled(key):
                self.safe(out, key, lambda fn=fn: fn(data))
        return out

    def status(self, data):
        s = data.get("status") or {}
        status, level = INDICATOR.get(s.get("indicator"), (WARN, 1))
        maint = [m.get("name", "") for m in data.get("scheduled_maintenances") or [] if m.get("status") == "in_progress"]
        return self.result("status", status, s.get("description", s.get("indicator", "?")),
                           ("maintenance in progress: " + "; ".join(maint[:3])) if maint else "", numeric=float(level))

    def components(self, data):
        bad = [(c.get("name", "?"), COMPONENT.get(c.get("status"), WARN), c.get("status", ""))
               for c in data.get("components") or [] if not c.get("group")]
        bad = [b for b in bad if b[2] not in ("operational", "under_maintenance")]
        if not bad:
            return self.result("components", OK, "all operational", numeric=0.0)
        worst = max((b[1] for b in bad), key=RANK.get)
        bad.sort(key=lambda b: -RANK[b[1]])
        names = ", ".join(f"{n} ({st.replace('_', ' ')})" for n, _, st in bad[:5]) + (f" and {len(bad) - 5} more" if len(bad) > 5 else "")
        return self.result("components", worst, f"{len(bad)} affected", names, numeric=float(len(bad)))

    def incidents(self, data):
        inc = [i for i in data.get("incidents") or [] if i.get("status") not in ("resolved", "postmortem", "completed")]
        if not inc:
            return self.result("incidents", OK, "none", numeric=0.0)
        worst = FAIL if any(i.get("impact") in ("major", "critical") for i in inc) else WARN
        return self.result("incidents", worst, f"{len(inc)} open", "; ".join(i.get("name", "?") for i in inc[:3]),
                           numeric=float(len(inc)))

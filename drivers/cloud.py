"""A cloud service's public status page (any page built on Atlassian Statuspage: GitHub, Cloudflare, Zoom, Meraki, Duo,
Discord and many more). The host is the status page's address, for example www.githubstatus.com.

To watch only some of a service's components, put their names in the device's custom fields (Edit device > Tags and fields):
    watch=Git Operations, Actions
A name matches any component whose name contains it (capitals do not matter)."""
import json
from datetime import datetime, timezone

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
        for key, fn in (("status", self.status), ("components", self.components), ("incidents", self.incidents), ("maintenance", self.maintenance)):
            if self.enabled(key):
                self.safe(out, key, lambda fn=fn: fn(data))
        return out

    def status(self, data):
        s = data.get("status") or {}
        status, level = INDICATOR.get(s.get("indicator"), (WARN, 1))
        maint = [m.get("name", "") for m in data.get("scheduled_maintenances") or [] if m.get("status") == "in_progress"]
        return self.result("status", status, s.get("description", s.get("indicator", "?")),
                           ("maintenance in progress: " + "; ".join(maint[:3])) if maint else "", numeric=float(level))

    def watched(self):
        """The component names to look at, from the 'watch' custom field; an empty list means all of them."""
        try:
            raw = self.dev.get("fields")
            fields = json.loads(raw) if isinstance(raw, str) and raw else (raw or {})
        except ValueError:
            fields = {}
        text = next((v for k, v in fields.items() if str(k).strip().lower() in ("watch", "components")), "")
        return [w.strip().lower() for w in str(text).replace(";", ",").split(",") if w.strip()]

    def maintenance(self, data):
        """Planned work in the next two days, so a quiet outage is not a surprise."""
        now, soon = datetime.now(timezone.utc), []
        for m in data.get("scheduled_maintenances") or []:
            if m.get("status") not in ("scheduled", "in_progress"):
                continue
            try:
                start = datetime.fromisoformat(str(m.get("scheduled_for", "")).replace("Z", "+00:00"))
            except ValueError:
                continue
            hours = (start - now).total_seconds() / 3600
            if m.get("status") == "in_progress" or -1 <= hours <= 48:
                soon.append((hours, m.get("name", "maintenance")))
        if not soon:
            return self.result("maintenance", OK, "none planned", "", numeric=0.0)
        soon.sort()
        first = soon[0]
        when = "now" if first[0] <= 0 else f"in {first[0]:.0f} h"
        return self.result("maintenance", WARN, f"{len(soon)} planned", f"{first[1]} ({when})" + (f"; and {len(soon) - 1} more" if len(soon) > 1 else ""), numeric=float(len(soon)))

    def components(self, data):
        watch = self.watched()
        bad = [(c.get("name", "?"), COMPONENT.get(c.get("status"), WARN), c.get("status", ""))
               for c in data.get("components") or [] if not c.get("group") and (not watch or any(w in str(c.get("name", "")).lower() for w in watch))]
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

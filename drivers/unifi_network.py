"""UniFi Network, through the Integration API of a console (Network application 9.x and later) with an API key.
The host is the console's address; the secret is the key. The Site field picks a site by name (default = the console's
default site; * or all = every site)."""
from core import display
from .base import OK, WARN, FAIL, grade, grade_low
from .unifiapi import UnifiApi, state_status

MAX_STATS = 250                          # devices asked for their statistics in one run


class UnifiNetworkDriver(UnifiApi):
    PREFIX = "/proxy/network/integration"

    def run(self):
        out = []
        info = self.get("/info")
        if self.enabled("reachability"):
            version = (info or {}).get("applicationVersion", "") if isinstance(info, dict) else ""
            out.append(self.result("reachability", OK, f"Network {version}" if version else "answering", "UniFi Network API"))
        sites = self.pick_sites(self.offset_pages("/sites"))
        many = len(sites) > 1
        for site in sites:
            tag = f"{site.get('name')} - " if many else ""
            self.site_checks(out, site, tag)
        if self.enabled("pending"):
            self.safe(out, "pending", self.pending)
        return out

    def pick_sites(self, sites):
        want = (self.dev.get("site") or "default").strip().lower()
        if want in ("*", "all"):
            return sites
        match = [s for s in sites if want in (str(s.get("name", "")).lower(), str(s.get("internalReference", "")).lower(),
                                              str(s.get("id", "")).lower())]
        if not match:
            avail = ", ".join(f"{s.get('name')} ({s.get('internalReference')})" for s in sites) or "none visible"
            raise ValueError(f"site '{want}' not found; this key can see: {avail}")
        return match

    def pending(self):
        waiting = self.offset_pages("/pending-devices", optional=True)
        if not waiting:
            return self.result("pending", OK, "none")
        names = ", ".join(str(p.get("name") or p.get("model") or p.get("macAddress")) for p in waiting[:6])
        return self.result("pending", WARN, f"{len(waiting)} waiting", "waiting to be adopted: " + names, numeric=float(len(waiting)))

    # ---------------------------------------------------------------- one site
    def site_checks(self, out, site, tag):
        sid = site.get("id")
        devices = self.offset_pages(f"/sites/{sid}/devices")
        for dev in devices:
            self.safe_rows(out, f"{tag}{dev.get('name') or dev.get('macAddress')}", lambda r, dev=dev: self.one_device(r, sid, dev))
        if self.enabled("clients"):
            try:
                data = self.get(f"/sites/{sid}/clients", {"offset": 0, "limit": 1})
                total = int((data or {}).get("totalCount") or 0) if isinstance(data, dict) else 0
                r = self.result("clients" if not tag else f"clients ({site.get('name')})", OK, str(total), numeric=float(total))
                out.append(r)
            except Exception as e:                                 # a count is nice to have; do not lose the devices over it
                out.append(self.result("clients", WARN, "unavailable", f"{type(e).__name__}: {e}"))

    def safe_rows(self, out, label, fn):
        """Rows for one device; a failure on it is reported against it and does not stop the others."""
        rows = []
        try:
            fn(rows.append)
        except Exception as e:
            rows.append(self.row(label, "statistics", "ERROR", "", f"{type(e).__name__}: {e}"))
        for r in rows:
            r.device = f"{self.name} / {label}"
        out.extend(rows)

    def one_device(self, add, sid, dev):
        def put(check, status, value="", msg="", numeric=None):
            add(self.result(check, status, value, msg, numeric))

        if self.enabled("devices"):
            status, word = state_status(dev.get("state"))
            put("state", status, word, f"{dev.get('model', '')} {dev.get('ipAddress', '')}".strip() if status != OK else "")
        sev = self.opts["firmware_severity"]
        if dev.get("firmwareUpdatable") and self.enabled("firmware") and sev != "Ignore":
            put("firmware", FAIL if sev == "FAIL" else WARN, dev.get("firmwareVersion") or "", "an update is available")
        if str(dev.get("state", "")).upper() != "ONLINE" or not any(self.enabled(k) for k in ("uptime", "cpu", "memory", "retries")):
            return
        if getattr(self, "_asked", 0) >= MAX_STATS:
            return
        self._asked = getattr(self, "_asked", 0) + 1
        import requests
        try:
            stats = self.get(f"/sites/{sid}/devices/{dev['id']}/statistics/latest")
        except requests.HTTPError as e:
            if getattr(e.response, "status_code", 0) in (400, 404, 501):        # some kinds of device have none
                return
            raise
        if not isinstance(stats, dict):
            return
        if self.enabled("uptime") and stats.get("uptimeSec") is not None:
            secs = float(stats["uptimeSec"])
            t = self.th["uptime"]
            status = grade_low(secs / 3600, t["warn"], t["fail"])
            put("uptime", status, display.uptime(seconds=secs), "recent reboot" if status != OK else "", secs / 3600)
        for key, field in (("cpu", "cpuUtilizationPct"), ("memory", "memoryUtilizationPct")):
            if self.enabled(key) and stats.get(field) is not None:
                v, t = float(stats[field]), self.th[key]
                put(key, grade(v, t["warn"], t["fail"]), f"{v:.0f}%", numeric=v)
        if self.enabled("retries"):
            for radio in (stats.get("interfaces") or {}).get("radios") or []:
                if radio.get("txRetriesPct") is not None:
                    v, t = float(radio["txRetriesPct"]), self.th["tx_retries"]
                    put(f"tx retries ({radio.get('frequencyGHz'):g} GHz)" if isinstance(radio.get("frequencyGHz"), (int, float)) else "tx retries",
                        grade(v, t["warn"], t["fail"]), f"{v:.0f}%", numeric=v)

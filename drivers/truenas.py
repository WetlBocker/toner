"""TrueNAS (CORE and SCALE) through its REST API v2.0 with an API key (the user menu > API Keys). The host is the TrueNAS address; the secret is the key.
Pool health and space, the system's own alerts, load, uptime and the version."""
from core import display
from .base import OK, WARN, FAIL, grade, grade_low
from .restapi import RestApi


class TruenasDriver(RestApi):
    PREFIX = "/api/v2.0"
    NAME = "TrueNAS"

    def auth(self):
        return {"Authorization": f"Bearer {self.password or ''}"}, None

    def run(self):
        out = []
        self.info = self.get("/system/info")
        if self.enabled("reachability"):
            out.append(self.result("reachability", OK, str(self.info.get("version", "TrueNAS")), str(self.info.get("hostname", ""))))
        for key, fn in (("pools", self.pools), ("alerts", self.alerts), ("load", self.load), ("uptime", self.uptime)):
            if self.enabled(key):
                self.safe(out, key, fn)
        return out

    def pools(self):
        pools = self.get("/pool", optional=True) or []
        if not pools:
            return []
        out, t = [], self.th["disk"]
        for p in pools:
            label = f"{self.name} / {p.get('name', 'pool')}"
            state = str(p.get("status") or "?").upper()
            healthy = p.get("healthy", state == "ONLINE")
            bad = state != "ONLINE" or not healthy
            rows = [self.result("pool", (FAIL if state in ("FAULTED", "UNAVAIL", "OFFLINE", "REMOVED") or not healthy and state != "DEGRADED" else WARN) if bad else OK,
                                state.lower(), "the pool is not healthy" if bad else "")]
            scan = p.get("scan") or {}
            if scan.get("errors"):
                rows.append(self.result("pool errors", FAIL, f"{scan['errors']} error(s)", f"{str(scan.get('function', 'scan')).lower()} found errors"))
            size, used = p.get("size"), p.get("allocated")
            if size and used is not None:
                pct = float(used) / float(size) * 100
                rows.append(self.result("pool space", grade(pct, t["warn"], t["fail"]), f"{pct:.0f}%", f"{float(size) / 2 ** 40:.1f} TiB pool", numeric=pct))
            for r in rows:
                r.device = label
            out += rows
        return out

    def alerts(self):
        rows = self.get("/alert/list", optional=True)
        if rows is None:
            return []
        live = [a for a in rows if isinstance(a, dict) and not a.get("dismissed") and str(a.get("level", "")).upper() in ("WARNING", "ERROR", "CRITICAL", "ALERT", "EMERGENCY")]
        if not live:
            return self.result("alerts", OK, "none", "", numeric=0.0)
        worst = FAIL if any(str(a.get("level")).upper() in ("ERROR", "CRITICAL", "ALERT", "EMERGENCY") for a in live) else WARN
        text = "; ".join(" ".join(str(a.get("formatted") or a.get("klass") or "alert").split())[:90] for a in live[:3])
        return self.result("alerts", worst, f"{len(live)} active", text, numeric=float(len(live)))

    def load(self):
        loads, cores = self.info.get("loadavg"), int(self.info.get("cores") or 1) or 1
        if not isinstance(loads, list) or len(loads) < 2:
            return []
        per = float(loads[1]) / cores
        t = self.th["load_per_core"]
        return self.result("load", grade(per, t["warn"], t["fail"]), f"{float(loads[1]):.2f}", f"5-minute average on {cores} core(s) ({per:.2f} each)", numeric=per)

    def uptime(self):
        secs = self.info.get("uptime_seconds")
        if secs is None:
            return []
        hours = float(secs) / 3600
        t = self.th["uptime"]
        status = grade_low(hours, t["warn"], t["fail"])
        return self.result("uptime", status, display.uptime(hours), "recent reboot" if status != OK else "", numeric=hours)

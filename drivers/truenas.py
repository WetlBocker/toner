"""TrueNAS (CORE and SCALE) through its REST API v2.0 with an API key (the user menu > API Keys). The host is the TrueNAS address; the secret is the key.
Pool health and space, the system's own alerts, load, uptime and the version."""
from core import display, tlsverify
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
        self.found_software(self.info.get("version", "") if isinstance(self.info, dict) else "")
        if self.enabled("reachability"):
            out.append(self.result("reachability", OK, str(self.info.get("version", "TrueNAS")), str(self.info.get("hostname", ""))))
        for key, fn in (("pools", self.pools), ("alerts", self.alerts), ("load", self.load), ("uptime", self.uptime),
                        ("disks", self.disks), ("datasets", self.datasets), ("services", self.services)):
            if self.enabled(key):
                self.safe(out, key, fn)
        return out

    def disks(self):
        """Every disk: a failed SMART test is a FAIL, the hottest disk is graded against the temperature limit."""
        disks = self.get("/disk", optional=True) or []
        if not disks:
            return []
        names = [d.get("name") for d in disks if d.get("name")]
        failed = []
        results = self.get("/smart/test/results", optional=True) or []
        for r in results if isinstance(results, list) else []:
            tests = r.get("tests") or []
            last = tests[-1] if tests else {}
            if str(last.get("status") or "").upper() in ("FAILED", "FAIL") or str(r.get("status") or "").upper() == "FAILED":
                failed.append(str(r.get("disk") or r.get("name") or "disk"))
        hottest, hot_name = None, ""
        temps = self._temperatures(names)
        for n, t in temps.items():
            if isinstance(t, (int, float)) and (hottest is None or t > hottest):
                hottest, hot_name = float(t), n
        th = self.th["temperature"]
        st = FAIL if failed else (grade(hottest, th["warn"], th["fail"]) if hottest is not None else OK)
        msg = ("SMART failed: " + ", ".join(failed[:5])) if failed else (f"hottest {hot_name} at {hottest:.0f}C" if hottest is not None else "")
        return self.result("disks", st, f"{len(disks)} disk(s)", msg, numeric=hottest)

    def _temperatures(self, names):
        """{disk: C} from the temperatures call (SCALE and newer CORE); nothing when the API lacks it."""
        if not names:
            return {}
        try:
            import requests
            from core import proxy
            headers, _auth = self.auth()
            r = requests.post(self.base() + "/disk/temperatures", json={"names": names}, headers={"Accept": "application/json", **headers},
                              timeout=self.opts["http_timeout"], verify=tlsverify.verify(self.dev), **proxy.requests_kwargs(self.dev))
            if r.status_code != 200:
                return {}
            data = r.json()
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def datasets(self):
        """Each dataset's used space against the disk limit; the fullest ones are named."""
        sets = self.get("/pool/dataset", optional=True) or []
        rows = []
        for ds in self._flatten(sets):
            used, avail = (ds.get("used") or {}).get("parsed"), (ds.get("available") or {}).get("parsed")
            try:
                used, avail = float(used), float(avail)
            except (TypeError, ValueError):
                continue
            total = used + avail
            if total <= 0:
                continue
            rows.append((ds.get("name") or ds.get("id") or "dataset", used / total * 100, used, total))
        if not rows:
            return []
        t = self.th["disk"]
        rows.sort(key=lambda r: -r[1])
        full = [f"{n} ({p:.0f}%)" for n, p, _u, _t in rows if grade(p, t["warn"], t["fail"]) != OK]
        worst = grade(rows[0][1], t["warn"], t["fail"])
        return self.result("datasets", worst, f"{len(rows)} dataset(s)", "; ".join(full[:5]) if full else f"fullest {rows[0][0]} at {rows[0][1]:.0f}%", numeric=rows[0][1])

    @staticmethod
    def _flatten(sets):
        out = []
        for ds in sets or []:
            if isinstance(ds, dict):
                out.append(ds)
                out += TruenasDriver._flatten(ds.get("children") or [])
        return out

    def services(self):
        """A service set to start that is not running is a FAIL."""
        svcs = self.get("/service", optional=True)
        if svcs is None:
            return []
        running = [s for s in svcs if str(s.get("state") or "").upper() == "RUNNING"]
        stopped = [str(s.get("service") or "service") for s in svcs if s.get("enable") and str(s.get("state") or "").upper() != "RUNNING"]
        return self.result("services", FAIL if stopped else OK, f"{len(running)} running", "enabled but stopped: " + ", ".join(stopped[:6]) if stopped else "", numeric=float(len(stopped)))

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

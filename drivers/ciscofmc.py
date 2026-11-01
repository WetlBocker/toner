"""Cisco Secure Firewall Management Center (FMC) through its REST API: a user name and password make a token
(/api/fmc_platform/v1/auth/generatetoken) that lasts 30 minutes. What it checks: the FMC answers and its version, every managed
device's health and software, devices with a deployment waiting, and the state of HA pairs."""
from .base import OK, WARN, FAIL
from .webapi import WebApi


class CiscoFmcDriver(WebApi):
    NAME = "FMC"

    def login(self):
        r = self.call("POST", "/api/fmc_platform/v1/auth/generatetoken", raw=True, auth=(self.dev.get("username") or "", self.password or ""))
        headers = getattr(r, "headers", {}) or {}
        token = headers.get("X-auth-access-token") or headers.get("x-auth-access-token")
        if not token:
            raise ValueError("FMC gave no token back")
        self.session().headers["X-auth-access-token"] = token
        self.domain = headers.get("DOMAIN_UUID") or headers.get("domain_uuid") or ""
        if not self.domain:
            doms = self.get("/api/fmc_platform/v1/info/domain", optional=True) or {}
            items = doms.get("items") or []
            self.domain = (items[0].get("uuid") if items else "") or ""

    def run(self):
        out = []
        try:
            self.login()
            info = self.get("/api/fmc_platform/v1/info/serverversion", optional=True) or {}
            item = (info.get("items") or [{}])[0] if isinstance(info, dict) else {}
            version = str(item.get("serverVersion") or "")
            self.found_software(version)
            if self.enabled("reachability"):
                out.append(self.result("reachability", OK, version or "answering", f"domain {self.domain[:8]}" if self.domain else ""))
            self.devices_ = (self.get(f"/api/fmc_config/v1/domain/{self.domain}/devices/devicerecords", optional=True, params={"expanded": "true", "limit": 1000}) or {}).get("items") or []
            for key, fn in (("devices", self.devices), ("deployment", self.deployment), ("ha", self.ha)):
                if self.enabled(key):
                    self.safe(out, key, fn)
        finally:
            self.close()
        return out

    def devices(self):
        if not self.devices_:
            return self.result("devices", WARN, "none", "no managed devices")
        rows, bad = [], []
        for d in self.devices_:
            name = d.get("name") or d.get("hostName") or "device"
            health = str(d.get("healthStatus") or d.get("HealthStatus") or "").lower()
            sw = str(d.get("sw_version") or d.get("swVersion") or "")
            status = OK if health in ("green", "normal", "ok") else WARN if health in ("yellow", "warning", "disabled", "") else FAIL
            if status != OK:
                bad.append(f"{name} ({health or 'unknown'})")
            r = self.result("device health", status, health or "unknown", f"{d.get('model', '')} {sw}".strip())
            r.device = f"{self.name} / {name}"
            rows.append(r)
        rows.insert(0, self.result("devices", FAIL if any("red" in b or "critical" in b for b in bad) else WARN if bad else OK,
                                   f"{len(self.devices_) - len(bad)}/{len(self.devices_)} healthy", "; ".join(bad[:5]), numeric=float(len(self.devices_) - len(bad))))
        return rows

    def deployment(self):
        data = self.get(f"/api/fmc_config/v1/domain/{self.domain}/deployment/deployabledevices", optional=True, params={"expanded": "true", "limit": 1000})
        if not isinstance(data, dict):
            return []
        waiting = [d.get("name") or d.get("device", {}).get("name") or "device" for d in data.get("items") or [] if d.get("canBeDeployed", True)]
        return self.result("deployment", WARN if waiting else OK, f"{len(waiting)} waiting" if waiting else "none waiting",
                           ("changes not yet deployed to: " + ", ".join(waiting[:6])) if waiting else "", numeric=float(len(waiting)))

    def ha(self):
        data = self.get(f"/api/fmc_config/v1/domain/{self.domain}/devicehapairs/ftddevicehapairs", optional=True, params={"expanded": "true"})
        pairs = (data or {}).get("items") or [] if isinstance(data, dict) else []
        if not pairs:
            return []
        bad = []
        for p in pairs:
            name = p.get("name") or "pair"
            prim = str(((p.get("primaryStatus") or {}).get("currentStatus")) or "").lower()
            sec = str(((p.get("secondaryStatus") or {}).get("currentStatus")) or "").lower()
            states = {prim, sec}
            if not (("active" in states) and any(s in ("standby", "standby ready") for s in states)):
                bad.append(f"{name} ({prim or '?'} / {sec or '?'})")
        return self.result("ha", FAIL if bad else OK, f"{len(pairs) - len(bad)}/{len(pairs)} pairs healthy", "; ".join(bad[:4]), numeric=float(len(pairs) - len(bad)))

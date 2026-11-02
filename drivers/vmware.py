"""VMware vCenter through the vSphere Automation REST API: a user name and password open a session (POST /api/session). What it
checks: vCenter answers and its version, every host is connected and powered on, how many VMs are powered on, each datastore's
space, and the appliance's own health lights (system, memory, load, storage, database)."""
from .base import OK, WARN, FAIL, grade
from .webapi import WebApi
from core import quiet

LIGHT = {"green": OK, "gray": OK, "grey": OK, "yellow": WARN, "orange": WARN, "red": FAIL}


class VmwareDriver(WebApi):
    NAME = "vCenter"

    def login(self):
        sid = self.post("/api/session", auth=(self.dev.get("username") or "", self.password or ""))
        if not isinstance(sid, str) or not sid:
            raise ValueError("vCenter gave no session back")
        self.session().headers["vmware-api-session-id"] = sid

    def run(self):
        out = []
        try:
            self.login()
            ver = self.get("/api/appliance/system/version", optional=True) or {}
            version = str(ver.get("version") or "") if isinstance(ver, dict) else ""
            self.found_software(version, ver.get("build", "") if isinstance(ver, dict) else "")
            if self.enabled("reachability"):
                out.append(self.result("reachability", OK, version or "answering", str(ver.get("product") or "") if isinstance(ver, dict) else ""))
            for key, fn in (("hosts", self.hosts), ("vms", self.vms), ("datastores", self.datastores), ("health", self.health)):
                if self.enabled(key):
                    self.safe(out, key, fn)
        finally:
            try:
                self.call("DELETE", "/api/session", optional=True, raw=True)
            except Exception:
                quiet.ignored()
            self.close()
        return out

    def hosts(self):
        hosts = self.get("/api/vcenter/host") or []
        if not hosts:
            return self.result("hosts", WARN, "none", "vCenter lists no hosts")
        rows, bad = [], []
        for h in hosts:
            name = h.get("name") or h.get("host") or "host"
            conn, power = str(h.get("connection_state") or "").upper(), str(h.get("power_state") or "").upper()
            okay = conn == "CONNECTED" and power in ("POWERED_ON", "")
            if not okay:
                bad.append(f"{name} ({conn.lower() or '?'}{', ' + power.lower() if power else ''})")
            r = self.result("host", OK if okay else FAIL, f"{conn.lower()}{', ' + power.lower() if power else ''}", "")
            r.device = f"{self.name} / {name}"
            rows.append(r)
        rows.insert(0, self.result("hosts", FAIL if bad else OK, f"{len(hosts) - len(bad)}/{len(hosts)} connected", "; ".join(bad[:5]), numeric=float(len(hosts) - len(bad))))
        return rows

    def vms(self):
        vms = self.get("/api/vcenter/vm", optional=True)
        if vms is None:
            return []
        on = [v for v in vms if str(v.get("power_state") or "").upper() == "POWERED_ON"]
        return self.result("vms", OK, f"{len(on)} of {len(vms)} powered on", "", numeric=float(len(on)))

    def datastores(self):
        stores = self.get("/api/vcenter/datastore", optional=True) or []
        if not stores:
            return []
        rows, worst = [], OK
        t = self.th["disk"]
        full = []
        for s in stores:
            cap, free = s.get("capacity"), s.get("free_space")
            try:
                cap, free = float(cap), float(free)
            except (TypeError, ValueError):
                continue
            if cap <= 0:
                continue
            pct = (cap - free) / cap * 100
            st = grade(pct, t["warn"], t["fail"])
            if st != OK:
                full.append(f"{s.get('name', 'datastore')} ({pct:.0f}%)")
            r = self.result("datastore space", st, f"{pct:.0f}%", f"{free / 2 ** 30:.0f} GiB free of {cap / 2 ** 30:.0f}", numeric=pct)
            r.device = f"{self.name} / {s.get('name', 'datastore')}"
            rows.append(r)
            worst = FAIL if FAIL in (worst, st) else WARN if WARN in (worst, st) else OK
        if not rows:
            return []
        rows.insert(0, self.result("datastores", worst, f"{len(stores)} datastore(s)", "; ".join(full[:5]) if full else "all under the limits", numeric=float(len(full))))
        return rows

    def health(self):
        found, bad = [], []
        for part in ("system", "mem", "load", "storage", "database-storage", "swap"):
            light = self.get(f"/api/appliance/health/{part}", optional=True)
            if not isinstance(light, str):
                continue
            found.append(part)
            st = LIGHT.get(light.lower(), WARN)
            if st != OK:
                bad.append(f"{part}: {light.lower()}")
        if not found:
            return []
        worst = FAIL if any(b.endswith("red") for b in bad) else WARN if bad else OK
        return self.result("health", worst, "all green" if not bad else f"{len(bad)} not green", "; ".join(bad[:6]), numeric=float(len(bad)))

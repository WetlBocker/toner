"""Juniper Mist, the cloud: an API token (Organization > Settings > API Tokens) and the organization ID. The host is Mist's API
address for your region (api.mist.com, api.eu.mist.com, api.gc1.mist.com...). What it checks: Mist answers, every device in the
organization is connected (with its version and uptime), open alarms, and CPU and memory on the switches and gateways."""
from core import display
from .base import OK, WARN, FAIL, grade, grade_low
from .webapi import WebApi


class MistDriver(WebApi):
    NAME = "Mist"

    def session(self):
        s = super().session()
        s.headers["Authorization"] = f"Token {self.password or ''}"
        return s

    def org(self):
        org = (self.dev.get("site") or "").strip()
        if not org:
            raise ValueError("enter the organization ID in the device's Organization field")
        return org

    def run(self):
        out = []
        try:
            me = self.get("/api/v1/self") or {}
            org = self.org()
            self.devices_ = self.get(f"/api/v1/orgs/{org}/stats/devices", params={"type": "all", "limit": 1000}) or []
            if isinstance(self.devices_, dict):
                self.devices_ = self.devices_.get("results") or []
            if self.enabled("reachability"):
                out.append(self.result("reachability", OK, f"{len(self.devices_)} device(s)", str(me.get("email") or me.get("name") or "")))
            for key, fn in (("devices", self.devices), ("alarms", self.alarms), ("resources", self.resources)):
                if self.enabled(key):
                    self.safe(out, key, fn)
        finally:
            self.close()
        return out

    def devices(self):
        if not self.devices_:
            return self.result("devices", WARN, "none", "the organization has no devices")
        rows, down = [], []
        t = self.th["uptime"]
        for d in self.devices_:
            name = d.get("name") or d.get("mac") or "device"
            status = str(d.get("status") or "").lower()
            connected = status == "connected"
            if not connected:
                down.append(name)
            r = self.result("device", OK if connected else FAIL, status or "unknown", f"{d.get('type', '')} {d.get('model', '')} {d.get('version', '')}".strip())
            r.device = f"{self.name} / {name}"
            rows.append(r)
            if connected and isinstance(d.get("uptime"), (int, float)):
                hours = float(d["uptime"]) / 3600
                st = grade_low(hours, t["warn"], t["fail"])
                u = self.result("uptime", st, display.uptime(hours), "recent reboot" if st != OK else "", numeric=hours)
                u.device = f"{self.name} / {name}"
                rows.append(u)
        rows.insert(0, self.result("devices", FAIL if down else OK, f"{len(self.devices_) - len(down)}/{len(self.devices_)} connected",
                                   "disconnected: " + ", ".join(down[:6]) if down else "", numeric=float(len(self.devices_) - len(down))))
        return rows

    def alarms(self):
        data = self.get(f"/api/v1/orgs/{self.org()}/alarms/search", optional=True, params={"duration": "1d", "limit": 200})
        if not isinstance(data, dict):
            return []
        items = data.get("results") or []
        open_ = [a for a in items if not a.get("acked")]
        kinds = {}
        for a in open_:
            kinds[a.get("type") or "alarm"] = kinds.get(a.get("type") or "alarm", 0) + 1
        return self.result("alarms", WARN if open_ else OK, str(len(open_)), ", ".join(f"{k} x{n}" for k, n in sorted(kinds.items())[:6]) if open_ else "no open alarms today", numeric=float(len(open_)))

    def resources(self):
        rows = []
        for d in self.devices_:
            if str(d.get("type") or "") not in ("switch", "gateway"):
                continue
            name = d.get("name") or d.get("mac") or "device"
            cpu = d.get("cpu_stat") or {}
            idle = cpu.get("idle") if isinstance(cpu, dict) else None
            if isinstance(idle, (int, float)):
                val = 100 - float(idle)
                t = self.th["cpu"]
                r = self.result("cpu", grade(val, t["warn"], t["fail"]), f"{val:.0f}%", "", numeric=val)
                r.device = f"{self.name} / {name}"
                rows.append(r)
            mem = d.get("memory_stat") or {}
            usage = mem.get("usage") if isinstance(mem, dict) else None
            if isinstance(usage, (int, float)):
                val = float(usage)
                t = self.th["memory"]
                r = self.result("memory", grade(val, t["warn"], t["fail"]), f"{val:.0f}%", "", numeric=val)
                r.device = f"{self.name} / {name}"
                rows.append(r)
        return rows

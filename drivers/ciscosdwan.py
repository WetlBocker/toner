"""Cisco Catalyst SD-WAN Manager (vManage) through its REST API: a user name and password sign in (j_security_check), then
/dataservice. What it checks: the Manager answers and its version, every device in the overlay is reachable, control connections
and BFD sessions on the edges, open alarms, and the Manager's own CPU and memory."""
from .base import OK, WARN, FAIL, grade
from .webapi import WebApi
from core import quiet


class CiscoSdwanDriver(WebApi):
    NAME = "SD-WAN Manager"

    def login(self):
        s = self.session()
        r = self.call("POST", "/j_security_check", raw=True, data={"j_username": self.dev.get("username") or "", "j_password": self.password or ""},
                      headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "*/*"})
        if "<html" in (getattr(r, "text", "") or "").lower():
            from .base import AuthRejected
            raise AuthRejected("SD-WAN Manager rejected the user name or password")
        try:
            tok = self.call("GET", "/dataservice/client/token", raw=True, headers={"Accept": "text/plain"})
            if tok is not None and getattr(tok, "text", ""):
                s.headers["X-XSRF-TOKEN"] = tok.text.strip()
        except Exception:
            quiet.ignored()

    def run(self):
        out = []
        try:
            self.login()
            about = self.get("/dataservice/client/about", optional=True) or {}
            version = str((about.get("data") or {}).get("version") or about.get("version") or "") if isinstance(about, dict) else ""
            self.devices_ = (self.get("/dataservice/device") or {}).get("data") or []
            if not version:
                version = next((str(d.get("version") or "") for d in self.devices_ if str(d.get("device-type") or "").lower() == "vmanage"), "")
            self.found_software(version)
            if self.enabled("reachability"):
                out.append(self.result("reachability", OK, version or "answering", f"{len(self.devices_)} device(s) in the overlay"))
            for key, fn in (("devices", self.devices), ("control connections", self.control), ("bfd", self.bfd), ("alarms", self.alarms), ("resources", self.resources)):
                if self.enabled(key):
                    self.safe(out, key, fn)
        finally:
            self.close()
        return out

    @staticmethod
    def _name(d):
        return d.get("host-name") or d.get("system-ip") or d.get("deviceId") or "device"

    def devices(self):
        down = [self._name(d) for d in self.devices_ if str(d.get("reachability") or "").lower() != "reachable"]
        total = len(self.devices_)
        if not total:
            return self.result("devices", WARN, "none", "the Manager lists no devices")
        return self.result("devices", FAIL if down else OK, f"{total - len(down)}/{total} reachable", "unreachable: " + ", ".join(down[:6]) if down else "", numeric=float(total - len(down)))

    def _edges(self):
        return [d for d in self.devices_ if str(d.get("device-type") or "").lower() in ("vedge", "cedge", "edge")]

    def control(self):
        edges = self._edges()
        if not edges:
            return []
        none = [self._name(d) for d in edges if str(d.get("reachability") or "").lower() == "reachable" and self._int(d.get("controlConnections")) == 0]
        return self.result("control connections", FAIL if none else OK, f"{len(edges) - len(none)}/{len(edges)} edges connected",
                           "no control connection: " + ", ".join(none[:6]) if none else "", numeric=float(len(edges) - len(none)))

    def bfd(self):
        edges = self._edges()
        up = total = 0
        short = []
        for d in edges:
            t, u = self._int(d.get("bfdSessions")), self._int(d.get("bfdSessionsUp"))
            if t is None:
                continue
            total += t
            up += u if u is not None else t
            if u is not None and u < t:
                short.append(f"{self._name(d)} ({u}/{t})")
        if not total:
            return []
        return self.result("bfd", WARN if short else OK, f"{up}/{total} up", "sessions down on: " + ", ".join(short[:6]) if short else "", numeric=float(up))

    def alarms(self):
        data = self.get("/dataservice/alarms/count", optional=True)
        if not isinstance(data, dict):
            return []
        count = self._int(data.get("count")) if "count" in data else None
        if count is None:
            inner = data.get("data") or {}
            count = self._int(inner.get("count")) if isinstance(inner, dict) else None
        if count is None:
            return []
        return self.result("alarms", WARN if count else OK, str(count), "open alarms" if count else "no open alarms", numeric=float(count))

    def resources(self):
        mgr = next((d for d in self.devices_ if str(d.get("device-type") or "").lower() == "vmanage"), None)
        if not mgr:
            return []
        data = self.get("/dataservice/device/system/status", optional=True, params={"deviceId": mgr.get("system-ip") or mgr.get("deviceId")})
        rows = ((data or {}).get("data") or []) if isinstance(data, dict) else []
        if not rows:
            return []
        s = rows[0]
        out = []
        idle = self._float(s.get("cpu_idle"))
        if idle is not None:
            cpu = 100 - idle
            t = self.th["cpu"]
            out.append(self.result("cpu", grade(cpu, t["warn"], t["fail"]), f"{cpu:.0f}%", "the Manager", numeric=cpu))
        pct = self.pct(s.get("mem_used"), s.get("mem_total"))
        if pct is not None:
            t = self.th["memory"]
            out.append(self.result("memory", grade(pct, t["warn"], t["fail"]), f"{pct:.0f}%", "the Manager", numeric=pct))
        return out

    @staticmethod
    def _int(v):
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _float(v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

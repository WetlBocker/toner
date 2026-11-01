"""SonicWall firewalls through the SonicOS API (Device > Settings > Administration > Audit / SonicOS API: enable it and RFC-2617
HTTP Basic authentication; an administrator user). What it checks: the firewall answers and its firmware, uptime, CPU and memory
from the system status report, interfaces, HA state and licences. The exact report paths differ between SonicOS 6.5 and 7:
each is tried and skipped when the firewall does not have it."""
import re

from .base import OK, WARN, FAIL, grade, grade_low
from core import display
from .webapi import WebApi


class SonicwallDriver(WebApi):
    NAME = "SonicOS API"
    PREFIX = "/api/sonicos"

    def login(self):
        self.post("/auth", auth=(self.dev.get("username") or "", self.password or ""), json={"override": True}, optional=True)

    def run(self):
        out = []
        try:
            self.login()
            ver = self.get("/version", optional=True) or {}
            version = str(ver.get("firmware_version") or ver.get("version") or "") if isinstance(ver, dict) else ""
            self.found_software(version)
            if self.enabled("reachability"):
                out.append(self.result("reachability", OK, version or "answering", str(ver.get("model") or "") if isinstance(ver, dict) else ""))
            self.status_ = self.get("/reporting/status/system", optional=True) or {}
            for key, fn in (("uptime", self.uptime), ("resources", self.resources), ("interfaces", self.interfaces), ("ha", self.ha), ("licenses", self.licenses)):
                if self.enabled(key):
                    self.safe(out, key, fn)
        finally:
            try:
                self.call("DELETE", "/auth", optional=True, raw=True)
            except Exception:
                pass
            self.close()
        return out

    def _find(self, obj, *words):
        """The first value whose key holds every word (case-insensitive), anywhere in a nested reply."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                lk = str(k).lower().replace("-", "_")
                if all(w in lk for w in words) and not isinstance(v, (dict, list)):
                    return v
            for v in obj.values():
                found = self._find(v, *words)
                if found is not None:
                    return found
        elif isinstance(obj, list):
            for v in obj:
                found = self._find(v, *words)
                if found is not None:
                    return found
        return None

    def uptime(self):
        text = self._find(self.status_, "uptime") or self._find(self.status_, "up_time")
        if text is None:
            return []
        hours = None
        if isinstance(text, (int, float)):
            hours = float(text) / 3600
        else:
            days = re.search(r"(\d+)\s*day", str(text), re.I)
            hm = re.search(r"(\d+)\s*hour", str(text), re.I) or re.search(r"(\d+):(\d+)", str(text))
            hours = (int(days.group(1)) * 24 if days else 0) + (int(hm.group(1)) if hm else 0)
        t = self.th["uptime"]
        st = grade_low(hours, t["warn"], t["fail"])
        return self.result("uptime", st, display.uptime(hours), "recent reboot" if st != OK else "", numeric=float(hours))

    def resources(self):
        out = []
        cpu = self._find(self.status_, "cpu")
        mem = self._find(self.status_, "memory") or self._find(self.status_, "ram")
        for key, raw in (("cpu", cpu), ("memory", mem)):
            if raw is None:
                continue
            m = re.search(r"\d+(?:\.\d+)?", str(raw))
            if not m:
                continue
            val = float(m.group(0))
            t = self.th[key]
            out.append(self.result(key, grade(val, t["warn"], t["fail"]), f"{val:.0f}%", "", numeric=val))
        return out

    def interfaces(self):
        data = self.get("/reporting/interfaces/ipv4", optional=True)
        if data is None:
            data = self.get("/interfaces/ipv4", optional=True)
        if not isinstance(data, dict):
            return []
        items = data.get("interfaces") or data.get("ipv4") or []
        states = []
        for it in items:
            inner = it.get("ipv4") or it
            name = inner.get("name") or it.get("name") or ""
            link = str(self._find(it, "link") or self._find(it, "status") or "").lower()
            if not name:
                continue
            if not link:
                continue
            states.append((name, "up" if "up" in link or "connected" in link else "down" if "down" in link or "no link" in link else "off"))
        return self.interfaces_row(states)

    def ha(self):
        data = self.get("/reporting/high-availability/status", optional=True)
        if not isinstance(data, dict):
            return []
        mode = str(self._find(data, "mode") or "").lower()
        if not mode or mode in ("none", "disabled", "off"):
            return []
        state = str(self._find(data, "state") or self._find(data, "status") or "").lower()
        peer = str(self._find(data, "peer") or "").lower()
        bad = ("standby" not in state and "active" not in state) or ("fail" in peer or "down" in peer)
        return self.result("ha", FAIL if bad else OK, state or mode, f"peer: {peer}" if peer else "")

    def licenses(self):
        data = self.get("/reporting/licenses", optional=True)
        if data is None:
            data = self.get("/licenses", optional=True)
        if not isinstance(data, (dict, list)):
            return []
        items = data.get("licenses") if isinstance(data, dict) else data
        if not isinstance(items, list):
            return []
        expired = [str(i.get("name") or i.get("service") or "licence") for i in items if isinstance(i, dict) and str(i.get("status") or "").lower() in ("expired", "not licensed", "inactive")]
        return self.result("licenses", WARN if expired else OK, f"{len(items) - len(expired)}/{len(items)} active", "expired: " + ", ".join(expired[:6]) if expired else "", numeric=float(len(items) - len(expired)))

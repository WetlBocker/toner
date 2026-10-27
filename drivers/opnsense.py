"""OPNsense through its API. In the web interface: System > Access > Users > (a user) > API keys: that makes a key and a secret. Store them as
key:secret in the password box. The host is the firewall's address. Firmware updates waiting, memory, disk, uptime and the state of each gateway."""
import re

from core import display
from .base import OK, WARN, FAIL, grade, grade_low
from .restapi import RestApi


def _uptime_hours(text):
    """'2 days, 3:04:05' or '3:04:05' or '1 day, 4 hours' ... -> hours."""
    t = str(text or "")
    days = re.search(r"(\d+)\s+day", t)
    clock = re.search(r"(\d+):(\d+)(?::(\d+))?", t)
    hours = re.search(r"(\d+)\s+hour", t)
    mins = re.search(r"(\d+)\s+min", t)
    total = int(days.group(1)) * 24 if days else 0
    if clock:
        total += int(clock.group(1)) + int(clock.group(2)) / 60 + int(clock.group(3) or 0) / 3600
    elif hours or mins:
        total += (int(hours.group(1)) if hours else 0) + (int(mins.group(1)) / 60 if mins else 0)
    return total if (days or clock or hours or mins) else None


class OpnsenseDriver(RestApi):
    NAME = "OPNsense"

    def auth(self):
        key, _, secret = (self.password or "").partition(":")
        return {}, (key, secret)

    def run(self):
        out = []
        fw = self.get("/api/core/firmware/status")
        self.found_software(fw.get("product_version", ""))
        if self.enabled("reachability"):
            out.append(self.result("reachability", OK, f"OPNsense {fw.get('product_version', '')}".strip(), ""))
        if self.enabled("firmware"):
            self.safe(out, "firmware", lambda: self.firmware(fw))
        for key, fn in (("memory", self.memory), ("disk", self.disk), ("uptime", self.uptime), ("gateways", self.gateways)):
            if self.enabled(key):
                self.safe(out, key, fn)
        return out

    def firmware(self, fw):
        status = str(fw.get("status") or "").lower()
        n = len(fw.get("upgrade_packages") or []) + len(fw.get("new_packages") or [])
        if status in ("update", "upgrade") or n:
            return self.result("firmware", WARN, f"{n or 'some'} update(s)", str(fw.get("status_msg") or "updates are available"), numeric=float(n))
        return self.result("firmware", OK, "up to date", str(fw.get("product_version", "")))

    def memory(self):
        res = self.get("/api/diagnostics/system/systemResources", optional=True)
        mem = (res or {}).get("memory") or {}
        total, used = mem.get("total"), mem.get("used")
        try:
            pct = float(used) / float(total) * 100
        except (TypeError, ValueError, ZeroDivisionError):
            return []
        return self.level_check("memory", pct)

    def disk(self):
        res = self.get("/api/diagnostics/system/systemDisk", optional=True)
        pcts = []
        for d in (res or {}).get("devices") or []:
            try:
                pcts.append((float(d.get("used_pct")), d.get("mountpoint", "?")))
            except (TypeError, ValueError):
                continue
        if not pcts:
            return []
        pct, mount = max(pcts)
        t = self.th["disk"]
        return self.result("disk", grade(pct, t["warn"], t["fail"]), f"{pct:.0f}%", mount, numeric=pct)

    def uptime(self):
        res = self.get("/api/diagnostics/system/systemTime", optional=True)
        hours = _uptime_hours((res or {}).get("uptime"))
        if hours is None:
            return []
        t = self.th["uptime"]
        status = grade_low(hours, t["warn"], t["fail"])
        return self.result("uptime", status, display.uptime(hours), "recent reboot" if status != OK else "", numeric=hours)

    def gateways(self):
        res = self.get("/api/routes/gateway/status", optional=True)
        items = (res or {}).get("items") or []
        if not items:
            return []
        out = []
        for g in items:
            state = str(g.get("status_translated") or g.get("status") or "").lower()
            if state in ("online", "none", ""):
                level = OK
            elif state in ("pending", "unknown", "force down"):
                level = WARN
            else:
                level = FAIL if "down" in state or "offline" in state else WARN
            detail = ", ".join(x for x in (g.get("delay"), (f"{g.get('loss')} loss" if g.get("loss") not in (None, "", "0.0 %", "~") else "")) if x and x != "~")
            r = self.result("gateway", level, state or "online", detail)
            r.device = f"{self.name} / {g.get('name', 'gateway')}"
            out.append(r)
        return out

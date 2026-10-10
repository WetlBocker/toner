from core import proxy
import re
import xml.etree.ElementTree as ET

import requests
import urllib3

from .base import Driver, OK, WARN, FAIL, grade, grade_low
from .sshbase import worse


class PaloAltoDriver(Driver):
    """PAN-OS firewalls through the XML API. The API key is the stored secret."""

    def _op(self, cmd):
        d = self.dev
        if not d.get("verify_ssl"):
            urllib3.disable_warnings()
        r = requests.get(f"https://{d['host']}:{d.get('port') or 443}/api/",
                         params={"type": "op", "cmd": cmd}, headers={"X-PAN-KEY": self.password or ""},
                         verify=bool(d.get("verify_ssl")), timeout=self.opts["http_timeout"], **proxy.requests_kwargs(d))
        r.raise_for_status()
        root = ET.fromstring(r.content)
        if root.get("status") != "success":
            msg = root.findtext(".//msg") or root.findtext(".//line") or "request failed"
            raise ValueError(f"PAN-OS API: {msg.strip()}")
        return root.find("result")

    def run(self):
        out = []
        for name, fn in (("resources", self.resources), ("uptime", self.uptime), ("firmware", self.firmware),
                         ("sessions", self.sessions), ("ha", self.ha), ("interfaces", self.interfaces)):
            if self.enabled(name):
                self.safe(out, name, fn)
        return out

    def _system(self):
        if not hasattr(self, "_sys"):
            res = self._op("<show><system><info/></system></show>")
            self._sys = res.find("system") if res is not None else None
            if self._sys is None:
                raise ValueError("no system information in the reply")
        return self._sys

    def resources(self):
        res = self._op("<show><system><resources/></system></show>")
        text = (res.text or "") if res is not None else ""
        idle = re.search(r"%Cpu\(s\):.*?([\d.]+)\s*id", text)
        mem = re.search(r"Mem\s*:\s*([\d.]+)\s*total,\s*([\d.]+)\s*free,\s*([\d.]+)\s*used(?:,\s*([\d.]+)\s*buff/cache)?",
                        text)
        if not (idle and mem):
            raise ValueError("could not read CPU and memory from 'show system resources'")
        total, free, cache = float(mem.group(1)), float(mem.group(2)), float(mem.group(4) or 0)
        return [self.level_check("cpu", 100 - float(idle.group(1))),
                self.level_check("memory", (total - free - cache) / total * 100)]

    def uptime(self):
        text = (self._system().findtext("uptime") or "").strip()
        m = re.match(r"(?:(\d+)\s+days?,\s*)?(\d+):(\d+):(\d+)", text)
        if not m:
            raise ValueError(f"unrecognised uptime '{text}'")
        hours = int(m.group(1) or 0) * 24 + int(m.group(2)) + int(m.group(3)) / 60
        t = self.th["uptime"]
        status = grade_low(hours, t["warn"], t["fail"])
        return self.result("uptime", status, text, "recent reboot" if status != OK else "", numeric=hours)

    def firmware(self):
        s = self._system()
        return self.result("firmware", OK, s.findtext("sw-version") or "?", s.findtext("model") or "")

    def sessions(self):
        res = self._op("<show><session><info/></session></show>")
        active, mx = res.findtext("num-active"), res.findtext("num-max")
        if not (active and mx and int(mx)):
            raise ValueError("could not read the session table size")
        pct = int(active) / int(mx) * 100
        t = self.th["sessions"]
        return self.result("sessions", grade(pct, t["warn"], t["fail"]), f"{pct:.0f}%",
                           f"{int(active):,} of {int(mx):,}", numeric=pct)

    def ha(self):
        res = self._op("<show><high-availability><state/></high-availability></show>")
        expected = bool(self.dev.get("ha_expected"))
        if (res.findtext("enabled") or "no").lower() != "yes":
            return self.result("ha", FAIL if expected else OK, "not configured",
                               "HA is expected but not enabled" if expected else "")
        local = (res.findtext(".//local-info/state") or "?").lower()
        peer = (res.findtext(".//peer-info/state") or "?").lower()
        conn = (res.findtext(".//peer-info/conn-status") or "up").lower()
        sync = (res.findtext(".//running-sync") or "synchronized").lower()
        status, msgs = OK, []
        if local in ("suspended", "non-functional", "tentative", "initial"):
            status, msgs = FAIL, [f"this unit is {local}"]
        if conn != "up":
            status, msgs = FAIL, msgs + ["peer unreachable"]
        if sync != "synchronized":
            status, msgs = worse(status, WARN), msgs + [f"config {sync}"]
        return self.result("ha", status, f"{local} / peer {peer}", "; ".join(msgs))

    def interfaces(self):
        res = self._op("<show><interface>all</interface></show>")
        hw = res.findall("hw/entry")
        if not hw:
            raise ValueError("no interfaces in the reply")
        up = [e.findtext("name") for e in hw if (e.findtext("state") or "").lower() == "up"]
        return self.result("interfaces", OK, f"{len(up)}/{len(hw)} up", numeric=float(len(up)))

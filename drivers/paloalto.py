from core import proxy, display
import re
import xml.etree.ElementTree as ET

import requests
import urllib3

from . import apichecks
from .base import AuthRejected, Driver, OK, WARN, FAIL, grade, grade_low
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
        if r.status_code in (401, 403):
            why = ""
            try:
                why = (ET.fromstring(r.content).findtext(".//msg") or "").strip()
            except ET.ParseError:
                pass
            raise AuthRejected("Palo Alto rejected the API key" + (f" ({why})" if why else f" (HTTP {r.status_code})") +
                               ": paste the key from a user that may use the XML API (Device > Administrators; the key itself is made with "
                               "https://<firewall>/api/?type=keygen&user=...&password=...), and check the address is the firewall's management one.")
        r.raise_for_status()
        root = ET.fromstring(r.content)
        if root.get("status") != "success":
            msg = root.findtext(".//msg") or root.findtext(".//line") or "request failed"
            raise ValueError(f"PAN-OS API: {msg.strip()}")
        return root.find("result")

    def run(self):
        out = []
        try:
            s = self._system()                               # a rejected key is said once, not once per check
            self.found_software(s.findtext("sw-version") or "")
        except AuthRejected:
            raise
        except Exception:
            pass                                             # anything else: each check reports its own reason
        for name, fn in (("resources", self.resources), ("uptime", self.uptime), ("firmware", self.firmware),
                         ("sessions", self.sessions), ("ha", self.ha), ("interfaces", self.interfaces), ("licenses", self.licenses),
                         ("content", self.content), ("disk", self.disk), ("panorama", self.panorama), ("last commit", self.last_commit)):
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
        hours = int(m.group(1) or 0) * 24 + int(m.group(2)) + int(m.group(3)) / 60 + int(m.group(4)) / 3600
        t = self.th["uptime"]
        status = grade_low(hours, t["warn"], t["fail"])
        return self.result("uptime", status, display.uptime(hours), "recent reboot" if status != OK else "", numeric=hours)

    def firmware(self):
        s = self._system()
        return self.result("firmware", OK, s.findtext("sw-version") or "?", s.findtext("model") or "")

    def licenses(self):
        res = self._op("<request><license><info/></license></request>")
        found = apichecks.pan_licenses(res.findall(".//entry") if res is not None else [])
        timed = [(f, d, x) for f, d, x in found if d is not None]
        expired = [f for f, d, x in found if x]
        if not timed and not expired:
            return []
        t = self.th["support_days"]
        feature, days, _ = min(timed, key=lambda x: x[1]) if timed else (expired[0], -1, True)
        status = FAIL if expired else grade_low(days, t["warn"], t["fail"])
        return self.result("licenses", status, "expired" if expired else f"{days} days", (f"expired: {', '.join(expired[:4])}" if expired else f"ends first: {feature}") if status != OK else "",
                           numeric=float(days))

    def content(self):
        ages = apichecks.pan_content_ages(self._system())
        if not ages:
            return []
        name, days = max(ages, key=lambda x: x[1])
        t = self.th["content_age"]
        return self.result("content", grade(days, t["warn"], t["fail"]), f"{days} days", f"oldest: {name} package" if days >= t["warn"] else "application, threat and antivirus content", numeric=float(days))

    def disk(self):
        res = self._op("<show><system><disk-space/></system></show>")
        worst = apichecks.pan_disk((res.text or "") if res is not None else "")
        if worst is None:
            return []
        return self.level_check("disk", float(worst[0]))

    def panorama(self):
        res = self._op("<show><panorama-status/></show>")
        state = apichecks.pan_panorama((res.text or "") if res is not None else "")
        if state is None:
            return []
        return self.result("panorama", OK if state else WARN, "connected" if state else "not connected", "" if state else "this firewall cannot reach Panorama")

    def last_commit(self):
        res = self._op("<show><jobs><all/></jobs></show>")
        last = apichecks.pan_last_commit(res.findall(".//job") if res is not None else [])
        if last is None:
            return []
        result, when = last
        return self.result("last commit", OK if result == "OK" else FAIL, "ok" if result == "OK" else result.lower() or "unknown", f"finished {when}" if when else "")

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

    def _if_states(self):
        hw = self._op("<show><interface>all</interface></show>").findall("hw/entry")
        if not hw:
            raise ValueError("no interfaces in the reply")
        return [(e.findtext("name") or "?", "up" if (e.findtext("state") or "").lower() == "up" else "down") for e in hw]

    def list_interfaces(self):
        return self._if_states()

    def interfaces(self):
        return self.interfaces_row(self._if_states())

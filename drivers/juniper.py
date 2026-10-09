import re

from .base import OK, WARN, FAIL
from .sshbase import SshDriver, compact_hours, uptime_hours

PHYSICAL = re.compile(r"^(ge-|xe-|et-|fe-|mge-|ae\d|em\d|me\d|fxp\d)")


class JuniperDriver(SshDriver):
    DEFAULT_PLATFORM = "juniper_junos"

    def checks(self):
        return [("cpu", self.cpu), ("memory", self.memory), ("uptime", self.uptime), ("alarms", self.alarms),
                ("interfaces", self.interfaces), ("bgp", self.bgp), ("ospf", self.ospf)]

    def _slots(self, c):
        cmd = "show chassis routing-engine"
        out = self.cmd(c, cmd)
        slots = [s for s in re.split(r"(?m)^\s*Slot \d+:", out)[1:] if s.strip()]
        if not slots:
            raise self.unreadable("the routing engine", cmd)
        return slots

    def cpu(self, c):
        busy = []
        for s in self._slots(c):
            m = re.search(r"5 min CPU utilization:.*?Idle\s+(\d+)\s+percent", s, re.S) or \
                re.search(r"Idle\s+(\d+)\s+percent", s)
            if m:
                busy.append(100 - int(m.group(1)))
        if not busy:
            raise self.unreadable("CPU", "show chassis routing-engine")
        return self.level_check("cpu", max(busy))

    def memory(self, c):
        used = [int(m) for s in self._slots(c) for m in re.findall(r"Memory utilization\s+(\d+)\s+percent", s)]
        if not used:
            raise self.unreadable("memory", "show chassis routing-engine")
        return self.level_check("memory", max(used))

    def uptime(self, c):
        m = re.search(r"(?m)^\s*Uptime\s+(.+)$", self.cmd(c, "show chassis routing-engine"))
        if m:
            return self.uptime_row(uptime_hours(m.group(1)), m.group(1).strip())
        out = self.cmd(c, "show system uptime")                  # "System booted: ... (3w2d 04:05 ago)"
        m = re.search(r"System booted:.*\((.+?) ago\)", out)
        if not m:
            raise self.unreadable("uptime", "show system uptime")
        return self.uptime_row(compact_hours(m.group(1)), m.group(1))

    def alarms(self, c):
        cmd = "show chassis alarms"
        out = self.cmd(c, cmd)
        if "No alarms currently active" in out:
            return self.result("alarms", OK, "none")
        m = re.search(r"(\d+) alarms? currently active", out)
        if not m:
            raise self.unreadable("alarms", cmd)
        major = len(re.findall(r"\sMajor\s", out))
        minor = len(re.findall(r"\sMinor\s", out))
        descr = [ln.split(None, 4)[-1].strip() for ln in out.splitlines()
                 if re.search(r"\s(Major|Minor)\s", ln)]
        return self.result("alarms", FAIL if major else WARN, f"{m.group(1)} active",
                           "; ".join(descr[:3]) or f"{major} major, {minor} minor", numeric=float(m.group(1)))

    def interfaces(self, c):
        cmd = "show interfaces terse"
        rows = re.findall(r"(?m)^(\S+)\s+(up|down)\s+(up|down)\s*$", self.cmd(c, cmd))
        phys = [(n, a, l) for n, a, l in rows if PHYSICAL.match(n) and "." not in n]
        if not phys:
            raise self.unreadable("interfaces", cmd)
        active = [r for r in phys if r[1] == "up"]               # ports an admin has switched on
        up = [r for r in active if r[2] == "up"]
        return self.link_summary(len(up), len(active))

    def bgp(self, c):
        out = self.cmd(c, "show bgp summary")
        if "not running" in out.lower():
            return []
        peers = re.findall(r"(?m)^(\S+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+.*?\s+(Establ|Active|Connect|Idle|OpenSent|"
                           r"OpenConfirm|\d+/\d+/\d+/\d+)\s*$", out)
        down = [p for p, st in peers if st not in ("Establ",) and "/" not in st]
        return self.peers_row("bgp", len(peers) - len(down), len(peers), down)

    def ospf(self, c):
        out = self.cmd(c, "show ospf neighbor")
        nbrs = re.findall(r"(?m)^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+(\w+)\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+\d+", out)
        bad = [f"{a} ({s})" for a, s in nbrs if s.lower() not in ("full", "2way")]
        return self.peers_row("ospf", len(nbrs) - len(bad), len(nbrs), bad)

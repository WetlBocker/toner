import re

from .base import OK, WARN, grade
from .sshbase import SshDriver, compact_hours
from .clirows import CliRows
from . import clichecks

_SIZE = {"b": 1, "kib": 1024, "mib": 1024 ** 2, "gib": 1024 ** 3}


def _bytes(text):
    m = re.match(r"([\d.]+)\s*([A-Za-z]+)", text.strip())
    return float(m.group(1)) * _SIZE.get(m.group(2).lower(), 1) if m else None


class MikrotikDriver(CliRows, SshDriver):
    DEFAULT_PLATFORM = "mikrotik_routeros"

    def checks(self):
        return [("cpu", self.cpu), ("memory", self.memory), ("uptime", self.uptime),
                ("firmware", self.firmware), ("interfaces", self.interfaces), ("ospf", self.ospf),
                ("health", self.health), ("disk", self.disk), ("routerboard", self.routerboard), ("ntp", self.ntp)]

    def _res(self, c):
        cmd = "/system resource print"
        kv = dict(re.findall(r"(?m)^\s*([a-z-]+):\s*(.*?)\s*$", self.cmd(c, cmd)))
        if "uptime" not in kv:
            raise self.unreadable("system resources", cmd)
        return kv

    def cpu(self, c):
        m = re.match(r"([\d.]+)", self._res(c).get("cpu-load", ""))
        if not m:
            raise self.unreadable("CPU", "/system resource print")
        return self.level_check("cpu", float(m.group(1)))

    def memory(self, c):
        kv = self._res(c)
        total, free = _bytes(kv.get("total-memory", "")), _bytes(kv.get("free-memory", ""))
        if not (total and free is not None):
            raise self.unreadable("memory", "/system resource print")
        return self.level_check("memory", (total - free) / total * 100)

    def uptime(self, c):
        text = self._res(c)["uptime"]
        return self.uptime_row(compact_hours(text), text)

    def firmware(self, c):
        kv = self._res(c)
        return self.result("firmware", OK, kv.get("version", "?"), kv.get("board-name", ""))

    def health(self, c):
        """Temperature and supply voltage (boards with sensors only)."""
        temps, volt = clichecks.mikrotik_health(self.cmd(c, "/system health print"))
        if not temps:
            return []
        hottest = max(temps.values())
        t = self.th["temperature"]
        return self.result("health", grade(hottest, t["warn"], t["fail"]), f"{hottest:.0f}C", f"{', '.join(f'{k} {v:.0f}C' for k, v in list(temps.items())[:3])}" + (f"; {volt:g} V" if volt else ""),
                           numeric=float(hottest))

    def disk(self, c):
        pct = clichecks.mikrotik_disk(self._res(c))
        if pct is None:
            return []
        return self.level_check("disk", pct)

    def routerboard(self, c):
        """The RouterBOARD firmware is a separate thing from RouterOS: it needs its own upgrade, and then a reboot."""
        fw = clichecks.mikrotik_firmware(self.cmd(c, "/system routerboard print"))
        if fw is None:
            return []
        cur, up = fw
        if cur == up:
            return self.result("routerboard", OK, cur, "firmware is current")
        return self.result("routerboard", WARN, f"{cur} to {up}", "RouterBOARD firmware can be upgraded (/system routerboard upgrade, then reboot)")

    def ntp(self, c):
        state = clichecks.mikrotik_ntp(self.cmd(c, "/system ntp client print"))
        if state in (None, "off"):
            return []
        return self.ntp_row(state)

    def interfaces(self, c):
        return self.interfaces_row(self.if_states(c))

    def if_states(self, c):
        cmd = "/interface print terse"
        rows = re.findall(r"(?m)^\s*\d+\s+(?:([A-Z]+)\s+)?name=(\S+)", self.cmd(c, cmd))
        if not rows:
            raise self.unreadable("interfaces", cmd)
        return [(n, "off" if "X" in f else "up" if "R" in f else "down") for f, n in rows]      # X = switched off by an admin, R = running

    def ospf(self, c):
        out = self.cmd(c, "/routing ospf neighbor print terse")
        if "bad command" in out.lower() or "no such" in out.lower():
            return self.peers_row("ospf", 0, 0, [], protocol="OSPF")
        nbrs = re.findall(r"(?m)^\s*\d+.*?address=(\S+).*?state=(\S+)", out)
        bad = [f"{a} ({s})" for a, s in nbrs if s.lower() not in ("full", "2-way")]
        running = bool(nbrs) or any(re.search(r"(?m)^\s*\d+\s", self.cmd(c, cmd)) and "bad command" not in self.cmd(c, cmd).lower()
                                    for cmd in ("/routing ospf interface-template print terse", "/routing ospf network print terse"))   # v7, v6
        return self.peers_row("ospf", len(nbrs) - len(bad), len(nbrs), bad, protocol="OSPF", running=running)

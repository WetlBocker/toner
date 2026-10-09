import re

from .base import OK
from .sshbase import SshDriver, compact_hours

_SIZE = {"b": 1, "kib": 1024, "mib": 1024 ** 2, "gib": 1024 ** 3}


def _bytes(text):
    m = re.match(r"([\d.]+)\s*([A-Za-z]+)", text.strip())
    return float(m.group(1)) * _SIZE.get(m.group(2).lower(), 1) if m else None


class MikrotikDriver(SshDriver):
    DEFAULT_PLATFORM = "mikrotik_routeros"

    def checks(self):
        return [("cpu", self.cpu), ("memory", self.memory), ("uptime", self.uptime),
                ("firmware", self.firmware), ("interfaces", self.interfaces), ("ospf", self.ospf)]

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

    def interfaces(self, c):
        cmd = "/interface print terse"
        rows = re.findall(r"(?m)^\s*\d+\s+(?:([A-Z]+)\s+)?name=(\S+)", self.cmd(c, cmd))
        enabled = [(f, n) for f, n in rows if "X" not in f]          # X = switched off by an admin
        if not rows:
            raise self.unreadable("interfaces", cmd)
        up = [n for f, n in enabled if "R" in f]
        return self.link_summary(len(up), len(enabled))

    def ospf(self, c):
        out = self.cmd(c, "/routing ospf neighbor print terse")
        if "bad command" in out.lower() or "no such" in out.lower():
            return []
        nbrs = re.findall(r"(?m)^\s*\d+.*?address=(\S+).*?state=(\S+)", out)
        bad = [f"{a} ({s})" for a, s in nbrs if s.lower() not in ("full", "2-way")]
        return self.peers_row("ospf", len(nbrs) - len(bad), len(nbrs), bad)

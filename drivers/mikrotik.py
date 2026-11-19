import re

from .base import OK, WARN, grade
from .sshbase import SshDriver, compact_hours
from .clirows import CliRows
from . import clichecks

_SIZE = {"b": 1, "kib": 1024, "mib": 1024 ** 2, "gib": 1024 ** 3}


def _bytes(text):
    m = re.match(r"([\d.]+)\s*([A-Za-z]+)", text.strip())
    return float(m.group(1)) * _SIZE.get(m.group(2).lower(), 1) if m else None


def _items(out):
    """[(flags, text)] for each numbered item of a RouterOS 'print', whether an item is one line (terse) or several; ';;;' starts its comment."""
    return re.findall(r"(?ms)^\s*\d+\s+([A-Z]*)\s*((?:;;;|\S+=).*?)(?=^\s*\d+\s+[A-Z]*\s*(?:;;;|\S+=)|\Z)", out)


def bgp_neighbors(peers, connections=""):
    """(total, down) from '/routing bgp session print' (v7) or '/routing bgp peer print status' (v6): flag E = established, X = disabled.
    v7 makes no session for a peer that never came up, so a connection to one address that has no session is a neighbor down."""
    up = {}
    for flags, text in _items(peers):
        m = re.search(r"\bremote[.-]address=(\S+)", text) or re.search(r'\bname="?([^"\s]+)', text)      # remote-address and state= are v6 (its manual is retired: not re-read)
        if m and "X" not in flags:
            up[m.group(1)] = up.get(m.group(1)) or "E" in flags or "state=established" in text            # v7 keeps a stopped session cached beside the live one
    for flags, text in _items(connections):
        m = re.search(r"\bremote\.address=((?:\d+\.){3}\d+|[\dA-Fa-f]*:[\dA-Fa-f:.]*)(?:/(?:32|128))?(?=\s|$)", text)   # a range to listen on or a host name is no single peer
        if m and "X" not in flags:
            up.setdefault(m.group(1), False)                                                              # inferred: the manual does not say a session shows the connection's address as written
    return len(up), [a for a, e in up.items() if not e]


class MikrotikDriver(CliRows, SshDriver):
    DEFAULT_PLATFORM = "mikrotik_routeros"

    def checks(self):
        return [("cpu", self.cpu), ("memory", self.memory), ("uptime", self.uptime),
                ("firmware", self.firmware), ("interfaces", self.interfaces), ("bgp", self.bgp), ("ospf", self.ospf),
                ("health", self.health), ("disk", self.disk), ("routerboard", self.routerboard), ("ntp", self.ntp)]

    def software(self, c):
        self.found_software(self._res(c).get("version", ""))

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

    def bgp(self, c):
        out, conns = self.cmd(c, "/routing bgp session print"), ""
        if "bad command" in out.lower() or "no such" in out.lower():
            out = self.cmd(c, "/routing bgp peer print status")               # v6: every peer set up is listed, with its state
        else:
            conns = self.cmd(c, "/routing bgp connection print")
        total, down = bgp_neighbors(out, conns)
        return self.peers_row("bgp", total - len(down), total, down, protocol="BGP", running=any("X" not in f for f, _t in _items(conns)))

    def ospf(self, c):
        out = self.cmd(c, "/routing ospf neighbor print terse")
        if "bad command" in out.lower() or "no such" in out.lower():
            return self.peers_row("ospf", 0, 0, [], protocol="OSPF")
        nbrs = re.findall(r"(?m)^\s*\d+.*?address=(\S+).*?state=(\S+)", out)
        bad = [f"{a} ({s})" for a, s in nbrs if s.lower() not in ("full", "2-way")]
        running = bool(nbrs) or any(re.search(r"(?m)^\s*\d+\s", self.cmd(c, cmd)) and "bad command" not in self.cmd(c, cmd).lower()
                                    for cmd in ("/routing ospf interface-template print terse", "/routing ospf network print terse"))   # v7, v6
        return self.peers_row("ospf", len(nbrs) - len(bad), len(nbrs), bad, protocol="OSPF", running=running)

import json
import re

from .base import OK, WARN, FAIL, grade
from .sshbase import SshDriver, worse


class AristaDriver(SshDriver):
    DEFAULT_PLATFORM = "arista_eos"

    def checks(self):
        return [("cpu", self.cpu), ("memory", self.memory), ("uptime", self.uptime),
                ("temperature", self.temperature), ("interfaces", self.interfaces),
                ("bgp", self.bgp), ("ospf", self.ospf)]

    def json(self, c, command):
        out = self.cmd(c, command + " | json")
        try:
            return json.loads(out)
        except ValueError:
            raise self.unreadable(command, command + " | json") from None

    def cpu(self, c):
        cmd = "show processes top once"
        m = re.search(r"%Cpu\(s\):.*?([\d.]+)\s*id", self.cmd(c, cmd))
        if not m:
            raise self.unreadable("CPU", cmd)
        return self.level_check("cpu", 100 - float(m.group(1)))

    def memory(self, c):
        v = self.json(c, "show version")
        total, free = float(v["memTotal"]), float(v["memFree"])
        return self.level_check("memory", (total - free) / total * 100)

    def uptime(self, c):
        secs = float(self.json(c, "show uptime")["upTime"])
        d, r = divmod(int(secs), 86400)
        return self.uptime_row(secs / 3600, f"{d}d {r // 3600}h")

    def temperature(self, c):
        env = self.json(c, "show system environment temperature")
        temps = [float(s["currentTemperature"]) for s in env.get("tempSensors", [])
                 if isinstance(s.get("currentTemperature"), (int, float))]
        status = env.get("systemStatus", "")
        if not temps and not status:
            return []
        hottest = max(temps) if temps else 0
        t = self.th["temperature"]
        st = grade(hottest, t["warn"], t["fail"])
        msg = ""
        if status and not status.lower().endswith("ok"):
            st, msg = worse(st, WARN), f"system status: {status}"
        return self.result("temperature", st, f"{hottest:.0f}C" if temps else status, msg,
                           numeric=hottest if temps else None)

    def interfaces(self, c):
        ifs = self.json(c, "show interfaces status").get("interfaceStatuses", {})
        if not ifs:
            raise self.unreadable("interfaces", "show interfaces status | json")
        up = [n for n, i in ifs.items() if i.get("linkStatus") == "connected"]
        bad = [n for n, i in ifs.items() if i.get("linkStatus") == "errdisabled"]
        return self.link_summary(len(up), len(ifs), warn_names=[f"{n} (err-disabled)" for n in bad])

    def bgp(self, c):
        out = self.cmd(c, "show ip bgp summary | json")
        if "inactive" in out.lower() or not out.strip().startswith("{"):
            return []
        peers = {}
        for vrf in json.loads(out).get("vrfs", {}).values():
            peers.update(vrf.get("peers", {}))
        down = [p for p, i in peers.items() if i.get("peerState") != "Established"]
        return self.peers_row("bgp", len(peers) - len(down), len(peers), down)

    def ospf(self, c):
        out = self.cmd(c, "show ip ospf neighbor | json")
        if not out.strip().startswith("{"):
            return []
        nbrs = []

        def walk(node):
            if isinstance(node, dict):
                if "adjacencyState" in node:
                    nbrs.append(node)
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        walk(json.loads(out))
        bad = [f"{n.get('routerId', '?')} ({n['adjacencyState']})" for n in nbrs
               if str(n["adjacencyState"]).lower() not in ("full", "twoway", "2way")]
        return self.peers_row("ospf", len(nbrs) - len(bad), len(nbrs), bad)

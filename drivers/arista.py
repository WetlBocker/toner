import json
import re

from .base import OK, WARN, FAIL, grade
from .sshbase import SshDriver, worse
from .clirows import CliRows
from . import clichecks


class AristaDriver(CliRows, SshDriver):
    DEFAULT_PLATFORM = "arista_eos"

    def checks(self):
        return [("cpu", self.cpu), ("memory", self.memory), ("uptime", self.uptime),
                ("temperature", self.temperature), ("interfaces", self.interfaces),
                ("bgp", self.bgp), ("ospf", self.ospf), ("environment", self.environment), ("mlag", self.mlag), ("ntp", self.ntp), ("flash", self.flash)]

    def json(self, c, command):
        out = self.cmd(c, command + " | json")
        try:
            return json.loads(out)
        except ValueError:
            raise self.unreadable(command, command + " | json") from None

    # ---------------------------------------------------------------- health and redundancy
    def environment(self, c):
        found, seen = [], 0
        for part in ("cooling", "power"):
            try:
                data = json.loads(self.cmd(c, f"show system environment {part} | json"))
            except ValueError:
                continue
            seen += 1
            found += clichecks.deep_status(data)
        if not seen:
            return []
        if not found:
            return self.result("environment", OK, "ok", "cooling and power", numeric=0.0)
        return self.result("environment", FAIL if any(lv == FAIL for lv, _ in found) else WARN, f"{len(found)} not ok", "; ".join(m for _, m in found[:3]), numeric=float(len(found)))

    def mlag(self, c):
        try:
            data = json.loads(self.cmd(c, "show mlag | json"))
        except ValueError:
            return []
        problems = clichecks.mlag_problems(data)
        if problems is None:
            return []
        return self.result("mlag", FAIL if problems else OK, "problem" if problems else "active", "; ".join(problems))

    def ntp(self, c):
        return self.ntp_row(clichecks.ntp_state(self.cmd(c, "show ntp status")))

    def flash(self, c):
        return self.flash_row(c, "dir flash:")

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
        return self.uptime_row(secs / 3600, "")

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

    def if_states(self, c):
        ifs = self.json(c, "show interfaces status").get("interfaceStatuses", {})
        if not ifs:
            raise self.unreadable("interfaces", "show interfaces status | json")
        return [(n, "up" if i.get("linkStatus") == "connected" else "errdisabled" if i.get("linkStatus") == "errdisabled"
                 else "off" if i.get("linkStatus") == "disabled" else "down") for n, i in ifs.items()]

    def interfaces(self, c):
        return self.interfaces_row(self.if_states(c))

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

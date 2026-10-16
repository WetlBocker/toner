import re

from .base import OK, WARN, FAIL
from .sshbase import SshDriver, compact_hours, uptime_hours
from .clirows import CliRows
from . import clichecks

PHYSICAL = re.compile(r"^(ge-|xe-|et-|fe-|mge-|ae\d|em\d|me\d|fxp\d)")


class JuniperDriver(CliRows, SshDriver):
    DEFAULT_PLATFORM = "juniper_junos"

    def checks(self):
        return [("cpu", self.cpu), ("memory", self.memory), ("uptime", self.uptime), ("alarms", self.alarms),
                ("interfaces", self.interfaces), ("bgp", self.bgp), ("ospf", self.ospf),
                ("environment", self.environment), ("ntp", self.ntp), ("uncommitted", self.uncommitted), ("core dumps", self.core_dumps),
                ("bfd", self.bfd), ("storage", self.storage), ("virtual chassis", self.virtual_chassis)]

    # ---------------------------------------------------------------- health and redundancy
    def environment(self, c):
        return self.env_row(c, "show chassis environment")

    def ntp(self, c):
        return self.ntp_row(clichecks.junos_ntp(self.cmd(c, "show ntp associations")))

    def uncommitted(self, c):
        """Changes made in the candidate configuration that nobody has committed."""
        out = self.cmd(c, "show | compare")
        if "error" in out.lower() or "syntax" in out.lower() or "invalid" in out.lower():
            return []
        lines = [ln for ln in out.splitlines() if ln.startswith(("+", "-")) and not ln.startswith(("+++", "---"))]
        if not lines:
            return self.result("uncommitted", OK, "committed", "")
        return self.result("uncommitted", WARN, f"{len(lines)} changed line(s)", "the candidate configuration differs from the running one: commit or roll back", numeric=float(len(lines)))

    def core_dumps(self, c):
        out = self.cmd(c, "show system core-dumps")
        if "syntax error" in out.lower() or "unknown command" in out.lower():
            return []
        files = clichecks.junos_core_dumps(out)
        if not files:
            return self.result("core dumps", OK, "none", "")
        return self.result("core dumps", WARN, f"{len(files)} file(s)", "a process crashed: " + ", ".join(f.rsplit("/", 1)[-1] for f in files[:3]), numeric=float(len(files)))

    def bfd(self, c):
        out = self.cmd(c, "show bfd session")
        if "error" in out.lower() or "no bfd" in out.lower() or not out.strip():
            return []
        total = len(re.findall(r"(?m)^\s*\d+\.\d+\.\d+\.\d+\s+\w+", out))
        down = clichecks.junos_bfd_down(out)
        if not total:
            return []
        return self.result("bfd", FAIL if down else OK, f"{total - len(down)}/{total} up", ("down: " + ", ".join(down[:5])) if down else "", numeric=float(total - len(down)))

    def storage(self, c):
        out = self.cmd(c, "show system storage")
        worst = None
        for m in re.finditer(r"(?m)^\S+\s+\S+\s+\S+\s+\S+\s+(\d+)%\s+(/\S*)\s*$", out):
            pct, mount = int(m.group(1)), m.group(2)
            if mount == "/dev" or mount.startswith(("/packages", "/junos", "/proc", "/mnt/", "/oam", "/jail", "/dev/")):
                continue                           # read-only images are always 100% full
            if worst is None or pct > worst[0]:
                worst = (pct, mount)
        if worst is None:
            return []
        return self.level_check("storage", float(worst[0]), th_key="disk")

    def virtual_chassis(self, c):
        out = self.cmd(c, "show virtual-chassis status")
        rows = re.findall(r"(?m)^\s*(\d+)\s+\(FPC\s+\d+\)\s+(Prsnt|NotPrsnt|Inactive|Unprvsnd)\b", out)
        if not rows:
            return []
        bad = [f"member {n} ({s})" for n, s in rows if s != "Prsnt"]
        return self.result("virtual chassis", FAIL if bad else OK, f"{len(rows) - len(bad)}/{len(rows)} present", "; ".join(bad), numeric=float(len(rows) - len(bad)))

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
        return self.interfaces_row(self.if_states(c))

    def if_states(self, c):
        cmd = "show interfaces terse"
        rows = re.findall(r"(?m)^(\S+)\s+(up|down)\s+(up|down)\s*$", self.cmd(c, cmd))
        phys = [(n, a, l) for n, a, l in rows if PHYSICAL.match(n) and "." not in n]
        if not phys:
            raise self.unreadable("interfaces", cmd)
        return [(n, "off" if a != "up" else "up" if l == "up" else "down") for n, a, l in phys]       # off: an admin switched the port off

    def bgp(self, c):
        out = self.cmd(c, "show bgp summary")
        if "not running" in out.lower():
            return self.peers_row("bgp", 0, 0, [], protocol="BGP")
        peers = re.findall(r"(?m)^(\S+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+.*?\s+(Establ|Active|Connect|Idle|OpenSent|"
                           r"OpenConfirm|\d+/\d+/\d+/\d+)\s*$", out)
        down = [p for p, st in peers if st not in ("Establ",) and "/" not in st]
        running = bool(re.search(r"Groups:\s*\d+\s+Peers:", out))
        return self.peers_row("bgp", len(peers) - len(down), len(peers), down, protocol="BGP", running=running)

    def ospf(self, c):
        out = self.cmd(c, "show ospf neighbor")
        nbrs = re.findall(r"(?m)^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+(\w+)\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+\d+", out)
        bad = [f"{a} ({s})" for a, s in nbrs if s.lower() not in ("full", "2way")]
        running = bool(nbrs) or bool(re.search(r"Router ID:", self.cmd(c, "show ospf overview")))
        return self.peers_row("ospf", len(nbrs) - len(bad), len(nbrs), bad, protocol="OSPF", running=running)

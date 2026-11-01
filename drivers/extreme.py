"""Extreme Networks switches by SSH: Switch Engine / EXOS (the Summit and X series) and Fabric Engine / VOSS (the VSP series).
Version, uptime, CPU, memory, ports that are down, fans and power supplies."""
import re

from .base import OK, WARN, FAIL
from .clirows import CliRows
from .sshbase import SshDriver, uptime_hours


class ExtremeDriver(CliRows, SshDriver):
    DEFAULT_PLATFORM = "extreme_exos"

    def checks(self):
        return [("cpu", self.cpu), ("memory", self.memory), ("uptime", self.uptime), ("interfaces", self.interfaces), ("environment", self.environment)]

    def voss(self):
        return self.plat in ("extreme_vsp", "extreme_voss")

    def prepare(self, c):
        try:
            c.send_command("disable clipaging" if not self.voss() else "terminal more disable")
        except Exception:
            pass

    def software(self, c):
        if self.voss():
            m = re.search(r"SysDescr\s*:.*?\(([\d.]+)\)", self.cmd(c, "show sys-info"), re.S) or re.search(r"Version\s*:\s*(\S+)", self.cmd(c, "show sys-info"))
        else:
            m = re.search(r"ExtremeXOS version\s+(\S+)", self.cmd(c, "show version")) or re.search(r"Image\s*:\s*\S+\s+version\s+(\S+)", self.cmd(c, "show version"))
        if m:
            self.found_software(m.group(1))

    def cpu(self, c):
        if self.voss():
            cmd = "show khi performance cpu"
            m = re.search(r"[Uu]tilization.*?(\d+(?:\.\d+)?)", self.cmd(c, cmd), re.S)
        else:
            cmd = "show cpu-monitoring"
            m = re.search(r"^\s*System\s+(\d+(?:\.\d+)?)", self.cmd(c, cmd), re.M)
        if not m:
            raise self.unreadable("CPU", cmd)
        return self.level_check("cpu", float(m.group(1)))

    def memory(self, c):
        if self.voss():
            cmd = "show khi performance memory"
            text = self.cmd(c, cmd)
            used = re.search(r"Used\s*:?\s*(\d+)", text, re.I)
            free = re.search(r"Free\s*:?\s*(\d+)", text, re.I)
            if used and free:
                u, f = float(used.group(1)), float(free.group(1))
                return self.level_check("memory", u / (u + f) * 100 if u + f else 0)
        else:
            cmd = "show memory"
            text = self.cmd(c, cmd)
            total = re.search(r"Total DRAM\s*\(KB\)\s*:\s*(\d+)", text, re.I)
            free = re.search(r"Free\s*\(KB\)\s*:\s*(\d+)", text, re.I)
            if total and free:
                t, f = float(total.group(1)), float(free.group(1))
                return self.level_check("memory", (t - f) / t * 100 if t else 0)
        raise self.unreadable("memory", cmd)

    def uptime(self, c):
        if self.voss():
            m = re.search(r"SysUpTime\s*:\s*(.+)", self.cmd(c, "show sys-info"))
        else:
            m = re.search(r"(?:System )?Up ?[Tt]ime\s*:\s*(.+)", self.cmd(c, "show switch"))
        if not m:
            raise self.unreadable("uptime", "show sys-info" if self.voss() else "show switch")
        text = m.group(1).strip()
        return self.uptime_row(uptime_hours(text), text)

    def if_states(self, c):
        states = []
        if self.voss():
            cmd = "show interfaces gigabitEthernet"
            for line in self.cmd(c, cmd).splitlines():
                m = re.match(r"^\s*(\d+/\d+(?:/\d+)?)\s+.*?\b(up|down)\b", line, re.I)
                if m:
                    states.append((m.group(1), m.group(2).lower()))
        else:
            cmd = "show ports no-refresh"
            for line in self.cmd(c, cmd).splitlines():
                m = re.match(r"^\s*(\d+(?::\d+)?)\s+.*?\s([ED])\s+(A|R|NP|L)\b", line)
                if m:
                    port, admin, link = m.groups()
                    states.append((port, "off" if admin == "D" else "up" if link == "A" else "down"))
        if not states:
            raise self.unreadable("ports", cmd)
        return states

    def interfaces(self, c):
        return self.interfaces_row(self.if_states(c))

    def environment(self, c):
        if self.voss():
            text = self.cmd(c, "show sys-info")
            fans = re.findall(r"Fan\s*\d*[^\n]*?\b(ok|up|normal|fail(?:ed)?|down|absent)\b", text, re.I)
            psus = re.findall(r"Power Supply[^\n]*?\b(ok|up|normal|fail(?:ed)?|down|absent|not present)\b", text, re.I)
        else:
            fans = re.findall(r"Fan[^\n]*?\b(operational|ok|fail(?:ed)?|not operational|absent|empty)\b", self.cmd(c, "show fans"), re.I)
            psus = re.findall(r"Power[Ss]upply[^\n]*?\b(Powered On|Powered Off|Fail(?:ed)?|Empty|Not Present|OK|Operational)\b", self.cmd(c, "show power"), re.I)
        if not fans and not psus:
            return []
        bad = [f"fan: {s}" for s in fans if re.search(r"fail|not operational|down", s, re.I)] + \
              [f"power supply: {s}" for s in psus if re.search(r"fail|off", s, re.I)]
        return self.result("environment", FAIL if any("fail" in b.lower() for b in bad) else WARN if bad else OK, "ok" if not bad else f"{len(bad)} not ok",
                           "; ".join(bad[:4]) or f"{len(fans)} fan(s), {len(psus)} power suppl{'y' if len(psus) == 1 else 'ies'}", numeric=float(len(bad)))

"""Dell PowerSwitch by SSH: SmartFabric OS10 first, with OS9 (the S-series and Z-series before OS10) and OS6 (the N-series) as
other platforms. CPU, memory, uptime, interfaces that are down, fans and power supplies. The commands differ per platform; each
reader tries the forms the platform prints."""
import re

from .base import OK, WARN, FAIL
from .clirows import CliRows
from .sshbase import SshDriver, uptime_hours


class DellDriver(CliRows, SshDriver):
    DEFAULT_PLATFORM = "dell_os10"

    def checks(self):
        return [("cpu", self.cpu), ("memory", self.memory), ("uptime", self.uptime), ("interfaces", self.interfaces), ("environment", self.environment)]

    def os10(self):
        return self.plat == "dell_os10"

    def os6(self):
        return self.plat == "dell_os6"

    def software(self, c):
        text = self.cmd(c, "show version")
        m = re.search(r"OS Version\s*:\s*(\S+)", text) or re.search(r"Dell (?:EMC )?Networking OS Version\s*:?\s*(\S+)", text) \
            or re.search(r"Software Version[.\s]*:?\s*(\S+)", text) or re.search(r"[Vv]ersion\s*:?\s*([\d][\d.()]+)", text)
        if m:
            self.found_software(m.group(1))

    def cpu(self, c):
        if self.os10():
            cmd = "show processes node-id 1 | grep Cpu"
            m = re.search(r"([\d.]+)\s*id", self.cmd(c, cmd))
            if not m:
                raise self.unreadable("CPU", cmd)
            return self.level_check("cpu", 100 - float(m.group(1)))
        if self.os6():
            cmd = "show process cpu"
            m = re.search(r"Total CPU Utilization.*?(\d+(?:\.\d+)?)\s*%", self.cmd(c, cmd), re.S)
        else:
            cmd = "show processes cpu summary"
            m = re.search(r"CPU utilization.*?(\d+)\s*%", self.cmd(c, cmd), re.S)
        if not m:
            raise self.unreadable("CPU", cmd)
        return self.level_check("cpu", float(m.group(1)))

    def memory(self, c):
        if self.os10():
            cmd = "show processes memory node-id 1"
        elif self.os6():
            cmd = "show memory cpu"
        else:
            cmd = "show memory"
        text = self.cmd(c, cmd)
        total = re.search(r"Total(?:\s*Memory)?\s*[:=]?\s*(\d+)", text, re.I)
        free = re.search(r"(?:Free|Available)(?:\s*Memory)?\s*[:=]?\s*(\d+)", text, re.I)
        used = re.search(r"Used\s*[:=]?\s*(\d+)", text, re.I)
        if total and (free or used):
            t = float(total.group(1))
            u = float(used.group(1)) if used else t - float(free.group(1))
            return self.level_check("memory", u / t * 100 if t else 0)
        nums = re.findall(r"^\s*(\d{5,})\s+(\d{5,})\s+(\d{5,})", text, re.M)          # OS9: Total(b) Used(b) Free(b)
        if nums:
            t, u, _f = (float(x) for x in nums[0])
            return self.level_check("memory", u / t * 100 if t else 0)
        raise self.unreadable("memory", cmd)

    def uptime(self, c):
        text = self.cmd(c, "show system") if not self.os6() else self.cmd(c, "show system")
        m = re.search(r"Up\s*Time\s*:?\s*(.+)", text, re.I)
        if not m and not self.os10():
            text = self.cmd(c, "show version")
            m = re.search(r"uptime is (.+)", text, re.I)
        if not m:
            raise self.unreadable("uptime", "show system")
        return self.uptime_row(uptime_hours(m.group(1).strip()), m.group(1).strip())

    def if_states(self, c):
        cmd = "show interface status" if self.os10() else "show interfaces status"
        text = self.cmd(c, cmd)
        states = []
        for line in text.splitlines():
            m = re.match(r"^\s*((?:Eth|Te|Gi|Fo|Hu|Tf|Twe|Ma|Po|Vl)\S*\s*\S*)\s+.*?\b(up|down|admin[- ]down|disabled|Up|Down)\b", line)
            if not m:
                continue
            name = " ".join(m.group(1).split())
            state = m.group(2).lower()
            states.append((name, "up" if state == "up" else "off" if "admin" in state or state == "disabled" else "down"))
        if not states:
            raise self.unreadable("interfaces", cmd)
        return states

    def interfaces(self, c):
        return self.interfaces_row(self.if_states(c))

    def environment(self, c):
        """Fans and power supplies from show environment: each table says its kind in its heading; a 'fail' in a row is a FAIL,
        'down' a WARN, an absent slot nothing."""
        text = self.cmd(c, "show environment")
        if not re.search(r"\b(?:fan|psu|power supply|power)\b", text, re.I):
            return []
        kind, problems, seen, comps = "", [], 0, []
        for line in text.splitlines():
            low = line.lower()
            if re.search(r"\bfan", low):
                kind = "fan"
            elif re.search(r"\bpsu\b|power", low):
                kind = "power supply"
            m = re.search(r"\b(ok|up|good|normal|fail(?:ed)?|absent|down|not present)\b", low)
            if not m or not kind or re.search(r"status", low):
                continue
            seen += 1
            word = m.group(1)
            if word not in ("absent", "not present"):
                comps.append(self.item(f"{kind} {' '.join(line.split()[:2])}", text=word,
                                       status=FAIL if word.startswith("fail") else WARN if word == "down" else OK))
            if word.startswith("fail"):
                problems.append((FAIL, f"{kind} {' '.join(line.split()[:2])}: failed"))
            elif word == "down":
                problems.append((WARN, f"{kind} {' '.join(line.split()[:2])}: down"))
        if not seen:
            return []
        worst = FAIL if any(s == FAIL for s, _ in problems) else WARN if problems else OK
        return self.result("environment", worst, "ok" if not problems else f"{len(problems)} not ok", "; ".join(m for _, m in problems[:4]), numeric=float(len(problems)), items=comps)

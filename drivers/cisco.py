import re
from netmiko import ConnectHandler
from .base import Driver, OK, WARN, FAIL, grade_low
from .sshbase import Recorder
from core import quiet

_UPTIME_UNITS = {"year": 8760, "week": 168, "day": 24, "hour": 1, "minute": 1 / 60}

def uptime_hours(text):
    """'1 year, 2 weeks, 3 days, 4 hours, 5 minutes' -> hours."""
    return sum(int(n) * _UPTIME_UNITS[u] for n, u in re.findall(r"(\d+)\s+(year|week|day|hour|minute)", text))

class CiscoDriver(Driver):
    def run(self):
        d = self.dev
        self.plat = d.get("platform") or "cisco_ios"
        out = []
        with self.connect() as conn:
            c = Recorder(conn, self.transcript)
            try:
                c.enable()
            except Exception:
                quiet.ignored()
            for name, fn in (("cpu", self.cpu), ("memory", self.memory), ("uptime", self.uptime),
                             ("interfaces", self.interfaces), ("bgp", self.bgp), ("ospf", self.ospf)):
                if self.enabled(name):
                    self.safe(out, name, lambda fn=fn: fn(c))
            custom_ssh = [x for x in getattr(self, "custom", []) if x["kind"] == "ssh"]
            if custom_ssh:
                from core import custom
                out.extend(custom.run_ssh(self, c, custom_ssh))
        return out

    DEFAULT_PLATFORM = "cisco_ios"

    def connect(self):
        d, t = self.dev, self.opts["ssh_timeout"]
        args = dict(device_type=self.plat, host=d["host"], username=d["username"], password=self.password,
                    secret=self.password, timeout=t, conn_timeout=t)
        if d.get("port"):
            args["port"] = d["port"]
        from core import jump
        sock, closers = jump.open_channel(d, t)          # (None, []) unless the device is behind a jump host
        if sock is not None:
            args["sock"] = sock
            return jump.Managed(ConnectHandler(**args), closers)
        return ConnectHandler(**args)

    def cpu(self, c):
        if "nxos" in self.plat:
            m = re.search(r"CPU states\s*:\s*([\d.]+)%\s*user,\s*([\d.]+)%\s*kernel",
                          c.send_command("show system resources"))
            return self.level_check("cpu", float(m.group(1)) + float(m.group(2))) if m else []
        m = re.search(r"five minutes: (\d+)%", c.send_command("show processes cpu"))
        return self.level_check("cpu", int(m.group(1))) if m else []

    def memory(self, c):
        if "nxos" in self.plat:
            m = re.search(r"(\d+)K total,\s+(\d+)K used", c.send_command("show system resources"))
        else:
            m = re.search(r"Processor Pool Total:\s+(\d+)\s+Used:\s+(\d+)",
                          c.send_command("show processes memory | include Processor"))
        return self.level_check("memory", int(m.group(2)) / int(m.group(1)) * 100) if m else []

    def uptime(self, c):
        m = re.search(r"uptime is (.+)", c.send_command("show version"))
        if not m:
            return []
        text = m.group(1).strip()
        hours = uptime_hours(text)
        t = self.th["uptime"]
        status = grade_low(hours, t["warn"], t["fail"])
        return self.result("uptime", status, text, "recent reboot" if status != OK else "", numeric=hours)

    def interfaces(self, c):
        ifs = c.send_command("show interfaces", use_textfsm=True)
        if not isinstance(ifs, list):
            return []
        up = [i for i in ifs if i.get("link_status", "").lower() == "up"]
        errs = {i["interface"]: int(i.get("crc") or 0) + int(i.get("input_errors") or 0) for i in up}
        rows = [self.result("interfaces", OK, f"{len(up)}/{len(ifs)} up")]
        if not self.delta_mode:                      # any interface that has ever counted an error
            bad = [n for n, e in errs.items() if e > 0]
            rows.append(self.result("interface errors", WARN if bad else OK, len(bad),
                                    ", ".join(bad[:5]), numeric=float(len(bad))))
            return rows
        grew = {}                                    # only interfaces whose counters rose since last run
        first = False
        for name, e in errs.items():
            d = self.delta(f"if:{name}", e)
            if d is None:
                first = True
            elif d > 0:
                grew[name] = d
        if first and not grew and not self._baseline:
            rows.append(self.result("interface errors", OK, "baseline set",
                                    "counters recorded; changes are reported from the next run"))
        else:
            rows.append(self.result("interface errors", WARN if grew else OK, len(grew),
                                    ", ".join(f"{n} (+{d:.0f})" for n, d in list(grew.items())[:5]),
                                    numeric=float(len(grew))))
        return rows

    def bgp(self, c):
        peers = []
        for line in c.send_command("show ip bgp summary").splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+.*\s(\S+)\s*$", line)
            if m and "Admin" not in line:
                peers.append((m.group(1), m.group(2)))
        if not peers:
            return []                      # BGP not configured
        down = [ip for ip, state in peers if not state.isdigit()]
        return self.result("bgp", FAIL if down else OK, f"{len(peers) - len(down)}/{len(peers)} established",
                           "down: " + ", ".join(down) if down else "", numeric=float(len(peers) - len(down)))

    def ospf(self, c):
        if "asa" in self.plat:
            return []
        nbrs = []
        for line in c.send_command("show ip ospf neighbor").splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+([A-Za-z0-9]+)", line)
            if m:
                nbrs.append((m.group(1), m.group(2).upper()))
        if not nbrs:
            return []                      # OSPF not configured
        bad = [f"{i} ({s})" for i, s in nbrs if s not in ("FULL", "2WAY")]
        return self.result("ospf", FAIL if bad else OK, f"{len(nbrs) - len(bad)}/{len(nbrs)} adjacent",
                           "; ".join(bad), numeric=float(len(nbrs) - len(bad)))

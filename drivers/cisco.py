import re
from core.netconn import connect as ConnectHandler      # netmiko's, with Toner's fixes for some devices (ASA)
from .base import Driver, OK, WARN, FAIL, grade_low
from .sshbase import Recorder
from .clirows import CliRows
from . import clichecks
from core import quiet, display

_UPTIME_UNITS = {"year": 8760, "week": 168, "day": 24, "hour": 1, "min": 1 / 60}

def uptime_hours(text):
    """'1 year, 2 weeks, 3 days, 4 hours, 5 minutes' (IOS) or '12 days 3 hours 4 mins' (ASA) -> hours."""
    return sum(int(n) * _UPTIME_UNITS[u] for n, u in re.findall(r"(\d+)\s+(year|week|day|hour|min)", text))

class CiscoDriver(CliRows, Driver):
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
                             ("interfaces", self.interfaces), ("bgp", self.bgp), ("ospf", self.ospf), ("eigrp", self.eigrp),
                             ("environment", self.environment), ("ntp", self.ntp), ("unsaved config", self.unsaved), ("flash", self.flash),
                             ("stack", self.stack), ("hsrp", self.hsrp), ("port-channels", self.port_channels), ("failover", self.failover)):
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
        if getattr(self, "session_log", None):          # Command Runner records the session (passwords left out)
            args["session_log"] = self.session_log
        from core import jump
        sock, closers = jump.open_channel(d, t)          # (None, []) unless the device is behind a jump host
        if sock is not None:
            args["sock"] = sock
            return jump.Managed(ConnectHandler(**args), closers)
        return ConnectHandler(**args)

    @staticmethod
    def unreadable(what, command):
        return ValueError(f"could not read {what} from '{command}' (unexpected output)")

    def cpu(self, c):
        if "asa" in self.plat:
            pct = clichecks.asa_cpu(c.send_command("show cpu usage"))
            if pct is None:
                raise self.unreadable("the CPU load", "show cpu usage")
            return self.level_check("cpu", pct)
        if "nxos" in self.plat:
            m = re.search(r"CPU states\s*:\s*([\d.]+)%\s*user,\s*([\d.]+)%\s*kernel",
                          c.send_command("show system resources"))
            return self.level_check("cpu", float(m.group(1)) + float(m.group(2))) if m else []
        m = re.search(r"five minutes: (\d+)%", c.send_command("show processes cpu"))
        return self.level_check("cpu", int(m.group(1))) if m else []

    def memory(self, c):
        if "asa" in self.plat:
            pct = clichecks.asa_memory(c.send_command("show memory"))
            if pct is None:
                raise self.unreadable("the memory use", "show memory")
            return self.level_check("memory", pct)
        if "nxos" in self.plat:
            m = re.search(r"(\d+)K total,\s+(\d+)K used", c.send_command("show system resources"))
        else:
            m = re.search(r"Processor Pool Total:\s+(\d+)\s+Used:\s+(\d+)",
                          c.send_command("show processes memory | include Processor"))
        return self.level_check("memory", int(m.group(2)) / int(m.group(1)) * 100) if m else []

    def uptime(self, c):
        if "asa" in self.plat:                     # 'fw1 up 12 days 3 hours'
            text = clichecks.asa_uptime(c.send_command("show version"))
            if text is None:
                raise self.unreadable("the uptime", "show version")
        else:
            m = re.search(r"uptime is (.+)", c.send_command("show version"))
            if not m:
                return []
            text = m.group(1).strip()
        hours = uptime_hours(text)
        t = self.th["uptime"]
        status = grade_low(hours, t["warn"], t["fail"])
        return self.result("uptime", status, display.uptime(hours), "recent reboot" if status != OK else "", numeric=hours)

    # ---------------------------------------------------------------- health and redundancy
    def environment(self, c):
        return self.env_row(c, "show environment" if ("nxos" in self.plat or "asa" in self.plat) else "show environment all")

    def ntp(self, c):
        if "nxos" in self.plat:
            return []
        return self.ntp_row(clichecks.ntp_state(c.send_command("show ntp status")))

    def unsaved(self, c):
        """The running configuration changed since it was last saved to the startup configuration (IOS and IOS XE)."""
        if "nxos" in self.plat or "asa" in self.plat:
            return []
        r = clichecks.unsaved_ios(c.send_command("show running-config | include ^! Last configuration change|^! NVRAM config last updated"))
        if r is None:
            return []
        return self.result("unsaved config", WARN if r[0] else OK, "not saved" if r[0] else "saved", r[1])

    def flash(self, c):
        if "asa" in self.plat:
            return self.flash_row(c, "dir disk0:")
        return self.flash_row(c, "dir bootflash:" if "nxos" in self.plat else "dir flash:", "dir bootflash:")

    def stack(self, c):
        if "nxos" in self.plat or "asa" in self.plat:
            return []
        members = clichecks.stack_members(c.send_command("show switch"))
        if len(members) < 2:
            return []                      # a single switch, or one that cannot stack
        bad = [f"switch {n} ({st})" for n, role, st in members if st.strip().lower() != "ready"]
        return self.result("stack", FAIL if bad else OK, f"{len(members) - len(bad)}/{len(members)} ready", "not ready: " + ", ".join(bad) if bad else "",
                           numeric=float(len(members) - len(bad)))

    def hsrp(self, c):
        if "asa" in self.plat:
            return []
        groups = clichecks.hsrp_groups(c.send_command("show standby brief")) or clichecks.hsrp_groups(c.send_command("show vrrp brief"))
        if not groups:
            return []
        stuck = [f"{i} group {g} ({s})" for i, g, s in groups if s in ("Init", "Listen", "Speak", "Learn", "Disabled")]
        return self.result("hsrp", WARN if stuck else OK, f"{len(groups) - len(stuck)}/{len(groups)} active or standby", "not settled: " + ", ".join(stuck[:4]) if stuck else "",
                           numeric=float(len(groups) - len(stuck)))

    def port_channels(self, c):
        if "asa" in self.plat:
            return []
        chans = clichecks.etherchannels(c.send_command("show port-channel summary" if "nxos" in self.plat else "show etherchannel summary"))
        if not chans:
            return []
        down = [name for name, flags, _ in chans if "D" in flags and "U" not in flags]
        weak = [f"{name}: {m} ({f})" for name, flags, members in chans for m, f in members if not set(f) & {"P", "H"} and name not in down]
        status = FAIL if down else WARN if weak else OK
        return self.result("port-channels", status, f"{len(chans) - len(down)}/{len(chans)} up",
                           ("down: " + ", ".join(down)) if down else ("members not bundled: " + ", ".join(weak[:4])) if weak else "", numeric=float(len(chans) - len(down)))

    def failover(self, c):
        if "asa" not in self.plat:
            return []
        text = c.send_command("show failover")
        r = clichecks.asa_failover(text)
        if r is None:
            if "failover off" in text.lower() or "not supported" in text.lower():
                return self.not_applicable("failover", "off", "failover is not configured")
            raise self.unreadable("the failover state", "show failover")
        this, other, problems = r
        return self.result("failover", FAIL if problems else OK, f"{this} / {other}", "; ".join(problems))

    @staticmethod
    def _states(ifs):
        out = []
        for i in ifs:
            link = str(i.get("link_status", "")).lower()
            out.append((i["interface"], "up" if link == "up" else "off" if link.startswith("admin") else "down"))
        return out

    def _interfaces(self, c):
        if "asa" in self.plat:
            ifs = clichecks.asa_interfaces(c.send_command("show interface"))
            if not ifs:
                raise self.unreadable("the interfaces", "show interface")
            return ifs
        return c.send_command("show interfaces", use_textfsm=True)

    def if_states(self, c):
        ifs = self._interfaces(c)
        return self._states(ifs) if isinstance(ifs, list) else []

    def list_interfaces(self):
        """For Edit device > Checks > Choose interfaces."""
        self.plat = self.dev.get("platform") or self.DEFAULT_PLATFORM
        with self.connect() as conn:
            c = Recorder(conn, self.transcript)
            try:
                c.enable()
            except Exception:
                quiet.ignored()
            return self.if_states(c)

    def interfaces(self, c):
        ifs = self._interfaces(c)
        if not isinstance(ifs, list):
            return []
        up = [i for i in ifs if i.get("link_status", "").lower() == "up"]
        errs = {i["interface"]: int(i.get("crc") or 0) + int(i.get("input_errors") or 0) for i in up if self.wanted_interface(i["interface"])}
        rows = self.interfaces_row(self._states(ifs))
        rows = [rows] if rows else []
        if not errs:
            return rows
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
        text = c.send_command("show bgp summary" if "asa" in self.plat else "show ip bgp summary")
        for line in text.splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+.*\s(\S+)\s*$", line)
            if m and "Admin" not in line:
                peers.append((m.group(1), m.group(2)))
        down = [ip for ip, state in peers if not state.isdigit()]
        return self.neighbors_row("bgp", "BGP", clichecks.bgp_running(text), len(peers), down,
                                  value=f"{len(peers) - len(down)}/{len(peers)} established")

    def ospf(self, c):
        nbrs = []
        for line in c.send_command("show ospf neighbor" if "asa" in self.plat else "show ip ospf neighbor").splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+([A-Za-z0-9]+)", line)
            if m:
                nbrs.append((m.group(1), m.group(2).upper()))
        running = bool(nbrs) or clichecks.ospf_running(c.send_command("show ospf" if "asa" in self.plat else "show ip ospf"))
        bad = [f"{i} ({s})" for i, s in nbrs if s not in ("FULL", "2WAY")]
        return self.neighbors_row("ospf", "OSPF", running, len(nbrs), bad,
                                  value=f"{len(nbrs) - len(bad)}/{len(nbrs)} adjacent", message="; ".join(bad))

    def eigrp(self, c):
        """A neighbor that goes down leaves EIGRP's table, so the count is compared with the previous run's."""
        running, nbrs = clichecks.eigrp_neighbors(c.send_command("show eigrp neighbors" if "asa" in self.plat else "show ip eigrp neighbors"))
        n = len({a for a, _i in nbrs})
        before = self.previous("eigrp:neighbors", n) if running else None
        if not n:
            return self.neighbors_row("eigrp", "EIGRP", running, 0, [])
        value = f"{n} neighbor{'s' if n != 1 else ''}"
        if before is not None and n < before:
            return self.result("eigrp", WARN, value, f"{before - n:.0f} fewer than the last run ({before:.0f})", numeric=float(n))
        return self.result("eigrp", OK, value, numeric=float(n))

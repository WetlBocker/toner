"""Generic SNMP device: CPU, memory, storage, uptime, interfaces, errors, utilisation, temperature.

Works on anything that answers standard MIBs (HOST-RESOURCES, IF-MIB, ENTITY-SENSOR, UCD-SNMP) and falls back
to a few common vendor MIBs for CPU and memory. Checks a device does not support are left out, not failed.
"""
import time

from core import snmp
from core.snmp import number_of, text_of
from .base import Driver, OK, WARN, FAIL, grade, grade_low

N = snmp.NAMES
HR_RAM = "1.3.6.1.2.1.25.2.1.2"
HR_DISK = "1.3.6.1.2.1.25.2.1.4"
VIRTUAL_IF = {"24", "53", "131", "135", "136", "142", "161"}      # loopback, virtual, tunnel, vlan, lag helpers


class SnmpDriver(Driver):
    def run(self):
        creds, port = snmp.credentials_for(self.dev)
        out = []
        with snmp.Client(self.dev["host"], port, creds, timeout=min(self.opts["http_timeout"], 10), retries=1) as c:
            self.c = c
            ident = self._identity()                           # also proves the credentials work
            if self.enabled("reachability"):
                out.append(ident)
            for key, fn in (("cpu", self.cpu), ("memory", self.memory), ("storage", self.storage),
                            ("uptime", self.uptime), ("temperature", self.temperature),
                            ("interfaces", self.interfaces), ("interface errors", self.errors),
                            ("bandwidth", self.bandwidth)):
                if self.enabled(key):
                    self.safe(out, key, fn)
        return out

    # ---------------------------------------------------------------- identity
    def _identity(self):
        c = self.c
        got = c.get(N["sysDescr"] + ".0", N["sysObjectID"] + ".0", N["sysName"] + ".0", N["sysUpTime"] + ".0")
        if not got:
            raise ValueError("the device answered but returned no system information")
        self._uptime_ticks = number_of(got.get(N["sysUpTime"] + ".0"))
        name = text_of(got.get(N["sysName"] + ".0", ""))
        descr = " ".join(text_of(got.get(N["sysDescr"] + ".0", "")).split())
        vendor = snmp.vendor_from_oid(text_of(got.get(N["sysObjectID"] + ".0", "")))
        return self.result("reachability", OK, name or "answering", (descr[:110] + (f"  [{vendor}]" if vendor else "")))

    # ---------------------------------------------------------------- cpu / memory / storage
    def cpu(self):
        c = self.c
        probes = (("hr", N["hrProcessorLoad"]), ("cisco", N["cpmCPUTotal5minRev"]),
                  ("juniper", N["jnxOperatingCPU"]))
        for _, root in probes:
            vals = [number_of(v) for v in c.try_column(root).values()]
            vals = [v for v in vals if v is not None]
            if vals:
                return self.level_check("cpu", max(vals))
        fg = c.try_get(N["fgSysCpuUsage"] + ".0")
        if fg:
            return self.level_check("cpu", number_of(next(iter(fg.values())), 0))
        idle = c.try_get(N["ssCpuIdle"] + ".0")
        if idle:
            return self.level_check("cpu", 100 - number_of(next(iter(idle.values())), 100))
        return []

    def memory(self):
        c = self.c
        u = c.try_get(*(N[k] + ".0" for k in ("memTotalReal", "memAvailReal", "memBuffer", "memCached")))
        total, avail = number_of(u.get(N["memTotalReal"] + ".0")), number_of(u.get(N["memAvailReal"] + ".0"))
        if total and avail is not None:                                        # Linux/BSD: cache is reclaimable
            used = total - avail - number_of(u.get(N["memBuffer"] + ".0"), 0) - number_of(u.get(N["memCached"] + ".0"), 0)
            return self.level_check("memory", max(0.0, used) / total * 100)
        types, size, used = (c.try_column(f"{N['hrStorageType'][:-2]}.{i}") for i in (2, 5, 6))
        rams = [i for i, v in types.items() if text_of(v) in (HR_RAM, "hrStorageRam") or str(v) == HR_RAM]
        for i in rams:
            s, un = number_of(size.get(i)), number_of(used.get(i))
            if s and un is not None:
                return self.level_check("memory", un / s * 100)
        for pool_used, pool_free in ((N["ciscoMemoryPoolUsed"], N["ciscoMemoryPoolFree"]),):
            a, b = c.try_column(pool_used), c.try_column(pool_free)
            idx = "1" if "1" in a and "1" in b else next(iter(a), None)
            if idx and idx in b:
                tot = number_of(a[idx], 0) + number_of(b[idx], 0)
                if tot:
                    return self.level_check("memory", number_of(a[idx], 0) / tot * 100)
        jb = c.try_column(N["jnxOperatingBuffer"])
        vals = [number_of(v) for v in jb.values() if number_of(v)]
        if vals:
            return self.level_check("memory", max(vals))
        fg = c.try_get(N["fgSysMemUsage"] + ".0")
        if fg:
            return self.level_check("memory", number_of(next(iter(fg.values())), 0))
        return []

    def storage(self):
        c = self.c
        base = N["hrStorageType"][:-2]
        types, descr, unit, size, used = (c.try_column(f"{base}.{i}") for i in (2, 3, 4, 5, 6))
        worst = None
        for i, t in types.items():
            if str(t) != HR_DISK and text_of(t) != "hrStorageFixedDisk":
                continue
            s, un = number_of(size.get(i)), number_of(used.get(i))
            if not s or un is None:
                continue
            pct = un / s * 100
            if worst is None or pct > worst[0]:
                worst = (pct, text_of(descr.get(i, i)))
        if worst is None:
            return []
        t = self.th["disk"]
        return self.result("storage", grade(worst[0], t["warn"], t["fail"]), f"{worst[0]:.0f}%", worst[1],
                           numeric=float(worst[0]))

    # ---------------------------------------------------------------- uptime / temperature
    def uptime(self):
        ticks = self._uptime_ticks
        if ticks is None:
            return []
        hours = ticks / 100 / 3600
        d, r = divmod(int(ticks / 100), 86400)
        t = self.th["uptime"]
        status = grade_low(hours, t["warn"], t["fail"])
        return self.result("uptime", status, f"{d}d {r // 3600}h", "recent reboot" if status != OK else "", numeric=hours)

    def temperature(self):
        c = self.c
        temps = []
        types = c.try_column(N["entPhySensorType"])
        base = N["entPhySensorType"][:-1]
        for i, t in types.items():
            if number_of(t) != 8:                                              # 8 = celsius
                continue
            got = c.try_get(f"{base}2.{i}", f"{base}3.{i}", f"{base}4.{i}")
            raw, scale, prec = (number_of(got.get(f"{base}{k}.{i}")) for k in (4, 2, 3))
            if raw is None:
                continue
            value = raw * 10 ** (((scale or 9) - 9) * 3) / (10 ** (prec or 0))
            if -40 < value < 150:
                temps.append(value)
        if not temps:                                                          # Cisco environment monitor
            temps = [v for v in (number_of(x) for x in c.try_column("1.3.6.1.4.1.9.9.13.1.3.1.3").values())
                     if v is not None and 0 < v < 150]
        if not temps:
            return []
        hottest = max(temps)
        t = self.th["temperature"]
        return self.result("temperature", grade(hottest, t["warn"], t["fail"]), f"{hottest:.0f}C",
                           f"{len(temps)} sensor(s)", numeric=hottest)

    # ---------------------------------------------------------------- interfaces
    def _ifs(self):
        if not hasattr(self, "_if_cache"):
            c = self.c
            descr = c.try_column(N["ifDescr"])
            self._if_cache = {
                "descr": descr, "name": c.try_column(N["ifName"]), "type": c.try_column(N["ifType"]),
                "admin": c.try_column(N["ifAdminStatus"]), "oper": c.try_column(N["ifOperStatus"])}
        return self._if_cache

    def _label(self, i):
        d = self._ifs()
        return text_of(d["name"].get(i)) or text_of(d["descr"].get(i, i))

    def _real_ifs(self):
        d, out = self._ifs(), []
        for i in d["descr"]:
            kind = number_of(d["type"].get(i))
            if kind is None or str(int(kind)) not in VIRTUAL_IF:
                out.append(i)
        return out

    def interfaces(self):
        d = self._ifs()
        ifs = self._real_ifs()
        if not ifs:
            return []
        active = [i for i in ifs if number_of(d["admin"].get(i)) == 1]
        up = [i for i in active if number_of(d["oper"].get(i)) == 1]
        down = [self._label(i) for i in active if i not in up]
        return self.result("interfaces", OK, f"{len(up)}/{len(active)} up",
                           ("down: " + ", ".join(down[:5])) if down else "", numeric=float(len(up)))

    def errors(self):
        c = self.c
        ifs = [i for i in self._real_ifs() if number_of(self._ifs()["oper"].get(i)) == 1]
        if not ifs:
            return []
        inn, out = c.try_column(N["ifInErrors"]), c.try_column(N["ifOutErrors"])
        errs = {self._label(i): int((number_of(inn.get(i), 0) or 0) + (number_of(out.get(i), 0) or 0)) for i in ifs}
        return self.error_counter_rows("interface errors", errs)

    def bandwidth(self):
        c = self.c
        ifs = [i for i in self._real_ifs() if number_of(self._ifs()["oper"].get(i)) == 1]
        if not ifs:
            return []
        hc_in, hc_out = c.try_column(N["ifHCInOctets"]), c.try_column(N["ifHCOutOctets"])
        if not hc_in:
            hc_in, hc_out = c.try_column(N["ifInOctets"]), c.try_column(N["ifOutOctets"])
        high, low = c.try_column(N["ifHighSpeed"]), c.try_column(N["ifSpeed"])
        elapsed = self.delta("bw:t", time.time())
        worst = None
        for i in ifs:
            speed = (number_of(high.get(i), 0) or 0) * 1e6 or (number_of(low.get(i), 0) or 0)
            din = self.delta(f"bw:in:{i}", number_of(hc_in.get(i), 0) or 0)
            dout = self.delta(f"bw:out:{i}", number_of(hc_out.get(i), 0) or 0)
            if elapsed and elapsed >= 5 and speed and din is not None and dout is not None:
                util = max(din, dout) * 8 / elapsed / speed * 100
                if worst is None or util > worst[0]:
                    worst = (util, self._label(i), max(din, dout) * 8 / elapsed)
        if worst is None:
            return self.result("bandwidth", OK, "baseline set", "rates are reported from the next run")
        t = self.th["utilization"]
        return self.result("bandwidth", grade(worst[0], t["warn"], t["fail"]), f"{worst[0]:.0f}%",
                           f"busiest: {worst[1]} at {snmp.fmt_bps(worst[2])}", numeric=float(worst[0]))

"""More SNMP checks, for the devices an MSP finds in a server room and a back office: a fan or power supply gone bad on any switch,
router or firewall, UPS batteries, printer toner and paper, Synology and QNAP storage, and Linux load. Each one asks for what it needs and
says nothing when the device does not have it, so they are safe to switch on for every SNMP device.

OIDs: ENTITY-SENSOR-MIB (RFC 3433), CISCO-ENVMON-MIB, JUNIPER-MIB, UPS-MIB (RFC 1628), APC PowerNet-MIB, Printer-MIB (RFC 3805),
SYNOLOGY-SYSTEM-MIB, UCD-SNMP-MIB.
"""
from core.snmp import number_of, text_of
from .base import OK, WARN, FAIL, grade, grade_low

SEVERITY = {OK: 0, WARN: 1, FAIL: 2}

ENT_SENSOR_STATUS = "1.3.6.1.2.1.99.1.1.1.5"           # 1 ok, 2 unavailable, 3 nonoperational
ENT_NAME, ENT_DESCR = "1.3.6.1.2.1.47.1.1.1.1.7", "1.3.6.1.2.1.47.1.1.1.1.2"
CISCO_ENV = (("fan", "1.3.6.1.4.1.9.9.13.1.4.1"), ("power supply", "1.3.6.1.4.1.9.9.13.1.5.1"), ("temperature sensor", "1.3.6.1.4.1.9.9.13.1.3.1"))
CISCO_STATE = {"2": (WARN, "warning"), "3": (FAIL, "critical"), "4": (FAIL, "shutdown"), "6": (FAIL, "not functioning")}
JNX_STATE, JNX_DESCR = "1.3.6.1.4.1.2636.3.1.13.1.6", "1.3.6.1.4.1.2636.3.1.13.1.5"

LA_LOAD = "1.3.6.1.4.1.2021.10.1.3"                      # laLoad.1 / .2 / .3 : 1, 5 and 15 minutes, as text
HR_PROCESSOR = "1.3.6.1.2.1.25.3.3.1.2"

UPS = "1.3.6.1.2.1.33.1"
APC = "1.3.6.1.4.1.318.1.1.1"

PRT_SUPPLY = "1.3.6.1.2.1.43.11.1.1"                      # .4 class, .6 description, .8 max capacity, .9 level
PRT_INPUT = "1.3.6.1.2.1.43.8.2.1"                        # .9 max capacity, .10 current level, .13 name

SYNO = "1.3.6.1.4.1.6574"
QNAP = "1.3.6.1.4.1.24681.1.2"


def _worst(items):
    return max((s for s, _ in items), key=lambda s: SEVERITY[s], default=OK)


def _num_text(raw):
    """A number out of text such as '0.15' or '45 C/113 F'."""
    import re
    m = re.search(r"-?\d+(?:\.\d+)?", text_of(raw))
    return float(m.group(0)) if m else None


class SnmpExtras:
    """Mixed into the SNMP driver. self.c is the open client, self.th the limits, self.result() builds a row."""

    # ---------------------------------------------------------------- fans, power supplies and sensors
    def environment(self):
        c = self.c
        problems, total = [], 0
        ops = c.try_column(ENT_SENSOR_STATUS)
        if ops:
            names, descr = c.try_column(ENT_NAME), c.try_column(ENT_DESCR)
            for i, v in ops.items():
                total += 1
                if number_of(v) == 3:
                    problems.append((FAIL, f"{text_of(names.get(i)) or text_of(descr.get(i)) or 'sensor ' + i}: not operating"))
        for kind, root in CISCO_ENV:
            states = c.try_column(f"{root}.{3 if kind != 'temperature sensor' else 6}")
            if not states:
                continue
            descr = c.try_column(f"{root}.2")
            for i, v in states.items():
                state = str(int(number_of(v, 0) or 0))
                if state == "5":                                   # not present: an empty slot
                    continue
                total += 1
                if state in CISCO_STATE:
                    level, word = CISCO_STATE[state]
                    problems.append((level, f"{text_of(descr.get(i)) or kind + ' ' + i}: {word}"))
        states = c.try_column(JNX_STATE)
        if states:
            descr = c.try_column(JNX_DESCR)
            for i, v in states.items():
                total += 1
                if number_of(v) == 6:
                    problems.append((FAIL, f"{text_of(descr.get(i)) or 'component ' + i}: down"))
        if not total:
            return []
        status = _worst(problems)
        if not problems:
            return self.result("environment", OK, f"{total} ok", "fans, power supplies and sensors", numeric=0.0)
        shown = "; ".join(m for _, m in problems[:4]) + (f"; and {len(problems) - 4} more" if len(problems) > 4 else "")
        return self.result("environment", status, f"{len(problems)} of {total} not ok", shown, numeric=float(len(problems)))

    # ---------------------------------------------------------------- load average (Linux, BSD and anything running net-snmp)
    def load(self):
        c = self.c
        got = c.try_get(*(f"{LA_LOAD}.{i}" for i in (1, 2, 3)))
        one, five = _num_text(got.get(f"{LA_LOAD}.1")), _num_text(got.get(f"{LA_LOAD}.2"))
        if five is None:
            return []
        cores = max(1, len(c.try_column(HR_PROCESSOR)))
        per = five / cores
        t = self.th["load_per_core"]
        return self.result("load", grade(per, t["warn"], t["fail"]), f"{five:.2f}",
                           f"5-minute average on {cores} core{'s' if cores != 1 else ''} ({per:.2f} each)" + (f", 1-minute {one:.2f}" if one is not None else ""),
                           numeric=float(per))

    # ---------------------------------------------------------------- UPS (UPS-MIB, with APC PowerNet as the fallback)
    def ups(self):
        c = self.c
        std = c.try_get(*(f"{UPS}.{o}" for o in ("2.1.0", "2.3.0", "2.4.0", "4.1.0", "2.7.0")))
        apc = {} if std else c.try_get(*(f"{APC}.{o}" for o in ("2.1.1.0", "2.2.1.0", "2.2.3.0", "2.2.4.0", "4.1.1.0", "4.2.3.0", "2.2.2.0")))
        if not std and not apc:
            return []
        out, problems = [], []
        if std:
            status = {2: (OK, "normal"), 3: (WARN, "battery low"), 4: (FAIL, "battery depleted")}.get(number_of(std.get(f"{UPS}.2.1.0")), (OK, "unknown"))
            source = number_of(std.get(f"{UPS}.4.1.0"))
            on_batt = source == 5
            charge, minutes = number_of(std.get(f"{UPS}.2.4.0")), number_of(std.get(f"{UPS}.2.3.0"))
            load = [number_of(v) for v in c.try_column(f"{UPS}.4.4.1.5").values() if number_of(v) is not None]
            load = max(load) if load else None
            replace = False
        else:
            status = {2: (OK, "normal"), 3: (WARN, "battery low"), 4: (FAIL, "battery fault")}.get(number_of(apc.get(f"{APC}.2.1.1.0")), (OK, "unknown"))
            on_batt = number_of(apc.get(f"{APC}.4.1.1.0")) == 3
            charge = number_of(apc.get(f"{APC}.2.2.1.0"))
            ticks = number_of(apc.get(f"{APC}.2.2.3.0"))
            minutes = ticks / 6000 if ticks is not None else None                 # hundredths of a second
            load = number_of(apc.get(f"{APC}.4.2.3.0"))
            replace = number_of(apc.get(f"{APC}.2.2.4.0")) == 2
        level, word = status
        if on_batt:
            level, word = (FAIL if level == FAIL else WARN), "running on battery"
        if replace and level == OK:
            level, word = WARN, "battery needs replacing"
        out.append(self.result("ups", level, word, "mains power lost" if on_batt else ""))
        if charge is not None or minutes is not None:
            t_b, t_r = self.th["ups_battery"], self.th["ups_runtime"]
            levels = []
            if charge is not None:
                levels.append(grade_low(charge, t_b["warn"], t_b["fail"]))
            if minutes is not None and minutes < 10000:
                levels.append(grade_low(minutes, t_r["warn"], t_r["fail"]))
            worst = max(levels or [OK], key=lambda s: SEVERITY[s])
            bits = ([f"{charge:.0f}%"] if charge is not None else []) + ([f"{minutes:.0f} min left"] if minutes is not None and minutes < 10000 else [])
            out.append(self.result("ups battery", worst, "  ".join(bits), numeric=float(charge if charge is not None else minutes)))
        if load is not None:
            t = self.th["ups_load"]
            out.append(self.result("ups load", grade(load, t["warn"], t["fail"]), f"{load:.0f}%", numeric=float(load)))
        return out

    # ---------------------------------------------------------------- printers (Printer-MIB)
    def printer(self):
        c = self.c
        levels = c.try_column(f"{PRT_SUPPLY}.9")
        out = []
        if levels:
            descr, cap, cls = (c.try_column(f"{PRT_SUPPLY}.{k}") for k in (6, 8, 4))
            found = []
            for i, raw in levels.items():
                lvl, mx = number_of(raw), number_of(cap.get(i))
                if lvl is None or mx is None or mx <= 0 or lvl < 0:                # -3 'some remaining', -2 unknown
                    continue
                if number_of(cls.get(i)) == 4:                                     # a waste container fills up: 100% is bad, not good
                    found.append((100 - lvl / mx * 100, text_of(descr.get(i)) or f"supply {i}"))
                else:
                    found.append((lvl / mx * 100, text_of(descr.get(i)) or f"supply {i}"))
            if found:
                found.sort()
                t = self.th["toner"]
                lowest = found[0]
                low = [f"{n} {p:.0f}%" for p, n in found if p < t["warn"]]
                out.append(self.result("supplies", grade_low(lowest[0], t["warn"], t["fail"]), f"{lowest[0]:.0f}%",
                                       (", ".join(low[:4]) if low else f"lowest: {lowest[1]}"), numeric=float(lowest[0])))
        cur = c.try_column(f"{PRT_INPUT}.10")
        if cur:
            cap, names = c.try_column(f"{PRT_INPUT}.9"), c.try_column(f"{PRT_INPUT}.13")
            empty = [text_of(names.get(i)) or f"tray {i}" for i, v in cur.items() if number_of(v) == 0 and (number_of(cap.get(i), 0) or 0) != 0]
            out.append(self.result("paper", WARN if empty else OK, f"{len(empty)} empty" if empty else "ok", ", ".join(empty[:4]), numeric=float(len(empty))))
        return out

    # ---------------------------------------------------------------- NAS (Synology, QNAP)
    def nas(self):
        c = self.c
        syn = c.try_get(*(f"{SYNO}.1.{o}" for o in ("1.0", "2.0", "3.0", "4.1.0", "4.2.0", "5.4.0")))
        if syn:
            return self._synology(syn)
        qn = c.try_get(f"{QNAP}.6.0")
        return self._qnap(qn) if qn or c.try_column(f"{QNAP}.11.1.4") else []

    def _synology(self, syn):
        c = self.c
        out, problems = [], []
        if number_of(syn.get(f"{SYNO}.1.1.0")) == 2:
            problems.append((FAIL, "the system reports a failure"))
        if number_of(syn.get(f"{SYNO}.1.3.0")) == 2:
            problems.append((FAIL, "power supply failed"))
        for key, word in ((f"{SYNO}.1.4.1.0", "system fan failed"), (f"{SYNO}.1.4.2.0", "CPU fan failed")):
            if number_of(syn.get(key)) == 2:
                problems.append((FAIL, word))
        temp = number_of(syn.get(f"{SYNO}.1.2.0"))
        if temp is not None:
            t = self.th["temperature"]
            if grade(temp, t["warn"], t["fail"]) != OK:
                problems.append((grade(temp, t["warn"], t["fail"]), f"system {temp:.0f} C"))
        disk_status, disk_name, disk_temp = (c.try_column(f"{SYNO}.2.1.1.{k}") for k in (5, 2, 6))
        bad_disks = []
        for i, v in disk_status.items():
            s = number_of(v)
            label = text_of(disk_name.get(i)) or f"disk {i}"
            if s in (4, 5):
                bad_disks.append((FAIL, f"{label}: {'crashed' if s == 5 else 'system partition failed'}"))
            elif s == 3:
                bad_disks.append((WARN, f"{label}: not initialised"))
            t = self.th["temperature"]
            dt = number_of(disk_temp.get(i))
            if dt is not None and grade(dt, t["warn"] + 10, t["fail"] + 10) != OK:      # disks run hotter than a CPU
                bad_disks.append((grade(dt, t["warn"] + 10, t["fail"] + 10), f"{label}: {dt:.0f} C"))
        problems += bad_disks
        raid_status, raid_name = c.try_column(f"{SYNO}.3.1.1.3"), c.try_column(f"{SYNO}.3.1.1.2")
        for i, v in raid_status.items():
            s = number_of(v)
            label = text_of(raid_name.get(i)) or f"volume {i}"
            if s in (11, 12):                                                # degraded, crashed
                problems.append((FAIL, f"{label}: {'degraded' if s == 11 else 'crashed'}"))
            elif s in (2, 3, 4, 7, 8, 9, 10):                                # rebuilding, migrating, expanding, syncing, checking
                problems.append((WARN, f"{label}: {({2: 'repairing', 3: 'migrating', 4: 'expanding', 7: 'syncing', 8: 'checking parity', 9: 'assembling', 10: 'cancelling'})[int(s)]}"))
        if number_of(syn.get(f"{SYNO}.1.5.4.0")) == 1:
            problems.append((WARN, "a DSM update is available"))
        status = _worst(problems)
        total = len(disk_status) + len(raid_status)
        if not problems:
            out.append(self.result("nas", OK, f"{len(disk_status)} disk(s), {len(raid_status)} volume(s) ok", "Synology"))
        else:
            out.append(self.result("nas", status, f"{len(problems)} issue(s)", "; ".join(m for _, m in problems[:4]) + (f"; and {len(problems) - 4} more" if len(problems) > 4 else ""),
                                   numeric=float(len(problems))))
        return out

    def _qnap(self, qn):
        c = self.c
        problems = []
        temp = _num_text(qn.get(f"{QNAP}.6.0"))
        if temp is not None:
            t = self.th["temperature"]
            if grade(temp, t["warn"], t["fail"]) != OK:
                problems.append((grade(temp, t["warn"], t["fail"]), f"system {temp:.0f} C"))
        status, desc = c.try_column(f"{QNAP}.11.1.4"), c.try_column(f"{QNAP}.11.1.2")
        for i, v in status.items():
            s = number_of(v)
            if s is not None and s < 0 and s != -5:                           # -5 is an empty bay
                problems.append((FAIL, f"{text_of(desc.get(i)) or 'disk ' + i}: {({-4: 'unknown', -6: 'invalid', -9: 'read/write error'}).get(int(s), 'error')}"))
        if not problems:
            return self.result("nas", OK, f"{len(status)} disk(s) ok", "QNAP")
        return self.result("nas", _worst(problems), f"{len(problems)} issue(s)", "; ".join(m for _, m in problems[:4]), numeric=float(len(problems)))

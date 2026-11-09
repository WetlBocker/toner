"""Sophos Firewall (SFOS, the XG and XGS series) by SNMP: turn SNMP on under Administration > SNMP (v3 or a v2c community). The
standard MIBs give CPU, memory, interfaces and uptime; Sophos's own SFOS-FIREWALL-MIB (enterprise 2604.5.1) gives the firmware
version, disk and memory use, the services, HA and the licences. The SFOS objects are read when the firewall has them and skipped
when it does not, so the driver is safe on any firmware."""
from core.snmp import number_of, text_of
from .base import OK, WARN, FAIL, grade
from .snmpdev import SnmpDriver

SFOS = "1.3.6.1.4.1.2604.5.1"
DEVICE_NAME, DEVICE_TYPE, FW_VERSION = f"{SFOS}.1.1.0", f"{SFOS}.1.2.0", f"{SFOS}.1.3.0"
DISK_PCT, MEM_PCT, SWAP_PCT = f"{SFOS}.2.4.2.0", f"{SFOS}.2.5.4.0", f"{SFOS}.2.5.2.0"
SERVICES = f"{SFOS}.3"                                  # one object per service: untouched(0) stopped(1) initializing(2) running(3) exiting(4) dead(5) frozen(6)
SERVICE_NAMES = {"1": "POP3", "2": "IMAP4", "3": "SMTP", "4": "FTP", "5": "HTTP", "6": "antivirus", "7": "anti-spam", "8": "DNS", "9": "HA", "10": "IPS",
                 "11": "Apache", "12": "NTP", "13": "Tomcat", "14": "SSL VPN", "15": "IPsec VPN", "16": "database", "17": "network", "18": "Garner",
                 "19": "dynamic routing", "20": "SSH", "21": "DGD"}
SERVICE_STATE = {"0": "untouched", "1": "stopped", "2": "initializing", "3": "running", "4": "exiting", "5": "dead", "6": "frozen"}
HA = f"{SFOS}.4"                                        # .1 enabled(1)/disabled(0), .2 current state, .3 peer state  (best effort)
LICENSES = f"{SFOS}.5"                                  # per module: .N.1 registration status, .N.2 expiry date (best effort)


class SophosDriver(SnmpDriver):
    def check_list(self):
        return [("cpu", self.cpu), ("memory", self.memory), ("storage", self.storage), ("uptime", self.uptime),
                ("interfaces", self.interfaces), ("interface errors", self.errors), ("bandwidth", self.bandwidth),
                ("wan usage", self.wan_usage), ("version", self.version), ("disk", self.disk), ("services", self.services), ("ha", self.ha), ("licenses", self.licenses)]

    def version(self):
        got = self.c.try_get(FW_VERSION, DEVICE_TYPE, DEVICE_NAME)
        if not got:
            return []
        version = text_of(got.get(FW_VERSION, ""))
        self.found_software(version)
        return self.result("version", OK, version or "unknown", text_of(got.get(DEVICE_TYPE, "")))

    def memory(self):
        got = self.c.try_get(MEM_PCT)
        if got:
            pct = number_of(next(iter(got.values())))
            if pct is not None:
                return self.level_check("memory", float(pct))
        return super().memory()

    def disk(self):
        got = self.c.try_get(DISK_PCT)
        if not got:
            return []
        pct = number_of(next(iter(got.values())))
        if pct is None:
            return []
        t = self.th["disk"]
        return self.result("disk", grade(float(pct), t["warn"], t["fail"]), f"{pct:.0f}%", "the firewall's disk", numeric=float(pct))

    def services(self):
        col = self.c.try_column(SERVICES)
        if not col:
            return []
        bad, total = [], 0
        for idx, raw in col.items():
            n = idx.split(".")[0]
            name = SERVICE_NAMES.get(n, f"service {n}")
            code = number_of(raw)
            state = SERVICE_STATE.get(str(int(code)), "") if code is not None else ""
            if not state or state == "untouched":
                continue
            total += 1
            if state in ("stopped", "dead", "frozen", "exiting"):
                bad.append(f"{name}: {state}")
        if not total:
            return []
        return self.result("services", FAIL if any(": dead" in b or ": frozen" in b for b in bad) else WARN if bad else OK,
                           f"{total - len(bad)}/{total} running", "; ".join(bad[:6]), numeric=float(total - len(bad)))

    def ha(self):
        col = self.c.try_column(HA)
        if not col:
            return []
        enabled = number_of(col.get("1.0", col.get("1")))
        if not enabled:
            return []
        state = text_of(col.get("2.0", col.get("2", ""))).lower()
        peer = text_of(col.get("3.0", col.get("3", ""))).lower()
        bad = bool(state) and not any(w in state for w in ("primary", "auxiliary", "standby", "active", "1", "2"))
        return self.result("ha", WARN if bad or "fault" in peer or "down" in peer else OK, state or "enabled", f"peer: {peer}" if peer else "")

    def licenses(self):
        col = self.c.try_column(LICENSES)
        if not col:
            return []
        expired = []
        for idx, raw in col.items():
            parts = idx.split(".")
            if len(parts) >= 2 and parts[1] == "1":
                status = text_of(raw).lower()
                if status and any(w in status for w in ("expired", "unsubscribed", "not")):
                    expired.append(f"module {parts[0]}: {status}")
        return self.result("licenses", WARN if expired else OK, "ok" if not expired else f"{len(expired)} not active", "; ".join(expired[:5]), numeric=float(len(expired)))

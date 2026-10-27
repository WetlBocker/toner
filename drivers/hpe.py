import re

from .sshbase import SshDriver, uptime_hours
from .clirows import CliRows
from . import clichecks


class HpeDriver(CliRows, SshDriver):
    """Aruba / HPE switches: AOS-CX (aruba_aoscx) and AOS-S, formerly ProCurve (aruba_osswitch)."""
    DEFAULT_PLATFORM = "aruba_aoscx"

    @property
    def cx(self):
        return self.plat == "aruba_aoscx"

    def checks(self):
        return [("cpu", self.cpu), ("memory", self.memory), ("uptime", self.uptime),
                ("interfaces", self.interfaces), ("environment", self.environment), ("ntp", self.ntp)]

    def environment(self, c):
        if self.cx:
            return self.env_row(c, "show environment fan", "show environment power-supply", "show environment temperature")
        return self.env_row(c, "show system fans", "show system power-supply", "show system temperature")

    def ntp(self, c):
        return self.ntp_row(clichecks.ntp_state(self.cmd(c, "show ntp status"))) if self.cx else []

    def software(self, c):
        """AOS-CX: 'ArubaOS-CX Version : FL.10.08.1021' on `show system` (the uptime's screen); AOS-S: 'Software revision : WC.16.10.0012'
        on `show system information`."""
        if self.cx:
            m = re.search(r"(?im)^\s*(?:ArubaOS-CX|Software) Version\s*:\s*(\S+)", self.cmd(c, "show system"))
        else:
            m = re.search(r"(?im)^\s*Software revision\s*:\s*(\S+)", self._info(c))
        if m:
            self.found_software(m.group(1))

    # AOS-S: everything is on one screen; AOS-CX: resource usage and system info are separate commands.
    def _info(self, c):
        return self.cmd(c, "show system information")

    def _usage(self, c):
        return self.cmd(c, "show system resource-utilization")

    def _percent(self, text, word):
        m = re.search(rf"(?im)^[^\n]*\b{word}\b[^\n\d]*?(\d+(?:\.\d+)?)\s*%", text)
        return float(m.group(1)) if m else None

    def cpu(self, c):
        if self.cx:
            v = self._percent(self._usage(c), "cpu")
            where = "show system resource-utilization"
        else:
            m = re.search(r"CPU Util \(%\)\s*:\s*(\d+)", self._info(c))
            v, where = (float(m.group(1)) if m else None), "show system information"
        if v is None:
            raise self.unreadable("CPU", where)
        return self.level_check("cpu", v)

    def memory(self, c):
        if self.cx:
            v = self._percent(self._usage(c), "memory")
            if v is None:
                raise self.unreadable("memory", "show system resource-utilization")
            return self.level_check("memory", v)
        info = self._info(c)
        total = re.search(r"Total\s*:\s*([\d,]+)", info)
        free = re.search(r"Free\s*:\s*([\d,]+)", info)
        if not (total and free):
            raise self.unreadable("memory", "show system information")
        t, f = int(total.group(1).replace(",", "")), int(free.group(1).replace(",", ""))
        return self.level_check("memory", (t - f) / t * 100)

    def uptime(self, c):
        out = self.cmd(c, "show system") if self.cx else self._info(c)
        m = re.search(r"Up Time\s*:\s*(.+)", out)
        if not m:
            raise self.unreadable("uptime", "show system" if self.cx else "show system information")
        text = re.split(r"\s{2,}|Memory", m.group(1).strip())[0]      # AOS-S shares the line with memory figures
        return self.uptime_row(uptime_hours(text), text)

    def interfaces(self, c):
        return self.interfaces_row(self.if_states(c))

    def if_states(self, c):
        if self.cx:
            cmd = "show interface brief"
            rows = re.findall(r"(?m)^\s*(\d+/\d+/\d+|lag\s?\d+)\s.*?\s(up|down)\b", self.cmd(c, cmd), re.I)
        else:
            cmd = "show interfaces brief"
            rows = re.findall(r"(?m)^\s*([A-Za-z]?\d+)\s+\S+\s*\|\s*\S+\s+\S+\s+(Up|Down)\b", self.cmd(c, cmd))
        if not rows:
            raise self.unreadable("interfaces", cmd)
        return [(n, "up" if s.lower() == "up" else "down") for n, s in rows]

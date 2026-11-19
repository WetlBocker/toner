import re

from .sshbase import SshDriver, uptime_hours
from .clirows import CliRows
from . import clichecks

_IP = r"\d+\.\d+\.\d+\.\d+"


def cx_bgp_peers(text):
    """`show bgp all summary` (AOS-CX; every VRF and address family): [(neighbor, state)], a neighbor once per VRF however many
    address families list it. Columns: Neighbor Remote-AS MsgRcvd MsgSent Up/Down-Time State AdminStatus; a * marks a dynamic one."""
    peers, vrf = {}, ""
    for line in (text or "").splitlines():
        m = re.match(r"\s*VRF\s*:\s*(\S+)", line)
        if m:
            vrf = m.group(1)
        m = re.match(r"\s*\*?\s*(\S+)\s+[\d.]+\s+\d+\s+\d+\s+\S+\s+(\w+)\s+(\w+)\s*$", line)
        if m and m.group(3).lower() == "up":             # inferred: the guide shows AdminStatus 'Up' only; anything else is taken as shut down by an admin
            peers[(vrf, m.group(1))] = m.group(2)
    return [(n, s) for (_vrf, n), s in peers.items()]


def cx_ospf_neighbors(text):
    """`show ip ospf neighbors all-vrfs` (AOS-CX): [(router ID, state)]; 'FULL/DR' gives FULL."""
    return re.findall(rf"(?m)^\s*({_IP})\s+\d+\s+([^\s/]+)(?:/\S*)?\s+{_IP}\s", text or "")


def aoss_bgp_peers(text):
    """`show ip bgp summary` (AOS-S): [(address, state)]. Columns: Remote-Address Remote-AS Local-AS State Admin-Status."""
    rows = re.findall(rf"(?m)^\s*({_IP})\s+[\d.]+\s+[\d.]+\s+(\w+)\s+(\w+)\s*$", text or "")
    return [(a, s) for a, s, admin in rows if admin.lower() != "stop"]      # inferred: the guide shows 'Start' only; 'Stop' is a peer an admin stopped


def aoss_ospf_neighbors(text):
    """`show ip ospf neighbor` (AOS-S): [(router ID, state)]. NbIfState (DR, BDR) is blank for a neighbor that is neither."""
    return re.findall(rf"(?m)^\s*({_IP})\s+\d+\s+{_IP}\s+(?:B?DR\s+)?(\w+)\s+\d+\s+\d+", text or "")



class HpeDriver(CliRows, SshDriver):
    """Aruba / HPE switches: AOS-CX (aruba_aoscx) and AOS-S, formerly ProCurve (aruba_osswitch)."""
    DEFAULT_PLATFORM = "aruba_aoscx"

    @property
    def cx(self):
        return self.plat == "aruba_aoscx"

    def checks(self):
        return [("cpu", self.cpu), ("memory", self.memory), ("uptime", self.uptime),
                ("interfaces", self.interfaces), ("bgp", self.bgp), ("ospf", self.ospf), ("environment", self.environment), ("ntp", self.ntp)]

    def bgp(self, c):
        """A switch without BGP (not configured, not licensed, no such command) prints no neighbor rows and no local AS: not configured."""
        if self.cx:
            out = self.cmd(c, "show bgp all summary")
            peers = cx_bgp_peers(out)
        else:
            peers = aoss_bgp_peers(self.cmd(c, "show ip bgp summary"))
            # inferred: the AOS-S guide prints no sample of `show ip bgp general`; 'Local AS : n' is how its `show ip bgp` screen names the AS
            out = "" if peers else self.cmd(c, "show ip bgp general")
        running = bool(peers) or bool(re.search(r"Local AS\s*:\s*[1-9]", out))
        down = [n for n, s in peers if s.lower() != "established"]
        return self.peers_row("bgp", len(peers) - len(down), len(peers), down, protocol="BGP", running=running)

    def ospf(self, c):
        if self.cx:
            nbrs = cx_ospf_neighbors(self.cmd(c, "show ip ospf neighbors all-vrfs"))
            running = bool(nbrs) or bool(re.search(r"OSPFv2\s*:\s*Enabled", self.cmd(c, "show ip ospf all-vrfs")))
        else:
            nbrs = aoss_ospf_neighbors(self.cmd(c, "show ip ospf neighbor"))
            running = bool(nbrs) or bool(re.search(r"OSPF protocol\s*:\s*enabled", self.cmd(c, "show ip ospf general")))
        bad = [f"{r} ({s})" for r, s in nbrs if not clichecks.adjacent(s)]
        return self.peers_row("ospf", len(nbrs) - len(bad), len(nbrs), bad, protocol="OSPF", running=running)

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

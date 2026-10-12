"""Shared plumbing for the drivers that log in over SSH (netmiko)."""
import re

from netmiko import ConnectHandler

from .base import Driver, OK, WARN, FAIL, SEVERITY, grade_low
from core import display

_UNITS = {"year": 8760, "week": 168, "day": 24, "hour": 1, "minute": 1 / 60}


def uptime_hours(text):
    """'1 year, 2 weeks, 3 days, 4 hours, 5 minutes' -> hours."""
    return sum(int(n) * _UNITS[u] for n, u in re.findall(r"(\d+)\s+(year|week|day|hour|minute)", text))


def compact_hours(text):
    """'3w2d4h5m6s' (RouterOS) or '13w3d 22:40' (Junos) -> hours."""
    mult = {"y": 8760, "w": 168, "d": 24, "h": 1, "m": 1 / 60, "s": 1 / 3600}
    total = sum(int(n) * mult[u] for n, u in re.findall(r"(\d+)([ywdhms])", text))
    m = re.search(r"(\d+):(\d+)(?::(\d+))?", text)
    if m:
        total += int(m.group(1)) + int(m.group(2)) / 60 + int(m.group(3) or 0) / 3600
    return total


def worse(a, b):
    return a if SEVERITY[a] >= SEVERITY[b] else b


class Recorder:
    """Wraps a netmiko connection and remembers every command and what came back."""

    def __init__(self, conn, store):
        self._conn, self._store = conn, store

    def send_command(self, command, *a, **k):
        out = self._conn.send_command(command, *a, **k)
        self._store[command] = out if isinstance(out, str) else repr(out)[:4000]
        return out

    def __getattr__(self, name):
        return getattr(self._conn, name)


class SshDriver(Driver):
    """Subclasses set DEFAULT_PLATFORM and implement checks() -> [(key, method)]."""
    DEFAULT_PLATFORM = ""

    def checks(self):
        raise NotImplementedError

    def prepare(self, c):
        """Hook run once after login (e.g. to switch off paging)."""

    def connect(self):
        d = self.dev
        t = self.opts["ssh_timeout"]
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

    def run(self):
        out = []
        self._cache = {}
        self.plat = self.dev.get("platform") or self.DEFAULT_PLATFORM
        with self.connect() as conn:
            c = Recorder(conn, self.transcript)
            self.prepare(c)
            for name, fn in self.checks():
                if self.enabled(name):
                    self.safe(out, name, lambda fn=fn: fn(c))
            custom_ssh = [x for x in getattr(self, "custom", []) if x["kind"] == "ssh"]
            if custom_ssh:
                from core import custom
                out.extend(custom.run_ssh(self, c, custom_ssh))
        return out

    def cmd(self, c, command):
        """Run a command once per run, even if several checks read it."""
        if command not in self._cache:
            self._cache[command] = c.send_command(command)
        return self._cache[command]

    @staticmethod
    def unreadable(what, command):
        return ValueError(f"could not read {what} from '{command}' (unexpected output)")

    def uptime_row(self, hours, text):
        t = self.th["uptime"]
        status = grade_low(hours, t["warn"], t["fail"])
        return self.result("uptime", status, display.uptime(hours), "recent reboot" if status != OK else "", numeric=hours)

    def link_summary(self, up, total, names_down=(), warn_names=()):
        """'interfaces' row: counts, plus a WARN for ports in a bad state (e.g. err-disabled)."""
        msg = ", ".join(list(warn_names)[:5])
        status = WARN if warn_names else OK
        return self.result("interfaces", status, f"{up}/{total} up", msg, numeric=float(up))

    def peers_row(self, check, established, total, down, fail=True):
        if not total:
            return []                              # protocol not configured
        status = (FAIL if fail else WARN) if down else OK
        return self.result(check, status, f"{established}/{total} established", "down: " + ", ".join(down[:5])
                           if down else "", numeric=float(established))

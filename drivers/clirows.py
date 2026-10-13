"""Result rows shared by the SSH drivers (Cisco, Juniper, Arista, HPE, MikroTik): fans and power supplies, the clock, flash space. They turn what
drivers/clichecks.py read into a row; a platform without the command, or output that is not understood, gives no row."""
from . import clichecks
from .base import OK, WARN, FAIL, grade


class CliRows:
    def _out(self, c, command):
        """What a command printed (once per run when the driver caches, else straight from the connection)."""
        return self.cmd(c, command) if hasattr(self, "cmd") else c.send_command(command)

    def env_row(self, c, *commands):
        """Fans, power supplies and temperature, from one or more environment commands (those the platform lacks are ignored)."""
        scan = clichecks.scan_environment("\n".join(self._out(c, x) for x in commands))
        if scan is None:
            return []
        seen, problems = scan
        if not problems:
            return self.result("environment", OK, f"{seen} ok", "fans, power supplies and temperature", numeric=0.0)
        level = FAIL if any(lv == FAIL for lv, _ in problems) else WARN
        shown = "; ".join(m for _, m in problems[:3]) + (f"; and {len(problems) - 3} more" if len(problems) > 3 else "")
        return self.result("environment", level, f"{len(problems)} of {seen} not ok", shown, numeric=float(len(problems)))

    def ntp_row(self, state):
        if state is None:
            return []
        if state == "synchronized":
            return self.result("ntp", OK, "synchronized")
        return self.result("ntp", WARN, "not synchronized", "the clock is not following an NTP server, so logs and certificates show the wrong time")

    def flash_row(self, c, *commands):
        """Space used on the flash (the first command that prints a total wins)."""
        for command in commands:
            used = clichecks.flash_usage(self._out(c, command))
            if used:
                pct, free = used
                t = self.th["disk"]
                return self.result("flash", grade(pct, t["warn"], t["fail"]), f"{pct:.0f}%", f"{free / 1e6:.0f} MB free ({command.split()[-1]})", numeric=float(pct))
        return []

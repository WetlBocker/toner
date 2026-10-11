"""Windows computers and servers: CPU, memory, disks, uptime, pending reboot, services, event log errors, certificates
and patch age. The data comes from an agent that reports to Toner, from WinRM, or from this computer (core/winmon.py);
the checks are the same for all three."""
from datetime import datetime, timezone

from core import agents, winmon
from .base import Driver, OK, WARN, FAIL, grade, grade_low


class WindowsDriver(Driver):
    def fetch(self):
        """(report, minutes since it was made or None, how it was fetched)."""
        how = winmon.transport(self.dev)
        if how == "agent":
            report, age = agents.latest(self.name)
            if report is None:
                raise RuntimeError("no report has arrived from this computer's agent yet. Install it with the agent script "
                                   "(Inventory > edit > Windows > Get agent script) and check Settings > Agents "
                                   "is listening.")
            return report, age, how
        if how == "local":
            return winmon.collect_local(), None, how
        return winmon.collect_winrm(self.dev, self.password, timeout=int(self.opts["ssh_timeout"])), None, how

    def run(self):
        report, age, how = self.fetch()
        self.report, self.opts_w = report, winmon.options(self.dev)
        out = []
        silent = self._silent(out, age, how)
        if silent == FAIL:
            return out                                   # old numbers would only mislead
        if self.enabled("reachability") and not out:
            out.append(self.result("reachability", OK, report.get("computer", "answering"), winmon.summary(report)))
        for key, fn in (("cpu", self.cpu), ("memory", self.memory), ("disks", self.disks), ("uptime", self.uptime),
                        ("pending reboot", self.reboot), ("services", self.services), ("events", self.events),
                        ("certificates", self.certs), ("patches", self.patches), ("changes", self.changes)):
            if self.enabled(key):
                self.safe(out, key, fn)
        return out

    # ---------------------------------------------------------------- agent freshness
    def _silent(self, out, age, how):
        if how != "agent" or age is None:
            return OK
        t = self.th["agent_silent"]
        status = grade(age, t["warn"], t["fail"])
        shown = f"{age:.0f} min ago" if age < 120 else f"{age / 60:.1f} h ago"
        if status == OK:
            return OK
        out.append(self.result("reachability", status, f"last report {shown}",
                               "the agent has stopped reporting: the computer is off, offline, or the agent was removed"
                               if status == FAIL else "reports are late", numeric=float(age)))
        return status

    # ---------------------------------------------------------------- checks
    def cpu(self):
        v = self.report.get("cpu")
        return self.level_check("cpu", float(v)) if v is not None else []

    def memory(self):
        total, free = self.report.get("mem_total_mb"), self.report.get("mem_free_mb")
        if not total or free is None:
            return []
        used = (total - free) / total * 100
        return self.result("memory", grade(used, self.th["memory"]["warn"], self.th["memory"]["fail"]), f"{used:.0f}%",
                           f"{(total - free) / 1024:.1f} of {total / 1024:.1f} GB used", numeric=float(used))

    def disks(self):
        rows = []
        for d in self.report.get("disks") or []:
            if d.get("size"):
                rows.append((d["drive"], (1 - d["free"] / d["size"]) * 100, d["free"]))
        if not rows:
            return []
        worst = max(rows, key=lambda r: r[1])
        t = self.th["disk"]
        text = ", ".join(f"{drive} {pct:.0f}% ({winmon._fmt_bytes(free)} free)" for drive, pct, free in rows[:8])
        return self.result("disks", grade(worst[1], t["warn"], t["fail"]), f"{worst[1]:.0f}%",
                           f"fullest {worst[0]}; {text}", numeric=float(worst[1]))

    def uptime(self):
        hours = self.report.get("uptime_h")
        if hours is None:
            return []
        d, rest = divmod(int(hours * 3600), 86400)
        t = self.th["uptime"]
        status = grade_low(hours, t["warn"], t["fail"])
        return self.result("uptime", status, f"{d}d {rest // 3600}h", "recent reboot" if status != OK else "", numeric=float(hours))

    def reboot(self):
        reasons = self.report.get("reboot") or []
        return self.result("pending reboot", WARN if reasons else OK, "yes" if reasons else "no", ", ".join(reasons),
                           numeric=float(len(reasons)))

    def services(self):
        states = self.report.get("service_states") or {}
        lower = {k.lower(): v for k, v in states.items()}
        down_watched = [n for n in self.opts_w["watch"]
                        if n.lower() not in lower or lower[n.lower()] != "R"]
        missing = [n for n in down_watched if n.lower() not in lower]
        stopped = [s["name"] for s in winmon.stopped_services(self.report, self.opts_w["ignore"])
                   if s["name"] not in down_watched]
        if down_watched:
            names = [f"{n} (not installed)" if n in missing else n for n in down_watched]
            return self.result("services", FAIL, f"{len(down_watched)} required down", ", ".join(names[:6]),
                               numeric=float(len(down_watched) + len(stopped)))
        if stopped:
            return self.result("services", WARN, f"{len(stopped)} stopped", "automatic but not running: " + ", ".join(stopped[:6])
                               + (f" and {len(stopped) - 6} more" if len(stopped) > 6 else ""), numeric=float(len(stopped)))
        return self.result("services", OK, "all running", f"{len(self.opts_w['watch'])} watched" if self.opts_w["watch"] else "",
                           numeric=0.0)

    def events(self):
        ev = self.report.get("events")
        if not isinstance(ev, dict):
            return []
        n = int(ev.get("count") or 0)
        t = self.th["win_events"]
        top = ", ".join(f"{x['source']} x{x['count']}" for x in (ev.get("top") or [])[:3])
        return self.result("events", grade(n, t["warn"], t["fail"]), f"{n}{'+' if ev.get('capped') else ''}",
                           ("Critical/Error in the last 24 h: " + top) if n else "no Critical or Error events in 24 h", numeric=float(n))

    def certs(self):
        certs = self.report.get("certs")
        if certs is None:
            return []
        if not certs:
            return self.result("certificates", OK, "none expiring", "")
        worst = min(certs, key=lambda c: c.get("days", 9999))
        t = self.th["cert_days"]
        text = "; ".join(f"{c['subject'][:50]} ({c['days']} d)" for c in sorted(certs, key=lambda c: c["days"])[:4])
        return self.result("certificates", grade_low(worst["days"], t["warn"], t["fail"]),
                           f"{worst['days']} days" if worst["days"] >= 0 else "expired", text, numeric=float(worst["days"]))

    def changes(self):
        """What changed since the last check: installed software, local administrators, listening ports. The first check
        only records what is there; after that anything new is reported once."""
        r = self.report
        now = {"software": r.get("software"), "admins": r.get("admins"), "ports": r.get("ports")}
        if all(v is None for v in now.values()):
            return []
        before = agents.facts(self.name)
        if not self.opts.get("dry_run"):
            agents.set_facts(self.name, now)               # a Test or preview must not use up a change
        if before is None:
            return self.result("changes", OK, "baseline set", "changes are reported from the next check")
        notes = []
        if now["admins"] is not None and before.get("admins") is not None:
            added, gone = sorted(set(now["admins"]) - set(before["admins"])), sorted(set(before["admins"]) - set(now["admins"]))
            if added:
                notes.append("NEW ADMINISTRATOR: " + ", ".join(added))
            if gone:
                notes.append("administrator removed: " + ", ".join(gone))
        if now["software"] is not None and before.get("software") is not None:
            new = sorted(set(now["software"]) - set(before["software"]))
            gone = sorted(set(before["software"]) - set(now["software"]))
            upd = sorted(k for k in set(now["software"]) & set(before["software"]) if now["software"][k] != before["software"][k])
            for label, names in (("installed", new), ("removed", gone), ("updated", upd)):
                if names:
                    notes.append(f"{label}: " + ", ".join(names[:4]) + (f" and {len(names) - 4} more" if len(names) > 4 else ""))
        if now["ports"] is not None and before.get("ports") is not None:
            def fixed(ports):
                return {p for p in ports if int(p.split("/")[0]) < 49152}          # the dynamic range changes with every reboot
            opened, closed = sorted(fixed(now["ports"]) - fixed(before["ports"])), sorted(fixed(before["ports"]) - fixed(now["ports"]))
            if opened:
                notes.append("now listening: " + ", ".join(opened[:5]))
            if closed:
                notes.append("stopped listening: " + ", ".join(closed[:5]))
        if not notes:
            return self.result("changes", OK, "none", "", numeric=0.0)
        return self.result("changes", WARN, f"{len(notes)} kind(s)", "; ".join(notes), numeric=float(len(notes)))

    def patches(self):
        when = winmon._when(self.report.get("patched"))
        if when is None:
            return []
        days = max(0.0, (datetime.now(timezone.utc) - when).total_seconds() / 86400)
        t = self.th["patch_days"]
        return self.result("patches", grade(days, t["warn"], t["fail"]), f"{days:.0f} days",
                           f"last update installed {when:%Y-%m-%d}", numeric=float(days))

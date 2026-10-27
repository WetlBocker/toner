"""Windows computers and servers: CPU, memory, disks, uptime, pending reboot, services, event log errors, certificates
and patch age. The data comes from an agent that reports to Toner, from WinRM, or from this computer (core/winmon.py);
the checks are the same for all three."""
from datetime import datetime, timedelta, timezone

from core import agents, display, winmon
from .base import Driver, OK, WARN, FAIL, grade, grade_low


class WindowsDriver(Driver):
    def fetch(self):
        """(report, minutes since it was made or None, how it was fetched)."""
        how = winmon.transport(self.dev)
        if how == "agent":
            report, age = agents.latest(self.name)
            if report is not None:
                self._answered = datetime.now(timezone.utc) - timedelta(minutes=age)         # when the agent's report arrived
            if report is None:
                raise RuntimeError("no report has arrived from this computer's agent yet. Install it with the agent script "
                                   "(Inventory > edit > Windows > Get agent script) and check Settings > Agents "
                                   "is listening.")
            return report, age, how
        if how == "local":
            report = winmon.collect_local()
        else:
            report = winmon.collect_winrm(self.dev, self.password, timeout=int(self.opts["ssh_timeout"]))
        self._answered = datetime.now(timezone.utc)                    # when the answer arrived, to compare with the computer's own clock
        return report, None, how

    def run(self):
        report, age, how = self.fetch()
        self.report, self.opts_w = report, winmon.options(self.dev)
        if report.get("os"):                                 # 'Microsoft Windows Server 2022 Standard (build 20348)'
            self.found_software(str(report["os"]).strip() + (f" (build {report['build']})" if report.get("build") else ""))
        out = []
        silent = self._silent(out, age, how)
        if silent == FAIL:
            return out                                   # old numbers would only mislead
        if self.enabled("reachability") and not out:
            out.append(self.result("reachability", OK, report.get("computer", "answering"), winmon.summary(report)))
        for key, fn in (("cpu", self.cpu), ("memory", self.memory), ("disks", self.disks), ("uptime", self.uptime),
                        ("pending reboot", self.reboot), ("services", self.services), ("events", self.events),
                        ("certificates", self.certs), ("patches", self.patches), ("changes", self.changes),
                        ("disk health", self.disk_health), ("bitlocker", self.bitlocker), ("antivirus", self.antivirus), ("firewall", self.firewall),
                        ("clock", self.clock), ("logons", self.logons), ("activation", self.activation), ("sessions", self.sessions),
                        ("tasks", self.tasks), ("ad replication", self.ad), ("hyper-v", self.hyperv), ("backup", self.backup)):
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
        t = self.th["uptime"]
        status = grade_low(hours, t["warn"], t["fail"])
        return self.result("uptime", status, display.uptime(hours), "recent reboot" if status != OK else "", numeric=float(hours))

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

    # ---------------------------------------------------------------- the machine's own health
    def disk_health(self):
        phys, vols = self.report.get("physical"), self.report.get("volumes")
        if not phys and not vols:
            return []
        bad = []
        for d in phys or []:
            health, op = (d.get("health") or ""), (d.get("op") or "")
            if health.lower() == "healthy" and op in ("OK", ""):
                continue
            hard = health.lower() == "unhealthy" or "fail" in op.lower() or "lost" in op.lower()
            bad.append((FAIL if hard else WARN, f"{d.get('name') or 'disk'}: {health}" + (f" ({op})" if op not in ("", "OK") else "")))
        for v in vols or []:
            health = (v.get("health") or "")
            if health.lower() not in ("healthy", ""):
                bad.append((FAIL if health.lower() == "unhealthy" else WARN, f"volume {v.get('drive')}: {health}"))
        n = len(phys or []) + len(vols or [])
        if not bad:
            return self.result("disk health", OK, f"{n} ok", f"{len(phys or [])} physical disk(s), {len(vols or [])} volume(s)", numeric=0.0)
        worst = FAIL if any(s == FAIL for s, _ in bad) else WARN
        return self.result("disk health", worst, f"{len(bad)} not healthy", "; ".join(m for _, m in bad[:4]), numeric=float(len(bad)))

    def bitlocker(self):
        vols = self.report.get("bitlocker")
        if not vols:
            return []
        off = [v for v in vols if str(v.get("protection")).lower() in ("off", "0")]
        if not off:
            return self.result("bitlocker", OK, f"{len(vols)} protected", "", numeric=0.0)
        return self.result("bitlocker", WARN, f"{len(off)} not protected", "not encrypted: " + ", ".join(str(v.get("mount")) for v in off[:5]), numeric=float(len(off)))

    def antivirus(self):
        d, products = self.report.get("defender"), self.report.get("av_products") or []
        third_party = [p for p in products if "defender" not in p.lower()]
        if d is None and not products:
            return []
        if d and d.get("enabled") and str(d.get("mode") or "").lower() in ("passive", "edr block mode", "sxs passive mode") and third_party:
            return self.result("antivirus", OK, ", ".join(third_party[:2]), "Defender is in passive mode")
        if d and d.get("enabled"):
            if not d.get("realtime"):
                return self.result("antivirus", FAIL, "real-time protection off", "Windows Defender")
            t = self.th["av_age"]
            days = float(d.get("sig_days") or 0)
            return self.result("antivirus", grade(days, t["warn"], t["fail"]), "Defender, up to date" if days < t["warn"] else f"signatures {days:.0f} days old",
                               f"signatures {days:.0f} day(s) old", numeric=days)
        if third_party:
            return self.result("antivirus", OK, ", ".join(third_party[:2]), "its own state is not read")
        return self.result("antivirus", FAIL, "no antivirus running", "Windows Defender is off and no other product is registered")

    def firewall(self):
        profs = self.report.get("firewall")
        if not profs:
            return []
        off = [p.get("name") for p in profs if not p.get("on")]
        if not off:
            return self.result("firewall", OK, "on", "all profiles", numeric=0.0)
        return self.result("firewall", WARN, f"{len(off)} off", "Windows Firewall is off for: " + ", ".join(map(str, off)), numeric=float(len(off)))

    def clock(self):
        rep_now, ref = winmon._when(self.report.get("now")), getattr(self, "_answered", None)
        if rep_now is None or ref is None:
            return []
        off = (rep_now - ref).total_seconds()
        t = self.th["clock_offset"]
        status = grade(abs(off), t["warn"], t["fail"])
        return self.result("clock", status, f"{off:+.0f} s", ("the computer's clock is " + ("ahead of" if off > 0 else "behind") + " Toner's") if status != OK else "",
                           numeric=float(abs(off)))

    def logons(self):
        lg = self.report.get("logons")
        if not isinstance(lg, dict) or lg.get("failed") is None:
            return []
        t, tl = self.th["failed_logons"], self.th["lockouts"]
        n, locks = int(lg.get("failed") or 0), int(lg.get("lockouts") or 0)
        s1, s2 = grade(n, t["warn"], t["fail"]), grade(locks, tl["warn"], tl["fail"])
        status = FAIL if FAIL in (s1, s2) else WARN if WARN in (s1, s2) else OK
        top = ", ".join(f"{u['user']} x{u['count']}" for u in (lg.get("top") or [])[:3])
        bits = ([f"top: {top}"] if top and n else []) + ([f"{locks} account lockout(s)"] if locks else [])
        return self.result("logons", status, f"{n}{'+' if lg.get('capped') else ''} failed", "; ".join(bits) or "in the last 24 h", numeric=float(n))

    def activation(self):
        a = self.report.get("activation")
        if not isinstance(a, dict):
            return []
        s = int(a.get("status") or 0)
        if s == 1:
            return self.result("activation", OK, "licensed", "")
        if s in (2, 3, 4, 6):
            days = (a.get("grace_min") or 0) / 1440
            return self.result("activation", WARN if days > 7 else FAIL, "not activated", f"in a grace period: {days:.0f} day(s) left", numeric=float(days))
        return self.result("activation", FAIL, "not licensed" if s == 0 else "activation needed", "Windows is not activated")

    def sessions(self):
        s = self.report.get("sessions")
        if not isinstance(s, dict):
            return []
        d, a = int(s.get("disconnected") or 0), int(s.get("active") or 0)
        t = self.th["rdp_disconnected"]
        return self.result("sessions", grade(d, t["warn"], t["fail"]), f"{a} active, {d} disconnected",
                           "disconnected sessions keep running programs: log them off" if d >= t["warn"] else "", numeric=float(d))

    def tasks(self):
        failed = self.report.get("task_failures")
        if failed is None:
            return []
        failed = [f for f in failed if isinstance(f, dict) and not winmon._matches(f.get("name", ""), self.opts_w["ignore"])]
        if not failed:
            return self.result("tasks", OK, "none failed", "scheduled tasks outside Microsoft's, last 7 days", numeric=0.0)
        return self.result("tasks", WARN, f"{len(failed)} failed", "; ".join(f"{f.get('name')} ({f.get('result')})" for f in failed[:4]), numeric=float(len(failed)))

    def ad(self):
        a = self.report.get("ad")
        if not isinstance(a, dict):
            return []
        fails, total = int(a.get("repl_fail") or 0), int(a.get("repl_total") or 0)
        if not fails:
            return self.result("ad replication", OK, f"{total} ok", "Active Directory replication", numeric=0.0)
        return self.result("ad replication", FAIL, f"{fails} of {total} failing", "run repadmin /showrepl on this domain controller", numeric=float(fails))

    def hyperv(self):
        h = self.report.get("hyperv")
        if not isinstance(h, dict):
            return []
        bad = h.get("bad") or []
        if not bad:
            return self.result("hyper-v", OK, f"{h.get('running', 0)} running, {h.get('off', 0)} off", "", numeric=0.0)
        return self.result("hyper-v", FAIL, f"{len(bad)} need attention", ", ".join(map(str, bad[:4])), numeric=float(len(bad)))

    def backup(self):
        b = self.report.get("backup")
        if not isinstance(b, dict):
            return []
        when = winmon._when(b.get("last"))
        if when is None:
            return []
        days = max(0.0, (datetime.now(timezone.utc) - when).total_seconds() / 86400)
        t = self.th["backup_days"]
        failed = int(b.get("result") or 0) != 0
        status = FAIL if failed else grade(days, t["warn"], t["fail"])
        return self.result("backup", status, f"{days:.0f} days ago", f"last good Windows Server Backup {when:%Y-%m-%d %H:%M}" + ("; the latest run failed" if failed else ""),
                           numeric=float(days))

    def patches(self):
        when = winmon._when(self.report.get("patched"))
        if when is None:
            return []
        days = max(0.0, (datetime.now(timezone.utc) - when).total_seconds() / 86400)
        t = self.th["patch_days"]
        return self.result("patches", grade(days, t["warn"], t["fail"]), f"{days:.0f} days",
                           f"last update installed {when:%Y-%m-%d}", numeric=float(days))

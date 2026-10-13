"""UniFi Site Manager (api.ui.com): every console and site on the account at once, through one API key. It reports device status and
firmware per console, the health figures UniFi keeps for each site, the ISP's latency and packet loss, and SD-WAN topologies.
The Site field is an optional filter on console and site names ('default', blank, * and all mean everything)."""
from datetime import datetime, timezone

from .base import OK, WARN, FAIL, grade, grade_low
from .unifiapi import CLOUD_HOST, UnifiApi, state_status


class UnifiCloudDriver(UnifiApi):
    LOCAL = False

    def base(self):
        return f"https://{(self.dev.get('host') or '').strip() or CLOUD_HOST}/v1"

    def run(self):
        out = []
        hosts = self.token_pages("/hosts")
        if self.enabled("reachability"):
            out.append(self.result("reachability", OK, f"{len(hosts)} console{'s' if len(hosts) != 1 else ''}", "UniFi Site Manager API"))
        if self.enabled("consoles"):
            self.safe(out, "consoles", lambda: self.consoles(out, hosts))
        sites = self.token_pages("/sites") if any(self.enabled(k) for k in ("sites", "isp latency", "isp loss")) else []
        names = {(s.get("hostId"), s.get("siteId")): ((s.get("meta") or {}).get("name") or s.get("siteId")) for s in sites}
        if self.enabled("devices") or self.enabled("firmware"):
            self.safe(out, "devices", lambda: self.devices(out))
        if self.enabled("sites"):
            for s in sites:
                if self.wanted((s.get("meta") or {}).get("name"), s.get("siteId"), s.get("hostId")):
                    self.site(out, s)
        if self.enabled("isp latency") or self.enabled("isp loss"):
            self.safe(out, "isp", lambda: self.isp(out, names))
        if self.enabled("sd-wan"):
            self.safe(out, "sd-wan", lambda: self.sdwan(out))
        return out

    # ---------------------------------------------------------------- the consoles themselves
    def consoles(self, out, hosts):
        """Each console's last backup (an old one means backups have stopped) and whether it has been blocked from the account."""
        names = {}
        for entry in self.token_pages("/devices"):
            names[entry.get("hostId")] = entry.get("hostName")
        t = self.th["backup_days"]
        for h in hosts:
            label = names.get(h.get("id")) or h.get("ipAddress") or h.get("id")
            if not self.wanted(label, h.get("id")):
                continue
            if h.get("isBlocked"):
                out.append(self.row(label, "console", FAIL, "blocked", "this console is blocked from the account"))
                continue
            when = h.get("latestBackupTime")
            days = None
            try:
                days = (datetime.now(timezone.utc) - datetime.fromisoformat(str(when).replace("Z", "+00:00"))).total_seconds() / 86400 if when else None
            except ValueError:
                days = None
            if days is None:
                continue
            days = max(0.0, days)
            out.append(self.row(label, "console", grade(days, t["warn"], t["fail"]), f"backup {days:.0f} days ago" if days >= 1 else "backed up today",
                                "backups may have stopped" if days >= t["warn"] else "", numeric=days))

    # ---------------------------------------------------------------- devices, per console
    def devices(self, out):
        sev = self.opts["firmware_severity"]
        for host in self.token_pages("/devices"):
            label = host.get("hostName") or host.get("hostId")
            if not self.wanted(label, host.get("hostId")):
                continue
            devs = [d for d in host.get("devices") or [] if isinstance(d, dict)]
            if not devs:
                continue
            if self.enabled("devices"):
                bad = [(d, state_status(d.get("status"))) for d in devs]
                down = [(d, s) for d, s in bad if s[0] != OK]
                if not down:
                    out.append(self.row(label, "devices", OK, f"{len(devs)} online", numeric=0.0))
                else:
                    console_down = any(d.get("isConsole") and s[0] == FAIL for d, s in down)
                    names = ", ".join(f"{d.get('name') or d.get('mac')} ({s[1]})" for d, s in down[:6])
                    out.append(self.row(label, "devices", FAIL if console_down or any(s[0] == FAIL for _d, s in down) else WARN,
                                        f"{len(devs) - len(down)}/{len(devs)} online", names + (f" and {len(down) - 6} more" if len(down) > 6 else ""),
                                        numeric=float(len(down))))
            if self.enabled("firmware") and sev != "Ignore":
                old = [d for d in devs if d.get("updateAvailable")]
                if old:
                    out.append(self.row(label, "firmware", FAIL if sev == "FAIL" else WARN, f"{len(old)} to update",
                                        ", ".join(f"{d.get('name') or d.get('mac')} -> {d.get('updateAvailable')}" for d in old[:6]), numeric=float(len(old))))

    # ---------------------------------------------------------------- sites
    def site(self, out, s):
        meta, stats = s.get("meta") or {}, s.get("statistics") or {}
        label = meta.get("name") or s.get("siteId")
        counts = stats.get("counts") or {}
        issues = stats.get("internetIssues") or []
        offline, critical = int(counts.get("offlineDevice") or 0), int(counts.get("criticalNotification") or 0)
        problems = []
        if offline:
            problems.append(f"{offline} device{'s' if offline != 1 else ''} offline")
        if issues:
            problems.append(f"{len(issues)} internet issue{'s' if len(issues) != 1 else ''}")
        if critical:
            problems.append(f"{critical} critical notification{'s' if critical != 1 else ''}")
        status = FAIL if (offline and counts.get("offlineGatewayDevice")) else WARN if problems else OK
        total = counts.get("totalDevice")
        out.append(self.row(label, "site health", status, "; ".join(problems[:1]) or (f"{total} devices" if total is not None else "ok"),
                            "; ".join(problems) if len(problems) > 1 else "", numeric=float(offline)))
        wan = (stats.get("percentages") or {}).get("wanUptime")
        if wan is not None:
            t = self.th["wan_uptime"]
            out.append(self.row(label, "wan uptime", grade_low(float(wan), t["warn"], t["fail"]), f"{float(wan):.2f}%", numeric=float(wan)))

    # ---------------------------------------------------------------- the ISP
    def isp(self, out, names):
        data = self.get("/isp-metrics/5m", {"duration": "24h"})
        for entry in (data.get("data") if isinstance(data, dict) else data) or []:
            site = names.get((entry.get("hostId"), entry.get("siteId")), entry.get("siteId"))
            if not self.wanted(site, entry.get("siteId"), entry.get("hostId")):
                continue
            periods = [p for p in entry.get("periods") or [] if isinstance(p, dict)]
            if not periods:
                continue
            latest = sorted(periods, key=lambda p: str(p.get("metricTime", "")))[-1]
            wan = (latest.get("data") or {}).get("wan") or {}
            isp = wan.get("ispName") or ""
            if self.enabled("isp latency") and wan.get("avgLatency") is not None:
                v, t = float(wan["avgLatency"]), self.th["isp_latency"]
                out.append(self.row(site, "isp latency", grade(v, t["warn"], t["fail"]), f"{v:.0f} ms", isp, numeric=v))
            if self.enabled("isp loss") and wan.get("packetLoss") is not None:
                v, t = float(wan["packetLoss"]), self.th["isp_loss"]
                out.append(self.row(site, "isp loss", grade(v, t["warn"], t["fail"]), f"{v:g}%", isp, numeric=v))

    # ---------------------------------------------------------------- SD-WAN
    def sdwan(self, out):
        for cfg in self.token_pages("/sd-wan-configs", optional=True):
            if not self.wanted(cfg.get("name"), cfg.get("id")):
                continue
            data = self.get(f"/sd-wan-configs/{cfg.get('id')}/status", optional=True)
            st = (data.get("data") if isinstance(data, dict) and "data" in data else data) or {}
            label = f"SD-WAN {cfg.get('name') or cfg.get('id')}"
            generate = str(st.get("generateStatus") or "")
            members = [m for m in (st.get("hubs") or []) + (st.get("spokes") or []) if isinstance(m, dict)]
            failed = [m for m in members if str(m.get("applyStatus") or "ok") not in ("ok", "creating", "updating", "removing")]
            down = [(m, c) for m in (st.get("spokes") or []) if isinstance(m, dict) for c in m.get("connections") or []
                    for t in c.get("tunnels") or [] if t.get("status") == "disconnected"]
            errors = list(st.get("errors") or [])
            if generate == "GENERATE_FAILED" or errors:
                out.append(self.row(label, "sd-wan", FAIL, "configuration failed", "; ".join(str(e) for e in errors[:3])))
            elif failed or down:
                bits = ([f"{len(failed)} not applied"] if failed else []) + ([f"{len(down)} tunnel{'s' if len(down) != 1 else ''} down"] if down else [])
                out.append(self.row(label, "sd-wan", WARN, ", ".join(bits), numeric=float(len(failed) + len(down))))
            else:
                out.append(self.row(label, "sd-wan", OK, f"{len(members)} members", generate.lower() if generate not in ("", "OK") else ""))

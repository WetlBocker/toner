import requests
import urllib3
from .base import Driver, OK, WARN, FAIL, grade, grade_low

STATES = {0: "disconnected", 1: "connected", 2: "pending", 4: "upgrading",
          5: "provisioning", 6: "heartbeat missed", 7: "adopting", 11: "isolated"}

def fmt_uptime(s):
    d, r = divmod(int(s), 86400)
    return f"{d}d {r // 3600}h"

class UnifiDriver(Driver):
    def run(self):
        d = self.dev
        verify = bool(d.get("verify_ssl"))
        if not verify:
            urllib3.disable_warnings()
        base = f"https://{d['host']}" + (f":{d['port']}" if d.get("port") else "")
        s = requests.Session()
        s.verify = verify
        timeout = self.opts["http_timeout"]
        r = s.post(f"{base}/api/auth/login", timeout=timeout,
                   json={"username": d["username"], "password": self.password})
        r.raise_for_status()
        if "X-CSRF-Token" in r.headers:
            s.headers["X-CSRF-Token"] = r.headers["X-CSRF-Token"]

        def get(url):
            resp = s.get(url, timeout=timeout)
            resp.raise_for_status()
            return resp.json()["data"]

        # The API path needs the site's internal name; accept the display name too.
        want = (d.get("site") or "default").strip()
        sites = get(f"{base}/proxy/network/api/self/sites")
        match = next((x for x in sites if want.lower() in (x.get("name", "").lower(),
                                                           x.get("desc", "").lower())), None)
        if not match:
            avail = ", ".join(f"{x.get('desc')} ({x.get('name')})" for x in sites) or "none visible"
            raise ValueError(f"site '{want}' not found; this account can see: {avail}")

        api = f"{base}/proxy/network/api/s/{match['name']}"
        devices = get(f"{api}/stat/device")
        health = get(f"{api}/stat/health")
        if not devices and not health:
            raise ValueError(f"site '{want}' returned no devices or health data "
                             "(check the account's permissions on this site)")

        out = []
        for h in health if self.enabled("site health") else []:
            ok = h.get("status") in ("ok", "unknown")
            out.append(self.result(f"site {h['subsystem']}", OK if ok else WARN, h.get("status", "?")))
        for dev in devices:
            self.safe(out, "device", lambda dev=dev: self.check_device(dev))
        try:
            s.post(f"{base}/api/auth/logout", timeout=min(5, timeout))
        except requests.RequestException:
            pass
        return out

    def check_device(self, dev):
        label = f"{self.name} / {dev.get('name') or dev.get('mac')}"
        rows = []
        def add(check, status, value="", msg="", numeric=None):
            r = self.result(check, status, value, msg, numeric)
            r.device = label
            rows.append(r)
        def level(check, v, key=None, unit="%"):
            t = self.th[key or check]
            add(check, grade(v, t["warn"], t["fail"]), f"{v:.0f}{unit}", numeric=float(v))

        st = dev.get("state")
        add("state", OK if st == 1 else FAIL, STATES.get(st, st))
        if st != 1:
            return rows
        if self.enabled("uptime"):
            secs = dev.get("uptime", 0)
            t = self.th["uptime"]
            status = grade_low(secs / 3600, t["warn"], t["fail"])
            add("uptime", status, fmt_uptime(secs), "recent reboot" if status != OK else "",
                numeric=secs / 3600)
        stats = dev.get("system-stats", {})
        if "cpu" in stats and self.enabled("cpu"):
            level("cpu", float(stats["cpu"]))
        if "mem" in stats and self.enabled("memory"):
            level("memory", float(stats["mem"]))
        if dev.get("general_temperature") and self.enabled("temperature"):
            level("temperature", float(dev["general_temperature"]), unit=" C")
        sev = self.opts["firmware_severity"]
        if dev.get("upgradable") and self.enabled("firmware") and sev != "Ignore":
            add("firmware", FAIL if sev == "FAIL" else WARN, dev.get("version"),
                f"update: {dev.get('upgrade_to_firmware')}")

        # Switch / gateway ports
        ports = dev.get("port_table") or []
        if ports:
            dead = [p.get("name", p.get("port_idx")) for p in ports if p.get("is_uplink") and not p.get("up")]
            if dead and self.enabled("uplink"):
                add("uplink", FAIL, "down", ", ".join(map(str, dead)))
            if self.enabled("port errors"):
                errs = sum(p.get("rx_errors", 0) + p.get("tx_errors", 0) for p in ports if p.get("up"))
                t = self.th["port_errors"]
                if not self.delta_mode:
                    add("port errors", grade(errs, t["warn"], t["fail"]), errs, numeric=float(errs))
                else:                                # new errors since the previous run
                    new = self.delta(f"{label}|port errors", errs)
                    if new is None:
                        add("port errors", OK, "baseline set", "counted from the next run")
                    else:
                        add("port errors", grade(new, t["warn"], t["fail"]), f"+{new:.0f}",
                            numeric=float(new))

        # Access points
        if dev.get("type") == "uap":
            if self.enabled("clients"):
                add("clients", OK, dev.get("num_sta", 0), numeric=float(dev.get("num_sta", 0)))
            for rad in (dev.get("radio_table_stats") or []) if self.enabled("channel util") else []:
                if rad.get("cu_total") is not None:
                    level(f"channel util ({rad.get('radio', '?')})", float(rad["cu_total"]), "channel_util")
        return rows

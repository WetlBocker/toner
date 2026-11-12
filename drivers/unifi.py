from core import proxy, display, tlsverify
import requests
from .base import AuthRejected, Driver, OK, WARN, FAIL, grade, grade_low

STATES = {0: "disconnected", 1: "connected", 2: "pending", 4: "upgrading",
          5: "provisioning", 6: "heartbeat missed", 7: "adopting", 11: "isolated"}

def fmt_uptime(s):
    return display.uptime(seconds=s)


def sign_in(s, base, username, password, timeout, verify):
    """Sign a session in to a UniFi OS console. A refusal (401 or 403: a console answers a wrong password with 403) says so in words,
    with the console's own reason and never the password; it is not retried (repeating a refused login is how accounts get locked)."""
    r = s.post(f"{base}/api/auth/login", timeout=timeout, verify=verify, json={"username": username, "password": password})
    if getattr(r, "status_code", 200) in (401, 403):
        try:
            body = r.json()
            said = str(body.get("message") or body.get("code") or "") if isinstance(body, dict) else ""
        except ValueError:
            said = ""
        raise AuthRejected(f"the console did not accept the user name and password (HTTP {r.status_code})" + (f": {said[:200]}" if said else ""))
    r.raise_for_status()
    token = getattr(r, "headers", {}).get("X-CSRF-Token")
    if token:
        s.headers["X-CSRF-Token"] = token


def own_device(devices, host):
    """The device a console's entry itself stands for: the one at the entry's address, else the only gateway (UDM, UGW, UXG). Its rows
    are the entry's own; every other device is listed under the entry (core/unifikids.py), as the Network API driver does."""
    host = (host or "").strip().lower()
    here = [d for d in devices if host and str(d.get("ip") or "").lower() == host]
    gws = [d for d in devices if str(d.get("type") or "").lower() in ("ugw", "udm", "uxg")]
    return here[0] if here else gws[0] if len(gws) == 1 else None

class UnifiDriver(Driver):
    def run(self):
        d = self.dev
        verify = tlsverify.verify(d)
        base = f"https://{d['host']}" + (f":{d['port']}" if d.get("port") else "")
        s = requests.Session()
        s.proxies.update(proxy.requests_kwargs(d).get("proxies", {}))
        timeout = self.opts["http_timeout"]
        # requests lets REQUESTS_CA_BUNDLE (core/trust.py sets it) override a session's verify=False, so each call carries the flag itself
        sign_in(s, base, d["username"], self.password, timeout, verify)

        def get(url):
            resp = s.get(url, timeout=timeout, verify=verify)
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
        own = own_device(devices, d.get("host"))
        for dev in devices:
            self.safe(out, "device", lambda dev=dev: self.check_device(dev, dev is own))
        try:
            s.post(f"{base}/api/auth/logout", timeout=min(5, timeout), verify=verify)
        except requests.RequestException:
            pass
        return out

    def check_device(self, dev, own=False):
        label = self.name if own else f"{self.name} / {dev.get('name') or dev.get('mac')}"
        rows = []
        def add(check, status, value="", msg="", numeric=None):
            r = self.result(check, status, value, msg, numeric)
            r.device = label
            if not own:                              # listed under the console in the Inventory, by its MAC
                r.kid = (dev.get("mac") or dev.get("name"), dev.get("shortname") or dev.get("model") or "")
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

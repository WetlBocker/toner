from core import proxy
import requests
import urllib3
from datetime import datetime, timezone

from . import apichecks
from .base import AuthRejected, Driver, OK, WARN, FAIL, grade, grade_low

class FortinetDriver(Driver):
    def _get(self, path):
        d = self.dev
        if not d.get("verify_ssl"):
            urllib3.disable_warnings()
        port = d.get("port") or 443
        r = requests.get(f"https://{d['host']}:{port}/api/v2/monitor/{path}",
                         headers={"Authorization": f"Bearer {self.password}"},
                         verify=bool(d.get("verify_ssl")), timeout=self.opts["http_timeout"], **proxy.requests_kwargs(d))
        r.raise_for_status()
        return r.json()["results"]

    def _optional(self, path):
        """Some of these exist only when the feature is licensed or switched on; the firewall answers 400, 404 or 424 when it is not."""
        try:
            return self._get(path)
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code in (400, 403, 404, 405, 424):
                return None
            raise

    def run(self):
        out = []
        try:
            status = self._get("system/status")              # a rejected token is said once, not once per check
            if isinstance(status, dict):
                self.found_software(status.get("version", ""))
        except requests.HTTPError as e:
            code = getattr(e.response, "status_code", None)
            if code == 401:
                raise AuthRejected("FortiGate rejected the API token (HTTP 401): check the token stored for this device, that it has not expired, "
                                   "and that this computer is in the API admin's trusted hosts.") from None
            if code == 403:
                raise AuthRejected("FortiGate refused the API token (HTTP 403): the REST API admin needs read access, and this computer must be in "
                                   "its trusted hosts.") from None
        except Exception:
            pass
        for name, fn in (("resources", self.resources), ("firmware", self.firmware),
                         ("wan links", self.wan), ("ha", self.ha), ("vpn", self.vpn), ("licenses", self.licenses), ("certificates", self.certificates),
                         ("interfaces", self.interfaces), ("ha sync", self.ha_sync), ("fortiaps", self.fortiaps), ("fortiswitches", self.fortiswitches),
                         ("log disk", self.log_disk)):
            if self.enabled(name):
                self.safe(out, name, fn)
        return out

    def resources(self):
        res = self._get("system/resource/usage?scope=global")
        return [self.level_check("cpu", res["cpu"][0]["current"]),
                self.level_check("memory", res["mem"][0]["current"])]

    def firmware(self):
        return self.result("firmware", OK, self._get("system/status").get("version", "?"))

    def wan(self):
        ifs = self._get("system/interface?scope=global")
        wans = {n: i for n, i in ifs.items() if i.get("role") == "wan"}
        down = [n for n, i in wans.items() if not i.get("link")]
        return self.result("wan links", FAIL if down else OK,
                           f"{len(wans) - len(down)}/{len(wans)} up", ", ".join(down))

    def ha(self):
        peers = self._get("system/ha-peer")
        expected = bool(self.dev.get("ha_expected"))
        n = len(peers) if isinstance(peers, list) else 0
        if not expected and n == 0:
            return self.result("ha", OK, "not configured")
        # a healthy cluster shows this unit plus its peers
        status = OK if n >= 1 else FAIL
        names = ", ".join(p.get("hostname", p.get("serial_no", "?")) for p in peers)
        return self.result("ha", status, f"{n + 1 if n else 1} member(s)",
                           names if n else "no HA peer visible", numeric=float(n + 1))

    def licenses(self):
        """FortiCare support and FortiGuard subscriptions: the one that ends first."""
        found = apichecks.fortinet_licenses(self._optional("license/status"))
        if not found:
            return []
        name, days, state = min(found, key=lambda x: x[1])
        t = self.th["support_days"]
        status = grade_low(days, t["warn"], t["fail"])
        soon = [f"{n} ({d:.0f} d)" for n, d, _ in sorted(found, key=lambda x: x[1]) if d < t["warn"]]
        return self.result("licenses", status, f"{days:.0f} days" if days >= 0 else "expired", ("ends first: " + name + (f"; also {', '.join(soon[1:4])}" if len(soon) > 1 else "")) if status != OK else "",
                           numeric=float(days))

    def certificates(self):
        found = apichecks.fortinet_cert_days(self._optional("system/available-certificates"))
        if not found:
            return []
        name, days = min(found, key=lambda x: x[1])
        t = self.th["cert_days"]
        return self.result("certificates", grade_low(days, t["warn"], t["fail"]), f"{days:.0f} days" if days >= 0 else "expired", name, numeric=float(days))

    def _physical(self):
        ifs = self._get("system/interface?scope=global")
        return {n: i for n, i in ifs.items() if str(i.get("type", "physical")).lower() == "physical"}

    @staticmethod
    def _if_state(i):
        if i.get("link"):
            return "up"
        return "down" if str(i.get("status", "up")).lower() == "up" and i.get("role") != "undefined" else "off"

    def list_interfaces(self):
        return [(n, self._if_state(i)) for n, i in self._physical().items()]

    def interfaces(self):
        phys = self._physical()
        if not phys:
            return []
        rows = self.interfaces_row([(n, self._if_state(i)) for n, i in phys.items()])
        rows = [rows] if rows else []
        errs = {n: int(i.get("rx_errors", 0) or 0) + int(i.get("tx_errors", 0) or 0) for n, i in phys.items() if i.get("link")}
        found = self.error_counter_rows("interface errors", errs) if errs else None
        if found:
            rows.append(found)
        return rows

    def ha_sync(self):
        differ = apichecks.fortinet_ha_sync(self._optional("system/ha-checksums"))
        if differ is None:
            return []
        if not differ:
            return self.result("ha sync", OK, "in sync", "")
        return self.result("ha sync", WARN, "out of sync", "configuration differs: " + ", ".join(differ[:5]), numeric=float(len(differ)))

    def _managed(self, path, check, what):
        rows = self._optional(path)
        if not rows:
            return []
        up, down = apichecks.fortinet_status_list(rows)
        total = up + len(down)
        return self.result(check, WARN if down else OK, f"{up}/{total} online", (f"{what} not online: " + ", ".join(down[:5])) if down else "", numeric=float(up))

    def fortiaps(self):
        return self._managed("wifi/managed_ap", "fortiaps", "access points")

    def fortiswitches(self):
        return self._managed("switch-controller/managed-switch/status", "fortiswitches", "switches")

    def log_disk(self):
        pct = apichecks.fortinet_log_disk(self._optional("log/current-disk-usage"))
        if pct is None:
            return []
        return self.level_check("log disk", pct, th_key="disk")

    def vpn(self):
        tunnels = self._get("vpn/ipsec")
        if not tunnels:
            return []
        down = [t["name"] for t in tunnels
                if not t.get("proxyid") or any(p.get("status") != "up" for p in t["proxyid"])]
        up = len(tunnels) - len(down)
        return self.result("ipsec tunnels", WARN if down else OK, f"{up}/{len(tunnels)} up",
                           "down: " + ", ".join(down[:5]) if down else "", numeric=float(up))
